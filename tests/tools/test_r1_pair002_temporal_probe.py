import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.common.models.evidence import Evidence
from tools.analysis.r1_pair002_temporal_probe import (
    APPROVED_POLICY_CONFIG_HASH,
    APPROVED_POLICY_ID,
    APPROVED_POLICY_VERSION,
    ATTACK_RUN_ID,
    EXTRACTOR_VERSION,
    NORMAL_RUN_ID,
    ArtifactHashes,
    PairRunSpec,
    _sha256_lf_normalized_text,
    run_probe,
)

ENTITY_ID = "fixture-target"
ATTACK_START = datetime(2026, 10, 5, 19, 33, 25, 834000, tzinfo=UTC)
NORMAL_START = datetime(2026, 10, 5, 19, 56, 52, 355000, tzinfo=UTC)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(
    *,
    evidence_id: str,
    run_id: str,
    timestamp: datetime,
    evidence_type: str,
    event_ids: list[str],
    features: dict[str, object] | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=run_id,
        timestamp=timestamp,
        entity_id=ENTITY_ID,
        evidence_type=evidence_type,
        event_ids=event_ids,
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version=EXTRACTOR_VERSION,
        features=features or {},
    )


def _write_artifacts(
    root: Path,
    *,
    run_id: str,
    evidences: list[Evidence],
    anchor_event_id: str,
    terminal_event_id: str,
) -> ArtifactHashes:
    run_root = root / run_id
    run_root.mkdir(parents=True)
    normalized_path = run_root / "normalized_events.jsonl"
    normalized_path.write_text(f'{{"run_id":"{run_id}"}}\n', encoding="utf-8", newline="\n")

    evidence_path = run_root / "r1_evidence.jsonl"
    evidence_path.write_text(
        "".join(f"{evidence.model_dump_json()}\n" for evidence in evidences),
        encoding="utf-8",
        newline="\n",
    )
    evidence_hash = _sha256(evidence_path)

    summary = {
        "diagnostics": [],
        "error_message": None,
        "error_type": None,
        "evidence_artifact_sha256": evidence_hash,
        "evidence_count": len(evidences),
        "extractor_version": EXTRACTOR_VERSION,
        "input_event_count": len({event_id for item in evidences for event_id in item.event_ids}),
        "lineage_inputs": [
            {
                "anchor_event_id": anchor_event_id,
                "policy_config_hash": APPROVED_POLICY_CONFIG_HASH,
                "policy_id": APPROVED_POLICY_ID,
                "policy_version": APPROVED_POLICY_VERSION,
                "terminal_event_id": terminal_event_id,
            }
        ],
        "run_id": run_id,
        "status": "completed",
        "telemetry_completeness": "not_provided",
        "warnings": [],
    }
    summary_path = run_root / "r1_extraction_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return ArtifactHashes(
        normalized_input=_sha256_lf_normalized_text(normalized_path),
        evidence=evidence_hash,
        extraction_summary=_sha256(summary_path),
    )


@pytest.fixture
def pair_artifacts(tmp_path: Path) -> tuple[Path, dict[str, PairRunSpec]]:
    attack_hashes = _write_artifacts(
        tmp_path,
        run_id=ATTACK_RUN_ID,
        anchor_event_id="attack-anchor",
        terminal_event_id="attack-terminal",
        evidences=[
            _evidence(
                evidence_id="E-attack-lineage",
                run_id=ATTACK_RUN_ID,
                timestamp=datetime(2026, 10, 5, 19, 38, 26, 253000, tzinfo=UTC),
                evidence_type="remote_session_process_lineage_deviation",
                event_ids=["attack-anchor", "attack-terminal"],
                features={
                    "policy_id": APPROVED_POLICY_ID,
                    "version": APPROVED_POLICY_VERSION,
                    "config_hash": APPROVED_POLICY_CONFIG_HASH,
                },
            ),
            _evidence(
                evidence_id="E-attack-network",
                run_id=ATTACK_RUN_ID,
                timestamp=datetime(2026, 10, 5, 19, 41, 26, 617000, tzinfo=UTC),
                evidence_type="remote_process_network_follow_on",
                event_ids=["attack-terminal", "attack-network"],
            ),
        ],
    )
    normal_hashes = _write_artifacts(
        tmp_path,
        run_id=NORMAL_RUN_ID,
        anchor_event_id="normal-anchor",
        terminal_event_id="normal-terminal",
        evidences=[
            _evidence(
                evidence_id="E-normal-network",
                run_id=NORMAL_RUN_ID,
                timestamp=datetime(2026, 10, 5, 20, 4, 52, 808000, tzinfo=UTC),
                evidence_type="remote_process_network_follow_on",
                event_ids=["normal-terminal", "normal-network"],
            )
        ],
    )
    specs = {
        ATTACK_RUN_ID: PairRunSpec(
            run_type="attack",
            run_start=ATTACK_START,
            run_end=datetime(2026, 10, 5, 19, 44, 28, 494000, tzinfo=UTC),
            replay_end=datetime(2026, 10, 5, 19, 44, 25, 834000, tzinfo=UTC),
            hashes=attack_hashes,
        ),
        NORMAL_RUN_ID: PairRunSpec(
            run_type="normal",
            run_start=NORMAL_START,
            run_end=datetime(2026, 10, 5, 20, 7, 54, 631000, tzinfo=UTC),
            replay_end=datetime(2026, 10, 5, 20, 7, 52, 355000, tzinfo=UTC),
            hashes=normal_hashes,
        ),
    }
    return tmp_path, specs


def test_reproduces_documented_pair002_temporal_mechanics(
    pair_artifacts: tuple[Path, dict[str, PairRunSpec]],
) -> None:
    # Given
    artifacts_root, run_specs = pair_artifacts

    # When
    result = run_probe(artifacts_root, run_specs=run_specs)

    # Then
    assert result["static_presence"] == {"attack": 1.0, "normal": 0.5}

    basic = result["basic_replay"]
    assert basic["attack"] == {
        "max_score": 1.0,
        "fusion_status": "detected",
        "fusion_time": "2026-10-05T19:41:45.834Z",
    }
    assert basic["normal"] == {
        "max_score": 0.5,
        "fusion_status": "miss",
        "fusion_time": None,
    }

    window = result["window_ablation_sec"]
    assert window["180"]["max_score"] == 0.5
    assert window["180"]["fusion_status"] == "miss"
    assert window["190"] == {
        "max_score": 1.0,
        "fusion_status": "miss",
        "fusion_time": None,
    }
    assert window["200"]["fusion_status"] == "detected"
    assert window["200"]["fusion_time"] == "2026-10-05T19:41:45.834Z"
    assert window["300"]["fusion_status"] == "detected"

    persistence = result["persistence_ablation_k"]
    assert persistence["1"]["fusion_status"] == "detected"
    assert persistence["1"]["fusion_time"] == "2026-10-05T19:41:35.834Z"
    assert persistence["2"]["fusion_status"] == "miss"
    assert persistence["3"]["fusion_status"] == "miss"

    cadence = result["cadence_ablation_sec"]
    assert cadence["5"]["fusion_status"] == "detected"
    assert cadence["5"]["fusion_time"] == "2026-10-05T19:41:35.834Z"
    assert cadence["10"]["fusion_status"] == "miss"
    assert cadence["20"]["max_score"] == 0.5
    assert cadence["20"]["fusion_status"] == "miss"


def test_fails_closed_when_an_input_hash_does_not_match(
    pair_artifacts: tuple[Path, dict[str, PairRunSpec]],
) -> None:
    # Given
    artifacts_root, run_specs = pair_artifacts
    normalized_path = artifacts_root / ATTACK_RUN_ID / "normalized_events.jsonl"
    normalized_path.write_text("tampered\n", encoding="utf-8", newline="\n")

    # When
    with pytest.raises(ValueError) as exc_info:
        run_probe(artifacts_root, run_specs=run_specs)

    # Then
    assert "normalized input SHA-256 mismatch" in str(exc_info.value)


def test_normalized_input_hash_is_portable_between_lf_and_crlf(
    pair_artifacts: tuple[Path, dict[str, PairRunSpec]],
) -> None:
    # Given
    artifacts_root, run_specs = pair_artifacts
    normalized_path = artifacts_root / ATTACK_RUN_ID / "normalized_events.jsonl"
    expected_lf_hash = run_specs[ATTACK_RUN_ID].hashes.normalized_input
    lf_content = normalized_path.read_bytes()
    lf_canonical_hash = _sha256_lf_normalized_text(normalized_path)
    crlf_content = lf_content.replace(b"\n", b"\r\n")

    # When
    normalized_path.write_bytes(crlf_content)
    canonical_hash = _sha256_lf_normalized_text(normalized_path)
    result = run_probe(artifacts_root, run_specs=run_specs)

    # Then
    assert hashlib.sha256(lf_content).hexdigest() == expected_lf_hash
    assert hashlib.sha256(crlf_content).hexdigest() != expected_lf_hash
    assert lf_canonical_hash == expected_lf_hash
    assert canonical_hash == expected_lf_hash
    assert result["static_presence"] == {"attack": 1.0, "normal": 0.5}


@pytest.mark.parametrize(
    ("filename", "error_text"),
    [
        ("r1_evidence.jsonl", "Evidence JSONL SHA-256 mismatch"),
        ("r1_extraction_summary.json", "extraction summary SHA-256 mismatch"),
    ],
)
def test_evidence_and_summary_hashes_remain_raw_byte_contracts(
    pair_artifacts: tuple[Path, dict[str, PairRunSpec]],
    filename: str,
    error_text: str,
) -> None:
    # Given
    artifacts_root, run_specs = pair_artifacts
    artifact_path = artifacts_root / ATTACK_RUN_ID / filename
    artifact_path.write_bytes(artifact_path.read_bytes().replace(b"\n", b"\r\n"))

    # When
    with pytest.raises(ValueError) as exc_info:
        run_probe(artifacts_root, run_specs=run_specs)

    # Then
    assert error_text in str(exc_info.value)
