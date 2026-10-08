import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tools.analysis.r1_pair002_temporal_probe as temporal_probe
from incident_awareness.common.models.evidence import Evidence
from tools.analysis.r1_pair002_temporal_probe import (
    APPROVED_POLICY_CONFIG_HASH,
    APPROVED_POLICY_ID,
    APPROVED_POLICY_VERSION,
    ATTACK_RUN_ID,
    EXTRACTOR_VERSION,
    NORMAL_RUN_ID,
    ArtifactHashes,
    ExecutionRevision,
    PairRunSpec,
    _git_execution_revision,
    _sha256_lf_normalized_text,
    main,
    run_probe,
)

ENTITY_ID = "fixture-target"
ATTACK_START = datetime(2026, 10, 5, 19, 33, 25, 834000, tzinfo=UTC)
NORMAL_START = datetime(2026, 10, 5, 19, 56, 52, 355000, tzinfo=UTC)
EXECUTION_COMMIT = "a" * 40
EXECUTION_REVISION = ExecutionRevision(
    execution_commit=EXECUTION_COMMIT,
    execution_dirty=True,
)


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
    result = run_probe(
        artifacts_root,
        execution_commit=EXECUTION_COMMIT,
        run_specs=run_specs,
        execution_revision=EXECUTION_REVISION,
    )

    # Then
    assert result["static_presence"] == {"attack": 1.0, "normal": 0.5}
    assert (
        result["analysis_revision"]["review_reproduction_base"]
        != (result["analysis_revision"]["execution_commit"])
    )
    assert result["analysis_revision"]["execution_commit"] == EXECUTION_COMMIT
    assert result["analysis_revision"]["execution_dirty"] is True

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
        run_probe(
            artifacts_root,
            execution_commit=EXECUTION_COMMIT,
            run_specs=run_specs,
            execution_revision=EXECUTION_REVISION,
        )

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
    result = run_probe(
        artifacts_root,
        execution_commit=EXECUTION_COMMIT,
        run_specs=run_specs,
        execution_revision=EXECUTION_REVISION,
    )

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
        run_probe(
            artifacts_root,
            execution_commit=EXECUTION_COMMIT,
            run_specs=run_specs,
            execution_revision=EXECUTION_REVISION,
        )

    # Then
    assert error_text in str(exc_info.value)


def test_cli_requires_execution_commit(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--artifacts-root",
                str(tmp_path),
                "--output",
                str(tmp_path / "result.json"),
            ]
        )

    assert exc_info.value.code == 2


def test_cli_rejects_invalid_execution_commit(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--artifacts-root",
                str(tmp_path),
                "--output",
                str(tmp_path / "result.json"),
                "--execution-commit",
                "not-a-full-git-sha",
            ]
        )

    assert exc_info.value.code == 2


def test_cli_fails_closed_when_execution_commit_does_not_match_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual_commit = "b" * 40

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout=f"{actual_commit}\n", stderr="")

    monkeypatch.setattr(temporal_probe.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="probe execution commit mismatch"):
        main(
            [
                "--artifacts-root",
                str(tmp_path),
                "--output",
                str(tmp_path / "result.json"),
                "--execution-commit",
                EXECUTION_COMMIT,
            ]
        )


def test_git_execution_revision_fails_closed_when_git_lookup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(128, args)

    monkeypatch.setattr(temporal_probe.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="unable to capture.*Git commit"):
        _git_execution_revision(tmp_path, expected_commit=EXECUTION_COMMIT)


def test_cli_records_matching_head_and_actual_dirty_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    captured: dict[str, object] = {}

    def fake_git_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = f"{EXECUTION_COMMIT}\n" if command[1] == "rev-parse" else " M file.py\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    def fake_run_probe(
        artifacts_root: Path,
        *,
        execution_commit: str,
        config_path: Path,
        execution_revision: ExecutionRevision,
    ) -> dict[str, object]:
        captured.update(
            artifacts_root=artifacts_root,
            execution_commit=execution_commit,
            config_path=config_path,
            execution_revision=execution_revision,
        )
        return {"ok": True}

    def fake_write_probe_result(result: dict[str, object], output: Path) -> None:
        captured.update(result=result, output=output)

    monkeypatch.setattr(temporal_probe.subprocess, "run", fake_git_run)
    monkeypatch.setattr(temporal_probe, "run_probe", fake_run_probe)
    monkeypatch.setattr(temporal_probe, "write_probe_result", fake_write_probe_result)
    output = tmp_path / "result.json"

    main(
        [
            "--artifacts-root",
            str(tmp_path),
            "--output",
            str(output),
            "--execution-commit",
            EXECUTION_COMMIT.upper(),
        ]
    )

    assert commands == [["git", "rev-parse", "HEAD"], ["git", "status", "--porcelain"]]
    assert captured["execution_commit"] == EXECUTION_COMMIT
    assert captured["execution_revision"] == ExecutionRevision(
        execution_commit=EXECUTION_COMMIT,
        execution_dirty=True,
    )
    assert captured["result"] == {"ok": True}
    assert captured["output"] == output
