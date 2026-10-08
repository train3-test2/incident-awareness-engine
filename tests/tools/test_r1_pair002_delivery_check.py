import hashlib
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.common.models.evidence import Evidence
from tools.analysis import r1_pair002_delivery_check as delivery


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
        entity_id="fixture-target",
        evidence_type=evidence_type,
        event_ids=event_ids,
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="r1-v0.1",
        features=features or {},
    )


def _write_run(
    root: Path,
    *,
    run_id: str,
    evidences: list[Evidence],
) -> tuple[dict[str, str], tuple[str, ...], tuple[tuple[str, int], ...]]:
    raw_path = root / "_repro" / "raw" / f"{run_id}_sysmon-0001.jsonl"
    normalized_path = root / "_repro" / "normalized" / f"{run_id}.jsonl"
    run_root = root / run_id
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True)
    raw_path.write_text(f'{{"raw":"{run_id}"}}\n', encoding="utf-8", newline="\n")
    normalized_path.write_text(f'{{"normalized":"{run_id}"}}\n', encoding="utf-8", newline="\n")

    evidence_path = run_root / "r1_evidence.jsonl"
    evidence_path.write_text(
        "".join(f"{item.model_dump_json()}\n" for item in evidences),
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
        "extractor_version": "r1-v0.1",
        "input_event_count": len({event_id for item in evidences for event_id in item.event_ids}),
        "lineage_inputs": [
            {
                "anchor_event_id": f"{run_id}-anchor",
                "policy_config_hash": delivery.APPROVED_POLICY["config_hash"],
                "policy_id": delivery.APPROVED_POLICY["policy_id"],
                "policy_version": delivery.APPROVED_POLICY["version"],
                "terminal_event_id": f"{run_id}-terminal",
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
    type_counts = tuple(sorted({item.evidence_type for item in evidences}))
    return (
        {
            "raw": _sha256(raw_path),
            "normalized": _sha256(normalized_path),
            "evidence": evidence_hash,
            "summary": _sha256(summary_path),
        },
        tuple(item.evidence_id for item in evidences),
        tuple(
            (evidence_type, sum(item.evidence_type == evidence_type for item in evidences))
            for evidence_type in type_counts
        ),
    )


def _write_zip(delivery_root: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in delivery_root.rglob("*") if item.is_file()):
            relative = path.relative_to(delivery_root).as_posix()
            archive.write(path, f"r1_pair002_delivery/9ee8680482/{relative}")


@pytest.fixture
def delivery_fixture(tmp_path: Path) -> tuple[Path, Path, delivery.DeliveryExpectation]:
    root = tmp_path / "delivery" / "9ee8680482"
    attack_evidences = [
        _evidence(
            evidence_id="E-fixture-attack-lineage",
            run_id=delivery.ATTACK_RUN_ID,
            timestamp=datetime(2026, 10, 5, 19, 38, 26, 253000, tzinfo=UTC),
            evidence_type="remote_session_process_lineage_deviation",
            event_ids=[
                f"{delivery.ATTACK_RUN_ID}-anchor",
                f"{delivery.ATTACK_RUN_ID}-terminal",
            ],
            features={
                "policy_id": delivery.APPROVED_POLICY["policy_id"],
                "version": delivery.APPROVED_POLICY["version"],
                "config_hash": delivery.APPROVED_POLICY["config_hash"],
            },
        ),
        _evidence(
            evidence_id="E-fixture-attack-network",
            run_id=delivery.ATTACK_RUN_ID,
            timestamp=datetime(2026, 10, 5, 19, 41, 26, 617000, tzinfo=UTC),
            evidence_type="remote_process_network_follow_on",
            event_ids=[f"{delivery.ATTACK_RUN_ID}-terminal", "attack-network"],
        ),
    ]
    normal_evidences = [
        _evidence(
            evidence_id="E-fixture-normal-network",
            run_id=delivery.NORMAL_RUN_ID,
            timestamp=datetime(2026, 10, 5, 20, 4, 52, 808000, tzinfo=UTC),
            evidence_type="remote_process_network_follow_on",
            event_ids=[f"{delivery.NORMAL_RUN_ID}-terminal", "normal-network"],
        )
    ]
    run_data = {
        delivery.ATTACK_RUN_ID: _write_run(
            root, run_id=delivery.ATTACK_RUN_ID, evidences=attack_evidences
        ),
        delivery.NORMAL_RUN_ID: _write_run(
            root, run_id=delivery.NORMAL_RUN_ID, evidences=normal_evidences
        ),
    }
    run_expectations = {
        run_id: delivery.RunExpectation(
            classification="Attack" if run_id == delivery.ATTACK_RUN_ID else "Normal",
            raw_sha256=hashes["raw"],
            normalized_sha256=hashes["normalized"],
            evidence_sha256=hashes["evidence"],
            summary_sha256=hashes["summary"],
            evidence_ids=evidence_ids,
            evidence_types=evidence_types,
            static_presence=1.0 if run_id == delivery.ATTACK_RUN_ID else 0.5,
        )
        for run_id, (hashes, evidence_ids, evidence_types) in run_data.items()
    }
    regeneration = {
        "selector_policy": delivery.SELECTOR_POLICY,
        "approved_policy": delivery.APPROVED_POLICY,
        "runs": [
            {
                "classification": expectation.classification,
                "run_id": run_id,
                "raw_sha256": expectation.raw_sha256,
                "normalized_sha256": expectation.normalized_sha256,
                "selector_diagnostics": [],
                "extraction_diagnostics": [],
                "evidence_types": dict(expectation.evidence_types),
                "evidence_count": len(expectation.evidence_ids),
                "evidence_sha256": expectation.evidence_sha256,
                "summary_sha256": expectation.summary_sha256,
                "resolved_evidence_count": len(expectation.evidence_ids),
            }
            for run_id, expectation in run_expectations.items()
        ],
    }
    regeneration_path = root / "_repro" / "regeneration-result.json"
    regeneration_path.write_text(
        json.dumps(regeneration, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    provenance_values = [
        delivery.DELIVERY_COMMIT,
        delivery.SELECTOR_POLICY["policy_id"],
        delivery.SELECTOR_POLICY["version"],
        delivery.SELECTOR_POLICY["config_hash"],
        delivery.APPROVED_POLICY["policy_id"],
        delivery.APPROVED_POLICY["version"],
        delivery.APPROVED_POLICY["config_hash"],
        *(
            value
            for expectation in run_expectations.values()
            for value in (
                expectation.raw_sha256,
                expectation.normalized_sha256,
                expectation.evidence_sha256,
                expectation.summary_sha256,
            )
        ),
        "OFFLINE WHOLE-EPISODE ONLY",
        "Temporal Replay: `NOT SUPPORTED`",
        "TTSD: `NOT SUPPORTED`",
    ]
    provenance_path = root / "provenance.md"
    provenance_path.write_text(
        "\n".join(str(value) for value in provenance_values) + "\n", encoding="utf-8", newline="\n"
    )
    expectations = delivery.DeliveryExpectation(
        provenance_sha256=_sha256(provenance_path),
        regeneration_result_sha256=_sha256(regeneration_path),
        delivery_commit=delivery.DELIVERY_COMMIT,
        selector_policy=delivery.SELECTOR_POLICY,
        approved_policy=delivery.APPROVED_POLICY,
        runs=run_expectations,
    )
    zip_path = tmp_path / "r1_pair002_delivery.zip"
    _write_zip(root, zip_path)
    return zip_path, root, expectations


def test_validates_and_consumes_each_whole_episode_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    delivery_fixture: tuple[Path, Path, delivery.DeliveryExpectation],
) -> None:
    # Given
    zip_path, root, expectations = delivery_fixture
    artifact_calls: list[str] = []
    summary_calls: list[str] = []
    artifact_loader = delivery.load_r1_evidence_artifacts
    summary_loader = delivery.load_r1_extraction_summary

    def load_artifacts(path: Path):
        artifact_calls.append(path.name)
        return artifact_loader(path)

    def load_summary(path: Path):
        summary_calls.append(path.name)
        return summary_loader(path)

    monkeypatch.setattr(delivery, "load_r1_evidence_artifacts", load_artifacts)
    monkeypatch.setattr(delivery, "load_r1_extraction_summary", load_summary)

    # When
    result = delivery.validate_delivery(
        delivery_zip=zip_path,
        delivery_root=root,
        repository_root=tmp_path / "repository",
        execution_invocation=delivery.ExecutionInvocation(
            sys_argv=("checker.py", "--delivery-zip", "fixture.zip"),
            sys_executable="C:\\Python313\\python.exe",
            cwd="C:\\fixture-repository",
        ),
        reproduction_command="fixture reproduction command",
        expectations=expectations,
        execution_revision=delivery.ExecutionRevision(
            execution_commit="fixture-commit",
            execution_dirty=True,
            status_porcelain=(" M fixture",),
        ),
    )

    # Then
    assert artifact_calls == [delivery.ATTACK_RUN_ID, delivery.NORMAL_RUN_ID]
    assert summary_calls == [delivery.ATTACK_RUN_ID, delivery.NORMAL_RUN_ID]
    assert result["temporal_replay_used"] is False
    assert result["stopping_policy_used"] is False
    assert result["ttsd_computed"] is False
    assert result["online_or_per_time_processing_used"] is False
    assert result["runs"][delivery.ATTACK_RUN_ID]["static_presence"] == 1.0
    assert result["runs"][delivery.NORMAL_RUN_ID]["static_presence"] == 0.5
    assert result["runs"][delivery.ATTACK_RUN_ID]["hashes"]["evidence_sha256"] == (
        expectations.runs[delivery.ATTACK_RUN_ID].evidence_sha256
    )
    assert result["execution"]["execution_commit"] == "fixture-commit"
    assert result["execution"]["execution_dirty"] is True
    assert result["execution"]["sys_argv"] == [
        "checker.py",
        "--delivery-zip",
        "fixture.zip",
    ]
    assert result["execution"]["sys_executable"] == "C:\\Python313\\python.exe"
    assert result["execution"]["cwd"] == "C:\\fixture-repository"
    assert "command" not in result["execution"]
    assert result["reproduction_command"] == "fixture reproduction command"
    assert result["input"]["delivery_zip_sha256"] == _sha256(zip_path)

    output_hash = result.pop("output_sha256")
    assert output_hash == hashlib.sha256(delivery._canonical_json_bytes(result)).hexdigest()


def test_fails_closed_before_loading_when_an_artifact_hash_differs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    delivery_fixture: tuple[Path, Path, delivery.DeliveryExpectation],
) -> None:
    # Given
    zip_path, root, expectations = delivery_fixture
    normalized_path = root / "_repro" / "normalized" / f"{delivery.ATTACK_RUN_ID}.jsonl"
    normalized_path.write_text("tampered\n", encoding="utf-8", newline="\n")
    _write_zip(root, zip_path)
    monkeypatch.setattr(
        delivery,
        "load_r1_evidence_artifacts",
        lambda _: pytest.fail("artifact loader must not run after a hash mismatch"),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        delivery.validate_delivery(
            delivery_zip=zip_path,
            delivery_root=root,
            repository_root=tmp_path / "repository",
            execution_invocation=delivery.ExecutionInvocation(
                sys_argv=("checker.py",),
                sys_executable="C:\\Python313\\python.exe",
                cwd="C:\\fixture-repository",
            ),
            reproduction_command="fixture reproduction command",
            expectations=expectations,
            execution_revision=delivery.ExecutionRevision(
                execution_commit="fixture-commit",
                execution_dirty=True,
                status_porcelain=(" M fixture",),
            ),
        )

    # Then
    assert "Normalized SHA-256 mismatch" in str(exc_info.value)


def test_captures_actual_process_invocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Given
    argv = ["checker.py", "--delivery-zip", "delivery.zip"]
    executable = "C:\\runtime\\python.exe"
    monkeypatch.setattr(delivery.sys, "argv", argv)
    monkeypatch.setattr(delivery.sys, "executable", executable)
    monkeypatch.chdir(tmp_path)

    # When
    invocation = delivery._execution_invocation()

    # Then
    assert invocation.sys_argv == tuple(argv)
    assert invocation.sys_executable == executable
    assert invocation.cwd == str(tmp_path)
