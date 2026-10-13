import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    R1_CAUSAL_FUSION_RESULT_FILENAME,
    R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
    R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
    load_r1_causal_replay_artifacts,
)
from scripts.dev import run_r1_causal_dev_replay as replay


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _schema_versions() -> SchemaVersions:
    return SchemaVersions(
        run_metadata="v0.2",
        event="v0.3",
        evidence="v0.2",
        fast_hit="v0.2",
        detection_result="v0.2",
        fusion_result="v0.3",
        decision_result="v0.2",
        execution_record="v0.1",
        evaluation_input="v0.1",
    )


@dataclass(frozen=True, slots=True)
class ReplayFixture:
    inputs_root: Path
    extracted_root: Path
    approval_path: Path
    outputs_root: Path
    manifest_path: Path
    manifest: dict[str, object]
    run_directories: dict[str, Path]


def _write_run_sources(
    fixture_root: Path,
    manifest_directory: Path,
    *,
    run_id: str,
    index: int,
) -> tuple[dict[str, object], Path]:
    artifact_directory = manifest_directory / run_id
    artifact_directory.mkdir(parents=True)
    normalized_path = artifact_directory / "normalized_events.jsonl"
    provenance_path = artifact_directory / "provenance_validation.json"
    evidence_path = artifact_directory / "r1_evidence.jsonl"
    summary_path = artifact_directory / "r1_extraction_summary.json"
    normalized_path.write_text(
        json.dumps({"run_id": run_id}, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _write_json(provenance_path, {"run_id": run_id, "status": "PASS"})
    evidence_path.write_bytes(b"")
    evidence_hash = _sha256(evidence_path)
    _write_json(
        summary_path,
        {
            "diagnostics": [],
            "error_message": None,
            "error_type": None,
            "evidence_artifact_sha256": evidence_hash,
            "evidence_count": 0,
            "extractor_version": "r1-v0.1",
            "input_event_count": 0,
            "lineage_inputs": [
                {
                    "anchor_event_id": f"{run_id}-anchor",
                    "policy_config_hash": replay.EXPECTED_APPROVED_POLICY_SHA256,
                    "policy_id": replay.APPROVED_POLICY_ID,
                    "policy_version": replay.APPROVED_POLICY_VERSION,
                    "terminal_event_id": f"{run_id}-terminal",
                }
            ],
            "run_id": run_id,
            "selector": {
                "config_hash": replay.EXPECTED_SELECTOR_POLICY_SHA256,
                "diagnostics": [],
                "policy_id": replay.SELECTOR_POLICY_PAYLOAD["policy_id"],
                "status": "selected",
                "version": replay.SELECTOR_POLICY_PAYLOAD["version"],
            },
            "status": "completed",
            "telemetry_completeness": "not_provided",
            "warnings": [],
        },
    )

    start = datetime(2026, 10, 8, 17, 0, tzinfo=UTC) + timedelta(hours=index)
    metadata = RunMetadata(
        run_id=run_id,
        scenario_id="R1",
        run_type=RunType.ATTACK if index % 2 == 0 else RunType.NORMAL,
        target_host=replay.EXPECTED_TARGET_HOST,
        start_time=start,
        end_time=start + timedelta(seconds=30),
        family_id=replay.EXPECTED_FAMILY_ID,
        variation_id="V02",
        repetition=index + 1,
        schema_versions=_schema_versions(),
    )
    metadata_path = (
        fixture_root
        / "pair-packages"
        / replay.EXPECTED_PAIR_IDS[run_id]
        / run_id
        / "data"
        / "ground_truth"
        / run_id
        / "run_metadata.json"
    )
    metadata_path.parent.mkdir(parents=True)
    metadata_path.write_text(
        metadata.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    file_records = {
        path.name: {
            "path": f"{run_id}/{path.name}",
            "sha256": _sha256(path),
        }
        for path in (normalized_path, provenance_path, evidence_path, summary_path)
    }
    manifest_run = {
        "pair_id": replay.EXPECTED_PAIR_IDS[run_id],
        "run_id": run_id,
        "run_type": metadata.run_type.value,
        "files": file_records,
        "selector": {
            "policy_id": replay.SELECTOR_POLICY_PAYLOAD["policy_id"],
            "version": replay.SELECTOR_POLICY_PAYLOAD["version"],
            "config_hash": replay.EXPECTED_SELECTOR_POLICY_SHA256,
            "status": "selected",
            "diagnostics": [],
        },
        "approved_policy": {
            "policy_id": replay.APPROVED_POLICY_ID,
            "version": replay.APPROVED_POLICY_VERSION,
            "config_hash": replay.EXPECTED_APPROVED_POLICY_SHA256,
            "family_id": replay.EXPECTED_FAMILY_ID,
            "lifecycle": "frozen",
        },
        "extractor_version": "r1-v0.1",
    }
    return manifest_run, artifact_directory


def _refresh_manifest_approval(
    fixture: ReplayFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_json(fixture.manifest_path, fixture.manifest)
    manifest_hash = _sha256(fixture.manifest_path)
    monkeypatch.setattr(replay, "EXPECTED_SOURCE_MANIFEST_SHA256", manifest_hash)
    approval = {
        "record_version": "v0.1",
        "package_id": replay.EXPECTED_PACKAGE_ID,
        "source_manifest_relative_path": fixture.manifest_path.relative_to(
            fixture.extracted_root
        ).as_posix(),
        "source_manifest_sha256": manifest_hash,
        "permitted_use": sorted(replay.REQUIRED_PERMITTED_USES),
        "prohibited_use": sorted(replay.REQUIRED_PROHIBITED_USES),
        "output_classification": "development-only",
        "preserves_original_artifacts": True,
    }
    _write_json(fixture.approval_path, approval)


@pytest.fixture
def replay_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReplayFixture:
    inputs_root = tmp_path / "R1-causal-inputs"
    extracted_root = inputs_root / "extracted"
    manifest_directory = extracted_root / "outer" / replay.EXPECTED_PACKAGE_ID
    manifest_path = manifest_directory / "manifest.json"
    approval_path = inputs_root / "development-replay" / "approval" / "usage-scope-v0.1.json"
    outputs_root = inputs_root / "development-replay" / "outputs"
    outputs_root.mkdir(parents=True)
    runs: list[dict[str, object]] = []
    run_directories: dict[str, Path] = {}
    for index, run_id in enumerate(replay.TARGET_RUN_IDS):
        manifest_run, run_directory = _write_run_sources(
            extracted_root,
            manifest_directory,
            run_id=run_id,
            index=index,
        )
        runs.append(manifest_run)
        run_directories[run_id] = run_directory
    fixture = ReplayFixture(
        inputs_root=inputs_root,
        extracted_root=extracted_root,
        approval_path=approval_path,
        outputs_root=outputs_root,
        manifest_path=manifest_path,
        manifest={"package_id": replay.EXPECTED_PACKAGE_ID, "runs": runs},
        run_directories=run_directories,
    )
    _refresh_manifest_approval(fixture, monkeypatch)
    return fixture


def _validate(
    fixture: ReplayFixture,
    *,
    run_ids: tuple[str, ...] = replay.TARGET_RUN_IDS,
    approved_policy_config: Path = replay.DEFAULT_APPROVED_POLICY_CONFIG_PATH,
    outputs_root: Path | None = None,
) -> replay.ValidationPlan:
    return replay.validate_development_replay_inputs(
        inputs_root=fixture.inputs_root,
        approval_path=fixture.approval_path,
        outputs_root=fixture.outputs_root if outputs_root is None else outputs_root,
        fusion_config_path=replay.DEFAULT_FUSION_CONFIG_PATH,
        approved_policy_config_path=approved_policy_config,
        run_ids=run_ids,
    )


def _add_expired_evidence(fixture: ReplayFixture, *, run_id: str) -> None:
    run_index = replay.TARGET_RUN_IDS.index(run_id)
    run_directory = fixture.run_directories[run_id]
    metadata_path = next(
        path for path in fixture.extracted_root.rglob("run_metadata.json") if run_id in path.parts
    )
    metadata = RunMetadata.model_validate_json(metadata_path.read_bytes())
    run_end = metadata.start_time + timedelta(seconds=400)
    metadata = metadata.model_copy(update={"end_time": run_end})
    metadata_path.write_text(
        metadata.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    anchor_event_id = f"{run_id}-anchor"
    terminal_event_id = f"{run_id}-terminal"
    evidences = (
        Evidence(
            evidence_id=f"{run_id}-lineage",
            run_id=run_id,
            timestamp=metadata.start_time + timedelta(seconds=10),
            entity_id=replay.EXPECTED_TARGET_HOST,
            evidence_type="remote_session_process_lineage_deviation",
            event_ids=[anchor_event_id, f"{run_id}-middle", terminal_event_id],
            derived_from_source_layer="raw_telemetry",
            feature_channel_group="fusion_feature",
            extractor_version="r1-v0.1",
            features={
                "policy_id": replay.APPROVED_POLICY_ID,
                "version": replay.APPROVED_POLICY_VERSION,
                "config_hash": replay.EXPECTED_APPROVED_POLICY_SHA256,
            },
        ),
        Evidence(
            evidence_id=f"{run_id}-network",
            run_id=run_id,
            timestamp=metadata.start_time + timedelta(seconds=20),
            entity_id=replay.EXPECTED_TARGET_HOST,
            evidence_type="remote_process_network_follow_on",
            event_ids=[terminal_event_id, f"{run_id}-network-event"],
            derived_from_source_layer="raw_telemetry",
            feature_channel_group="fusion_feature",
            extractor_version="r1-v0.1",
        ),
    )
    evidence_path = run_directory / "r1_evidence.jsonl"
    evidence_path.write_text(
        "".join(f"{evidence.model_dump_json()}\n" for evidence in evidences),
        encoding="utf-8",
        newline="\n",
    )
    summary_path = run_directory / "r1_extraction_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["evidence_artifact_sha256"] = _sha256(evidence_path)
    summary["evidence_count"] = len(evidences)
    summary["input_event_count"] = 4
    _write_json(summary_path, summary)

    manifest_runs = fixture.manifest["runs"]
    assert isinstance(manifest_runs, list)
    manifest_run = manifest_runs[run_index]
    assert isinstance(manifest_run, dict)
    files = manifest_run["files"]
    assert isinstance(files, dict)
    for path in (evidence_path, summary_path):
        record = files[path.name]
        assert isinstance(record, dict)
        record["sha256"] = _sha256(path)


def test_check_validates_all_runs_without_creating_outputs(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    revision = replay.ExecutionRevision(
        commit="a" * 40,
        dirty=True,
        status_porcelain=("?? new-development-files",),
    )

    # When
    plan = _validate(replay_fixture)
    report = replay.build_check_report(plan, revision)

    # Then
    assert [run.run_id for run in plan.runs] == list(replay.TARGET_RUN_IDS)
    assert all(run.envelope.watermark_at == run.run_metadata.end_time for run in plan.runs)
    assert all(
        all(item.available_at == run.run_metadata.end_time for item in run.envelope.evidences)
        for run in plan.runs
    )
    assert report["mode"] == "check"
    assert report["official_evaluation_authorized"] is False
    assert report["execution"]["dirty"] is True  # type: ignore[index]
    assert report["execution"]["handoff_eligible"] is False  # type: ignore[index]
    assert not any(
        (replay_fixture.outputs_root / run_id).exists() for run_id in replay.TARGET_RUN_IDS
    )


def test_check_can_select_exactly_one_target_run(replay_fixture: ReplayFixture) -> None:
    # Given
    selected_run_id = replay.TARGET_RUN_IDS[2]

    # When
    plan = _validate(replay_fixture, run_ids=(selected_run_id,))

    # Then
    assert tuple(run.run_id for run in plan.runs) == (selected_run_id,)
    assert plan.runs[0].pair_id == replay.EXPECTED_PAIR_IDS[selected_run_id]


def test_validation_rejects_source_file_tampering(replay_fixture: ReplayFixture) -> None:
    # Given
    normalized_path = (
        replay_fixture.run_directories[replay.TARGET_RUN_IDS[0]] / "normalized_events.jsonl"
    )
    normalized_path.write_bytes(normalized_path.read_bytes() + b"tampered\n")

    # When / Then
    with pytest.raises(ValueError, match="source SHA-256 mismatch"):
        _validate(replay_fixture, run_ids=(replay.TARGET_RUN_IDS[0],))


def test_validation_rejects_source_manifest_tampering(replay_fixture: ReplayFixture) -> None:
    # Given
    replay_fixture.manifest_path.write_bytes(replay_fixture.manifest_path.read_bytes() + b" \n")

    # When / Then
    with pytest.raises(ValueError, match="source manifest SHA-256"):
        _validate(replay_fixture, run_ids=(replay.TARGET_RUN_IDS[0],))


def test_validation_rejects_usage_approval_manifest_hash_mismatch(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    approval = json.loads(replay_fixture.approval_path.read_text(encoding="utf-8"))
    approval["source_manifest_sha256"] = "0" * 64
    _write_json(replay_fixture.approval_path, approval)

    # When / Then
    with pytest.raises(ValueError, match="unexpected manifest SHA-256"):
        _validate(replay_fixture, run_ids=(replay.TARGET_RUN_IDS[0],))


def test_validation_rejects_selector_payload_hash_mismatch(
    replay_fixture: ReplayFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setitem(replay.SELECTOR_POLICY_PAYLOAD, "lineage_event_count", 4)

    # When / Then
    with pytest.raises(ValueError, match="selector policy payload SHA-256"):
        _validate(replay_fixture, run_ids=(replay.TARGET_RUN_IDS[0],))


def test_validation_rejects_approved_policy_hash_mismatch(
    replay_fixture: ReplayFixture,
    tmp_path: Path,
) -> None:
    # Given
    policy_path = tmp_path / "changed-approved-policy.yaml"
    content = replay.DEFAULT_APPROVED_POLICY_CONFIG_PATH.read_text(encoding="utf-8")
    policy_path.write_text(
        content.replace("      - powershell.exe", "      - pwsh.exe"),
        encoding="utf-8",
        newline="\n",
    )

    # When / Then
    with pytest.raises(ValueError, match="canonical SHA-256"):
        _validate(
            replay_fixture,
            run_ids=(replay.TARGET_RUN_IDS[0],),
            approved_policy_config=policy_path,
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_validation_rejects_missing_or_duplicate_manifest_runs(
    replay_fixture: ReplayFixture,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    # Given
    runs = replay_fixture.manifest["runs"]
    assert isinstance(runs, list)
    if mutation == "missing":
        runs.pop()
    else:
        runs.append(dict(runs[0]))
    _refresh_manifest_approval(replay_fixture, monkeypatch)

    # When / Then
    expected_message = "Run set mismatch" if mutation == "missing" else "duplicate run_id"
    with pytest.raises(ValueError, match=expected_message):
        _validate(replay_fixture, run_ids=(replay.TARGET_RUN_IDS[0],))


def test_validation_rejects_duplicate_discovered_run_artifacts(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    run_id = replay.TARGET_RUN_IDS[0]
    duplicate = replay_fixture.extracted_root / "duplicate" / run_id
    shutil.copytree(replay_fixture.run_directories[run_id], duplicate)

    # When / Then
    with pytest.raises(ValueError, match="exactly one Evidence directory"):
        _validate(replay_fixture, run_ids=(run_id,))


def test_validation_rejects_existing_output_directory(replay_fixture: ReplayFixture) -> None:
    # Given
    run_id = replay.TARGET_RUN_IDS[0]
    (replay_fixture.outputs_root / run_id).mkdir()

    # When / Then
    with pytest.raises(FileExistsError, match="output directory already exists"):
        _validate(replay_fixture, run_ids=(run_id,))


@pytest.mark.parametrize(
    "protected_location",
    ["repository", "extracted", "approval"],
)
def test_validation_rejects_outputs_inside_protected_directories(
    replay_fixture: ReplayFixture,
    protected_location: str,
) -> None:
    # Given
    protected_outputs = {
        "repository": replay.REPOSITORY_ROOT / "blocked-development-output",
        "extracted": replay_fixture.extracted_root / "blocked-development-output",
        "approval": replay_fixture.approval_path.parent / "blocked-development-output",
    }[protected_location]

    # When / Then
    with pytest.raises(ValueError, match="outputs_root must be outside"):
        _validate(
            replay_fixture,
            run_ids=(replay.TARGET_RUN_IDS[0],),
            outputs_root=protected_outputs,
        )


def test_validation_rejects_canonical_path_traversal_into_repository(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    outputs_root = replay.REPOSITORY_ROOT / "scripts" / ".." / "blocked-output"

    # When / Then
    with pytest.raises(ValueError, match="Git repository"):
        _validate(
            replay_fixture,
            run_ids=(replay.TARGET_RUN_IDS[0],),
            outputs_root=outputs_root,
        )


def test_validation_rejects_symlink_into_protected_directory(
    replay_fixture: ReplayFixture,
    tmp_path: Path,
) -> None:
    # Given
    symlink = tmp_path / "repository-link"
    try:
        symlink.symlink_to(replay.REPOSITORY_ROOT, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    # When / Then
    with pytest.raises(ValueError, match="Git repository"):
        _validate(
            replay_fixture,
            run_ids=(replay.TARGET_RUN_IDS[0],),
            outputs_root=symlink / "blocked-output",
        )


def test_dirty_execute_is_rejected_before_output_creation(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    run_id = replay.TARGET_RUN_IDS[0]
    plan = _validate(replay_fixture, run_ids=(run_id,))
    revision = replay.ExecutionRevision(
        commit="b" * 40,
        dirty=True,
        status_porcelain=(" M scripts/dev/run_r1_causal_dev_replay.py",),
    )
    invocation = replay.ExecutionInvocation(
        executable=sys.executable,
        argv=("run_r1_causal_dev_replay.py", "--execute", "--run-id", run_id),
        cwd=str(Path.cwd()),
    )

    # When / Then
    with pytest.raises(ValueError, match="clean Git worktree"):
        replay.execute_development_replays(
            plan,
            revision=revision,
            invocation=invocation,
        )
    assert not (replay_fixture.outputs_root / run_id).exists()


def test_execute_cleans_staging_directory_when_index_validation_fails(
    replay_fixture: ReplayFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    run_id = replay.TARGET_RUN_IDS[0]
    plan = _validate(replay_fixture, run_ids=(run_id,))
    revision = replay.ExecutionRevision(commit="d" * 40, dirty=False, status_porcelain=())
    invocation = replay.ExecutionInvocation(
        executable=sys.executable,
        argv=("run_r1_causal_dev_replay.py", "--execute", "--run-id", run_id),
        cwd=str(Path.cwd()),
    )

    def reject_index(*args: object, **kwargs: object) -> str:
        raise ValueError("injected index validation failure")

    monkeypatch.setattr(replay, "_validate_development_index", reject_index)

    # When / Then
    with pytest.raises(ValueError, match="injected index validation failure"):
        replay.execute_development_replays(
            plan,
            revision=revision,
            invocation=invocation,
        )
    assert not (replay_fixture.outputs_root / run_id).exists()
    assert list(replay_fixture.outputs_root.iterdir()) == []


def test_execute_preserves_output_created_after_validation(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    run_id = replay.TARGET_RUN_IDS[0]
    plan = _validate(replay_fixture, run_ids=(run_id,))
    existing_output = replay_fixture.outputs_root / run_id
    existing_output.mkdir()
    marker = existing_output / "successful-output.marker"
    marker.write_text("preserve me\n", encoding="utf-8", newline="\n")
    revision = replay.ExecutionRevision(commit="e" * 40, dirty=False, status_porcelain=())
    invocation = replay.ExecutionInvocation(
        executable=sys.executable,
        argv=("run_r1_causal_dev_replay.py", "--execute", "--run-id", run_id),
        cwd=str(Path.cwd()),
    )

    # When / Then
    with pytest.raises(FileExistsError, match="output directory already exists"):
        replay.execute_development_replays(
            plan,
            revision=revision,
            invocation=invocation,
        )
    assert marker.read_text(encoding="utf-8") == "preserve me\n"
    assert {path.name for path in replay_fixture.outputs_root.iterdir()} == {run_id}


def test_execute_uses_same_causal_runtime_and_reloads_hash_bound_outputs(
    replay_fixture: ReplayFixture,
) -> None:
    # Given
    selected_run_ids = replay.TARGET_RUN_IDS[:2]
    plan = _validate(replay_fixture, run_ids=selected_run_ids)
    source_hashes_before = {
        source.path: _sha256(source.path)
        for run in plan.runs
        for source in (*run.source_files.values(), run.run_metadata_source)
    }
    revision = replay.ExecutionRevision(
        commit="c" * 40,
        dirty=False,
        status_porcelain=(),
    )
    invocation = replay.ExecutionInvocation(
        executable=sys.executable,
        argv=("run_r1_causal_dev_replay.py", "--execute", "--all-runs"),
        cwd=str(Path.cwd()),
    )

    # When
    reports = replay.execute_development_replays(
        plan,
        revision=revision,
        invocation=invocation,
    )
    restored = [
        load_r1_causal_replay_artifacts(replay_fixture.outputs_root / run_id)
        for run_id in selected_run_ids
    ]

    # Then
    assert len(reports) == 2
    assert [item.fusion_result.fusion_status for item in restored] == ["miss", "miss"]
    runtime_contracts = []
    for run_id, artifact_run in zip(selected_run_ids, restored, strict=True):
        output_directory = replay_fixture.outputs_root / run_id
        assert {
            R1_CAUSAL_FUSION_RESULT_FILENAME,
            R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
            R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
            replay.DEVELOPMENT_INDEX_FILENAME,
        } == {path.name for path in output_directory.iterdir()}
        assert artifact_run.provenance.execution_commit == revision.commit
        assert artifact_run.provenance.watermark_basis == "authoritative_run_end"
        index = json.loads(
            (output_directory / replay.DEVELOPMENT_INDEX_FILENAME).read_text(encoding="utf-8")
        )
        assert index["output_classification"] == "development-only"
        assert index["official_evaluation_authorized"] is False
        assert index["execution"]["commit"] == revision.commit
        assert index["execution"]["dirty"] is False
        assert index["execution"]["argv"] == list(invocation.argv)
        assert set(index["outputs"]) == {
            R1_CAUSAL_FUSION_RESULT_FILENAME,
            R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
            R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
        }
        for output in index["outputs"].values():
            assert Path(output["path"]).parent == output_directory.resolve()
            assert _sha256(Path(output["path"])) == output["sha256"]
        runtime = artifact_run.provenance.fusion_runtime_config.model_dump()
        runtime.pop("run_id")
        runtime.pop("entity_id")
        runtime_contracts.append(runtime)
    assert runtime_contracts[0] == runtime_contracts[1]
    assert source_hashes_before == {path: _sha256(path) for path in source_hashes_before}


def test_execute_joins_and_expires_non_empty_attack_and_normal_evidence(
    replay_fixture: ReplayFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    selected_run_ids = replay.TARGET_RUN_IDS[:2]
    for run_id in selected_run_ids:
        _add_expired_evidence(replay_fixture, run_id=run_id)
    _refresh_manifest_approval(replay_fixture, monkeypatch)
    plan = _validate(replay_fixture, run_ids=selected_run_ids)
    revision = replay.ExecutionRevision(commit="f" * 40, dirty=False, status_porcelain=())
    invocation = replay.ExecutionInvocation(
        executable=sys.executable,
        argv=("run_r1_causal_dev_replay.py", "--execute", "--all-runs"),
        cwd=str(Path.cwd()),
    )

    for run in plan.runs:
        assert run.artifact_run.evidences
        assert run.envelope.source_evidence_count == 2
        assert {item.evidence_id for item in run.envelope.evidences} == {
            evidence.evidence_id for evidence in run.artifact_run.evidences
        }
        assert all(
            item.available_at == run.run_metadata.end_time for item in run.envelope.evidences
        )
        assert run.run_metadata.end_time is not None
        window_start = run.run_metadata.end_time - timedelta(
            seconds=plan.fusion_config.window.window_size_sec
        )
        assert all(evidence.timestamp < window_start for evidence in run.artifact_run.evidences)
    assert [run.run_metadata.run_type for run in plan.runs] == [
        RunType.ATTACK,
        RunType.NORMAL,
    ]

    # When
    reports = replay.execute_development_replays(
        plan,
        revision=revision,
        invocation=invocation,
    )
    restored = {
        run_id: load_r1_causal_replay_artifacts(replay_fixture.outputs_root / run_id)
        for run_id in selected_run_ids
    }

    # Then
    assert [report["fusion_status"] for report in reports] == ["miss", "miss"]
    for run in plan.runs:
        artifacts = restored[run.run_id]
        output_directory = replay_fixture.outputs_root / run.run_id
        assert artifacts.fusion_result.fusion_status == "miss"
        assert artifacts.fusion_result.contributing_evidence_ids == []
        assert artifacts.fusion_stopping_trace.points
        assert all(point.score == 0 for point in artifacts.fusion_stopping_trace.points)
        assert (
            artifacts.provenance.source_evidence_artifact_sha256
            == run.envelope.source_evidence_artifact_sha256
        )
        assert (
            artifacts.provenance.source_extraction_summary_sha256
            == run.envelope.source_extraction_summary_sha256
        )
        assert {
            R1_CAUSAL_FUSION_RESULT_FILENAME,
            R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
            R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
            replay.DEVELOPMENT_INDEX_FILENAME,
        } == {path.name for path in output_directory.iterdir()}
        index = json.loads(
            (output_directory / replay.DEVELOPMENT_INDEX_FILENAME).read_text(encoding="utf-8")
        )
        for filename, output in index["outputs"].items():
            assert Path(output["path"]) == (output_directory / filename).resolve()
            assert _sha256(Path(output["path"])) == output["sha256"]


def test_cli_has_no_ground_truth_or_manual_availability_branch() -> None:
    # Given
    script_path = Path(replay.__file__)

    # When
    source = script_path.read_text(encoding="utf-8")

    # Then
    assert ".run_type" not in source
    assert ".reference_time" not in source
    assert "available_at=" not in source
    assert "build_r1_causal_availability_envelope_from_artifacts(" in source
    assert "run_and_write_r1_causal_replay(" in source
    assert "load_r1_causal_replay_artifacts(" in source


def test_development_fusion_config_preserves_connection_settings_and_warning() -> None:
    # Given
    config_path = replay.DEFAULT_FUSION_CONFIG_PATH

    # When
    config, source = replay._load_development_fusion_config(config_path)
    config_text = config_path.read_text(encoding="utf-8")

    # Then
    assert config.config_version == replay.EXPECTED_FUSION_CONFIG_VERSION
    assert config.window.window_size_sec == 300
    assert config.replay.step_size_sec == 10
    assert config.scoring.evidence_types == replay.EXPECTED_SCORING_EVIDENCE_TYPES
    assert config.stopping.threshold_on == 0.8
    assert config.stopping.threshold_off == 0.4
    assert config.stopping.persistence_k == 2
    assert source.sha256 == _sha256(config_path)
    assert "not an official R1 optimum" in config_text
    assert "TTSD evidence" in config_text
