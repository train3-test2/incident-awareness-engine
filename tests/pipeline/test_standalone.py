import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import incident_awareness.pipeline.standalone as standalone_module
from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.pipeline_runtime import PipelineRuntimeState, PipelineStage
from incident_awareness.common.models.run import RunType
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.pipeline.standalone import (
    DEFAULT_STANDALONE_DECISION_CONFIG_VERSION,
    DEFAULT_STANDALONE_FAST_MODE,
    DEFAULT_STANDALONE_FUSION_CONFIG_PATH,
    _allocate_identifiers,
    _order_standalone_sysmon_records,
    build_default_standalone_fast_detection,
    build_run_metadata_from_sysmon_jsonl,
    build_sysmon_artifacts_from_jsonl,
    prepare_standalone_run,
    run_prepared_standalone_run,
    select_standalone_execution_config,
    validate_standalone_sysmon_jsonl,
)


def _record(utc_time: str, *, time_created: str) -> dict[str, object]:
    return {
        "RecordId": 1,
        "EventId": 1,
        "TimeCreated": time_created,
        "Computer": "WIN-01",
        "EventData": {
            "UtcTime": utc_time,
            "Image": "C:\\Windows\\System32\\cmd.exe",
        },
    }


def test_builds_run_metadata_from_sysmon_event_time_range(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:00.001", time_created="2026-10-03T01:00:00.000Z"),
            _record("2026-10-03 00:00:10.123456", time_created="2026-10-03T00:00:00.000Z"),
        ],
    )

    metadata = build_run_metadata_from_sysmon_jsonl(
        jsonl_path,
        run_id="RUN-20261003-001",
        scenario_id="S0",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
    )

    assert metadata.start_time == datetime(2026, 10, 3, 0, 0, 0, 1000, tzinfo=UTC)
    assert metadata.end_time == datetime(2026, 10, 3, 0, 0, 10, 123000, tzinfo=UTC)
    assert metadata.schema_versions.event == "v0.3"
    assert metadata.schema_versions.fusion_result == "v0.3"


def test_rejects_empty_sysmon_jsonl(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    jsonl_path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain at least one record"):
        build_run_metadata_from_sysmon_jsonl(
            jsonl_path,
            run_id="RUN-20261003-001",
            scenario_id="S0",
            run_type=RunType.ATTACK,
            target_host="WIN-01",
        )


def test_rejects_missing_sysmon_event_time(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe"},
            }
        ],
    )

    with pytest.raises(ValueError, match="EventData.UtcTime must be non-blank"):
        build_run_metadata_from_sysmon_jsonl(
            jsonl_path,
            run_id="RUN-20261003-001",
            scenario_id="S0",
            run_type=RunType.ATTACK,
            target_host="WIN-01",
        )


def test_builds_manifest_sha256_and_raw_log_provenance(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "uploaded-sysmon.jsonl"
    _write_jsonl(
        jsonl_path, [_record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z")]
    )

    artifacts = build_sysmon_artifacts_from_jsonl(jsonl_path, run_id="RUN-20261003-001")

    jsonl_item = artifacts.manifest["items"][1]
    assert artifacts.manifest["run_id"] == "RUN-20261003-001"
    assert jsonl_item == {
        "raw_log_id": "RAW-RUN-20261003-001-SYSMON-001",
        "path": "raw/RUN-20261003-001/telemetry/sysmon-0001.jsonl",
        "sha256": _sha256(jsonl_path),
        "layer": "raw_telemetry",
        "source": "sysmon",
        "derived_from": "raw/RUN-20261003-001/telemetry/sysmon-0001.evtx",
    }
    assert artifacts.normalization_context.run_id == "RUN-20261003-001"
    assert artifacts.normalization_context.raw_log_id == jsonl_item["raw_log_id"]
    assert artifacts.normalization_context.segment_no == 1


def test_builds_not_evaluated_fast_result_without_fast_artifacts() -> None:
    result = build_default_standalone_fast_detection(
        run_id="RUN-20261003-001",
        entity_id="WIN-01",
    )

    assert DEFAULT_STANDALONE_FAST_MODE == "not_evaluated"
    assert result.detection_result.run_id == "RUN-20261003-001"
    assert result.detection_result.entity_id == "WIN-01"
    assert result.detection_result.detector_status == "not_evaluated"
    assert result.detection_result.detector_time is None
    assert result.source_hit_ids == ()
    assert result.selected_source_hit_id is None


def test_selects_default_s0_fusion_and_parallel_hybrid_config() -> None:
    config = select_standalone_execution_config()

    assert config.fusion_config_path == DEFAULT_STANDALONE_FUSION_CONFIG_PATH
    assert config.fusion_config.config_version == "fusion-config-s0-pair-v0.1"
    assert config.decision_config_version == DEFAULT_STANDALONE_DECISION_CONFIG_VERSION


def test_rejects_unsupported_standalone_hybrid_config() -> None:
    with pytest.raises(ValueError, match="supports only decision config"):
        select_standalone_execution_config(decision_config_version="optional-v1")


def test_materializes_runnable_standalone_artifacts(tmp_path: Path) -> None:
    source_jsonl = tmp_path / "source.jsonl"
    _write_jsonl(
        source_jsonl,
        [_record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z")],
    )

    prepared = prepare_standalone_run(
        sysmon_jsonl_path=source_jsonl,
        output_dir=tmp_path / "output" / "RUN-20261003-001",
        run_id="RUN-20261003-001",
        decision_id="DEC-RUN-20261003-001",
    )

    assert prepared.inputs.run_metadata_path.is_file()
    assert prepared.inputs.manifest_path.is_file()
    assert prepared.inputs.sysmon_jsonl_path.is_file()
    assert prepared.inputs.sysmon_jsonl_path.read_bytes() == source_jsonl.read_bytes()
    manifest = json.loads(prepared.inputs.manifest_path.read_text(encoding="utf-8"))
    assert manifest["run_id"] == "RUN-20261003-001"
    assert manifest["items"][1]["path"] == "raw/RUN-20261003-001/telemetry/sysmon-0001.jsonl"


def test_atomically_reserves_next_available_standalone_output_directory(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    (output_root / "RUN-20261003-001").mkdir(parents=True)

    reservation = _allocate_identifiers(
        _UnusedIdentifierConnection(),
        output_root,
        now=datetime(2026, 10, 3, tzinfo=UTC),
    )

    assert reservation.run_id == "RUN-20261003-002"
    assert reservation.decision_id == "DEC-RUN-20261003-002"
    assert reservation.output_dir == output_root / reservation.run_id
    assert reservation.output_dir.is_dir()


def test_standalone_run_persists_fusion_trace_and_runtime_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = SimpleNamespace(entity_id="WIN-01")
    prepared = SimpleNamespace(inputs=inputs)
    source_records = (
        SysmonJsonlRecord(
            record_no=1,
            data=_record("2026-10-03 00:00:10.000", time_created="2026-10-03T00:00:10Z"),
        ),
        SysmonJsonlRecord(
            record_no=2,
            data={
                **_record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z"),
                "RecordId": 2,
            },
        ),
    )
    artifacts = S0PipelineArtifacts(
        run_metadata=SimpleNamespace(run_id="RUN-20261003-001"),
        sysmon_records=source_records,
        normalization_context=SysmonNormalizationContext(
            run_id="RUN-20261003-001",
            raw_log_id="RAW-RUN-20261003-001-SYSMON-001",
            segment_no=1,
        ),
    )
    normalized_artifacts = object()
    fusion_result = object()
    stopping_trace = object()
    runtime_config_snapshot = object()
    fast_result = object()
    decision_result = object()
    summary = object()
    persisted: dict[str, object] = {}
    normalized_record_ids: list[int] = []

    monkeypatch.setattr(standalone_module, "load_s0_pipeline_artifacts", lambda _: artifacts)

    def normalize(
        ordered_artifacts: S0PipelineArtifacts,
        *,
        progress_callback,
    ) -> object:
        normalized_record_ids.extend(
            record.data["RecordId"] for record in ordered_artifacts.sysmon_records
        )
        progress_callback(1)
        progress_callback(2)
        return normalized_artifacts

    monkeypatch.setattr(standalone_module, "normalize_sysmon_and_extract_evidence", normalize)
    monkeypatch.setattr(
        standalone_module,
        "run_s0_fusion_with_trace",
        lambda *_: SimpleNamespace(
            fusion_result=fusion_result,
            stopping_trace=stopping_trace,
            runtime_config_snapshot=runtime_config_snapshot,
        ),
    )
    monkeypatch.setattr(
        standalone_module,
        "build_default_standalone_fast_detection",
        lambda **_: fast_result,
    )
    monkeypatch.setattr(
        standalone_module,
        "combine_parallel_decision",
        lambda *_: decision_result,
    )
    monkeypatch.setattr(
        standalone_module,
        "persist_s0_results",
        lambda *args, **kwargs: persisted.update(
            args=args,
            connection=kwargs["connection"],
            commit=kwargs["commit"],
        ),
    )
    monkeypatch.setattr(standalone_module, "build_execution_summary", lambda *_: summary)

    connection = object()
    snapshots = []

    assert (
        run_prepared_standalone_run(
            prepared,
            connection=connection,
            runtime_observer=snapshots.append,
        )
        is summary
    )
    assert normalized_record_ids == [2, 1]
    assert [record.data["RecordId"] for record in persisted["args"][0].sysmon_records] == [2, 1]
    assert persisted["args"][1:] == (
        normalized_artifacts,
        fusion_result,
        stopping_trace,
        runtime_config_snapshot,
        fast_result,
        decision_result,
    )
    assert persisted["connection"] is connection
    assert persisted["commit"] is True
    assert [snapshot.current_stage for snapshot in snapshots] == [
        PipelineStage.NORMALIZATION,
        PipelineStage.NORMALIZATION,
        PipelineStage.NORMALIZATION,
        PipelineStage.FUSION,
        PipelineStage.HYBRID,
        PipelineStage.PERSISTENCE,
        None,
    ]
    assert [snapshot.normalization_processed_count for snapshot in snapshots] == [
        0,
        1,
        2,
        2,
        2,
        2,
        2,
    ]
    assert all(snapshot.current_stage is not PipelineStage.FAST_HANDOFF for snapshot in snapshots)
    assert snapshots[-1].status is PipelineRuntimeState.COMPLETED


def test_standalone_invokes_r1_after_normalization_and_before_fusion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Given
    prepared, summary = _configure_runtime_stage_stubs(monkeypatch)
    prepared.output_dir = tmp_path / "output"
    prepared.r1_production_config = object()
    normalized_event = object()
    normalized_artifacts = SimpleNamespace(events=(normalized_event,))
    call_order: list[str] = []

    def normalize(*args, **kwargs):
        call_order.append("normalization")
        kwargs["progress_callback"](1)
        return normalized_artifacts

    def generate(events, *, run_id, output_directory, config):
        call_order.append("r1")
        assert events == (normalized_event,)
        assert run_id == "RUN-20261009-001"
        assert output_directory == tmp_path / "output" / "r1"
        assert config is prepared.r1_production_config
        return object()

    def fuse(*args):
        call_order.append("fusion")
        return SimpleNamespace(
            fusion_result=object(),
            stopping_trace=object(),
            runtime_config_snapshot=object(),
        )

    monkeypatch.setattr(standalone_module, "normalize_sysmon_and_extract_evidence", normalize)
    monkeypatch.setattr(standalone_module, "generate_r1_production_archive", generate)
    monkeypatch.setattr(standalone_module, "run_s0_fusion_with_trace", fuse)

    # When
    actual = run_prepared_standalone_run(prepared, connection=object())

    # Then
    assert actual is summary
    assert call_order == ["normalization", "r1", "fusion"]


def test_standalone_commit_false_does_not_publish_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    prepared, summary = _configure_runtime_stage_stubs(monkeypatch)
    snapshots = []

    # When
    actual = run_prepared_standalone_run(
        prepared,
        connection=object(),
        commit=False,
        runtime_observer=snapshots.append,
    )

    # Then
    assert actual is summary
    assert snapshots[-1].status is PipelineRuntimeState.RUNNING
    assert snapshots[-1].current_stage is PipelineStage.PERSISTENCE
    assert all(snapshot.status is not PipelineRuntimeState.COMPLETED for snapshot in snapshots)


def test_standalone_artifact_validation_failure_publishes_no_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = ValueError("invalid artifacts")
    prepared = SimpleNamespace(inputs=SimpleNamespace(entity_id="WIN-01"))
    snapshots = []
    monkeypatch.setattr(
        standalone_module,
        "load_s0_pipeline_artifacts",
        lambda _: (_ for _ in ()).throw(expected_error),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        run_prepared_standalone_run(
            prepared,
            connection=object(),
            runtime_observer=snapshots.append,
        )

    # Then
    assert exc_info.value is expected_error
    assert snapshots == []


@pytest.mark.parametrize(
    ("commit", "expected_state", "expected_failed_stage"),
    [
        (True, PipelineRuntimeState.COMPLETED, None),
        (False, PipelineRuntimeState.FAILED, PipelineStage.PERSISTENCE),
    ],
)
def test_standalone_summary_failure_uses_business_commit_outcome(
    monkeypatch: pytest.MonkeyPatch,
    commit: bool,
    expected_state: PipelineRuntimeState,
    expected_failed_stage: PipelineStage | None,
) -> None:
    # Given
    expected_error = RuntimeError("summary failed")
    prepared, _ = _configure_runtime_stage_stubs(monkeypatch)
    persistence_commits: list[bool] = []
    snapshots = []
    monkeypatch.setattr(
        standalone_module,
        "persist_s0_results",
        lambda *args, **kwargs: persistence_commits.append(kwargs["commit"]),
    )
    monkeypatch.setattr(
        standalone_module,
        "build_execution_summary",
        lambda *args: (_ for _ in ()).throw(expected_error),
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_prepared_standalone_run(
            prepared,
            connection=object(),
            commit=commit,
            runtime_observer=snapshots.append,
        )

    # Then
    assert exc_info.value is expected_error
    assert persistence_commits == [commit]
    assert snapshots[-1].status is expected_state
    assert snapshots[-1].failed_stage is expected_failed_stage


@pytest.mark.parametrize(
    ("failing_stage", "expected_stage"),
    [
        ("normalization", PipelineStage.NORMALIZATION),
        ("fusion", PipelineStage.FUSION),
        ("hybrid", PipelineStage.HYBRID),
        ("persistence", PipelineStage.PERSISTENCE),
    ],
)
def test_standalone_stage_failure_publishes_failed_stage(
    monkeypatch: pytest.MonkeyPatch,
    failing_stage: str,
    expected_stage: PipelineStage,
) -> None:
    # Given
    expected_error = RuntimeError(f"{failing_stage} failed")
    prepared, _ = _configure_runtime_stage_stubs(
        monkeypatch,
        failing_stage=failing_stage,
        error=expected_error,
    )
    snapshots = []

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_prepared_standalone_run(
            prepared,
            connection=object(),
            runtime_observer=snapshots.append,
        )

    # Then
    assert exc_info.value is expected_error
    assert snapshots[-1].status is PipelineRuntimeState.FAILED
    assert snapshots[-1].failed_stage is expected_stage


def test_standalone_observer_failure_does_not_change_business_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    prepared, summary = _configure_runtime_stage_stubs(monkeypatch)

    def failing_observer(status) -> None:
        raise RuntimeError("telemetry unavailable")

    # When
    actual = run_prepared_standalone_run(
        prepared,
        connection=object(),
        runtime_observer=failing_observer,
    )

    # Then
    assert actual is summary


@pytest.mark.parametrize("commit_fails", [False, True], ids=("commit-success", "commit-failure"))
def test_standalone_cli_finalizes_runtime_after_connection_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    commit_fails: bool,
) -> None:
    # Given
    events: list[str] = []
    tracker = _RuntimeTrackerSpy(events)
    execution = standalone_module.StandaloneExecution(
        output_dir=tmp_path / "output",
        summary=standalone_module.PipelineExecutionSummary(
            run_id="RUN-20261009-001",
            entity_id="WIN-01",
            normalized_event_count=1,
            evidence_count=1,
            fusion_status="detected",
            detector_status="not_evaluated",
            decision_path=None,
        ),
        _runtime_tracker=tracker,
    )
    observer = _ObserverContextSpy(events)
    connection = _ConnectionContextSpy(events, commit_fails=commit_fails)
    monkeypatch.setattr(
        standalone_module.DatabaseConfig,
        "from_environment",
        lambda: SimpleNamespace(url="postgresql://test"),
    )
    monkeypatch.setattr(standalone_module, "PostgresPipelineRuntimeObserver", lambda: observer)
    monkeypatch.setattr(standalone_module.psycopg, "connect", lambda *args, **kwargs: connection)

    def run_standalone(**kwargs):
        events.append("standalone")
        assert kwargs["runtime_observer"] is observer
        return execution

    monkeypatch.setattr(standalone_module, "run_standalone_sysmon_jsonl", run_standalone)
    argv = ["--sysmon-jsonl", str(tmp_path / "source.jsonl")]

    # When
    if commit_fails:
        with pytest.raises(RuntimeError, match="commit failed"):
            standalone_module.main(argv)
    else:
        assert standalone_module.main(argv) == 0

    # Then
    terminal_event = "failed:persistence" if commit_fails else "completed"
    assert events == [
        "observer-enter",
        "connection-enter",
        "standalone",
        "connection-exit",
        terminal_event,
        "observer-exit",
    ]


def _configure_runtime_stage_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failing_stage: str | None = None,
    error: Exception | None = None,
):
    prepared = SimpleNamespace(inputs=SimpleNamespace(entity_id="WIN-01"))
    artifacts = S0PipelineArtifacts(
        run_metadata=SimpleNamespace(run_id="RUN-20261009-001"),
        sysmon_records=(
            SysmonJsonlRecord(
                record_no=1,
                data=_record(
                    "2026-10-09 00:00:00.000",
                    time_created="2026-10-09T00:00:00Z",
                ),
            ),
        ),
        normalization_context=SysmonNormalizationContext(
            run_id="RUN-20261009-001",
            raw_log_id="RAW-RUN-20261009-001-SYSMON-001",
            segment_no=1,
        ),
    )
    normalized = object()
    fusion_result = object()
    fast_result = object()
    decision_result = object()
    summary = object()
    expected_error = error or RuntimeError("stage failed")
    monkeypatch.setattr(standalone_module, "load_s0_pipeline_artifacts", lambda _: artifacts)

    def normalize(value, *, progress_callback):
        if failing_stage == "normalization":
            raise expected_error
        progress_callback(1)
        return normalized

    def fuse(*args):
        if failing_stage == "fusion":
            raise expected_error
        return SimpleNamespace(
            fusion_result=fusion_result,
            stopping_trace=object(),
            runtime_config_snapshot=object(),
        )

    def combine(*args):
        if failing_stage == "hybrid":
            raise expected_error
        return decision_result

    def persist(*args, **kwargs):
        if failing_stage == "persistence":
            raise expected_error

    monkeypatch.setattr(standalone_module, "normalize_sysmon_and_extract_evidence", normalize)
    monkeypatch.setattr(standalone_module, "run_s0_fusion_with_trace", fuse)
    monkeypatch.setattr(
        standalone_module,
        "build_default_standalone_fast_detection",
        lambda **kwargs: fast_result,
    )
    monkeypatch.setattr(standalone_module, "combine_parallel_decision", combine)
    monkeypatch.setattr(standalone_module, "persist_s0_results", persist)
    monkeypatch.setattr(standalone_module, "build_execution_summary", lambda *args: summary)
    return prepared, summary


class _RuntimeTrackerSpy:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def complete(self) -> None:
        self._events.append("completed")

    def fail(self, stage: PipelineStage) -> None:
        self._events.append(f"failed:{stage.value}")


class _ObserverContextSpy:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def __enter__(self):
        self._events.append("observer-enter")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._events.append("observer-exit")


class _ConnectionContextSpy:
    def __init__(self, events: list[str], *, commit_fails: bool) -> None:
        self._events = events
        self._commit_fails = commit_fails

    def __enter__(self):
        self._events.append("connection-enter")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._events.append("connection-exit")
        if self._commit_fails:
            raise RuntimeError("commit failed")


class _UnusedIdentifierConnection:
    def execute(self, query: str, parameters: tuple[str, str]) -> "_UnusedIdentifierCursor":
        assert "SELECT EXISTS" in query
        assert parameters[0].startswith("RUN-20261003-")
        assert parameters[1] == f"DEC-{parameters[0]}"
        return _UnusedIdentifierCursor()


class _UnusedIdentifierCursor:
    def fetchone(self) -> tuple[bool]:
        return (False,)


def test_rejects_standalone_target_or_entity_outside_direct_host_mapping(tmp_path: Path) -> None:
    source_jsonl = tmp_path / "source.jsonl"
    _write_jsonl(
        source_jsonl,
        [_record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z")],
    )

    with pytest.raises(ValueError, match="target_host must match"):
        prepare_standalone_run(
            sysmon_jsonl_path=source_jsonl,
            output_dir=tmp_path / "wrong-target",
            run_id="RUN-20261003-001",
            decision_id="DEC-RUN-20261003-001",
            target_host="WIN-02",
        )
    with pytest.raises(ValueError, match="entity_id must match"):
        prepare_standalone_run(
            sysmon_jsonl_path=source_jsonl,
            output_dir=tmp_path / "wrong-entity",
            run_id="RUN-20261003-001",
            decision_id="DEC-RUN-20261003-001",
            entity_id="WIN-02",
        )


def test_accepts_supported_sysmon_event_ids(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z"),
            {
                "RecordId": 2,
                "EventId": 3,
                "TimeCreated": "2026-10-03T00:00:10Z",
                "Computer": "WIN-01",
                "EventData": {
                    "UtcTime": "2026-10-03 00:00:10.000",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ProcessId": "4242",
                    "DestinationPort": "443",
                },
            },
        ],
    )

    records = validate_standalone_sysmon_jsonl(jsonl_path)

    assert [record.data["EventId"] for record in records] == [1, 3]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventId": 7,
            },
            "unsupported",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventId": True,
            },
            "EventId must be an integer",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "TimeCreated": "2026-10-03T00:00:00",
            },
            "must include timezone",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventData": {"UtcTime": "2026-10-03 00:00:00.000"},
            },
            "Image must be a non-blank string",
        ),
    ],
)
def test_rejects_unsupported_or_malformed_sysmon_input(
    tmp_path: Path,
    record: dict[str, object],
    message: str,
) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(jsonl_path, [record])

    with pytest.raises((TypeError, ValueError), match=message):
        validate_standalone_sysmon_jsonl(jsonl_path)


def test_rejects_network_port_outside_contract_range(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            {
                "RecordId": 1,
                "EventId": 3,
                "TimeCreated": "2026-10-03T00:00:00Z",
                "Computer": "WIN-01",
                "EventData": {
                    "UtcTime": "2026-10-03 00:00:00.000",
                    "DestinationPort": "65536",
                },
            }
        ],
    )

    with pytest.raises(ValueError, match="between 0 and 65535"):
        validate_standalone_sysmon_jsonl(jsonl_path)


def test_rejects_invalid_jsonl_syntax(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    jsonl_path.write_text('{"EventId": 1\n', encoding="utf-8")

    with pytest.raises(ValueError, match="standalone Sysmon JSONL is not readable"):
        validate_standalone_sysmon_jsonl(jsonl_path)


def test_rejects_multiple_hosts(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z"),
            {
                **_record(
                    "2026-10-03 00:00:10.000",
                    time_created="2026-10-03T00:00:10Z",
                ),
                "RecordId": 2,
                "Computer": "WIN-02",
            },
        ],
    )

    with pytest.raises(ValueError, match="exactly one Computer value"):
        validate_standalone_sysmon_jsonl(jsonl_path)


def test_accepts_record_id_order_when_event_time_reverses(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:10.000", time_created="2026-10-03T00:00:10Z"),
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "RecordId": 2,
            },
        ],
    )

    records = validate_standalone_sysmon_jsonl(jsonl_path)

    assert [record.data["RecordId"] for record in records] == [1, 2]


def test_orders_standalone_processing_by_event_time_then_record_id(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:10.000", time_created="2026-10-03T00:00:10Z"),
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "RecordId": 3,
            },
            {
                **_record(
                    "2026-10-03 00:00:10.000",
                    time_created="2026-10-03T00:00:10Z",
                ),
                "RecordId": 2,
            },
        ],
    )

    ordered = _order_standalone_sysmon_records(validate_standalone_sysmon_jsonl(jsonl_path))

    assert [record.data["RecordId"] for record in ordered] == [3, 1, 2]


def test_orders_standalone_processing_with_sub_millisecond_event_times(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:00.000900", time_created="2026-10-03T00:00:00Z"),
            {
                **_record(
                    "2026-10-03 00:00:00.000100",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "RecordId": 2,
            },
        ],
    )

    ordered = _order_standalone_sysmon_records(validate_standalone_sysmon_jsonl(jsonl_path))

    assert [record.data["RecordId"] for record in ordered] == [2, 1]


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
