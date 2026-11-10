import logging
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from incident_awareness.common.models.pipeline_runtime import PipelineRuntimeState
from incident_awareness.pipeline import runner
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.fusion import S0FusionPipelineResult
from incident_awareness.pipeline.reporting import PipelineExecutionSummary
from incident_awareness.pipeline.runner import run_first_cycle_pipeline
from incident_awareness.pipeline.stage_timing import PipelineStageTimingCollector
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


class _Connection:
    def __init__(self, *, fail_rollback: bool = False) -> None:
        self.rollbacks = 0
        self._fail_rollback = fail_rollback

    def rollback(self) -> None:
        self.rollbacks += 1
        if self._fail_rollback:
            raise RuntimeError("database rollback failed")


def test_runs_each_first_cycle_stage_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    calls: list[str] = []
    connection = object()
    artifacts = SimpleNamespace(
        run_metadata=SimpleNamespace(run_id="RUN-20260920-001"),
        sysmon_records=(object(), object()),
    )
    normalized_artifacts = object()
    fusion_result = object()
    stopping_trace = object()
    runtime_config_snapshot = object()
    fusion_output = S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
    )
    fast_result = object()
    decision_result = object()
    summary = PipelineExecutionSummary(
        run_id="RUN-20260920-001",
        entity_id="WIN-01",
        normalized_event_count=2,
        evidence_count=2,
        fusion_status="detected",
        detector_status="detected",
        decision_path="fast_and_fusion",
    )

    monkeypatch.setattr(
        runner,
        "load_s0_pipeline_artifacts",
        lambda inputs: _record(calls, "artifact_validation", artifacts),
    )
    monkeypatch.setattr(
        runner,
        "normalize_sysmon_and_extract_evidence",
        lambda value, **kwargs: _record(calls, "normalization", normalized_artifacts),
    )
    monkeypatch.setattr(
        runner,
        "run_s0_fusion_with_trace",
        lambda inputs, value, normalized: _record(calls, "fusion", fusion_output),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        lambda inputs, value: _record(calls, "fast_handoff", fast_result),
    )

    def resolve_expected_supersedes(**kwargs) -> str:
        assert kwargs == {
            "decision_id": "D-001",
            "run_id": "RUN-20260920-001",
            "entity_id": "WIN-01",
            "connection": connection,
        }
        return _record(calls, "lifecycle_resolution", "D-000")

    def combine_decision(inputs, fast, fusion, *, supersedes_decision_id):
        assert supersedes_decision_id == "D-000"
        return _record(calls, "hybrid", decision_result)

    monkeypatch.setattr(
        runner,
        "resolve_expected_supersedes_decision_id",
        resolve_expected_supersedes,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        combine_decision,
    )

    def persist_results(*args, **kwargs) -> None:
        assert args == (
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            runtime_config_snapshot,
            fast_result,
            decision_result,
        )
        assert kwargs == {"connection": connection}
        _record(calls, "persistence", None)

    monkeypatch.setattr(runner, "persist_s0_results", persist_results)
    monkeypatch.setattr(runner, "build_execution_summary", lambda *args: summary)
    monkeypatch.setattr(runner, "log_execution_summary", lambda value: calls.append("summary"))

    # When
    actual_summary = run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert actual_summary == summary
    assert calls == [
        "artifact_validation",
        "normalization",
        "fusion",
        "fast_handoff",
        "lifecycle_resolution",
        "hybrid",
        "persistence",
        "summary",
    ]


def test_publishes_runtime_stage_and_normalization_progress_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    snapshots = []
    now = datetime(2026, 10, 4, 1, 2, 3, 456000, tzinfo=UTC)
    monkeypatch.setattr(runner, "generate_execution_id", lambda: "execution-001")
    monkeypatch.setattr(runner, "utc_now_milliseconds", lambda: now)

    # When
    actual = run_first_cycle_pipeline(_inputs(), runtime_observer=snapshots.append)

    # Then
    assert actual == summary
    assert [snapshot.current_stage for snapshot in snapshots] == [
        runner.PipelineStage.NORMALIZATION,
        runner.PipelineStage.NORMALIZATION,
        runner.PipelineStage.NORMALIZATION,
        runner.PipelineStage.FUSION,
        runner.PipelineStage.FAST_HANDOFF,
        runner.PipelineStage.HYBRID,
        runner.PipelineStage.PERSISTENCE,
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
        2,
    ]
    assert {snapshot.execution_id for snapshot in snapshots} == {"execution-001"}
    assert {snapshot.started_at for snapshot in snapshots} == {now}
    assert snapshots[-1].status is PipelineRuntimeState.COMPLETED


def test_artifact_validation_failure_publishes_no_runtime_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = ValueError("invalid artifacts")
    snapshots = []
    calls: list[str] = []
    monkeypatch.setattr(
        runner,
        "utc_now_milliseconds",
        lambda: _record(calls, "clock", datetime(2026, 10, 4, tzinfo=UTC)),
    )
    monkeypatch.setattr(
        runner,
        "generate_execution_id",
        lambda: _record(calls, "execution_id", "execution-001"),
    )

    def fail_artifact_validation(inputs):
        calls.append("artifact_validation")
        raise expected_error

    monkeypatch.setattr(
        runner,
        "load_s0_pipeline_artifacts",
        fail_artifact_validation,
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        run_first_cycle_pipeline(_inputs(), runtime_observer=snapshots.append)

    # Then
    assert exc_info.value is expected_error
    assert snapshots == []
    assert calls == ["clock", "artifact_validation"]


def test_started_at_capture_failure_does_not_stop_business_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    expected_error = RuntimeError("runtime clock unavailable")
    snapshots = []
    monkeypatch.setattr(
        runner,
        "utc_now_milliseconds",
        lambda: (_ for _ in ()).throw(expected_error),
    )

    # When
    with caplog.at_level(logging.ERROR):
        actual = run_first_cycle_pipeline(
            _inputs(),
            runtime_observer=snapshots.append,
        )

    # Then
    assert actual == summary
    assert snapshots == []
    assert caplog.text.count("Pipeline Runtime started_at capture failed") == 1


def test_execution_id_bootstrap_failure_does_not_stop_business_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    expected_error = RuntimeError("execution ID unavailable")
    snapshots = []
    monkeypatch.setattr(
        runner,
        "generate_execution_id",
        lambda: (_ for _ in ()).throw(expected_error),
    )

    # When
    with caplog.at_level(logging.ERROR):
        actual = run_first_cycle_pipeline(
            _inputs(),
            runtime_observer=snapshots.append,
        )

    # Then
    assert actual == summary
    assert snapshots == []
    assert caplog.text.count("Pipeline Runtime tracker bootstrap failed") == 1


@pytest.mark.parametrize(
    "failing_stage",
    ["normalization", "fusion", "fast_handoff", "hybrid", "persistence"],
)
def test_publishes_failed_runtime_snapshot_for_business_stage_error(
    monkeypatch: pytest.MonkeyPatch,
    failing_stage: str,
) -> None:
    # Given
    expected_error = RuntimeError(f"{failing_stage} failed")
    snapshots = []
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage=failing_stage,
        error=expected_error,
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), runtime_observer=snapshots.append)

    # Then
    assert exc_info.value is expected_error
    assert snapshots[-1].status is PipelineRuntimeState.FAILED
    assert snapshots[-1].failed_stage.value == failing_stage


def test_observer_failure_does_not_change_successful_pipeline_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)

    def failing_observer(status) -> None:
        raise RuntimeError("telemetry unavailable")

    # When
    actual = run_first_cycle_pipeline(_inputs(), runtime_observer=failing_observer)

    # Then
    assert actual == summary


def test_observer_failure_does_not_replace_business_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("fusion failed")
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="fusion",
        error=expected_error,
    )

    def failing_observer(status) -> None:
        raise ValueError("telemetry unavailable")

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), runtime_observer=failing_observer)

    # Then
    assert exc_info.value is expected_error


def test_tracker_stage_start_failure_does_not_stop_business_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    monkeypatch.setattr(runner, "utc_now_milliseconds", _clock_failing_on(2))

    # When
    actual = run_first_cycle_pipeline(_inputs())

    # Then
    assert actual == summary


def test_tracker_progress_failure_does_not_stop_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    monkeypatch.setattr(runner, "utc_now_milliseconds", _clock_failing_on(3))

    # When
    actual = run_first_cycle_pipeline(_inputs())

    # Then
    assert actual == summary


def test_tracker_failure_does_not_replace_fusion_business_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("fusion business failed")
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="fusion",
        error=expected_error,
    )
    monkeypatch.setattr(runner, "utc_now_milliseconds", _clock_failing_on(4))

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs())

    # Then
    assert exc_info.value is expected_error


def test_tracker_completion_failure_does_not_replace_successful_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    summary = _configure_completed_pipeline(monkeypatch)
    monkeypatch.setattr(runner, "utc_now_milliseconds", _clock_failing_on(9))

    # When
    actual = run_first_cycle_pipeline(_inputs())

    # Then
    assert actual == summary


def test_rolls_back_caller_connection_when_combine_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _Connection()
    error = RuntimeError("Decision combination failed")
    persistence_calls: list[object] = []
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="none",
        error=error,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        _raise_or_return("combine", "combine", error, None),
    )
    monkeypatch.setattr(
        runner,
        "persist_s0_results",
        lambda *args, **kwargs: persistence_calls.append(None),
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert exc_info.value is error
    assert connection.rollbacks == 1
    assert persistence_calls == []


def test_preserves_combine_error_when_rollback_fails(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    connection = _Connection(fail_rollback=True)
    error = RuntimeError("Decision combination failed")
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="none",
        error=error,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        _raise_or_return("combine", "combine", error, None),
    )

    # When
    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert exc_info.value is error
    assert connection.rollbacks == 1
    assert "Hybrid Decision rollback failed" in caplog.text


@pytest.mark.parametrize(
    ("failing_stage", "error"),
    [
        ("artifact_validation", ValueError("manifest run_id mismatch")),
        ("fast_handoff", ValueError("FastHit trace run_id mismatch")),
        ("hybrid", DecisionIntegrityError("Decision lifecycle is invalid")),
        ("persistence", RuntimeError("database connection lost")),
    ],
)
def test_logs_and_reraises_failure_at_each_external_boundary(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failing_stage: str,
    error: Exception,
) -> None:
    _configure_successful_stages(monkeypatch, runner, failing_stage=failing_stage, error=error)

    with (
        caplog.at_level(logging.ERROR, logger="incident_awareness.pipeline.reporting"),
        pytest.raises(type(error), match=str(error)),
    ):
        run_first_cycle_pipeline(_inputs(), connection=object())

    assert f"stage={failing_stage}" in caplog.text
    assert str(error) in caplog.text


def _configure_successful_stages(
    monkeypatch: pytest.MonkeyPatch,
    runner: object,
    *,
    failing_stage: str,
    error: Exception,
) -> None:
    artifacts = SimpleNamespace(
        run_metadata=SimpleNamespace(run_id="RUN-20260920-001"),
        sysmon_records=(object(),),
    )
    normalized_artifacts = object()
    fusion_result = object()
    stopping_trace = object()
    runtime_config_snapshot = object()
    fusion_output = S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
    )
    fast_result = object()
    decision_result = object()

    monkeypatch.setattr(
        runner,
        "load_s0_pipeline_artifacts",
        _raise_or_return(failing_stage, "artifact_validation", error, artifacts),
    )
    monkeypatch.setattr(
        runner,
        "normalize_sysmon_and_extract_evidence",
        _raise_or_return(failing_stage, "normalization", error, normalized_artifacts),
    )
    monkeypatch.setattr(
        runner,
        "run_s0_fusion_with_trace",
        _raise_or_return(failing_stage, "fusion", error, fusion_output),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        _raise_or_return(failing_stage, "fast_handoff", error, fast_result),
    )
    monkeypatch.setattr(
        runner,
        "resolve_expected_supersedes_decision_id",
        _raise_or_return(failing_stage, "hybrid", error, None),
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        lambda *args, **kwargs: decision_result,
    )
    monkeypatch.setattr(
        runner,
        "persist_s0_results",
        _raise_or_return(failing_stage, "persistence", error, None),
    )


def _configure_completed_pipeline(monkeypatch: pytest.MonkeyPatch) -> PipelineExecutionSummary:
    artifacts = SimpleNamespace(
        run_metadata=SimpleNamespace(run_id="RUN-20260920-001"),
        sysmon_records=(object(), object()),
    )
    normalized_artifacts = object()
    fusion_result = object()
    fusion_output = S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=object(),
        runtime_config_snapshot=object(),
    )
    summary = PipelineExecutionSummary(
        run_id="RUN-20260920-001",
        entity_id="WIN-01",
        normalized_event_count=2,
        evidence_count=2,
        fusion_status="detected",
        detector_status="detected",
        decision_path="fast_and_fusion",
    )
    monkeypatch.setattr(runner, "load_s0_pipeline_artifacts", lambda inputs: artifacts)

    def normalize(value, *, progress_callback=None, telemetry_collector=None):
        for count in (1, 2):
            if telemetry_collector is not None:
                telemetry_collector.record_success(telemetry_collector.begin_record(count))
            if progress_callback is not None:
                progress_callback(count)
        return normalized_artifacts

    monkeypatch.setattr(runner, "normalize_sysmon_and_extract_evidence", normalize)
    monkeypatch.setattr(runner, "run_s0_fusion_with_trace", lambda *args: fusion_output)
    monkeypatch.setattr(runner, "load_s0_fast_detection", lambda *args: object())
    monkeypatch.setattr(
        runner,
        "resolve_expected_supersedes_decision_id",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(runner, "combine_parallel_decision", lambda *args, **kwargs: object())
    monkeypatch.setattr(runner, "persist_s0_results", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "build_execution_summary", lambda *args: summary)
    monkeypatch.setattr(runner, "log_execution_summary", lambda value: None)
    return summary


def test_pipeline_shares_execution_and_flushes_short_batch(monkeypatch) -> None:
    # Given
    expected = _configure_completed_pipeline(monkeypatch)
    runtime, telemetry = [], []
    generated = []
    timing = PipelineStageTimingCollector()
    monkeypatch.setattr(
        runner, "generate_execution_id", lambda: generated.append("shared") or "shared"
    )

    # When
    actual = run_first_cycle_pipeline(
        _inputs(),
        runtime_observer=runtime.append,
        telemetry_observer=telemetry.append,
        stage_timing_collector=timing,
    )

    # Then
    assert actual == expected
    assert generated == ["shared"]
    assert {item.execution_id for item in runtime + telemetry} == {"shared"}
    assert timing.snapshot().execution_id == "shared"
    assert [record.stage for record in timing.snapshot().records] == list(runner.PipelineStage)
    latest = telemetry[-1]
    assert sum(bucket.input_accepted_count for bucket in latest.buckets) == 2
    assert sum(bucket.processing_completed_count for bucket in latest.buckets) == 2
    assert sum(bucket.latency_sample_count for bucket in latest.buckets) == 2
    assert (
        latest.input_total == runtime[-1].input_total == runtime[-1].normalization_processed_count
    )
    assert runtime[-1].status is PipelineRuntimeState.COMPLETED


def test_collector_creation_error_preserves_pipeline_summary_and_runtime(monkeypatch) -> None:
    # Given
    from incident_awareness.pipeline import timeseries_observer

    expected = _configure_completed_pipeline(monkeypatch)
    runtime, telemetry = [], []

    def fail(**kwargs):
        raise RuntimeError("Collector construction failed")

    monkeypatch.setattr(timeseries_observer, "create_pipeline_telemetry_collector", fail)

    # When
    actual = run_first_cycle_pipeline(
        _inputs(),
        runtime_observer=runtime.append,
        telemetry_observer=telemetry.append,
    )

    # Then
    assert actual == expected
    assert runtime[-1].status is PipelineRuntimeState.COMPLETED
    assert telemetry == []


def test_timeseries_observer_failure_cannot_fail_business_or_runtime(monkeypatch) -> None:
    # Given
    expected = _configure_completed_pipeline(monkeypatch)
    runtime = []

    def fail(snapshot):
        raise RuntimeError("timeseries unavailable")

    # When
    actual = run_first_cycle_pipeline(
        _inputs(), runtime_observer=runtime.append, telemetry_observer=fail
    )

    # Then
    assert actual == expected
    assert runtime[-1].status is PipelineRuntimeState.COMPLETED
    assert all(item.status is not PipelineRuntimeState.FAILED for item in runtime)


def test_disabled_runtime_tracker_does_not_disable_timeseries(monkeypatch) -> None:
    # Given
    expected = _configure_completed_pipeline(monkeypatch)
    telemetry = []

    def fail(self, stage):
        raise RuntimeError("Runtime internal error")

    monkeypatch.setattr(runner.PipelineRuntimeTracker, "_start_stage", fail)

    # When
    actual = run_first_cycle_pipeline(_inputs(), telemetry_observer=telemetry.append)

    # Then
    assert actual == expected
    assert sum(bucket.processing_completed_count for bucket in telemetry[-1].buckets) == 2
    assert telemetry[-1].observation_status == "observed"


def test_stage_timing_records_all_six_operations_without_changing_runtime_or_summary(
    monkeypatch,
) -> None:
    # Given
    from itertools import count

    expected = _configure_completed_pipeline(monkeypatch)
    runtime, published = [], []
    ticks = count(0, 123)
    timing = PipelineStageTimingCollector(
        monotonic_clock=lambda: next(ticks), observer=published.append
    )

    # When
    result = run_first_cycle_pipeline(
        _inputs(), runtime_observer=runtime.append, stage_timing_collector=timing
    )
    snapshot = timing.snapshot()

    # Then
    assert result is expected
    assert [record.stage for record in snapshot.records] == list(runner.PipelineStage)
    assert [record.duration_ns for record in snapshot.records] == [123] * 6
    assert [record.invocation_index for record in snapshot.records] == list(range(1, 7))
    assert snapshot.run_id == expected.run_id and snapshot.entity_id == expected.entity_id
    assert snapshot.execution_id == runtime[-1].execution_id
    assert published[0].run_id is None and published[0].execution_id is None
    assert published[1].execution_id == snapshot.execution_id
    assert published[0].records == published[1].records
    assert runtime[-1].status is PipelineRuntimeState.COMPLETED


@pytest.mark.parametrize("stage", list(runner.PipelineStage))
def test_stage_timing_preserves_previous_success_and_failure_and_never_runs_later_stages(
    monkeypatch, stage
) -> None:
    # Given
    error = ValueError("fixture stage failed")
    _configure_successful_stages(monkeypatch, runner, failing_stage=stage.value, error=error)
    timing = PipelineStageTimingCollector()
    runtime = []

    # When
    with pytest.raises(ValueError) as caught:
        run_first_cycle_pipeline(
            _inputs(), runtime_observer=runtime.append, stage_timing_collector=timing
        )
    snapshot = timing.snapshot()

    # Then
    assert caught.value is error
    expected = list(runner.PipelineStage)[: list(runner.PipelineStage).index(stage) + 1]
    assert [record.stage for record in snapshot.records] == expected
    assert [record.outcome for record in snapshot.records] == ["completed"] * (
        len(expected) - 1
    ) + ["failed"]
    assert all(record.duration_ns >= 0 for record in snapshot.records)
    assert snapshot.active_stage is None
    if stage is runner.PipelineStage.ARTIFACT_VALIDATION:
        assert runtime == []
        assert (
            snapshot.run_id is None and snapshot.entity_id is None and snapshot.execution_id is None
        )
    else:
        assert runtime[-1].failed_stage is stage
        assert snapshot.execution_id == runtime[-1].execution_id


def test_stage_timing_separates_same_run_executions_and_refuses_collector_reuse(
    monkeypatch,
) -> None:
    # Given
    expected = _configure_completed_pipeline(monkeypatch)
    first, second = PipelineStageTimingCollector(), PipelineStageTimingCollector()

    # When
    assert run_first_cycle_pipeline(_inputs(), stage_timing_collector=first) == expected
    first_snapshot = first.snapshot()
    assert run_first_cycle_pipeline(_inputs(), stage_timing_collector=second) == expected
    assert run_first_cycle_pipeline(_inputs(), stage_timing_collector=first) == expected

    # Then
    assert first.snapshot() == first_snapshot
    assert first.snapshot().run_id == second.snapshot().run_id
    assert first.snapshot().execution_id != second.snapshot().execution_id
    assert first.snapshot().attempt_id != second.snapshot().attempt_id
    assert len(first.snapshot().records) == len(second.snapshot().records) == 6


@pytest.mark.parametrize("fault", ["bootstrap", "begin", "finish", "bind", "observer"])
@pytest.mark.parametrize("business_fails", [False, True])
def test_stage_instrumentation_errors_never_replace_summary_or_original_exception(
    monkeypatch, fault, business_fails
) -> None:
    # Given
    error = ValueError("original pipeline failure")
    expected = _configure_completed_pipeline(monkeypatch)
    if business_fails:
        _configure_successful_stages(monkeypatch, runner, failing_stage="fusion", error=error)
    timing = PipelineStageTimingCollector()

    def broken(*args, **kwargs):
        raise RuntimeError("fixture instrumentation failure")

    if fault == "bootstrap":
        monkeypatch.setattr(runner, "PipelineStageTimingCollector", broken)
        from incident_awareness.pipeline import stage_timing

        monkeypatch.setattr(stage_timing, "PipelineStageTimingCollector", broken)
        timing = None
    elif fault == "observer":
        timing = PipelineStageTimingCollector(observer=broken)
    else:
        monkeypatch.setattr(timing, fault, broken)

    # When / Then
    if business_fails:
        with pytest.raises(ValueError) as caught:
            run_first_cycle_pipeline(_inputs(), stage_timing_collector=timing)
        assert caught.value is error
    else:
        assert run_first_cycle_pipeline(_inputs(), stage_timing_collector=timing) is expected


def test_timing_survives_runtime_bootstrap_failure_without_inventing_execution_join(
    monkeypatch,
) -> None:
    # Given
    expected = _configure_completed_pipeline(monkeypatch)
    timing = PipelineStageTimingCollector()
    monkeypatch.setattr(runner, "_capture_runtime_started_at", lambda: None)

    # When
    result = run_first_cycle_pipeline(_inputs(), stage_timing_collector=timing)

    # Then
    assert result is expected
    assert len(timing.snapshot().records) == 6
    assert timing.snapshot().execution_id is None
    assert timing.snapshot().run_id == expected.run_id
    assert timing.snapshot().attempt_id


def _raise_or_return(
    failing_stage: str,
    current_stage: str,
    error: Exception,
    value: object,
):
    def operation(*args, **kwargs):
        if current_stage == failing_stage:
            raise error
        return value

    return operation


def _record(calls: list[str], stage: str, value: object) -> object:
    calls.append(stage)
    return value


def _clock_failing_on(failing_call: int):
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        if calls == failing_call:
            raise RuntimeError("runtime telemetry clock failed")
        return datetime(2026, 10, 4, 1, 2, 3, calls * 1000, tzinfo=UTC)

    return clock


def _inputs() -> PipelineInputs:
    unused_path = Path("unused")
    return PipelineInputs(
        run_metadata_path=unused_path,
        manifest_path=unused_path,
        sysmon_jsonl_path=unused_path,
        fast_hits_path=unused_path,
        fast_trace_path=unused_path,
        fast_selection_path=unused_path,
        fusion_config_path=unused_path,
        entity_id="WIN-01",
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )
