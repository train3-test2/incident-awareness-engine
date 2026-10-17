from datetime import UTC, datetime, timedelta, timezone
from itertools import count

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_stage_timing import (
    PipelineStageTimingRecord,
    PipelineStageTimingSnapshot,
)
from incident_awareness.pipeline import runner, stage_timing
from incident_awareness.pipeline.stage_timing import (
    PipelineStageTimingCollector,
    start_stage_timing,
)

NOW = datetime(2026, 10, 17, 1, 2, 3, 456000, tzinfo=UTC)


def _collector(**kwargs) -> PipelineStageTimingCollector:
    ticks = count(0, 17)
    return PipelineStageTimingCollector(
        clock=kwargs.pop("clock", lambda: NOW),
        monotonic_clock=kwargs.pop("monotonic_clock", lambda: next(ticks)),
        **kwargs,
    )


def _record(**kwargs) -> PipelineStageTimingRecord:
    return PipelineStageTimingRecord.model_validate(
        {
            "stage": "fusion",
            "invocation_index": 1,
            "outcome": "completed",
            "started_at": NOW,
            "ended_at": NOW,
            "duration_ns": 17,
            **kwargs,
        }
    )


def test_ended_operations_have_exact_ns_and_repeated_stages_have_distinct_ordinals() -> None:
    # Given
    timing = start_stage_timing(_collector())

    # When
    for stage in [*PipelineStage, PipelineStage.FUSION]:
        token = timing.begin(stage)
        timing.finish(token, failed=False)
    timing.bind(execution_id="execution-1", run_id="RUN-20261017-001", entity_id="WIN-01")
    snapshot = timing.snapshot()

    # Then
    assert [r.stage for r in snapshot.records] == [*PipelineStage, PipelineStage.FUSION]
    assert [r.invocation_index for r in snapshot.records] == list(range(1, 8))
    assert [r.duration_ns for r in snapshot.records] == [17] * 7
    assert all(r.outcome == "completed" for r in snapshot.records)
    assert snapshot.execution_id == "execution-1"
    assert snapshot.quality_status == "observed"
    assert snapshot.active_stage is None


def test_running_operation_has_no_duration_or_completed_record() -> None:
    # Given
    timing = start_stage_timing(_collector())

    # When
    timing.begin(PipelineStage.FUSION)
    snapshot = timing.snapshot()

    # Then
    assert snapshot.records == ()
    assert snapshot.active_stage is PipelineStage.FUSION
    assert snapshot.active_invocation_index == 1
    assert snapshot.quality_status == "unavailable"


def test_duplicate_finish_is_idempotent_and_conflicting_outcome_cannot_rewrite_record() -> None:
    # Given
    delivered = []
    timing = start_stage_timing(_collector(observer=delivered.append))
    token = timing.begin(PipelineStage.FUSION)
    timing.finish(token, failed=True)
    before = timing.snapshot()

    # When
    timing.finish(token, failed=False)
    timing.finish(token, failed=True)

    # Then
    assert timing.snapshot() == before
    assert len(delivered) == 1
    assert timing.snapshot().records[0].outcome == "failed"


def test_attempt_scope_binding_and_observer_snapshots_are_immutable() -> None:
    # Given
    delivered = []
    timing = start_stage_timing(_collector(observer=delivered.append))
    timing.finish(timing.begin(PipelineStage.ARTIFACT_VALIDATION), failed=False)
    unbound = delivered[-1]

    # When
    timing.bind(execution_id="execution-1", run_id="RUN-20261017-001", entity_id="WIN-01")
    bound = delivered[-1]
    timing.bind(execution_id="execution-1", run_id="RUN-20261017-001", entity_id="WIN-01")

    # Then
    assert unbound.run_id is None and unbound.execution_id is None
    assert bound.attempt_id == unbound.attempt_id
    assert bound.records == unbound.records
    assert bound.revision > unbound.revision
    assert len(delivered) == 2
    with pytest.raises(ValueError, match="identity cannot change"):
        timing.bind(execution_id="other", run_id="RUN-20261017-001", entity_id="WIN-01")
    with pytest.raises(ValidationError):
        bound.records[0].duration_ns = 0


def test_foreign_tokens_and_reused_collectors_cannot_mix_attempts() -> None:
    # Given
    first, second = start_stage_timing(_collector()), start_stage_timing(_collector())
    token = first.begin(PipelineStage.FUSION)

    # When / Then
    with pytest.raises(ValueError, match="another attempt"):
        second.finish(token, failed=False)
    assert start_stage_timing(first) is None
    assert second.snapshot().records == ()
    assert first.snapshot().attempt_id != second.snapshot().attempt_id


@pytest.mark.parametrize("bad", [-1, True, 1.5, float("nan"), "17"])
def test_model_rejects_invalid_duration(bad) -> None:
    # Given / When / Then
    with pytest.raises(ValidationError):
        _record(duration_ns=bad)


@pytest.mark.parametrize(
    "bad",
    [
        NOW.replace(tzinfo=None),
        NOW.astimezone(timezone(timedelta(hours=9))),
        NOW.replace(microsecond=1),
        123,
        "123",
    ],
)
def test_model_rejects_non_utc_or_non_millisecond_or_numeric_time(bad) -> None:
    # Given / When / Then
    with pytest.raises((ValidationError, TypeError)):
        _record(started_at=bad)


def test_utc_json_roundtrip_and_real_zero_duration() -> None:
    # Given
    record = _record(duration_ns=0)

    # When
    serialized = record.model_dump(mode="json")

    # Then
    assert serialized["started_at"] == "2026-10-17T01:02:03.456Z"
    assert serialized["ended_at"] == "2026-10-17T01:02:03.456Z"
    assert serialized["duration_ns"] == 0
    assert PipelineStageTimingRecord.model_validate(serialized) == record


@pytest.mark.parametrize("bad", [-1, True, 2.5, None, "bad"])
@pytest.mark.parametrize("boundary", [0, 1])
def test_invalid_monotonic_boundary_yields_partial_not_zero(bad, boundary) -> None:
    # Given
    values = [100, 117]
    values[boundary] = bad
    times = iter(values)
    timing = start_stage_timing(_collector(monotonic_clock=lambda: next(times)))

    # When
    timing.finish(timing.begin(PipelineStage.FUSION), failed=False)
    snapshot = timing.snapshot()

    # Then
    assert snapshot.quality_status == "partial"
    assert snapshot.records[0].duration_ns is None
    assert "monotonic_clock_error" in snapshot.records[0].issues


def test_monotonic_regression_is_unknown_and_wall_regression_is_independent() -> None:
    # Given
    utc = iter([NOW, NOW - timedelta(seconds=2), NOW, NOW - timedelta(seconds=2)])
    ns = iter([100, 90, 100, 117])
    timing = start_stage_timing(
        _collector(clock=lambda: next(utc), monotonic_clock=lambda: next(ns))
    )

    # When
    for _ in range(2):
        timing.finish(timing.begin(PipelineStage.FUSION), failed=False)

    # Then
    first, second = timing.snapshot().records
    assert first.duration_ns is None and "invalid_duration" in first.issues
    assert second.duration_ns == 17
    assert all("wall_clock_regression" in r.issues for r in [first, second])


@pytest.mark.parametrize("boundary", [0, 1])
def test_missing_utc_boundary_preserves_monotonic_duration_and_partial_quality(boundary) -> None:
    # Given
    times = [NOW, NOW]
    times[boundary] = None
    utc = iter(times)
    timing = start_stage_timing(_collector(clock=lambda: next(utc)))

    # When
    timing.finish(timing.begin(PipelineStage.FUSION), failed=True)
    record = timing.snapshot().records[0]

    # Then
    assert record.duration_ns == 17
    assert record.outcome == "failed"
    assert "utc_clock_error" in record.issues
    assert timing.snapshot().quality_status == "partial"


def test_clock_and_observer_exceptions_do_not_change_operation_result() -> None:
    # Given
    def broken():
        raise RuntimeError("test clock failure")

    def observer(_):
        raise RuntimeError("test observer failure")

    timing = start_stage_timing(_collector(clock=broken, monotonic_clock=broken, observer=observer))
    expected = object()

    # When
    actual = runner._run_stage(PipelineStage.FUSION, lambda: expected, stage_timing=timing)

    # Then
    assert actual is expected
    assert timing.snapshot().records[0].duration_ns is None
    assert "observer_error" in timing.snapshot().issues


@pytest.mark.parametrize("fails", [False, True])
def test_outer_runtime_observers_and_final_flush_are_excluded_but_operation_callbacks_included(
    fails,
) -> None:
    # Given
    ns = [0]
    events = []

    def advance(name, amount):
        events.append(name)
        ns[0] += amount

    class Runtime:
        def start_stage(self, _):
            advance("runtime-start", 1000)

        def fail(self, _):
            advance("runtime-fail", 2000)

    class Session:
        def flush(self, **kwargs):
            advance("final-flush", 4000)

    timing = start_stage_timing(
        _collector(
            monotonic_clock=lambda: ns[0],
            observer=lambda _: advance("timing-observer", 3000),
        )
    )
    expected = ValueError("business failed")

    def operation():
        advance("operation-callback", 17)
        if fails:
            raise expected
        return "result"

    # When
    if fails:
        with pytest.raises(ValueError) as caught:
            runner._run_stage(
                PipelineStage.FUSION,
                operation,
                runtime_tracker=Runtime(),
                telemetry_session=Session(),
                stage_timing=timing,
            )
        assert caught.value is expected
    else:
        assert (
            runner._run_stage(
                PipelineStage.FUSION,
                operation,
                runtime_tracker=Runtime(),
                telemetry_session=Session(),
                stage_timing=timing,
            )
            == "result"
        )

    # Then
    assert timing.snapshot().records[0].duration_ns == 17
    assert events == [
        "runtime-start",
        "operation-callback",
        "timing-observer",
        *(["runtime-fail"] if fails else []),
        "final-flush",
    ]


def test_buffer_limit_keeps_prior_records_and_does_not_generate_unexecuted_duration(
    monkeypatch,
) -> None:
    # Given
    monkeypatch.setattr(stage_timing, "_MAX_RECORDS", 1)
    timing = start_stage_timing(_collector())

    # When
    assert runner._run_stage(PipelineStage.FUSION, lambda: 1, stage_timing=timing) == 1
    assert runner._run_stage(PipelineStage.HYBRID, lambda: 2, stage_timing=timing) == 2

    # Then
    assert len(timing.snapshot().records) == 1
    assert timing.snapshot().issues == ("buffer_limit",)
    assert timing.snapshot().quality_status == "partial"


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "RUN-20261017-001"},
        {"execution_id": "execution-1"},
        {"active_stage": PipelineStage.FUSION},
        {"quality_status": "observed"},
        {"records": (_record(), _record())},
    ],
)
def test_snapshot_rejects_inconsistent_scope_or_coverage(change) -> None:
    # Given
    snapshot = _collector().snapshot().model_dump()

    # When / Then
    with pytest.raises(ValidationError):
        PipelineStageTimingSnapshot.model_validate({**snapshot, **change})


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(2)])
def test_business_base_exception_is_preserved_and_ended_as_failed(error) -> None:
    # Given
    timing = start_stage_timing(_collector())

    def operation():
        raise error

    # When
    with pytest.raises(type(error)) as caught:
        runner._run_stage(PipelineStage.FUSION, operation, stage_timing=timing)

    # Then
    assert caught.value is error
    assert timing.snapshot().records[0].outcome == "failed"
    assert timing.snapshot().records[0].duration_ns == 17


def test_broken_finish_and_quality_marker_do_not_mask_original_business_failure(
    monkeypatch,
) -> None:
    # Given
    timing = start_stage_timing(_collector())
    error = ValueError("original business error")

    def broken(*args, **kwargs):
        raise RuntimeError("instrumentation failure")

    def operation():
        raise error

    monkeypatch.setattr(timing, "finish", broken)
    monkeypatch.setattr(timing, "mark_internal_error", broken)

    # When
    with pytest.raises(ValueError) as caught:
        runner._run_stage(PipelineStage.FUSION, operation, stage_timing=timing)

    # Then
    assert caught.value is error
