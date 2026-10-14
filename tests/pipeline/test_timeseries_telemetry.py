import logging
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_telemetry import TelemetryObservationIssue
from incident_awareness.pipeline import timeseries_telemetry
from incident_awareness.pipeline.timeseries_telemetry import (
    PipelineTelemetryCollector,
    create_pipeline_telemetry_collector,
)

START = datetime(2026, 10, 14, 23, 59, 59, 900000, tzinfo=UTC)


class _Clock:
    def __init__(self, value: object) -> None:
        self.value = value
        self.calls = 0
        self.error: Exception | None = None

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.value


def _collector(wall: _Clock, monotonic: _Clock) -> PipelineTelemetryCollector:
    return PipelineTelemetryCollector(
        execution_id="existing-runtime-execution",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        clock=wall,
        monotonic_clock=monotonic,
    )


def test_records_one_success_with_nanosecond_precision_and_existing_execution() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(100)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        monotonic.value = 107
    snapshot = collector.snapshot()

    # Then
    assert snapshot.execution_id == "existing-runtime-execution"
    assert snapshot.snapshot_id == "pipeline-telemetry:existing-runtime-execution"
    assert snapshot.aggregation_basis == "execution_attempt"
    assert snapshot.latency_scope == "normalization_and_evidence"
    assert snapshot.observation_status == "observed"
    bucket = snapshot.buckets[0]
    assert bucket.input_accepted_count == bucket.processing_completed_count == 1
    assert bucket.processing_failed_count == 0
    assert bucket.latency_sample_count == 1
    assert bucket.latency_sum_ns == 7


def test_short_batch_preserves_multiple_successes_and_latency_sum_in_one_bucket() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(3)

    # When
    for record_no, duration in enumerate((7, 23, 1_234_567), start=1):
        with collector.measure_record(record_no):
            monotonic.value += duration
            wall.value += timedelta(milliseconds=1)
    snapshot = collector.snapshot()

    # Then
    assert len(snapshot.buckets) == 1
    bucket = snapshot.buckets[0]
    assert bucket.input_accepted_count == bucket.processing_completed_count == 3
    assert bucket.latency_sample_count == 3
    assert bucket.latency_sum_ns == 1_234_597
    assert bucket.first_observed_at == START
    assert bucket.last_observed_at == START + timedelta(milliseconds=3)


def test_places_completions_before_and_at_utc_second_and_day_boundary() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(2)

    # When
    with collector.measure_record(1):
        wall.value = START.replace(microsecond=999000)
        monotonic.value = 99
    with collector.measure_record(2):
        wall.value = datetime(2026, 10, 15, tzinfo=UTC)
        monotonic.value = 100
    buckets = collector.snapshot().buckets

    # Then
    assert [bucket.bucket_start for bucket in buckets] == [
        START.replace(microsecond=0),
        datetime(2026, 10, 15, tzinfo=UTC),
    ]
    assert buckets[0].bucket_end == buckets[1].bucket_start
    assert [bucket.processing_completed_count for bucket in buckets] == [1, 1]
    assert [bucket.latency_sum_ns for bucket in buckets] == [99, 1]
    assert [bucket.input_accepted_count for bucket in buckets] == [2, 0]


def test_long_record_uses_completion_bucket_without_filling_unobserved_seconds() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(10)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        wall.value += timedelta(seconds=20)
        monotonic.value += 20_000_000_000
    buckets = collector.snapshot().buckets

    # Then
    assert len(buckets) == 2
    assert [bucket.processing_completed_count for bucket in buckets] == [0, 1]
    assert buckets[1].bucket_start == (START + timedelta(seconds=20)).replace(microsecond=0)
    assert buckets[1].latency_sum_ns == 20_000_000_000


def test_excludes_failed_record_duration_and_preserves_business_exception_identity() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(2)
    business_error = RuntimeError("Evidence extraction failed")

    # When
    with collector.measure_record(1):
        monotonic.value = 7
    with pytest.raises(RuntimeError) as exc_info, collector.measure_record(2):
        monotonic.value = 1_000_000
        raise business_error
    bucket = collector.snapshot().buckets[0]

    # Then
    assert exc_info.value is business_error
    assert bucket.processing_completed_count == bucket.processing_failed_count == 1
    assert bucket.latency_sample_count == 1
    assert bucket.latency_sum_ns == 7


def test_does_not_count_duplicate_admission_starts_or_completion_callbacks() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    token = collector.begin_record(1)

    # When
    collector.accept_batch(1)
    duplicate = collector.begin_record(1)
    monotonic.value = 7
    collector.record_success(token)
    first = collector.snapshot()
    calls = wall.calls, monotonic.calls
    collector.record_success(token)
    collector.record_failure(token)
    with collector.measure_record(1):
        pass
    second = collector.snapshot()

    # Then
    assert duplicate is None
    assert second is first
    assert (wall.calls, monotonic.calls) == calls
    assert first.buckets[0].processing_completed_count == 1
    assert first.buckets[0].processing_failed_count == 0


def test_failed_record_cannot_later_be_counted_as_a_success() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    token = collector.begin_record(1)

    # When
    collector.record_failure(token)
    collector.record_success(token)

    # Then
    bucket = collector.snapshot().buckets[0]
    assert bucket.processing_failed_count == 1
    assert bucket.processing_completed_count == bucket.latency_sample_count == 0


def test_snapshot_is_deeply_immutable_and_old_revision_does_not_change() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    admitted = collector.snapshot()
    serialized = admitted.model_dump_json()

    # When
    with collector.measure_record(1):
        monotonic.value = 1
    completed = collector.snapshot()
    with pytest.raises(ValidationError):
        admitted.buckets[0].processing_completed_count = 99
    with pytest.raises(ValidationError):
        admitted.buckets = ()

    # Then
    assert admitted.model_dump_json() == serialized
    assert admitted.buckets[0].processing_completed_count == 0
    assert completed.buckets[0].processing_completed_count == 1
    assert completed.snapshot_id == admitted.snapshot_id
    assert completed.revision > admitted.revision
    assert completed.buckets[0].revision > admitted.buckets[0].revision
    assert collector.snapshot() is completed


def test_preserves_unchanged_bucket_revision_when_later_bucket_changes() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    admitted = collector.snapshot()

    # When
    with collector.measure_record(1):
        wall.value += timedelta(seconds=1)
        monotonic.value = 1
    completed = collector.snapshot()

    # Then
    assert completed.buckets[0] is admitted.buckets[0]
    assert completed.buckets[0].revision == admitted.buckets[0].revision


def test_wall_clock_regression_disables_collection_and_retains_partial_observations() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(2)
    token = collector.begin_record(1)

    # When
    wall.value -= timedelta(milliseconds=1)
    monotonic.value = 1
    collector.record_success(token)
    collector.accept_batch(2)
    snapshot = collector.snapshot()

    # Then
    assert collector.is_disabled
    assert snapshot.collection_disabled
    assert snapshot.observation_status == "partial"
    assert snapshot.observation_issues == (TelemetryObservationIssue.WALL_CLOCK_REGRESSION,)
    assert snapshot.last_observed_at == START
    assert len(snapshot.buckets) == 1
    assert snapshot.buckets[0].processing_completed_count == 0


def test_unavailable_is_distinct_from_partial_and_observed() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)

    # When
    before = collector.snapshot()
    wall.error = RuntimeError("wall clock unavailable")
    collector.accept_batch(1)
    unavailable = collector.snapshot()

    # Then
    assert before.observation_status == unavailable.observation_status == "unavailable"
    assert before.buckets == unavailable.buckets == ()
    assert not before.collection_disabled
    assert unavailable.collection_disabled
    assert unavailable.observation_issues == (TelemetryObservationIssue.INTERNAL_ERROR,)


def test_backward_monotonic_duration_keeps_success_count_without_fabricating_latency() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(100)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        monotonic.value = 99
    snapshot = collector.snapshot()

    # Then
    bucket = snapshot.buckets[0]
    assert bucket.processing_completed_count == 1
    assert bucket.latency_sample_count == bucket.latency_sum_ns == 0
    assert snapshot.observation_status == "partial"
    assert snapshot.observation_issues == (TelemetryObservationIssue.INVALID_MONOTONIC_DURATION,)


@pytest.mark.parametrize("value", [True, -1, 1.5, None])
def test_invalid_monotonic_clock_keeps_success_without_a_latency_sample(value: object) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(value)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        pass
    snapshot = collector.snapshot()

    # Then
    assert snapshot.buckets[0].processing_completed_count == 1
    assert snapshot.buckets[0].latency_sample_count == snapshot.buckets[0].latency_sum_ns == 0
    assert snapshot.observation_status == "partial"
    assert snapshot.observation_issues == (TelemetryObservationIssue.MONOTONIC_CLOCK_ERROR,)


@pytest.mark.parametrize("failure_at_start", [True, False])
def test_monotonic_clock_exception_preserves_success_count(failure_at_start: bool) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(1)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    if failure_at_start:
        monotonic.error = RuntimeError("clock failed")

    # When
    with collector.measure_record(1):
        monotonic.error = RuntimeError("clock failed")
    snapshot = collector.snapshot()

    # Then
    assert snapshot.buckets[0].processing_completed_count == 1
    assert snapshot.buckets[0].latency_sample_count == 0
    assert snapshot.observation_status == "partial"


def test_true_zero_duration_is_a_measured_sample() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        pass

    # Then
    bucket = collector.snapshot().buckets[0]
    assert bucket.latency_sample_count == 1
    assert bucket.latency_sum_ns == 0


@pytest.mark.parametrize("business_fails", [True, False])
def test_telemetry_clock_failure_preserves_business_return_or_exception(
    business_fails: bool, caplog: pytest.LogCaptureFixture
) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    business_error = RuntimeError("original business exception")

    def business() -> str:
        with collector.measure_record(1):
            wall.error = RuntimeError("telemetry failed")
            if business_fails:
                raise business_error
            return "business result"

    # When
    with caplog.at_level(logging.ERROR):
        if business_fails:
            with pytest.raises(RuntimeError) as exc_info:
                business()
        else:
            result = business()
        with collector.measure_record(2):
            pass

    # Then
    if business_fails:
        assert exc_info.value is business_error
    else:
        assert result == "business result"
    assert collector.snapshot().observation_status == "partial"
    assert len(caplog.records) == 1


def test_duration_ends_before_wall_clock_and_external_progress_callback() -> None:
    # Given
    monotonic = _Clock(10)

    def wall() -> datetime:
        monotonic.value += 1_000_000
        return START

    collector = PipelineTelemetryCollector(
        execution_id="execution",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        clock=wall,
        monotonic_clock=monotonic,
    )
    collector.accept_batch(1)

    # When
    with collector.measure_record(1):
        monotonic.value += 7
    monotonic.value += 9_000_000  # Existing progress callback / observer work is outside the span.

    # Then
    assert collector.snapshot().buckets[0].latency_sum_ns == 7


@pytest.mark.parametrize("record_no", [0, -1, 2, True, "1"])
def test_invalid_record_callbacks_do_not_affect_business_execution(record_no: object) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    with collector.measure_record(record_no):
        business_result = "unchanged"

    # Then
    assert business_result == "unchanged"
    assert collector.is_disabled
    assert collector.snapshot().buckets[0].processing_completed_count == 0


def test_completion_token_cannot_cross_execution_collectors() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    first, second = _collector(wall, monotonic), _collector(wall, monotonic)
    first.accept_batch(1)
    second.accept_batch(1)
    token = first.begin_record(1)

    # When
    second.record_success(token)

    # Then
    assert second.is_disabled
    assert second.snapshot().buckets[0].processing_completed_count == 0
    assert first.snapshot().observation_status == "observed"


def test_bootstrap_error_is_best_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    def fail(**kwargs: object) -> None:
        raise RuntimeError("telemetry bootstrap failed")

    monkeypatch.setattr(timeseries_telemetry, "PipelineTelemetryCollector", fail)

    # When
    collector = create_pipeline_telemetry_collector(
        execution_id="existing-execution", run_id="RUN-20261014-001", entity_id="WIN-01"
    )

    # Then
    assert collector is None


def test_best_effort_bootstrap_preserves_the_existing_execution_id() -> None:
    # Given
    execution_id = "shared-with-runtime"

    # When
    collector = create_pipeline_telemetry_collector(
        execution_id=execution_id, run_id="RUN-20261014-001", entity_id="WIN-01"
    )

    # Then
    assert collector is not None
    assert collector.snapshot().execution_id == execution_id


def test_snapshot_internal_failure_retains_valid_values_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    admitted = collector.snapshot()

    def fail() -> None:
        raise RuntimeError("snapshot construction failed")

    monkeypatch.setattr(collector, "_build_snapshot", fail)

    # When
    with collector.measure_record(1):
        monotonic.value = 7
    snapshot = collector.snapshot()

    # Then
    assert snapshot.collection_disabled
    assert snapshot.observation_status == "partial"
    assert snapshot.buckets == admitted.buckets
    assert snapshot.observation_issues == (TelemetryObservationIssue.INTERNAL_ERROR,)
    assert collector.snapshot() is snapshot


def test_logging_failure_cannot_replace_business_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    business_error = RuntimeError("original business exception")

    def fail_log(*args: object, **kwargs: object) -> None:
        raise RuntimeError("logging failed")

    monkeypatch.setattr(timeseries_telemetry._LOGGER, "exception", fail_log)

    # When
    with pytest.raises(RuntimeError) as exc_info, collector.measure_record(1):
        wall.error = RuntimeError("wall clock failed")
        raise business_error

    # Then
    assert exc_info.value is business_error
    assert collector.is_disabled


def test_distinct_execution_attempts_count_the_same_ordinal_separately() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    first = _collector(wall, monotonic)
    second = PipelineTelemetryCollector(
        execution_id="retry-execution",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        clock=wall,
        monotonic_clock=monotonic,
    )
    first.accept_batch(1)
    second.accept_batch(1)

    # When
    for collector in (first, second):
        with collector.measure_record(1):
            monotonic.value += 7

    # Then
    assert first.snapshot().snapshot_id != second.snapshot().snapshot_id
    assert first.snapshot().buckets[0].processing_completed_count == 1
    assert second.snapshot().buckets[0].processing_completed_count == 1


@pytest.mark.parametrize("input_total", [0, -1, True, 1.5, "1"])
def test_invalid_batch_admission_remains_unavailable(input_total: object) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)

    # When
    collector.accept_batch(input_total)

    # Then
    snapshot = collector.snapshot()
    assert snapshot.observation_status == "unavailable"
    assert snapshot.buckets == ()
    assert snapshot.collection_disabled


def test_changed_batch_admission_does_not_inflate_input_count() -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)

    # When
    collector.accept_batch(2)

    # Then
    snapshot = collector.snapshot()
    assert snapshot.input_total == snapshot.buckets[0].input_accepted_count == 1
    assert snapshot.observation_status == "partial"
    assert snapshot.collection_disabled


def test_records_without_model_validation_and_publishes_only_changed_buckets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    created: list[datetime] = []

    class CountingBucket(timeseries_telemetry.PipelineTelemetryBucket):
        def __init__(self, **data: object) -> None:
            created.append(data["bucket_start"])
            super().__init__(**data)

    monkeypatch.setattr(timeseries_telemetry, "PipelineTelemetryBucket", CountingBucket)
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(3)

    # When
    for record_no in (1, 2):
        with collector.measure_record(record_no):
            monotonic.value += 5
    created_before_snapshot = len(created)
    first = collector.snapshot()
    repeated = collector.snapshot()
    wall.value += timedelta(seconds=1)
    with collector.measure_record(3):
        monotonic.value += 5
    second = collector.snapshot()

    # Then
    assert created_before_snapshot == 0
    assert repeated is first
    assert created == [
        START.replace(microsecond=0),
        (START + timedelta(seconds=1)).replace(microsecond=0),
    ]
    assert second.buckets[0] is first.buckets[0]
    assert [bucket.revision for bucket in second.buckets] == [3, 1]
    assert [bucket.processing_completed_count for bucket in second.buckets] == [2, 1]
    assert [bucket.latency_sample_count for bucket in second.buckets] == [2, 1]
    assert [bucket.latency_sum_ns for bucket in second.buckets] == [10, 5]
    assert second.observation_status == "observed"


@pytest.mark.parametrize(
    "increments",
    [
        {},
        {"processing_completed_count": 1, "latency_sum_ns": 5},
        {"latency_sample_count": 1},
        {"processing_failed_count": -1},
        {"input_accepted_count": True},
    ],
)
def test_invalid_internal_observation_is_rejected_without_partial_mutation(
    increments: dict[str, object],
) -> None:
    # Given
    wall, monotonic = _Clock(START), _Clock(0)
    collector = _collector(wall, monotonic)
    collector.accept_batch(1)
    before = collector.snapshot()

    # When
    with pytest.raises(ValueError):
        collector._record_observation(START, **increments)

    # Then
    assert collector.snapshot() is before
    assert before.buckets[0].revision == 1
