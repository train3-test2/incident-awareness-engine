"""Best-effort, single-execution batch observations independent of persistence."""

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from time import monotonic_ns

from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetryBucket,
    PipelineTelemetryInputIdentity,
    PipelineTelemetrySnapshot,
    TelemetryObservationIssue,
    _validate_telemetry_datetime,
)
from incident_awareness.pipeline.runtime_telemetry import RuntimeClock, utc_now_milliseconds

_LOGGER = logging.getLogger(__name__)
_ONE_SECOND = timedelta(seconds=1)
type MonotonicNanosecondClock = Callable[[], int]


@dataclass(frozen=True, slots=True)
class RecordMeasurement:
    """Opaque completion token for one original, 1-based batch record ordinal."""

    record_no: int
    started_ns: int | None


@dataclass(slots=True)
class _BucketCounters:
    """Private mutable counters for one observed UTC second; never published directly.

    publish() validates the immutable Pydantic contract once per bucket revision, so
    the per-record path avoids model_dump()/model_validate() while snapshots keep the
    same validated values and reuse unchanged bucket objects.
    """

    bucket_start: datetime
    first_observed_at: datetime
    last_observed_at: datetime
    revision: int = 0
    input_accepted_count: int = 0
    processing_completed_count: int = 0
    processing_failed_count: int = 0
    latency_sample_count: int = 0
    latency_sum_ns: int = 0
    published: PipelineTelemetryBucket | None = None

    def publish(self) -> PipelineTelemetryBucket:
        published = self.published
        if published is None or published.revision != self.revision:
            published = PipelineTelemetryBucket(
                bucket_start=self.bucket_start,
                bucket_end=self.bucket_start + _ONE_SECOND,
                first_observed_at=self.first_observed_at,
                last_observed_at=self.last_observed_at,
                revision=self.revision,
                input_accepted_count=self.input_accepted_count,
                processing_completed_count=self.processing_completed_count,
                processing_failed_count=self.processing_failed_count,
                latency_sample_count=self.latency_sample_count,
                latency_sum_ns=self.latency_sum_ns,
            )
            self.published = published
        return published


class _ObservationError(ValueError):
    def __init__(self, issue: TelemetryObservationIssue, message: str) -> None:
        super().__init__(message)
        self.issue = issue


def _log_failure(operation: str) -> None:
    try:
        _LOGGER.exception("Pipeline timeseries telemetry failed during %s", operation)
    except Exception:  # noqa: BLE001 - logging must not replace a business outcome.
        return


class PipelineTelemetryCollector:
    """Collect observed events for one existing Runtime execution, on its business thread.

    Call accept_batch once after artifact validation. Wrap only normalization and
    Evidence extraction in measure_record, or call begin_record / record_success /
    record_failure explicitly. End timing before any progress callback or I/O.
    Duplicate record ordinals are no-ops within this attempt; distinct attempts remain
    distinct. Snapshot reads never consult a clock or create buckets. No continuous
    zero coverage, process liveness, persistence success, or E2E latency is inferred.
    """

    def __init__(
        self,
        *,
        execution_id: str,
        run_id: str,
        entity_id: str,
        input_identity: PipelineTelemetryInputIdentity | None = None,
        clock: RuntimeClock = utc_now_milliseconds,
        monotonic_clock: MonotonicNanosecondClock = monotonic_ns,
        max_buckets: int | None = None,
        max_records: int | None = None,
    ) -> None:
        for limit in (max_buckets, max_records):
            if limit is not None and (type(limit) is not int or limit < 1):
                raise ValueError("telemetry buffer limits must be positive integers")
        self._snapshot = PipelineTelemetrySnapshot(
            snapshot_id=f"pipeline-telemetry:{execution_id}",
            execution_id=execution_id,
            run_id=run_id,
            entity_id=entity_id,
            input_identity=input_identity,
            revision=0,
            observation_status="unavailable",
        )
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._buckets: dict[datetime, _BucketCounters] = {}
        self._records: dict[int, RecordMeasurement] = {}
        self._finished: set[int] = set()
        self._input_total: int | None = None
        self._input_accepted_at: datetime | None = None
        self._last_observed_at: datetime | None = None
        self._revision = 0
        self._issues: list[TelemetryObservationIssue] = []
        self._disabled = False
        self._logged_failure = False
        self._max_buckets = max_buckets
        self._max_records = max_records

    @property
    def is_disabled(self) -> bool:
        return self._disabled

    def accept_batch(self, input_total: int) -> None:
        """Record the validated batch once, as a pulse at admission time."""
        self._best_effort("batch admission", lambda: self._accept_batch(input_total))

    def _accept_batch(self, input_total: int) -> None:
        if type(input_total) is not int or input_total < 1:
            raise _ObservationError(
                TelemetryObservationIssue.INVALID_CALLBACK, "invalid batch size"
            )
        if self._input_total is not None:
            if input_total != self._input_total:
                raise _ObservationError(
                    TelemetryObservationIssue.INVALID_CALLBACK,
                    "batch size changed within execution",
                )
            return
        now = self._observe_time()
        self._record_observation(now, input_accepted_count=input_total)
        self._input_total = input_total
        self._input_accepted_at = now

    def begin_record(self, record_no: int) -> RecordMeasurement | None:
        """Start timing immediately before record processing; duplicates return None."""
        return self._best_effort("record start", lambda: self._begin_record(record_no))

    def _begin_record(self, record_no: int) -> RecordMeasurement | None:
        if (
            type(record_no) is not int
            or self._input_total is None
            or not 1 <= record_no <= self._input_total
        ):
            raise _ObservationError(
                TelemetryObservationIssue.INVALID_CALLBACK, "record requires an accepted ordinal"
            )
        if record_no in self._records:
            return None
        if self._max_records is not None and len(self._records) >= self._max_records:
            raise _ObservationError(
                TelemetryObservationIssue.BUFFER_LIMIT, "record buffer limit reached"
            )
        token = RecordMeasurement(record_no, self._read_monotonic())
        self._records[record_no] = token
        return token

    def record_success(self, token: RecordMeasurement | None) -> None:
        """End timing first, then record successful normalization + Evidence extraction."""
        self._best_effort("record success", lambda: self._finish_record(token, succeeded=True))

    def record_failure(self, token: RecordMeasurement | None) -> None:
        """Record a failed record separately; its duration never enters successful latency."""
        self._best_effort("record failure", lambda: self._finish_record(token, succeeded=False))

    def _finish_record(self, token: RecordMeasurement | None, *, succeeded: bool) -> None:
        if token is None:
            return
        if (
            not isinstance(token, RecordMeasurement)
            or self._records.get(token.record_no) is not token
        ):
            raise _ObservationError(
                TelemetryObservationIssue.INVALID_CALLBACK, "completion token belongs elsewhere"
            )
        if token.record_no in self._finished:
            return
        ended_ns = self._read_monotonic() if succeeded else None
        duration = None
        if succeeded and token.started_ns is not None and ended_ns is not None:
            if ended_ns < token.started_ns:
                self._mark_issue(TelemetryObservationIssue.INVALID_MONOTONIC_DURATION)
            else:
                duration = ended_ns - token.started_ns
        now = self._observe_time()
        self._record_observation(
            now,
            processing_completed_count=int(succeeded),
            processing_failed_count=int(not succeeded),
            latency_sample_count=int(duration is not None),
            latency_sum_ns=duration if duration is not None else 0,
        )
        self._finished.add(token.record_no)

    @contextmanager
    def measure_record(self, record_no: int) -> Iterator[None]:
        """Preserve the business return/exception; callers place callbacks outside this span."""
        token = self.begin_record(record_no)
        try:
            yield
        except BaseException:
            self.record_failure(token)
            raise
        else:
            self.record_success(token)

    def snapshot(self) -> PipelineTelemetrySnapshot:
        """Return a deeply immutable replacement snapshot, unchanged between observations."""
        if self._snapshot.revision == self._revision:
            return self._snapshot
        result = self._best_effort("snapshot", self._build_snapshot, allow_disabled=True)
        if result is not None:
            self._snapshot = result
        else:
            # Retain the last valid published values, but never report them as intact.
            self._snapshot = PipelineTelemetrySnapshot.model_validate(
                {
                    **self._snapshot.model_dump(),
                    "revision": self._revision,
                    "observation_status": "partial" if self._snapshot.buckets else "unavailable",
                    "observation_issues": tuple(self._issues),
                    "collection_disabled": self._disabled,
                }
            )
        return self._snapshot

    def mark_observation_issue(
        self, issue: TelemetryObservationIssue, *, disable: bool = False
    ) -> None:
        """Keep external Observer failures in this Collector's revision sequence."""

        def mark() -> None:
            self._mark_issue(issue)
            if disable and not self._disabled:
                self._disabled = True
                self._revision += 1

        self._best_effort("external observation issue", mark, allow_disabled=True)

    def _build_snapshot(self) -> PipelineTelemetrySnapshot:
        return PipelineTelemetrySnapshot(
            snapshot_id=self._snapshot.snapshot_id,
            execution_id=self._snapshot.execution_id,
            run_id=self._snapshot.run_id,
            entity_id=self._snapshot.entity_id,
            input_identity=self._snapshot.input_identity,
            revision=self._revision,
            input_total=self._input_total,
            input_accepted_at=self._input_accepted_at,
            last_observed_at=self._last_observed_at,
            observation_status=(
                "unavailable" if not self._buckets else "partial" if self._issues else "observed"
            ),
            observation_issues=tuple(self._issues),
            collection_disabled=self._disabled,
            buckets=tuple(self._buckets[start].publish() for start in sorted(self._buckets)),
        )

    def _observe_time(self) -> datetime:
        now = _validate_telemetry_datetime(self._clock(), field_name="observation timestamp")
        if self._last_observed_at is not None and now < self._last_observed_at:
            raise _ObservationError(
                TelemetryObservationIssue.WALL_CLOCK_REGRESSION, "wall clock moved backwards"
            )
        return now

    def _read_monotonic(self) -> int | None:
        try:
            value = self._monotonic_clock()
            if type(value) is not int or value < 0:
                raise ValueError("monotonic_ns must return a nonnegative integer")
            return value
        except Exception:  # noqa: BLE001 - keep counts even if duration cannot be measured.
            self._mark_issue(TelemetryObservationIssue.MONOTONIC_CLOCK_ERROR)
            self._log_once("monotonic clock")
            return None

    def _record_observation(
        self,
        now: datetime,
        *,
        input_accepted_count: int = 0,
        processing_completed_count: int = 0,
        processing_failed_count: int = 0,
        latency_sample_count: int = 0,
        latency_sum_ns: int = 0,
    ) -> None:
        """Apply one observation atomically; snapshot() validates the published contract.

        _observe_time() has already validated a non-decreasing UTC millisecond, so the
        observation lies in [bucket_start, bucket_end) after its prior observations.
        """
        start = now.replace(microsecond=0)
        bucket = self._buckets.get(start)
        if (
            bucket is None
            and self._max_buckets is not None
            and len(self._buckets) >= self._max_buckets
        ):
            raise _ObservationError(
                TelemetryObservationIssue.BUFFER_LIMIT, "bucket buffer limit reached"
            )
        increments = (
            input_accepted_count,
            processing_completed_count,
            processing_failed_count,
            latency_sample_count,
            latency_sum_ns,
        )
        if any(type(value) is not int or value < 0 for value in increments):
            raise ValueError("observation counts must be nonnegative integers")
        if not (input_accepted_count or processing_completed_count or processing_failed_count):
            raise ValueError("an unobserved bucket must not be generated")
        if latency_sample_count > processing_completed_count or (
            latency_sum_ns and not latency_sample_count
        ):
            raise ValueError("latency requires a measured successful record")
        if bucket is None:
            bucket = _BucketCounters(
                bucket_start=start, first_observed_at=now, last_observed_at=now
            )
            self._buckets[start] = bucket
        bucket.input_accepted_count += input_accepted_count
        bucket.processing_completed_count += processing_completed_count
        bucket.processing_failed_count += processing_failed_count
        bucket.latency_sample_count += latency_sample_count
        bucket.latency_sum_ns += latency_sum_ns
        bucket.last_observed_at = now
        bucket.revision += 1
        self._last_observed_at = now
        self._revision += 1

    def _mark_issue(self, issue: TelemetryObservationIssue) -> None:
        if issue not in self._issues:
            self._issues.append(issue)
            self._revision += 1

    def _log_once(self, operation: str) -> None:
        if not self._logged_failure:
            self._logged_failure = True
            _log_failure(operation)

    def _best_effort[T](
        self, operation: str, action: Callable[[], T], *, allow_disabled: bool = False
    ) -> T | None:
        if self._disabled and not allow_disabled:
            return None
        try:
            return action()
        except Exception as error:  # noqa: BLE001 - telemetry cannot change business outcomes.
            self._mark_issue(
                error.issue
                if isinstance(error, _ObservationError)
                else TelemetryObservationIssue.INTERNAL_ERROR
            )
            if not self._disabled:
                self._disabled = True
                self._revision += 1
            self._log_once(operation)
            return None


def create_pipeline_telemetry_collector(
    *,
    execution_id: str,
    run_id: str,
    entity_id: str,
    input_identity: PipelineTelemetryInputIdentity | None = None,
    clock: RuntimeClock = utc_now_milliseconds,
    monotonic_clock: MonotonicNanosecondClock = monotonic_ns,
    max_buckets: int | None = None,
    max_records: int | None = None,
) -> PipelineTelemetryCollector | None:
    """Best-effort bootstrap using the caller's existing Runtime execution identifier."""
    try:
        return PipelineTelemetryCollector(
            execution_id=execution_id,
            run_id=run_id,
            entity_id=entity_id,
            input_identity=input_identity,
            clock=clock,
            monotonic_clock=monotonic_clock,
            max_buckets=max_buckets,
            max_records=max_records,
        )
    except Exception:  # noqa: BLE001 - bootstrap must not block business execution.
        _log_failure("bootstrap")
        return None
