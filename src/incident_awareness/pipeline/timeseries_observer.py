"""Bounded, callback-driven telemetry flushes over an independent PostgreSQL connection."""

# Every catch-all in this module is an optional telemetry isolation boundary.
# ruff: noqa: BLE001

import math
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from time import monotonic
from typing import Self

import psycopg

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetrySnapshot,
    TelemetryObservationIssue,
)
from incident_awareness.pipeline.runtime_telemetry import PipelineRuntimeTracker
from incident_awareness.pipeline.telemetry_input import resolve_telemetry_input_identity
from incident_awareness.pipeline.timeseries_telemetry import (
    PipelineTelemetryCollector,
    RecordMeasurement,
    _log_failure,
    create_pipeline_telemetry_collector,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

type PipelineTelemetryObserver = Callable[[PipelineTelemetrySnapshot], bool | None]
_FLUSH_INTERVAL_SECONDS = 5.0
_MAX_FAILURES = 3
_MAX_BUCKETS = 3600
_MAX_RECORDS = 100_000


def _connect_telemetry_database(url: str) -> psycopg.Connection:
    return psycopg.connect(
        url,
        autocommit=False,
        connect_timeout=2,
        options="-c statement_timeout=2000 -c lock_timeout=2000 -c transaction_timeout=5000",
    )


class PostgresPipelineTelemetryObserver:
    """Retain at most one cumulative snapshot for one execution; errors return False.

    A newer snapshot subsumes the pending one. Flush retries never add counters.
    There is no background thread or heartbeat. The execution session supplies
    snapshots at callback opportunities and at stage/function boundaries.
    """

    def __init__(
        self,
        *,
        database_config_factory: Callable[[], DatabaseConfig] = DatabaseConfig.from_environment,
        connection_factory: Callable[[str], psycopg.Connection] = _connect_telemetry_database,
    ) -> None:
        self._database_config_factory = database_config_factory
        self._connection_factory = connection_factory
        self._connection: psycopg.Connection | None = None
        self._pending: PipelineTelemetrySnapshot | None = None
        self._last_saved: PipelineTelemetrySnapshot | None = None
        self._consecutive_failures = 0
        self._disabled = False
        self._closed = False

    @property
    def is_disabled(self) -> bool:
        return self._disabled

    @property
    def pending_snapshot(self) -> PipelineTelemetrySnapshot | None:
        return self._pending

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def buffer(self, snapshot: PipelineTelemetrySnapshot) -> None:
        """Refresh pending quality without triggering an immediate second DB attempt."""
        if len(snapshot.buckets) > _MAX_BUCKETS:
            raise ValueError("telemetry pending snapshot exceeds the bucket budget")
        reference = self._pending or self._last_saved
        if reference is not None:
            if snapshot.execution_id != reference.execution_id:
                raise ValueError("one telemetry Observer must serve only one execution")
            if snapshot.revision < reference.revision:
                return
            if snapshot.revision == reference.revision and snapshot != reference:
                raise ValueError("same pending revision has different payload")
        self._pending = snapshot

    def __call__(self, snapshot: PipelineTelemetrySnapshot) -> bool:
        if self._disabled or self._closed:
            return False
        try:
            self.buffer(snapshot)
        except Exception:
            self._failed()
            return False
        return self.flush()

    def flush(self) -> bool:
        if self._disabled or self._closed:
            return False
        if self._pending is None:
            self._consecutive_failures = 0
            return True
        if self._pending == self._last_saved:
            self._pending = None
            self._consecutive_failures = 0
            return True
        try:
            if self._connection is None:
                config = self._database_config_factory()
                self._connection = self._connection_factory(config.url)
            PipelineTelemetryRepository(self._connection).save_snapshot(self._pending)
            self._connection.commit()  # Includes stale/no-op: release the transaction lock.
        except Exception:
            self._failed()
            return False
        self._last_saved = self._pending
        self._pending = None
        self._consecutive_failures = 0
        return True

    def _failed(self) -> None:
        self._consecutive_failures += 1
        self._disabled = self._consecutive_failures >= _MAX_FAILURES
        _log_failure("timeseries storage")
        connection, self._connection = self._connection, None
        if connection is not None:
            for operation in (connection.rollback, connection.close):
                try:
                    operation()
                except Exception:
                    _log_failure("timeseries storage cleanup")

    def close(self) -> None:
        if self._closed:
            return
        self.flush()  # One bounded final retry of the pending cumulative snapshot.
        self._closed = True
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except Exception:
                _log_failure("timeseries storage close")


class PipelineTelemetrySession:
    """Keep collection and synchronous flush I/O outside the measured record span."""

    def __init__(
        self,
        collector: PipelineTelemetryCollector,
        observer: PipelineTelemetryObserver | None,
        *,
        clock: Callable[[], float] = monotonic,
        flush_interval_seconds: float = _FLUSH_INTERVAL_SECONDS,
    ) -> None:
        if not math.isfinite(flush_interval_seconds) or flush_interval_seconds <= 0:
            raise ValueError("flush interval must be finite and positive")
        self.collector = collector
        self._observer = observer
        self._clock = clock
        self._flush_interval_seconds = flush_interval_seconds
        self._last_attempt_at: float | None = None
        self._failures = 0
        self._disabled = False
        self._clock_failed = False

    def begin_record(self, record_no: int) -> RecordMeasurement | None:
        try:
            return self.collector.begin_record(record_no)
        except Exception:
            self._internal_failure()
            return None

    def record_success(self, token: RecordMeasurement | None) -> None:
        try:
            self.collector.record_success(token)  # End monotonic timing before flush I/O.
        except Exception:
            self._internal_failure()
        self.flush()

    def record_failure(self, token: RecordMeasurement | None) -> None:
        try:
            self.collector.record_failure(token)
        except Exception:
            self._internal_failure()
        self.flush(force=True)

    def flush(self, *, force: bool = False) -> None:
        if self._observer is None or self._disabled:
            return
        if self._clock_failed and not force:
            return
        now = None
        try:
            if not self._clock_failed:
                now = self._clock()
                if not math.isfinite(now):
                    raise ValueError("flush clock must be finite")
        except Exception:
            self._clock_failed = True
            self._internal_failure()
            if not force:
                return
        if (
            not force
            and self._last_attempt_at is not None
            and (now - self._last_attempt_at < self._flush_interval_seconds)
        ):
            return
        self._last_attempt_at = now
        try:
            snapshot = self.collector.snapshot()
        except Exception:
            self._internal_failure()
            return
        try:
            if self._observer(snapshot) is False:
                raise RuntimeError("timeseries Observer did not confirm its flush")
        except Exception:
            self._failures += 1
            self._disabled = self._failures >= _MAX_FAILURES
            self._mark_issue(TelemetryObservationIssue.STORAGE_ERROR, disable=self._disabled)
            _log_failure("timeseries flush")
            # Preserve the Collector-owned revision/quality for close or the next retry.
            if isinstance(self._observer, PostgresPipelineTelemetryObserver):
                try:
                    self._observer.buffer(self.collector.snapshot())
                except Exception:
                    _log_failure("timeseries pending quality")
        else:
            self._failures = 0

    def _internal_failure(self) -> None:
        self._mark_issue(TelemetryObservationIssue.INTERNAL_ERROR, disable=True)
        _log_failure("timeseries collection")

    def _mark_issue(self, issue: TelemetryObservationIssue, *, disable: bool) -> None:
        try:
            self.collector.mark_observation_issue(issue, disable=disable)
        except Exception:
            _log_failure("timeseries quality marker")


@contextmanager
def telemetry_session_context(
    runtime_tracker: PipelineRuntimeTracker | None,
    *,
    run_id: str,
    entity_id: str,
    input_total: int,
    observer: PipelineTelemetryObserver | None,
    input_path: Path | None = None,
    input_records: tuple[SysmonJsonlRecord, ...] = (),
    input_verified_sha256: str | None = None,
) -> Iterator[PipelineTelemetrySession | None]:
    session = None
    if runtime_tracker is not None:
        try:
            collector = create_pipeline_telemetry_collector(
                execution_id=runtime_tracker.execution_id,
                run_id=run_id,
                entity_id=entity_id,
                input_identity=(
                    resolve_telemetry_input_identity(
                        input_path, input_records, input_verified_sha256
                    )
                    if input_path is not None
                    else None
                ),
                max_buckets=_MAX_BUCKETS,
                max_records=_MAX_RECORDS,
            )
            if collector is not None:
                session = PipelineTelemetrySession(collector, observer)
                collector.accept_batch(input_total)
                session.flush(force=True)
        except Exception:
            _log_failure("timeseries bootstrap")
            session = None
    try:
        yield session
    finally:
        flush_telemetry(session)


def flush_telemetry(session: PipelineTelemetrySession | None) -> None:
    """Protect the business exception even from an unexpected flush implementation error."""
    if session is not None:
        try:
            session.flush(force=True)
        except Exception:
            _log_failure("timeseries final flush")


@contextmanager
def telemetry_observer_context() -> Iterator[PostgresPipelineTelemetryObserver | None]:
    observer = None
    try:
        observer = PostgresPipelineTelemetryObserver()
    except Exception:
        _log_failure("timeseries Observer bootstrap")
    try:
        yield observer
    finally:
        if observer is not None:
            try:
                observer.close()
            except Exception:
                _log_failure("timeseries Observer cleanup")
