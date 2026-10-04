"""Best-effort Runtime telemetry for one First Cycle pipeline invocation."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from time import monotonic
from types import TracebackType
from typing import Protocol, Self
from uuid import uuid4

import psycopg

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)

_LOGGER = logging.getLogger(__name__)
_NORMALIZATION_PROGRESS_WRITE_INTERVAL_SECONDS = 1.0
_CONNECT_TIMEOUT_SECONDS = 2
_MAX_CONSECUTIVE_FAILURES = 3

type PipelineRuntimeObserver = Callable[[PipelineRuntimeStatus], None]
type RuntimeClock = Callable[[], datetime]
type MonotonicClock = Callable[[], float]


class _TelemetryConnection(Protocol):
    def execute(
        self,
        query: str,
        params: tuple[object, ...],
    ) -> _TelemetryCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class _TelemetryCursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...


def _connect_telemetry_database(url: str) -> _TelemetryConnection:
    return psycopg.connect(url, connect_timeout=_CONNECT_TIMEOUT_SECONDS)


def generate_execution_id() -> str:
    """Generate one opaque identifier for a pipeline invocation."""
    return str(uuid4())


def utc_now_milliseconds() -> datetime:
    """Return an aware UTC timestamp aligned to the millisecond boundary."""
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


class PipelineRuntimeTracker:
    """Produce immutable Runtime snapshots and publish them best-effort."""

    def __init__(
        self,
        *,
        execution_id: str,
        run_id: str,
        entity_id: str,
        input_total: int,
        started_at: datetime,
        observer: PipelineRuntimeObserver | None = None,
        clock: RuntimeClock = utc_now_milliseconds,
    ) -> None:
        self._execution_id = execution_id
        self._run_id = run_id
        self._entity_id = entity_id
        self._input_total = input_total
        self._started_at = started_at
        self._observer = observer
        self._clock = clock
        self._normalization_processed_count = 0
        self._current_stage: PipelineStage | None = None
        self._stage_started_at: datetime | None = None
        self._status: PipelineRuntimeStatus | None = None
        self._disabled = False

    @property
    def status(self) -> PipelineRuntimeStatus | None:
        """Return the most recently produced immutable snapshot."""
        return self._status

    @property
    def is_disabled(self) -> bool:
        """Report whether an internal telemetry error disabled this tracker."""
        return self._disabled

    def start_stage(self, stage: PipelineStage) -> PipelineRuntimeStatus | None:
        """Enter a business stage and publish its running snapshot."""
        return self._run_best_effort("stage start", lambda: self._start_stage(stage))

    def _start_stage(self, stage: PipelineStage) -> PipelineRuntimeStatus:
        now = self._clock()
        self._current_stage = stage
        self._stage_started_at = now
        return self._publish(
            self._build_status(
                status=PipelineRuntimeState.RUNNING,
                current_stage=stage,
                stage_started_at=now,
                updated_at=now,
            )
        )

    def record_normalization_progress(
        self,
        processed_count: int,
    ) -> PipelineRuntimeStatus | None:
        """Publish an exact, successfully normalized record count."""
        return self._run_best_effort(
            "normalization progress",
            lambda: self._record_normalization_progress(processed_count),
        )

    def _record_normalization_progress(self, processed_count: int) -> PipelineRuntimeStatus:
        if self._current_stage is not PipelineStage.NORMALIZATION:
            raise RuntimeError("normalization progress requires the normalization stage")

        self._normalization_processed_count = processed_count
        return self._publish(
            self._build_status(
                status=PipelineRuntimeState.RUNNING,
                current_stage=PipelineStage.NORMALIZATION,
                stage_started_at=self._stage_started_at,
                updated_at=self._clock(),
            )
        )

    def complete(self) -> PipelineRuntimeStatus | None:
        """Publish the terminal completed snapshot."""
        return self._run_best_effort("completion", self._complete)

    def _complete(self) -> PipelineRuntimeStatus:
        now = self._clock()
        self._normalization_processed_count = self._input_total
        self._current_stage = None
        self._stage_started_at = None
        return self._publish(
            self._build_status(
                status=PipelineRuntimeState.COMPLETED,
                current_stage=None,
                stage_started_at=None,
                updated_at=now,
                completed_at=now,
            )
        )

    def fail(self, stage: PipelineStage) -> PipelineRuntimeStatus | None:
        """Publish the terminal failed snapshot for a business-stage error."""
        return self._run_best_effort("failure", lambda: self._fail(stage))

    def _fail(self, stage: PipelineStage) -> PipelineRuntimeStatus:
        self._current_stage = None
        self._stage_started_at = None
        return self._publish(
            self._build_status(
                status=PipelineRuntimeState.FAILED,
                current_stage=None,
                stage_started_at=None,
                updated_at=self._clock(),
                failed_stage=stage,
            )
        )

    def _build_status(
        self,
        *,
        status: PipelineRuntimeState,
        current_stage: PipelineStage | None,
        stage_started_at: datetime | None,
        updated_at: datetime,
        completed_at: datetime | None = None,
        failed_stage: PipelineStage | None = None,
    ) -> PipelineRuntimeStatus:
        return PipelineRuntimeStatus(
            execution_id=self._execution_id,
            run_id=self._run_id,
            entity_id=self._entity_id,
            status=status,
            current_stage=current_stage,
            input_total=self._input_total,
            normalization_processed_count=self._normalization_processed_count,
            started_at=self._started_at,
            stage_started_at=stage_started_at,
            updated_at=updated_at,
            completed_at=completed_at,
            failed_stage=failed_stage,
        )

    def _publish(self, status: PipelineRuntimeStatus) -> PipelineRuntimeStatus:
        self._status = status
        if self._observer is not None:
            try:
                self._observer(status)
            except Exception:
                _LOGGER.exception("Pipeline Runtime observer failed")
        return status

    def _run_best_effort(
        self,
        operation: str,
        action: Callable[[], PipelineRuntimeStatus],
    ) -> PipelineRuntimeStatus | None:
        if self._disabled:
            return self._status
        try:
            return action()
        except Exception:  # noqa: BLE001 - Runtime telemetry must not fail business execution.
            self._disable_after_internal_error(operation)
            return self._status

    def _disable_after_internal_error(self, operation: str) -> None:
        self._disabled = True
        _LOGGER.exception(
            "Pipeline Runtime tracker failed during %s; disabling telemetry for this invocation",
            operation,
        )


class PostgresPipelineRuntimeObserver:
    """Persist Runtime snapshots over a dedicated, lazily opened connection."""

    def __init__(
        self,
        *,
        database_config_factory: Callable[[], DatabaseConfig] = DatabaseConfig.from_environment,
        connection_factory: Callable[[str], _TelemetryConnection] = _connect_telemetry_database,
        monotonic_clock: MonotonicClock = monotonic,
        progress_write_interval_seconds: float = (_NORMALIZATION_PROGRESS_WRITE_INTERVAL_SECONDS),
    ) -> None:
        self._database_config_factory = database_config_factory
        self._connection_factory = connection_factory
        self._monotonic_clock = monotonic_clock
        self._progress_write_interval_seconds = progress_write_interval_seconds
        self._connection: _TelemetryConnection | None = None
        self._last_saved_status: PipelineRuntimeStatus | None = None
        self._last_normalization_attempt_status: PipelineRuntimeStatus | None = None
        self._last_normalization_attempt_at: float | None = None
        self._consecutive_failures = 0
        self._disabled = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __call__(self, status: PipelineRuntimeStatus) -> None:
        if self._disabled:
            return

        if self._should_throttle(status):
            return

        if _is_normalization_running(status):
            self._last_normalization_attempt_status = status
            self._last_normalization_attempt_at = self._monotonic_clock()

        try:
            connection = self._get_connection()
            saved = PipelineRuntimeStatusRepository(connection).save(status)
            connection.commit()
        except Exception:
            self._consecutive_failures += 1
            self._discard_failed_connection()
            if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                self._disabled = True
            raise

        self._consecutive_failures = 0
        if saved:
            self._last_saved_status = status

    def close(self) -> None:
        """Close an opened telemetry connection without affecting business execution."""
        connection = self._connection
        self._connection = None
        if connection is None:
            return
        try:
            connection.close()
        except Exception:
            _LOGGER.exception("Pipeline Runtime telemetry connection close failed")

    def _get_connection(self) -> _TelemetryConnection:
        if self._connection is None:
            database_config = self._database_config_factory()
            self._connection = self._connection_factory(database_config.url)
        return self._connection

    def _should_throttle(self, status: PipelineRuntimeStatus) -> bool:
        previous = self._last_normalization_attempt_status
        if (
            previous is None
            or not _is_normalization_running(previous)
            or not _is_normalization_running(status)
            or previous.execution_id != status.execution_id
            or previous.stage_started_at != status.stage_started_at
            or status.normalization_processed_count <= previous.normalization_processed_count
        ):
            return False

        last_attempt_at = self._last_normalization_attempt_at
        if last_attempt_at is None:
            return False
        return self._monotonic_clock() - last_attempt_at < self._progress_write_interval_seconds

    def _discard_failed_connection(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is None:
            return

        try:
            connection.rollback()
        except Exception:
            _LOGGER.exception("Pipeline Runtime telemetry rollback failed")
        try:
            connection.close()
        except Exception:
            _LOGGER.exception("Pipeline Runtime telemetry connection close failed")


def _is_normalization_running(status: PipelineRuntimeStatus) -> bool:
    return (
        status.status is PipelineRuntimeState.RUNNING
        and status.current_stage is PipelineStage.NORMALIZATION
    )


__all__ = [
    "PipelineRuntimeObserver",
    "PipelineRuntimeTracker",
    "PostgresPipelineRuntimeObserver",
    "generate_execution_id",
    "utc_now_milliseconds",
]
