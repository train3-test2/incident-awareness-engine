"""Best-effort stage snapshot writes on an independent, bounded DB connection."""

# Every broad catch here is an optional observation isolation boundary.
# ruff: noqa: BLE001
import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import psycopg

from incident_awareness.common.models.pipeline_stage_timing import PipelineStageTimingSnapshot
from incident_awareness.pipeline.stage_timing import PipelineStageTimingCollector
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
)

_LOGGER = logging.getLogger(__name__)


def _connect(url: str) -> psycopg.Connection:
    return psycopg.connect(
        url,
        autocommit=False,
        connect_timeout=2,
        options="-c statement_timeout=2000 -c lock_timeout=2000 -c transaction_timeout=5000",
    )


class PostgresPipelineStageTimingObserver:
    """One attempt, at most one pending snapshot, no timer or Business connection.

    Failures raise to the collector, which records observer_error without changing
    the Business outcome. Next publication or close retries the cumulative snapshot.
    After three consecutive failures writes are disabled for this observer.
    """

    def __init__(
        self,
        *,
        database_config_factory: Callable[[], DatabaseConfig] = DatabaseConfig.from_environment,
        connection_factory: Callable[[str], psycopg.Connection] = _connect,
    ) -> None:
        self._config = database_config_factory
        self._connect = connection_factory
        self._connection = None
        self._pending: PipelineStageTimingSnapshot | None = None
        self._last: PipelineStageTimingSnapshot | None = None
        self._failures = 0
        self._closed = False

    @property
    def pending_snapshot(self) -> PipelineStageTimingSnapshot | None:
        return self._pending

    @property
    def is_disabled(self) -> bool:
        return self._failures >= 3

    def __call__(self, snapshot: PipelineStageTimingSnapshot) -> None:
        if self._closed or self.is_disabled:
            raise RuntimeError("Stage timing storage is closed or disabled")
        reference = self._pending or self._last
        if reference is not None:
            if reference.attempt_id != snapshot.attempt_id:
                raise ValueError("One stage timing observer must serve one attempt")
            if reference.revision > snapshot.revision:
                return
            if reference.revision == snapshot.revision and reference != snapshot:
                raise ValueError("Conflicting stage timing revision")
        self._pending = snapshot
        self.flush()

    def flush(self) -> None:
        if self.is_disabled or self._closed or self._pending is None:
            return
        try:
            if self._connection is None:
                self._connection = self._connect(self._config().url)
            PipelineStageTimingRepository(self._connection).save_snapshot(self._pending)
            self._connection.commit()
        except Exception:
            self._failures += 1
            connection, self._connection = self._connection, None
            if connection is not None:
                for action in (connection.rollback, connection.close):
                    try:
                        action()
                    except Exception:
                        _LOGGER.warning("Stage timing storage cleanup failed")
            # Do not log exception text/traceback: it may contain a connection URL.
            _LOGGER.warning("Stage timing storage failed; observation remains pending")
            raise RuntimeError("Stage timing storage failed") from None
        self._last, self._pending = self._pending, None
        self._failures = 0

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.flush()
        except Exception:
            _LOGGER.warning("Stage timing final retry failed")
        self._closed = True
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                _LOGGER.warning("Stage timing storage close failed")


@contextmanager
def stage_timing_storage_context() -> Iterator[PipelineStageTimingCollector | None]:
    observer = None
    try:
        observer = PostgresPipelineStageTimingObserver()
        collector = PipelineStageTimingCollector(observer=observer)
    except Exception:
        _LOGGER.warning("Stage timing storage bootstrap failed")
        collector = None
    try:
        yield collector
    finally:
        if observer is not None:
            # Persist a collector's observer_error revision, including a final failed publication.
            if collector is not None and not observer.is_disabled:
                try:
                    snapshot = collector.snapshot()
                    if snapshot.revision > 0:
                        observer(snapshot)
                except Exception:
                    _LOGGER.warning("Stage timing final snapshot write failed")
            observer.close()
