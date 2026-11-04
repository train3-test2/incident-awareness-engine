from datetime import UTC, datetime

import psycopg
import pytest

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.pipeline import stage_timing_storage as storage
from incident_awareness.pipeline.runner import _run_stage
from incident_awareness.pipeline.stage_timing import (
    PipelineStageTimingCollector,
    start_stage_timing,
)
from incident_awareness.storage.config import DatabaseConfig


class Connection:
    def __init__(self, error=None, commit_error=False):
        self.error = error
        self.commit_error = commit_error
        self.commits = self.rollbacks = self.closes = 0
        self.payloads = []

    def execute(self, query, params=()):
        self.payloads.append(params[0].obj)
        if self.error:
            raise self.error
        return self

    def fetchone(self):
        return (True,)

    def commit(self):
        if self.commit_error:
            raise psycopg.OperationalError("secret connection value must not be logged")
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


def observer(factory):
    return storage.PostgresPipelineStageTimingObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://test"),
        connection_factory=factory,
    )


def collector(writer):
    return start_stage_timing(
        PipelineStageTimingCollector(
            clock=lambda: datetime(2026, 10, 17, tzinfo=UTC),
            observer=writer,
        )
    )


def test_observer_saves_actual_model_through_repository_on_its_own_connection():
    # Given
    connection = Connection()
    writer = observer(lambda _: connection)
    timing = collector(writer)
    # When
    result = _run_stage(PipelineStage.PERSISTENCE, lambda: "unchanged", stage_timing=timing)
    writer.close()
    # Then
    assert result == "unchanged"
    assert connection.commits == 1 and connection.rollbacks == 0 and connection.closes == 1
    assert connection.payloads[0]["records"][0]["stage"] == "persistence"
    assert writer.pending_snapshot is None


@pytest.mark.parametrize("failure", ["connect", "execute", "commit"])
def test_failed_write_is_pending_and_next_cumulative_publication_recovers(failure, caplog):
    # Given
    failed = Connection(
        error=psycopg.OperationalError("private DB URL") if failure == "execute" else None,
        commit_error=failure == "commit",
    )
    healthy = Connection()
    attempts = []

    def factory(_):
        attempts.append(1)
        if len(attempts) == 1:
            if failure == "connect":
                raise psycopg.OperationalError("private DB URL")
            return failed
        return healthy

    writer = observer(factory)
    timing = collector(writer)

    # When
    _run_stage(PipelineStage.ARTIFACT_VALIDATION, lambda: 1, stage_timing=timing)
    assert writer.pending_snapshot is not None
    assert "observer_error" in timing.snapshot().issues
    timing.bind(execution_id="execution", run_id="fixture", entity_id="host")
    _run_stage(PipelineStage.FUSION, lambda: 2, stage_timing=timing)
    writer.close()

    # Then
    assert writer.pending_snapshot is None and healthy.commits == 2
    assert len(healthy.payloads[-1]["records"]) == 2
    assert healthy.payloads[-1]["quality_status"] == "partial"
    assert "private DB URL" not in caplog.text
    if failure != "connect":
        assert failed.rollbacks == failed.closes == 1


def test_three_failures_disable_writes_without_changing_business_failure():
    # Given
    connections = []

    def factory(_):
        conn = Connection(error=psycopg.OperationalError("unavailable"))
        connections.append(conn)
        return conn

    writer = observer(factory)
    timing = collector(writer)
    error = ValueError("original operation failure")

    def operation():
        raise error

    # When
    for _ in range(5):
        with pytest.raises(ValueError) as caught:
            _run_stage(PipelineStage.FUSION, operation, stage_timing=timing)
        assert caught.value is error
    writer.close()
    # Then
    assert len(connections) == 3 and writer.is_disabled
    assert all(conn.commits == 0 and conn.rollbacks == 1 for conn in connections)
    assert len(timing.snapshot().records) == 5
    assert all(record.outcome == "failed" for record in timing.snapshot().records)


def test_close_retries_pending_snapshot_without_a_timer():
    # Given
    healthy = Connection()
    attempts = []

    def factory(_):
        attempts.append(1)
        if len(attempts) == 1:
            raise psycopg.OperationalError("unavailable")
        return healthy

    writer = observer(factory)
    timing = collector(writer)
    # When
    _run_stage(PipelineStage.FUSION, lambda: 1, stage_timing=timing)
    writer.close()
    writer.close()
    # Then
    assert len(attempts) == 2 and healthy.commits == 1 and healthy.closes == 1


def test_context_never_writes_unused_collector(monkeypatch):
    # Given
    connection = Connection()
    writer = observer(lambda _: connection)
    monkeypatch.setattr(storage, "PostgresPipelineStageTimingObserver", lambda: writer)
    # When
    with storage.stage_timing_storage_context():
        pass
    # Then
    assert connection.payloads == []


def test_context_persists_final_observer_error_revision_on_recovery(monkeypatch):
    # Given
    broken = Connection(error=psycopg.OperationalError("fixture unavailable"))
    healthy = Connection()
    connections = iter([broken, healthy])
    writer = observer(lambda _: next(connections))
    monkeypatch.setattr(storage, "PostgresPipelineStageTimingObserver", lambda: writer)
    # When
    with storage.stage_timing_storage_context() as timing:
        timing = start_stage_timing(timing)
        assert _run_stage(PipelineStage.FUSION, lambda: 1, stage_timing=timing) == 1
        assert "observer_error" in timing.snapshot().issues
    # Then
    assert healthy.commits == 1 and broken.commits == 0
    assert healthy.payloads[-1]["quality_status"] == "partial"
    assert healthy.payloads[-1]["issues"] == ["observer_error"]
    assert writer.pending_snapshot is None


def test_context_bootstrap_failure_does_not_replace_business_result(monkeypatch):
    # Given
    def broken():
        raise RuntimeError("collector construction failed")

    monkeypatch.setattr(storage, "PostgresPipelineStageTimingObserver", broken)
    # When / Then
    with storage.stage_timing_storage_context() as timing:
        assert timing is None
        assert _run_stage(PipelineStage.FUSION, lambda: "result", stage_timing=timing) == "result"


def test_write_connection_timeouts_do_not_reuse_business_connection(monkeypatch):
    # Given
    captured = []
    monkeypatch.setattr(storage.psycopg, "connect", lambda *args, **kwargs: captured.append(kwargs))
    # When
    storage._connect("postgresql://test")
    # Then
    assert captured[0]["autocommit"] is False
    assert captured[0]["connect_timeout"] == 2
    assert "statement_timeout=2000" in captured[0]["options"]
    assert "transaction_timeout=5000" in captured[0]["options"]
