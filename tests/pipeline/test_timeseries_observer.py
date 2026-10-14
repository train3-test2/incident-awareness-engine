from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetrySnapshot,
    TelemetryObservationIssue,
)
from incident_awareness.pipeline import timeseries_observer as module
from incident_awareness.pipeline.runtime_telemetry import PipelineRuntimeTracker
from incident_awareness.pipeline.timeseries_observer import (
    PipelineTelemetrySession,
    PostgresPipelineTelemetryObserver,
    flush_telemetry,
    telemetry_observer_context,
    telemetry_session_context,
)
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector
from incident_awareness.storage.config import DatabaseConfig

NOW = datetime(2026, 10, 14, 1, tzinfo=UTC)


def test_input_identity_lookup_defect_disables_only_timeseries_bootstrap(
    monkeypatch, tmp_path
) -> None:
    # Given
    runtime_snapshots, timeseries_snapshots = [], []
    tracker = PipelineRuntimeTracker(
        execution_id="shared-execution",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        input_total=1,
        started_at=NOW,
        observer=runtime_snapshots.append,
        clock=lambda: NOW,
    )
    original = RuntimeError("original business error")

    def fail(*args):
        raise RuntimeError("input identity bootstrap defect")

    monkeypatch.setattr(module, "resolve_telemetry_input_identity", fail)

    # When
    with (
        pytest.raises(RuntimeError) as caught,
        telemetry_session_context(
            tracker,
            run_id="RUN-20261014-001",
            entity_id="WIN-01",
            input_total=1,
            observer=timeseries_snapshots.append,
            input_path=tmp_path / "input.jsonl",
        ) as session,
    ):
        assert session is None
        tracker.start_stage(PipelineStage.NORMALIZATION)
        tracker.record_normalization_progress(1)
        raise original

    # Then
    assert caught.value is original
    assert timeseries_snapshots == []
    assert runtime_snapshots[-1].normalization_processed_count == 1


def _collector(**kwargs: object) -> PipelineTelemetryCollector:
    return PipelineTelemetryCollector(
        execution_id="shared-execution",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        clock=lambda: NOW,
        **kwargs,
    )


class _Connection:
    def __init__(self, *, save_error: bool = False, commit_error: bool = False) -> None:
        self.save_error = save_error
        self.commit_error = commit_error
        self.commits = self.rollbacks = self.closes = 0
        self.saved: list[PipelineTelemetrySnapshot] = []

    def commit(self) -> None:
        self.commits += 1
        if self.commit_error:
            raise RuntimeError("commit failed")

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closes += 1


class _Repository:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def save_snapshot(self, snapshot: PipelineTelemetrySnapshot) -> bool:
        if self.connection.save_error:
            raise RuntimeError("snapshot write failed")
        self.connection.saved.append(snapshot)
        return True


def _observer(connection_factory) -> PostgresPipelineTelemetryObserver:
    return PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig("unused-test-url"),
        connection_factory=connection_factory,
    )


def test_observer_is_lazy_commits_and_does_not_duplicate_saved_snapshot(monkeypatch) -> None:
    # Given
    connection = _Connection()
    connections = []
    monkeypatch.setattr(module, "PipelineTelemetryRepository", _Repository)
    observer = _observer(lambda url: connections.append(url) or connection)
    collector = _collector()
    collector.accept_batch(1)

    # When
    assert connections == []
    first = observer(collector.snapshot())
    repeated = observer(collector.snapshot())
    observer.close()

    # Then
    assert first and repeated
    assert connections == ["unused-test-url"]
    assert connection.saved == [collector.snapshot()]
    assert connection.commits == connection.closes == 1
    assert connection.rollbacks == 0
    assert observer.pending_snapshot is None


@pytest.mark.parametrize("commit_error", [False, True])
def test_write_or_commit_failure_rolls_back_reconnects_and_persists_quality(
    monkeypatch, commit_error
) -> None:
    # Given
    failed = _Connection(save_error=not commit_error, commit_error=commit_error)
    recovered = _Connection()
    connections = iter([failed, recovered])
    monkeypatch.setattr(module, "PipelineTelemetryRepository", _Repository)
    observer = _observer(lambda _: next(connections))
    collector = _collector()
    collector.accept_batch(1)
    session = PipelineTelemetrySession(collector, observer)

    # When
    session.flush(force=True)
    partial = collector.snapshot()
    session.flush(force=True)

    # Then
    assert failed.rollbacks == failed.closes == 1
    assert partial.observation_status == "partial"
    assert partial.observation_issues == (TelemetryObservationIssue.STORAGE_ERROR,)
    assert recovered.saved == [partial]
    assert recovered.commits == 1
    assert observer.pending_snapshot is None
    assert not observer.is_disabled


def test_close_retries_pending_quality_after_transient_failure(monkeypatch) -> None:
    # Given
    failed, recovered = _Connection(save_error=True), _Connection()
    connections = iter([failed, recovered])
    monkeypatch.setattr(module, "PipelineTelemetryRepository", _Repository)
    observer = _observer(lambda _: next(connections))
    collector = _collector()
    collector.accept_batch(1)
    session = PipelineTelemetrySession(collector, observer)

    # When
    session.flush(force=True)
    observer.close()

    # Then
    assert recovered.saved == [collector.snapshot()]
    assert recovered.saved[0].observation_status == "partial"
    assert recovered.commits == recovered.closes == 1


def test_three_connection_failures_disable_only_timeseries_collection() -> None:
    # Given
    calls = []

    def fail(url):
        calls.append(url)
        raise RuntimeError("connection unavailable")

    observer = _observer(fail)
    collector = _collector()
    collector.accept_batch(1)
    session = PipelineTelemetrySession(collector, observer)

    # When
    for _ in range(10):
        session.flush(force=True)
    observer.close()

    # Then
    assert len(calls) == 3
    assert observer.is_disabled
    assert collector.is_disabled
    assert collector.snapshot().collection_disabled
    assert collector.snapshot().observation_status == "partial"


def test_progress_flush_has_five_second_cadence_and_final_short_batch_flush() -> None:
    # Given
    now = [0.0]
    snapshots = []
    collector = _collector()
    collector.accept_batch(3)
    session = PipelineTelemetrySession(collector, snapshots.append, clock=lambda: now[0])
    session.flush(force=True)

    # When
    session.record_success(session.begin_record(1))
    now[0] = 4.999
    session.record_success(session.begin_record(2))
    before_due = len(snapshots)
    now[0] = 5.0
    session.record_success(session.begin_record(3))
    flush_telemetry(session)

    # Then
    assert before_due == 1
    assert len(snapshots) == 3
    assert snapshots[-1].buckets[0].processing_completed_count == 3
    assert snapshots[-1] is snapshots[-2]


def test_long_record_does_not_synthesize_flushes_or_missing_buckets() -> None:
    # Given
    now = [0.0]
    snapshots = []
    collector = _collector()
    collector.accept_batch(1)
    session = PipelineTelemetrySession(collector, snapshots.append, clock=lambda: now[0])
    session.flush(force=True)

    # When
    token = session.begin_record(1)
    now[0] = 60
    during_processing = len(snapshots)
    session.record_success(token)

    # Then
    assert during_processing == 1
    assert len(snapshots) == 2
    assert len(snapshots[-1].buckets) == 1
    assert snapshots[-1].buckets[0].processing_completed_count == 1


def test_bounded_record_memory_preserves_counts_and_marks_partial() -> None:
    # Given
    collector = _collector(max_records=1)
    collector.accept_batch(2)

    # When
    collector.record_success(collector.begin_record(1))
    collector.record_success(collector.begin_record(2))
    snapshot = collector.snapshot()

    # Then
    assert snapshot.collection_disabled
    assert snapshot.observation_issues == (TelemetryObservationIssue.BUFFER_LIMIT,)
    assert snapshot.buckets[0].input_accepted_count == 2
    assert snapshot.buckets[0].processing_completed_count == 1


def test_bounded_bucket_memory_preserves_last_valid_observations() -> None:
    # Given
    now = [NOW]
    collector = PipelineTelemetryCollector(
        execution_id="shared",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        clock=lambda: now[0],
        max_buckets=1,
    )
    collector.accept_batch(1)
    token = collector.begin_record(1)

    # When
    now[0] += timedelta(seconds=1)
    collector.record_success(token)
    snapshot = collector.snapshot()

    # Then
    assert len(snapshot.buckets) == 1
    assert snapshot.buckets[0].processing_completed_count == 0
    assert snapshot.collection_disabled
    assert snapshot.observation_issues == (TelemetryObservationIssue.BUFFER_LIMIT,)


def test_collector_bootstrap_failure_does_not_change_runtime_tracker(monkeypatch) -> None:
    # Given
    tracker = PipelineRuntimeTracker(
        execution_id="shared",
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        input_total=1,
        started_at=NOW,
    )

    def fail(**kwargs):
        raise RuntimeError("collector bootstrap failed")

    monkeypatch.setattr(module, "create_pipeline_telemetry_collector", fail)

    # When
    with telemetry_session_context(
        tracker,
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        input_total=1,
        observer=lambda _: None,
    ) as session:
        result = "business result"

    # Then
    assert session is None
    assert result == "business result"
    assert not tracker.is_disabled
    assert tracker.execution_id == "shared"


def test_session_final_flush_failure_preserves_business_exception_identity(monkeypatch) -> None:
    # Given
    collector = _collector()
    collector.accept_batch(1)
    session = PipelineTelemetrySession(collector, lambda _: None)
    business_error = RuntimeError("business failed")

    def fail(**kwargs):
        raise RuntimeError("unexpected flush failure")

    monkeypatch.setattr(session, "flush", fail)

    # When
    with pytest.raises(RuntimeError) as exc_info:
        try:
            raise business_error
        finally:
            flush_telemetry(session)

    # Then
    assert exc_info.value is business_error


def test_observer_bootstrap_failure_still_runs_business(monkeypatch) -> None:
    # Given
    def fail():
        raise RuntimeError("observer construction failed")

    monkeypatch.setattr(module, "PostgresPipelineTelemetryObserver", fail)

    # When
    with telemetry_observer_context() as observer:
        business_result = "completed"

    # Then
    assert observer is None
    assert business_result == "completed"


def test_default_connection_is_separate_transactional_and_time_bounded(monkeypatch) -> None:
    # Given
    received = {}
    connection = object()

    def connect(url, **kwargs):
        received.update(kwargs)
        return connection

    monkeypatch.setattr(module.psycopg, "connect", connect)

    # When
    actual = module._connect_telemetry_database("unused-test-url")

    # Then
    assert actual is connection
    assert received == {
        "autocommit": False,
        "connect_timeout": 2,
        "options": "-c statement_timeout=2000 -c lock_timeout=2000 -c transaction_timeout=5000",
    }


def test_flush_clock_failure_keeps_final_flush_and_marks_internal_quality() -> None:
    # Given
    collector = _collector()
    collector.accept_batch(1)
    snapshots = []

    def fail():
        raise RuntimeError("flush clock unavailable")

    session = PipelineTelemetrySession(collector, snapshots.append, clock=fail)

    # When
    session.flush(force=True)

    # Then
    assert snapshots == [collector.snapshot()]
    assert snapshots[0].collection_disabled
    assert snapshots[0].observation_issues == (TelemetryObservationIssue.INTERNAL_ERROR,)


def test_quality_marker_failure_cannot_replace_business_exception(monkeypatch) -> None:
    # Given
    collector = _collector()
    collector.accept_batch(1)
    business_error = RuntimeError("original business error")

    def fail(*args, **kwargs):
        raise RuntimeError("quality marker failed")

    monkeypatch.setattr(collector, "mark_observation_issue", fail)
    session = PipelineTelemetrySession(collector, lambda _: False)

    # When
    with pytest.raises(RuntimeError) as exc_info:
        try:
            raise business_error
        finally:
            session.flush(force=True)

    # Then
    assert exc_info.value is business_error
