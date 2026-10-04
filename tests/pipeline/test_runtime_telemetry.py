import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.pipeline import runtime_telemetry
from incident_awareness.pipeline.runtime_telemetry import (
    PipelineRuntimeTracker,
    PostgresPipelineRuntimeObserver,
    generate_execution_id,
    utc_now_milliseconds,
)
from incident_awareness.storage.config import DatabaseConfig

STARTED_AT = datetime(2026, 10, 4, 1, 0, tzinfo=UTC)


class _FakeConnection:
    def __init__(
        self,
        *,
        save_result: bool = True,
        save_error: Exception | None = None,
        commit_error: Exception | None = None,
        rollback_error: Exception | None = None,
    ) -> None:
        self.save_result = save_result
        self.save_error = save_error
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.saved: list[PipelineRuntimeStatus] = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def commit(self) -> None:
        self.commits += 1
        if self.commit_error is not None:
            error = self.commit_error
            self.commit_error = None
            raise error

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.rollback_error is not None:
            raise self.rollback_error

    def close(self) -> None:
        self.closes += 1


class _FakeRepository:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def save(self, status: PipelineRuntimeStatus) -> bool:
        self._connection.saved.append(status)
        if self._connection.save_error is not None:
            error = self._connection.save_error
            self._connection.save_error = None
            raise error
        return self._connection.save_result


def test_tracker_publishes_stage_progress_and_completed_snapshots() -> None:
    # Given
    snapshots: list[PipelineRuntimeStatus] = []
    times = iter(STARTED_AT + timedelta(seconds=index) for index in range(8))
    tracker = PipelineRuntimeTracker(
        execution_id="execution-001",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        input_total=2,
        started_at=STARTED_AT,
        observer=snapshots.append,
        clock=lambda: next(times),
    )

    # When
    tracker.start_stage(PipelineStage.NORMALIZATION)
    tracker.record_normalization_progress(1)
    tracker.record_normalization_progress(2)
    tracker.start_stage(PipelineStage.FUSION)
    tracker.start_stage(PipelineStage.FAST_HANDOFF)
    tracker.start_stage(PipelineStage.HYBRID)
    tracker.start_stage(PipelineStage.PERSISTENCE)
    completed = tracker.complete()

    # Then
    assert [snapshot.current_stage for snapshot in snapshots] == [
        PipelineStage.NORMALIZATION,
        PipelineStage.NORMALIZATION,
        PipelineStage.NORMALIZATION,
        PipelineStage.FUSION,
        PipelineStage.FAST_HANDOFF,
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
        2,
    ]
    assert len({snapshot.stage_started_at for snapshot in snapshots[:-1]}) == 5
    assert {snapshot.execution_id for snapshot in snapshots} == {"execution-001"}
    assert {snapshot.started_at for snapshot in snapshots} == {STARTED_AT}
    assert completed.status is PipelineRuntimeState.COMPLETED
    assert completed.completed_at == completed.updated_at
    assert completed.remaining_count == 0
    assert tracker.status is completed


def test_tracker_publishes_failed_stage_without_requiring_an_observer() -> None:
    # Given
    tracker = PipelineRuntimeTracker(
        execution_id="execution-001",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        input_total=3,
        started_at=STARTED_AT,
        clock=lambda: STARTED_AT,
    )
    tracker.start_stage(PipelineStage.NORMALIZATION)
    tracker.record_normalization_progress(1)

    # When
    failed = tracker.fail(PipelineStage.NORMALIZATION)

    # Then
    assert failed.status is PipelineRuntimeState.FAILED
    assert failed.failed_stage is PipelineStage.NORMALIZATION
    assert failed.current_stage is None
    assert failed.normalization_processed_count == 1
    assert failed.remaining_count == 2


def test_tracker_isolates_observer_failure(caplog: pytest.LogCaptureFixture) -> None:
    # Given
    def failing_observer(status: PipelineRuntimeStatus) -> None:
        raise RuntimeError("telemetry write failed")

    tracker = PipelineRuntimeTracker(
        execution_id="execution-001",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        input_total=1,
        started_at=STARTED_AT,
        observer=failing_observer,
        clock=lambda: STARTED_AT,
    )

    # When
    with caplog.at_level(logging.ERROR):
        status = tracker.start_stage(PipelineStage.NORMALIZATION)

    # Then
    assert status.status is PipelineRuntimeState.RUNNING
    assert tracker.status is status
    assert tracker.is_disabled is False
    assert "Pipeline Runtime observer failed" in caplog.text


def test_tracker_disables_itself_after_internal_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    clock_calls = 0

    def failing_clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        raise RuntimeError("clock failed")

    tracker = PipelineRuntimeTracker(
        execution_id="execution-001",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        input_total=2,
        started_at=STARTED_AT,
        clock=failing_clock,
    )

    # When
    with caplog.at_level(logging.ERROR):
        first = tracker.start_stage(PipelineStage.NORMALIZATION)
        second = tracker.start_stage(PipelineStage.FUSION)

    # Then
    assert first is None
    assert second is None
    assert tracker.is_disabled is True
    assert clock_calls == 1
    assert caplog.text.count("Pipeline Runtime tracker failed") == 1


def test_execution_id_and_runtime_clock_follow_runtime_contract() -> None:
    # Given / When
    execution_id = generate_execution_id()
    timestamp = utc_now_milliseconds()

    # Then
    assert str(UUID(execution_id)) == execution_id
    assert timestamp.tzinfo is UTC
    assert timestamp.microsecond % 1000 == 0


def test_postgres_observer_connects_lazily_commits_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _FakeConnection(save_result=False)
    connections: list[str] = []
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)

    def connect(url: str) -> _FakeConnection:
        connections.append(url)
        return connection

    # When
    with PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=connect,
    ) as observer:
        assert connections == []
        observer(_status())

    # Then
    assert connections == ["postgresql://runtime/test"]
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closes == 1
    assert connection.saved == [_status()]


def test_postgres_observer_rolls_back_resets_and_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("repository write failed")
    failed_connection = _FakeConnection()
    recovered_connection = _FakeConnection()
    available_connections = iter((failed_connection, recovered_connection))
    connection_count = 0
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)

    def connect(url: str) -> _FakeConnection:
        nonlocal connection_count
        connection_count += 1
        return next(available_connections)

    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=connect,
        progress_write_interval_seconds=0.0,
    )

    # When
    observer(_status())
    failed_connection.save_error = expected_error
    with pytest.raises(RuntimeError) as exc_info:
        observer(_status(processed_count=1, seconds=1))
    observer(_status(processed_count=2, seconds=2))
    observer.close()

    # Then
    assert exc_info.value is expected_error
    assert failed_connection.rollbacks == 1
    assert failed_connection.closes == 1
    assert failed_connection.commits == 1
    assert recovered_connection.commits == 1
    assert recovered_connection.closes == 1
    assert connection_count == 2


def test_postgres_observer_preserves_write_error_when_rollback_fails(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    expected_error = RuntimeError("repository write failed")
    connection = _FakeConnection(
        save_error=expected_error,
        rollback_error=RuntimeError("rollback failed"),
    )
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)
    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=lambda url: connection,
    )

    # When
    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError) as exc_info:
        observer(_status())

    # Then
    assert exc_info.value is expected_error
    assert connection.rollbacks == 1
    assert connection.closes == 1
    assert "Pipeline Runtime telemetry rollback failed" in caplog.text


def test_postgres_observer_throttles_retries_after_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("database unavailable")
    connection = _FakeConnection()
    connection_attempts = 0
    monotonic_time = [0.0]
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)

    def connect(url: str) -> _FakeConnection:
        nonlocal connection_attempts
        connection_attempts += 1
        if connection_attempts == 1:
            raise expected_error
        return connection

    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=connect,
        monotonic_clock=lambda: monotonic_time[0],
        progress_write_interval_seconds=1.0,
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        observer(_status())
    monotonic_time[0] = 0.2
    observer(_status(processed_count=1, seconds=1))
    monotonic_time[0] = 1.1
    observer(_status(processed_count=2, seconds=2))

    # Then
    assert exc_info.value is expected_error
    assert connection_attempts == 2
    assert connection.commits == 1
    assert [status.normalization_processed_count for status in connection.saved] == [2]


def test_postgres_observer_throttles_progress_after_stale_save(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _FakeConnection(save_result=False)
    monotonic_time = [0.0]
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)
    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=lambda url: connection,
        monotonic_clock=lambda: monotonic_time[0],
        progress_write_interval_seconds=1.0,
    )

    # When
    observer(_status())
    monotonic_time[0] = 0.2
    observer(_status(processed_count=1, seconds=1))

    # Then
    assert connection.commits == 1
    assert [status.normalization_processed_count for status in connection.saved] == [0]


def test_postgres_observer_does_not_throttle_stage_transition_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("database unavailable")
    connection = _FakeConnection()
    connection_attempts = 0
    monotonic_time = [0.0]
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)

    def connect(url: str) -> _FakeConnection:
        nonlocal connection_attempts
        connection_attempts += 1
        if connection_attempts == 1:
            raise expected_error
        return connection

    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=connect,
        monotonic_clock=lambda: monotonic_time[0],
        progress_write_interval_seconds=1.0,
    )

    # When
    with pytest.raises(RuntimeError):
        observer(_status())
    monotonic_time[0] = 0.1
    observer(_status(stage=PipelineStage.FUSION, seconds=1))

    # Then
    assert connection_attempts == 2
    assert connection.commits == 1
    assert connection.saved[0].current_stage is PipelineStage.FUSION


def test_postgres_observer_recovers_from_commit_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    expected_error = RuntimeError("commit failed")
    failed_connection = _FakeConnection(commit_error=expected_error)
    recovered_connection = _FakeConnection()
    available_connections = iter((failed_connection, recovered_connection))
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)
    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=lambda url: next(available_connections),
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        observer(_status())
    observer(_status(stage=PipelineStage.FUSION, seconds=1))
    observer.close()

    # Then
    assert exc_info.value is expected_error
    assert failed_connection.commits == 1
    assert failed_connection.rollbacks == 1
    assert failed_connection.closes == 1
    assert recovered_connection.commits == 1
    assert recovered_connection.closes == 1


def test_postgres_observer_throttles_only_same_stage_normalization_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _FakeConnection()
    monotonic_time = [0.0]
    monkeypatch.setattr(runtime_telemetry, "PipelineRuntimeStatusRepository", _FakeRepository)
    observer = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig("postgresql://runtime/test"),
        connection_factory=lambda url: connection,
        monotonic_clock=lambda: monotonic_time[0],
        progress_write_interval_seconds=1.0,
    )

    # When
    observer(_status())
    monotonic_time[0] = 0.2
    observer(_status(processed_count=1, seconds=1))
    monotonic_time[0] = 1.2
    observer(_status(processed_count=2, seconds=2))
    monotonic_time[0] = 1.3
    observer(_status(stage=PipelineStage.FUSION, processed_count=3, seconds=3))
    observer(_status(state=PipelineRuntimeState.COMPLETED, processed_count=3, seconds=4))
    observer(_status(state=PipelineRuntimeState.FAILED, processed_count=3, seconds=5))

    # Then
    assert [status.current_stage for status in connection.saved] == [
        PipelineStage.NORMALIZATION,
        PipelineStage.NORMALIZATION,
        PipelineStage.FUSION,
        None,
        None,
    ]
    assert [status.normalization_processed_count for status in connection.saved] == [
        0,
        2,
        3,
        3,
        3,
    ]
    assert connection.commits == 5


def _status(
    *,
    stage: PipelineStage = PipelineStage.NORMALIZATION,
    state: PipelineRuntimeState = PipelineRuntimeState.RUNNING,
    processed_count: int = 0,
    seconds: int = 0,
) -> PipelineRuntimeStatus:
    timestamp = STARTED_AT + timedelta(seconds=seconds)
    terminal = state is not PipelineRuntimeState.RUNNING
    return PipelineRuntimeStatus(
        execution_id="execution-001",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        status=state,
        current_stage=None if terminal else stage,
        input_total=3,
        normalization_processed_count=processed_count,
        started_at=STARTED_AT,
        stage_started_at=None if terminal else STARTED_AT,
        updated_at=timestamp,
        completed_at=timestamp if state is PipelineRuntimeState.COMPLETED else None,
        failed_stage=PipelineStage.FUSION if state is PipelineRuntimeState.FAILED else None,
    )
