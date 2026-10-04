from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta

import pytest
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    _SELECT_PIPELINE_RUNTIME_STATUS_PAYLOAD,
    _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS,
    _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE,
    _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS,
    _UPSERT_PIPELINE_RUNTIME_STATUS,
    PipelineRuntimeStatusRepository,
)

_BASE_TIME = datetime(2026, 10, 4, 1, tzinfo=UTC)


class _Cursor:
    def __init__(
        self,
        row: tuple[object, ...] | Mapping[str, object] | None = None,
        rows: list[tuple[object, ...] | Mapping[str, object]] | None = None,
    ) -> None:
        self._row = row
        self._rows = rows or []

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]:
        return self._rows


class _Connection:
    def __init__(self) -> None:
        self.statuses: dict[tuple[str, str], PipelineRuntimeStatus] = {}
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.raw_get_row: tuple[object, ...] | Mapping[str, object] | None = None
        self.use_raw_get_row = False

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))

        if query == _UPSERT_PIPELINE_RUNTIME_STATUS:
            payload = params[7]
            assert isinstance(payload, Jsonb)
            incoming = PipelineRuntimeStatus.model_validate(payload.obj)
            key = (incoming.run_id, incoming.entity_id)
            stored = self.statuses.get(key)
            if stored is None or _should_apply(stored, incoming):
                self.statuses[key] = incoming
                return _Cursor((1,))
            return _Cursor(None)

        if query == _SELECT_PIPELINE_RUNTIME_STATUS_PAYLOAD:
            if self.use_raw_get_row:
                return _Cursor(self.raw_get_row)
            stored = self.statuses.get((str(params[0]), str(params[1])))
            return _Cursor(None if stored is None else (stored.model_dump(mode="json"),))

        if query in {
            _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS,
            _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE,
        }:
            if query == _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS:
                limit = int(params[0])
                statuses = list(self.statuses.values())
            else:
                expected_state = str(params[0])
                limit = int(params[1])
                statuses = [
                    status for status in self.statuses.values() if status.status == expected_state
                ]
            statuses.sort(
                key=lambda status: (
                    status.status is not PipelineRuntimeState.RUNNING,
                    -status.updated_at.timestamp(),
                    status.run_id,
                    status.entity_id,
                )
            )
            return _Cursor(rows=[(status.model_dump(mode="json"),) for status in statuses[:limit]])

        if query == _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS:
            fresh_after = params[0]
            assert isinstance(fresh_after, datetime)
            limit = int(params[1])
            statuses = list(self.statuses.values())
            statuses.sort(
                key=lambda status: (
                    _freshness_group(status, fresh_after),
                    -status.updated_at.timestamp(),
                    status.run_id,
                    status.entity_id,
                )
            )
            return _Cursor(rows=[(status.model_dump(mode="json"),) for status in statuses[:limit]])

        raise AssertionError(f"unexpected query: {query}")

    def commit(self) -> None:
        self.commits += 1


def _should_apply(
    stored: PipelineRuntimeStatus,
    incoming: PipelineRuntimeStatus,
) -> bool:
    if stored.execution_id == incoming.execution_id:
        return (
            stored.started_at == incoming.started_at
            and stored.updated_at <= incoming.updated_at
            and (stored.status is PipelineRuntimeState.RUNNING or stored.status is incoming.status)
        )
    return stored.started_at < incoming.started_at


def _freshness_group(status: PipelineRuntimeStatus, fresh_after: datetime) -> int:
    if status.status is not PipelineRuntimeState.RUNNING:
        return 1
    return 0 if status.updated_at >= fresh_after else 2


def _running_status(
    *,
    execution_id: str = "execution-a",
    run_id: str = "RUN-20261004-001",
    entity_id: str = "WIN-01",
    started_offset: int = 0,
    updated_offset: int = 10,
    processed_count: int = 1,
) -> PipelineRuntimeStatus:
    started_at = _BASE_TIME + timedelta(seconds=started_offset)
    return PipelineRuntimeStatus(
        execution_id=execution_id,
        run_id=run_id,
        entity_id=entity_id,
        status=PipelineRuntimeState.RUNNING,
        current_stage=PipelineStage.NORMALIZATION,
        input_total=3,
        normalization_processed_count=processed_count,
        started_at=started_at,
        stage_started_at=started_at,
        updated_at=started_at + timedelta(seconds=updated_offset),
        completed_at=None,
        failed_stage=None,
    )


def _completed_status(
    *,
    execution_id: str = "execution-a",
    run_id: str = "RUN-20261004-001",
    entity_id: str = "WIN-01",
    started_offset: int = 0,
    updated_offset: int = 20,
) -> PipelineRuntimeStatus:
    started_at = _BASE_TIME + timedelta(seconds=started_offset)
    updated_at = started_at + timedelta(seconds=updated_offset)
    return PipelineRuntimeStatus(
        execution_id=execution_id,
        run_id=run_id,
        entity_id=entity_id,
        status=PipelineRuntimeState.COMPLETED,
        current_stage=None,
        input_total=3,
        normalization_processed_count=3,
        started_at=started_at,
        stage_started_at=None,
        updated_at=updated_at,
        completed_at=updated_at,
        failed_stage=None,
    )


def _failed_status(
    *,
    execution_id: str = "execution-a",
    run_id: str = "RUN-20261004-001",
    entity_id: str = "WIN-01",
    started_offset: int = 0,
    updated_offset: int = 20,
) -> PipelineRuntimeStatus:
    started_at = _BASE_TIME + timedelta(seconds=started_offset)
    return PipelineRuntimeStatus(
        execution_id=execution_id,
        run_id=run_id,
        entity_id=entity_id,
        status=PipelineRuntimeState.FAILED,
        current_stage=None,
        input_total=3,
        normalization_processed_count=1,
        started_at=started_at,
        stage_started_at=None,
        updated_at=started_at + timedelta(seconds=updated_offset),
        completed_at=None,
        failed_stage=PipelineStage.FUSION,
    )


def test_inserts_new_scope_as_jsonb_without_committing() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    status = _running_status()

    # When
    applied = repository.save(status)

    # Then
    assert applied is True
    assert connection.commits == 0
    assert len(connection.statements) == 1
    query, params = connection.statements[0]
    assert query == _UPSERT_PIPELINE_RUNTIME_STATUS
    assert params[:7] == (
        status.run_id,
        status.entity_id,
        status.execution_id,
        "running",
        "normalization",
        status.started_at,
        status.updated_at,
    )
    assert isinstance(params[7], Jsonb)
    assert params[7].obj == status.model_dump(mode="json")
    assert "ON CONFLICT (run_id, entity_id) DO UPDATE" in query
    assert "RETURNING 1" in query


def test_get_round_trips_canonical_payload() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    expected = _running_status()
    repository.save(expected)

    # When
    stored = repository.get(expected.run_id, expected.entity_id)

    # Then
    assert stored == expected
    assert connection.statements[-1] == (
        _SELECT_PIPELINE_RUNTIME_STATUS_PAYLOAD,
        (expected.run_id, expected.entity_id),
    )
    assert connection.commits == 0


def test_get_returns_none_for_missing_scope() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)

    # When
    stored = repository.get("RUN-20261004-001", "WIN-01")

    # Then
    assert stored is None


def test_get_rejects_non_object_payload() -> None:
    # Given
    connection = _Connection()
    connection.use_raw_get_row = True
    connection.raw_get_row = ("invalid",)
    repository = PipelineRuntimeStatusRepository(connection)

    # When
    with pytest.raises(TypeError, match="pipeline_runtime_status.payload"):
        repository.get("RUN-20261004-001", "WIN-01")

    # Then
    assert len(connection.statements) == 1


def test_get_preserves_contract_validation_error() -> None:
    # Given
    connection = _Connection()
    connection.use_raw_get_row = True
    connection.raw_get_row = ({"run_id": "RUN-20261004-001"},)
    repository = PipelineRuntimeStatusRepository(connection)

    # When
    with pytest.raises(ValidationError) as exc_info:
        repository.get("RUN-20261004-001", "WIN-01")

    # Then
    assert "execution_id" in str(exc_info.value)


@pytest.mark.parametrize(
    ("stored", "incoming", "expected_applied", "expected_execution_id", "expected_state"),
    [
        pytest.param(
            _running_status(updated_offset=10),
            _running_status(updated_offset=20, processed_count=2),
            True,
            "execution-a",
            PipelineRuntimeState.RUNNING,
            id="same-execution-newer-update",
        ),
        pytest.param(
            _running_status(updated_offset=10),
            _running_status(updated_offset=10, processed_count=2),
            True,
            "execution-a",
            PipelineRuntimeState.RUNNING,
            id="same-execution-equal-update",
        ),
        pytest.param(
            _running_status(updated_offset=20, processed_count=2),
            _running_status(updated_offset=10),
            False,
            "execution-a",
            PipelineRuntimeState.RUNNING,
            id="same-execution-older-update",
        ),
        pytest.param(
            _running_status(execution_id="execution-a", started_offset=10),
            _running_status(execution_id="execution-b", started_offset=20),
            True,
            "execution-b",
            PipelineRuntimeState.RUNNING,
            id="different-newer-execution",
        ),
        pytest.param(
            _running_status(execution_id="execution-b", started_offset=20),
            _running_status(execution_id="execution-a", started_offset=10, updated_offset=30),
            False,
            "execution-b",
            PipelineRuntimeState.RUNNING,
            id="different-older-execution",
        ),
        pytest.param(
            _running_status(execution_id="execution-a", started_offset=10),
            _running_status(execution_id="execution-b", started_offset=10),
            False,
            "execution-a",
            PipelineRuntimeState.RUNNING,
            id="different-equal-start",
        ),
        pytest.param(
            _running_status(updated_offset=10),
            _completed_status(updated_offset=20),
            True,
            "execution-a",
            PipelineRuntimeState.COMPLETED,
            id="running-to-completed",
        ),
        pytest.param(
            _running_status(updated_offset=10),
            _failed_status(updated_offset=20),
            True,
            "execution-a",
            PipelineRuntimeState.FAILED,
            id="running-to-failed",
        ),
        pytest.param(
            _completed_status(updated_offset=20),
            _running_status(updated_offset=30),
            False,
            "execution-a",
            PipelineRuntimeState.COMPLETED,
            id="completed-to-running",
        ),
        pytest.param(
            _completed_status(updated_offset=20),
            _failed_status(updated_offset=30),
            False,
            "execution-a",
            PipelineRuntimeState.COMPLETED,
            id="completed-to-failed",
        ),
        pytest.param(
            _failed_status(updated_offset=20),
            _running_status(updated_offset=30),
            False,
            "execution-a",
            PipelineRuntimeState.FAILED,
            id="failed-to-running",
        ),
        pytest.param(
            _failed_status(updated_offset=20),
            _completed_status(updated_offset=30),
            False,
            "execution-a",
            PipelineRuntimeState.FAILED,
            id="failed-to-completed",
        ),
    ],
)
def test_conditionally_applies_latest_state_transition(
    stored: PipelineRuntimeStatus,
    incoming: PipelineRuntimeStatus,
    expected_applied: bool,
    expected_execution_id: str,
    expected_state: PipelineRuntimeState,
) -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    assert repository.save(stored) is True

    # When
    applied = repository.save(incoming)
    latest = repository.get(stored.run_id, stored.entity_id)

    # Then
    assert applied is expected_applied
    assert latest is not None
    assert latest.execution_id == expected_execution_id
    assert latest.status is expected_state


def test_conditional_upsert_contains_atomic_stale_and_terminal_guards() -> None:
    # Given
    normalized_sql = " ".join(_UPSERT_PIPELINE_RUNTIME_STATUS.split())

    # When
    stale_guard = (
        "pipeline_runtime_status.execution_id = EXCLUDED.execution_id "
        "AND pipeline_runtime_status.started_at = EXCLUDED.started_at "
        "AND pipeline_runtime_status.updated_at <= EXCLUDED.updated_at"
    )
    newer_execution_guard = (
        "pipeline_runtime_status.execution_id <> EXCLUDED.execution_id "
        "AND pipeline_runtime_status.started_at < EXCLUDED.started_at"
    )

    # Then
    assert stale_guard in normalized_sql
    assert newer_execution_guard in normalized_sql
    assert "pipeline_runtime_status.status = 'running'" in normalized_sql
    assert "pipeline_runtime_status.status = EXCLUDED.status" in normalized_sql
    assert normalized_sql.endswith("RETURNING 1")


def test_list_recent_orders_running_first_then_by_recency_and_scope() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    statuses = (
        _completed_status(run_id="RUN-20261004-003", updated_offset=40),
        _running_status(run_id="RUN-20261004-002", entity_id="WIN-B", updated_offset=20),
        _running_status(run_id="RUN-20261004-001", entity_id="WIN-B", updated_offset=20),
        _running_status(run_id="RUN-20261004-001", entity_id="WIN-A", updated_offset=20),
        _failed_status(run_id="RUN-20261004-004", updated_offset=30),
    )
    for status in statuses:
        repository.save(status)

    # When
    recent = repository.list_recent(limit=100)

    # Then
    assert [(status.run_id, status.entity_id) for status in recent] == [
        ("RUN-20261004-001", "WIN-A"),
        ("RUN-20261004-001", "WIN-B"),
        ("RUN-20261004-002", "WIN-B"),
        ("RUN-20261004-003", "WIN-01"),
        ("RUN-20261004-004", "WIN-01"),
    ]
    assert connection.statements[-1] == (
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS,
        (100,),
    )


def test_list_recent_filters_by_state_and_applies_limit() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    for status in (
        _running_status(run_id="RUN-20261004-001", updated_offset=10),
        _failed_status(run_id="RUN-20261004-002", updated_offset=20),
        _failed_status(run_id="RUN-20261004-003", updated_offset=30),
    ):
        repository.save(status)

    # When
    recent = repository.list_recent(limit=1, status=PipelineRuntimeState.FAILED)

    # Then
    assert [status.run_id for status in recent] == ["RUN-20261004-003"]
    assert connection.statements[-1] == (
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE,
        ("failed", 1),
    )


@pytest.mark.parametrize("limit", [0, 101, True, 1.5])
def test_list_recent_rejects_invalid_limit(limit: object) -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)

    # When
    with pytest.raises(ValueError, match="between 1 and 100"):
        repository.list_recent(limit=limit)

    # Then
    assert connection.statements == []


def test_list_recent_with_running_freshness_orders_fresh_then_terminal_then_stale() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    fresh_after = _BASE_TIME + timedelta(seconds=100)
    for status in (
        _running_status(run_id="RUN-20261004-011", updated_offset=99),
        _completed_status(run_id="RUN-20261004-012", updated_offset=120),
        _failed_status(run_id="RUN-20261004-013", updated_offset=50),
        _running_status(run_id="RUN-20261004-014", updated_offset=150),
    ):
        repository.save(status)

    # When
    recent = repository.list_recent(limit=100, running_fresh_after=fresh_after)

    # Then
    assert [(status.run_id, status.status) for status in recent] == [
        ("RUN-20261004-014", PipelineRuntimeState.RUNNING),
        ("RUN-20261004-012", PipelineRuntimeState.COMPLETED),
        ("RUN-20261004-013", PipelineRuntimeState.FAILED),
        ("RUN-20261004-011", PipelineRuntimeState.RUNNING),
    ]
    assert connection.statements[-1] == (
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS,
        (fresh_after, 100),
    )


def test_list_recent_with_running_freshness_keeps_terminal_ahead_of_stale_running() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    fresh_after = _BASE_TIME + timedelta(seconds=100)
    for status in (
        _running_status(run_id="RUN-20261004-021", updated_offset=95),
        _running_status(run_id="RUN-20261004-022", updated_offset=90),
        _completed_status(run_id="RUN-20261004-023", updated_offset=80),
    ):
        repository.save(status)

    # When
    recent = repository.list_recent(limit=1, running_fresh_after=fresh_after)

    # Then
    assert [status.run_id for status in recent] == ["RUN-20261004-023"]
    assert connection.statements[-1] == (
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS,
        (fresh_after, 1),
    )


def test_list_recent_running_filter_returns_fresh_and_stale_running() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    fresh_after = _BASE_TIME + timedelta(seconds=100)
    for status in (
        _running_status(run_id="RUN-20261004-031", updated_offset=150),
        _running_status(run_id="RUN-20261004-032", updated_offset=99),
        _completed_status(run_id="RUN-20261004-033", updated_offset=120),
        _failed_status(run_id="RUN-20261004-034", updated_offset=110),
    ):
        repository.save(status)

    # When
    running = repository.list_recent(
        limit=100,
        status=PipelineRuntimeState.RUNNING,
        running_fresh_after=fresh_after,
    )

    # Then
    assert [(status.run_id, status.status) for status in running] == [
        ("RUN-20261004-031", PipelineRuntimeState.RUNNING),
        ("RUN-20261004-032", PipelineRuntimeState.RUNNING),
    ]
    assert connection.statements[-1] == (
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE,
        ("running", 100),
    )


@pytest.mark.parametrize(
    ("terminal_state", "terminal_status"),
    [
        (PipelineRuntimeState.COMPLETED, _completed_status),
        (PipelineRuntimeState.FAILED, _failed_status),
    ],
)
def test_list_recent_terminal_filter_ignores_running_freshness(
    terminal_state: PipelineRuntimeState,
    terminal_status: Callable[..., PipelineRuntimeStatus],
) -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    fresh_after = _BASE_TIME + timedelta(seconds=100)
    for status in (
        terminal_status(run_id="RUN-20261004-041", updated_offset=50),
        terminal_status(run_id="RUN-20261004-042", updated_offset=120),
        _running_status(run_id="RUN-20261004-043", updated_offset=150),
    ):
        repository.save(status)

    # When
    with_cutoff = repository.list_recent(
        limit=100,
        status=terminal_state,
        running_fresh_after=fresh_after,
    )
    without_cutoff = repository.list_recent(limit=100, status=terminal_state)

    # Then
    assert [status.run_id for status in with_cutoff] == ["RUN-20261004-042", "RUN-20261004-041"]
    assert with_cutoff == without_cutoff
    assert connection.statements[-2:] == [
        (_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE, (terminal_state.value, 100)),
        (_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE, (terminal_state.value, 100)),
    ]


def test_list_recent_treats_running_freshness_boundary_as_fresh() -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)
    fresh_after = _BASE_TIME + timedelta(seconds=100)
    boundary = _running_status(run_id="RUN-20261004-051", updated_offset=100)
    completed = _completed_status(run_id="RUN-20261004-052", updated_offset=120)
    stale = _running_status(run_id="RUN-20261004-053", updated_offset=99)
    for status in (boundary, completed, stale):
        repository.save(status)

    # When
    recent = repository.list_recent(limit=100, running_fresh_after=fresh_after)

    # Then
    assert boundary.updated_at == fresh_after
    assert recent == [boundary, completed, stale]


def test_running_freshness_orders_unfiltered_rows_without_filtering_status_queries() -> None:
    # Given
    unfiltered_sql = " ".join(
        _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS.split()
    )
    status_filter_sql = " ".join(_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE.split())

    # When
    freshness_order = (
        "CASE WHEN status = 'running' AND updated_at >= %s THEN 0 "
        "WHEN status = 'running' THEN 2 ELSE 1 END, "
        "updated_at DESC, run_id ASC, entity_id ASC"
    )

    # Then
    assert freshness_order in unfiltered_sql
    assert "WHERE" not in unfiltered_sql
    assert "WHERE status = %s ORDER BY" in status_filter_sql
    assert "updated_at >=" not in status_filter_sql


@pytest.mark.parametrize(
    "running_fresh_after",
    [_BASE_TIME.replace(tzinfo=None), "2026-10-04T01:00:00Z"],
    ids=("naive-datetime", "string"),
)
def test_list_recent_rejects_invalid_running_fresh_after(running_fresh_after: object) -> None:
    # Given
    connection = _Connection()
    repository = PipelineRuntimeStatusRepository(connection)

    # When
    with pytest.raises(ValueError) as exc_info:
        repository.list_recent(limit=20, running_fresh_after=running_fresh_after)

    # Then
    assert "timezone-aware" in str(exc_info.value)
    assert connection.statements == []
