from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.storage.repositories.run_repository import (
    _SELECT_RECENT_RUN_METADATA,
    _SELECT_RECENT_RUNS_WITH_TOTAL_COUNT,
    _SELECT_RUN_METADATA,
    _UPSERT_RUN,
    RunRepository,
)


class FakeCursor:
    def __init__(
        self,
        row: tuple[object, ...] | Mapping[str, object] | None = None,
        rows: list[tuple[object, ...] | Mapping[str, object]] | None = None,
    ) -> None:
        self._row = row
        self._rows = rows if rows is not None else []

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]:
        return self._rows


class FakeConnection:
    def __init__(
        self,
        row: tuple[object, ...] | Mapping[str, object] | None = None,
        rows: list[tuple[object, ...] | Mapping[str, object]] | None = None,
    ) -> None:
        self.row = row
        self.rows = rows
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> FakeCursor:
        self.statements.append((query, params))
        return FakeCursor(self.row, self.rows)

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture
def run_metadata() -> RunMetadata:
    return RunMetadata(
        run_id="RUN-20260911-001",
        scenario_id="scenario-001",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 11, 1, tzinfo=UTC),
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.2",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def test_save_upserts_run_metadata_without_committing(run_metadata: RunMetadata) -> None:
    connection = FakeConnection()

    RunRepository(connection).save(run_metadata)

    assert connection.commits == 0
    assert len(connection.statements) == 1
    query, params = connection.statements[0]
    assert query == _UPSERT_RUN
    assert params[:6] == (
        "RUN-20260911-001",
        "scenario-001",
        "attack",
        "WIN-01",
        datetime(2026, 9, 11, 1, tzinfo=UTC),
        None,
    )
    assert isinstance(params[6], Jsonb)
    assert params[6].obj["run_id"] == "RUN-20260911-001"


def test_get_rebuilds_run_metadata_from_json_payload(run_metadata: RunMetadata) -> None:
    connection = FakeConnection((run_metadata.model_dump(mode="json"),))

    stored_run = RunRepository(connection).get(run_metadata.run_id)

    assert stored_run == run_metadata
    assert connection.statements == [(_SELECT_RUN_METADATA, (run_metadata.run_id,))]


def test_get_returns_none_when_run_does_not_exist() -> None:
    connection = FakeConnection()

    assert RunRepository(connection).get("RUN-20260911-001") is None


def test_get_rejects_non_object_metadata() -> None:
    connection = FakeConnection(("not-an-object",))

    with pytest.raises(TypeError, match="JSON 객체"):
        RunRepository(connection).get("RUN-20260911-001")


def test_list_recent_rebuilds_runs_in_database_order(run_metadata: RunMetadata) -> None:
    # Given
    older_run = run_metadata.model_copy(
        update={
            "run_id": "RUN-20260910-001",
            "start_time": datetime(2026, 9, 10, 1, tzinfo=UTC),
        }
    )
    connection = FakeConnection(
        rows=[
            (run_metadata.model_dump(mode="json"),),
            {"metadata": older_run.model_dump(mode="json")},
        ]
    )

    # When
    runs = RunRepository(connection).list_recent(20)

    # Then
    assert runs == [run_metadata, older_run]
    assert connection.statements == [(_SELECT_RECENT_RUN_METADATA, (20,))]
    assert "ORDER BY start_time DESC, run_id DESC" in _SELECT_RECENT_RUN_METADATA


def test_list_recent_returns_empty_list() -> None:
    # Given
    connection = FakeConnection(rows=[])

    # When
    runs = RunRepository(connection).list_recent(5)

    # Then
    assert runs == []
    assert connection.statements == [(_SELECT_RECENT_RUN_METADATA, (5,))]


def test_list_recent_rejects_non_object_metadata() -> None:
    # Given
    connection = FakeConnection(rows=[("not-an-object",)])

    # When / Then
    with pytest.raises(TypeError, match="JSON 객체"):
        RunRepository(connection).list_recent(20)


@pytest.mark.parametrize("limit", [0, -1])
def test_list_recent_rejects_non_positive_limit(limit: int) -> None:
    # Given
    connection = FakeConnection()

    # When / Then
    with pytest.raises(ValueError, match="greater than zero"):
        RunRepository(connection).list_recent(limit)
    assert connection.statements == []


def test_list_recent_with_total_count_uses_one_statement_and_rebuilds_runs(
    run_metadata: RunMetadata,
) -> None:
    # Given
    older_run = run_metadata.model_copy(
        update={
            "run_id": "RUN-20260910-001",
            "start_time": datetime(2026, 9, 10, 1, tzinfo=UTC),
        }
    )
    connection = FakeConnection(
        rows=[
            (7, run_metadata.model_dump(mode="json")),
            {"total_runs": 7, "metadata": older_run.model_dump(mode="json")},
        ]
    )

    # When
    total_runs, recent_runs = RunRepository(connection).list_recent_with_total_count(5)

    # Then
    assert total_runs == 7
    assert recent_runs == [run_metadata, older_run]
    assert connection.statements == [(_SELECT_RECENT_RUNS_WITH_TOTAL_COUNT, (5,))]
    assert "SELECT COUNT(*) AS total_runs" in _SELECT_RECENT_RUNS_WITH_TOTAL_COUNT
    assert "ORDER BY start_time DESC, run_id DESC" in _SELECT_RECENT_RUNS_WITH_TOTAL_COUNT
    assert _SELECT_RECENT_RUNS_WITH_TOTAL_COUNT.count("LIMIT %s") == 1
    assert connection.commits == 0


def test_list_recent_with_total_count_returns_empty_overview() -> None:
    # Given
    connection = FakeConnection(rows=[(0, None)])

    # When
    result = RunRepository(connection).list_recent_with_total_count(5)

    # Then
    assert result == (0, [])
    assert connection.statements == [(_SELECT_RECENT_RUNS_WITH_TOTAL_COUNT, (5,))]


@pytest.mark.parametrize("stored_total", [True, -1, "3", None])
def test_list_recent_with_total_count_rejects_invalid_total(
    stored_total: object,
    run_metadata: RunMetadata,
) -> None:
    # Given
    connection = FakeConnection(rows=[(stored_total, run_metadata.model_dump(mode="json"))])

    # When / Then
    with pytest.raises(TypeError, match="total count"):
        RunRepository(connection).list_recent_with_total_count(5)
    assert connection.commits == 0


def test_list_recent_with_total_count_rejects_invalid_metadata() -> None:
    # Given
    connection = FakeConnection(rows=[(1, "not-an-object")])

    # When / Then
    with pytest.raises(TypeError, match="JSON object"):
        RunRepository(connection).list_recent_with_total_count(5)


def test_list_recent_with_total_count_rejects_null_metadata_for_nonempty_table() -> None:
    # Given
    connection = FakeConnection(rows=[(1, None)])

    # When / Then
    with pytest.raises(TypeError, match="may be null only"):
        RunRepository(connection).list_recent_with_total_count(5)


def test_list_recent_with_total_count_rejects_missing_result_row() -> None:
    # Given
    connection = FakeConnection(rows=[])

    # When / Then
    with pytest.raises(TypeError, match="at least one row"):
        RunRepository(connection).list_recent_with_total_count(5)


@pytest.mark.parametrize("limit", [0, -1])
def test_list_recent_with_total_count_rejects_non_positive_limit(limit: int) -> None:
    # Given
    connection = FakeConnection()

    # When / Then
    with pytest.raises(ValueError, match="greater than zero"):
        RunRepository(connection).list_recent_with_total_count(limit)
    assert connection.statements == []
