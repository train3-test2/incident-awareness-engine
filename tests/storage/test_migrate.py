from typing import Self

import pytest

from incident_awareness.storage import migrate
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.migrate import apply_first_cycle_migration, apply_migrations

FIRST_CYCLE_TABLES = {
    "runs",
    "events",
    "fusion_results",
    "detection_results",
    "decisions",
}


class _Cursor:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _Connection:
    def __init__(
        self,
        *,
        applied_migrations: set[str] | None = None,
        existing_tables: set[str] | None = None,
    ) -> None:
        self.applied_migrations = set(applied_migrations or set())
        self.existing_tables = set(existing_tables or set())
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Cursor:
        self.queries.append((query, params))

        if "SELECT 1 FROM schema_migrations" in query:
            migration_id = str(params[0])
            return _Cursor((1,) if migration_id in self.applied_migrations else None)

        if query == "SELECT to_regclass(%s)":
            table_name = str(params[0])
            return _Cursor((table_name if table_name in self.existing_tables else None,))

        if "CREATE TABLE runs" in query:
            self.existing_tables.update(FIRST_CYCLE_TABLES)

        if "CREATE TABLE fusion_stopping_traces" in query:
            self.existing_tables.add("fusion_stopping_traces")

        if query == "INSERT INTO schema_migrations (migration_id) VALUES (%s)":
            self.applied_migrations.add(str(params[0]))

        return _Cursor(None)


class _ContextConnection(_Connection):
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> None:
        return None


def test_applies_all_migrations_in_filename_order() -> None:
    # Given
    connection = _Connection()

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("001_first_cycle", "002_fusion_stopping_trace")
    assert connection.applied_migrations == {
        "001_first_cycle",
        "002_fusion_stopping_trace",
    }
    first_index = next(
        index for index, (query, _) in enumerate(connection.queries) if "CREATE TABLE runs" in query
    )
    second_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE fusion_stopping_traces" in query
    )
    assert first_index < second_index


def test_skips_migrations_that_are_already_recorded() -> None:
    # Given
    connection = _Connection(applied_migrations={"001_first_cycle", "002_fusion_stopping_trace"})

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ()
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )


def test_applies_only_second_migration_when_first_is_recorded() -> None:
    # Given
    connection = _Connection(applied_migrations={"001_first_cycle"})

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("002_fusion_stopping_trace",)
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert any("CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries)


def test_baselines_complete_legacy_first_cycle_schema_before_second_migration() -> None:
    # Given
    connection = _Connection(existing_tables=set(FIRST_CYCLE_TABLES))

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("001_first_cycle", "002_fusion_stopping_trace")
    assert connection.applied_migrations == {
        "001_first_cycle",
        "002_fusion_stopping_trace",
    }
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert any("CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries)


def test_baselines_complete_docker_initdb_schema_without_reapplying_migrations() -> None:
    # Given
    connection = _Connection(existing_tables={*FIRST_CYCLE_TABLES, "fusion_stopping_traces"})

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("001_first_cycle", "002_fusion_stopping_trace")
    assert connection.applied_migrations == {
        "001_first_cycle",
        "002_fusion_stopping_trace",
    }
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )


@pytest.mark.parametrize(
    "existing_tables",
    [
        {"runs"},
        {"runs", "events", "fusion_results"},
    ],
)
def test_rejects_partial_legacy_first_cycle_schema(existing_tables: set[str]) -> None:
    # Given
    connection = _Connection(existing_tables=existing_tables)

    # When
    with pytest.raises(RuntimeError, match="partial First Cycle schema"):
        apply_migrations(connection)

    # Then
    assert connection.applied_migrations == set()
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )


def test_first_cycle_compatibility_entry_point_only_applies_first_migration() -> None:
    # Given
    connection = _Connection()

    # When
    applied = apply_first_cycle_migration(connection)

    # Then
    assert applied is True
    assert connection.applied_migrations == {"001_first_cycle"}
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )


def test_main_uses_connection_managed_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _ContextConnection(
        applied_migrations={"001_first_cycle", "002_fusion_stopping_trace"}
    )
    received: dict[str, object] = {}

    def fake_connect(url: str, *, autocommit: bool) -> _ContextConnection:
        received.update(url=url, autocommit=autocommit)
        return connection

    monkeypatch.setattr(
        migrate.DatabaseConfig,
        "from_environment",
        lambda: DatabaseConfig("postgresql://user:password@host/database"),
    )
    monkeypatch.setattr(migrate.psycopg, "connect", fake_connect)

    # When
    result = migrate.main()

    # Then
    assert result == 0
    assert received == {
        "url": "postgresql://user:password@host/database",
        "autocommit": False,
    }
