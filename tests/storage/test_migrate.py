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
MIGRATION_IDS = (
    "001_first_cycle",
    "002_fusion_stopping_trace",
    "003_decision_runtime_snapshot",
    "004_fusion_runtime_config_snapshot",
    "005_pipeline_runtime_status",
    "006_s3_object_receipts",
    "007_r1_archive_publications",
    "008_r1_stream_delivery_ledger",
    "009_r1_stream_close_watermark_binding",
    "010_r1_stream_event_delivery_ledger",
    "011_pipeline_telemetry_timeseries",
    "012_pipeline_telemetry_input_identity",
    "013_r1_stream_position_close_ledger",
)
_INPUT_IDENTITY_MIGRATION = "012_pipeline_telemetry_input_identity"


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
        input_identity_artifacts: tuple[bool, ...] = (False,) * 6,
    ) -> None:
        self.applied_migrations = set(applied_migrations or set())
        self.existing_tables = set(existing_tables or set())
        self.input_identity_artifacts = input_identity_artifacts
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Cursor:
        self.queries.append((query, params))
        if query == migrate._INPUT_IDENTITY_BASELINE_SQL:
            return _Cursor(self.input_identity_artifacts)
        if "CREATE FUNCTION guard_pipeline_telemetry_input_identity" in query:
            self.input_identity_artifacts = (True,) * 6

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

        if "CREATE TABLE decision_runtime_snapshots" in query:
            self.existing_tables.add("decision_runtime_snapshots")

        if "CREATE TABLE fusion_runtime_config_snapshots" in query:
            self.existing_tables.add("fusion_runtime_config_snapshots")

        if "CREATE TABLE pipeline_runtime_status" in query:
            self.existing_tables.add("pipeline_runtime_status")

        if "CREATE TABLE s3_object_receipts" in query:
            self.existing_tables.add("s3_object_receipts")

        if "CREATE TABLE r1_archive_publications" in query:
            self.existing_tables.add("r1_archive_publications")

        if "CREATE TABLE r1_stream_chunks" in query:
            self.existing_tables.update(
                {"r1_stream_chunks", "r1_stream_watermarks", "r1_stream_run_closes"}
            )

        if "CREATE TABLE r1_stream_events" in query:
            self.existing_tables.add("r1_stream_events")

        if "CREATE TABLE r1_stream_position_closes" in query:
            self.existing_tables.add("r1_stream_position_closes")

        if "CREATE TABLE pipeline_telemetry_executions" in query:
            self.existing_tables.update(
                {"pipeline_telemetry_executions", "pipeline_telemetry_buckets"}
            )

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


def test_baselines_complete_input_identity_ddl_without_repeating_alter() -> None:
    # Given
    connection = _Connection(
        applied_migrations=set(MIGRATION_IDS) - {_INPUT_IDENTITY_MIGRATION},
        input_identity_artifacts=(True,) * 6,
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("012_pipeline_telemetry_input_identity",)
    assert not any(
        "CREATE FUNCTION guard_pipeline_telemetry_input_identity" in query
        for query, _ in connection.queries
    )
    assert apply_migrations(connection) == ()


@pytest.mark.parametrize("missing", range(6))
def test_partial_input_identity_schema_is_not_recorded_as_applied(missing: int) -> None:
    # Given
    artifacts = tuple(index != missing for index in range(6))
    connection = _Connection(
        applied_migrations=set(MIGRATION_IDS) - {_INPUT_IDENTITY_MIGRATION},
        input_identity_artifacts=artifacts,
    )

    # When / Then
    with pytest.raises(RuntimeError, match="partial 012"):
        apply_migrations(connection)
    assert "012_pipeline_telemetry_input_identity" not in connection.applied_migrations


def test_applies_all_migrations_in_filename_order() -> None:
    # Given
    connection = _Connection()

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS
    assert connection.applied_migrations == set(MIGRATION_IDS)
    _assert_migration_lock_precedes_history_table(connection)
    first_index = next(
        index for index, (query, _) in enumerate(connection.queries) if "CREATE TABLE runs" in query
    )
    second_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE fusion_stopping_traces" in query
    )
    third_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE decision_runtime_snapshots" in query
    )
    fourth_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE fusion_runtime_config_snapshots" in query
    )
    fifth_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE pipeline_runtime_status" in query
    )
    sixth_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE s3_object_receipts" in query
    )
    seventh_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE r1_archive_publications" in query
    )
    eighth_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE r1_stream_chunks" in query
    )
    telemetry_index = next(
        index
        for index, (query, _) in enumerate(connection.queries)
        if "CREATE TABLE pipeline_telemetry_executions" in query
    )
    assert (
        first_index
        < second_index
        < third_index
        < fourth_index
        < fifth_index
        < sixth_index
        < seventh_index
        < eighth_index
        < telemetry_index
    )


def test_skips_migrations_that_are_already_recorded() -> None:
    # Given
    connection = _Connection(applied_migrations=set(MIGRATION_IDS))

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ()
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries
    )
    assert not any("CREATE TABLE s3_object_receipts" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE r1_archive_publications" in query for query, _ in connection.queries
    )
    assert not any("CREATE TABLE r1_stream_chunks" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
    )


def test_applies_only_second_migration_when_first_is_recorded() -> None:
    # Given
    connection = _Connection(applied_migrations={"001_first_cycle"})

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS[1:]
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert any("CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries)
    assert any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert any("CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries)


def test_applies_only_third_migration_when_first_two_are_recorded() -> None:
    # Given
    connection = _Connection(applied_migrations={"001_first_cycle", "002_fusion_stopping_trace"})

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS[2:]
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )
    assert any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert any("CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries)


def test_applies_only_fourth_migration_when_first_three_are_recorded() -> None:
    # Given
    connection = _Connection(
        applied_migrations={
            "001_first_cycle",
            "002_fusion_stopping_trace",
            "003_decision_runtime_snapshot",
        }
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS[3:]
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert any("CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries)


def test_applies_only_fifth_migration_when_first_four_are_recorded() -> None:
    # Given
    connection = _Connection(
        applied_migrations={
            "001_first_cycle",
            "002_fusion_stopping_trace",
            "003_decision_runtime_snapshot",
            "004_fusion_runtime_config_snapshot",
        }
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS[4:]
    assert any("CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries)


def test_baselines_complete_legacy_first_cycle_schema_before_second_migration() -> None:
    # Given
    connection = _Connection(existing_tables=set(FIRST_CYCLE_TABLES))

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS
    assert connection.applied_migrations == set(MIGRATION_IDS)
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert any("CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries)
    assert any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert any("CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries)


def test_baselines_complete_docker_initdb_schema_without_reapplying_migrations() -> None:
    # Given
    connection = _Connection(
        input_identity_artifacts=(True,) * 6,
        existing_tables={
            *FIRST_CYCLE_TABLES,
            "fusion_stopping_traces",
            "decision_runtime_snapshots",
            "fusion_runtime_config_snapshots",
            "pipeline_runtime_status",
            "s3_object_receipts",
            "r1_archive_publications",
            "r1_stream_chunks",
            "r1_stream_watermarks",
            "r1_stream_run_closes",
            "r1_stream_events",
            "pipeline_telemetry_executions",
            "pipeline_telemetry_buckets",
        },
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == MIGRATION_IDS
    assert connection.applied_migrations == set(MIGRATION_IDS)
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
    )


def test_applies_telemetry_after_all_existing_migrations() -> None:
    # Given
    connection = _Connection(applied_migrations=set(MIGRATION_IDS[:-3]))

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == (
        "011_pipeline_telemetry_timeseries",
        "012_pipeline_telemetry_input_identity",
        "013_r1_stream_position_close_ledger",
    )
    assert any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries
    )
    assert apply_migrations(connection) == ()


def test_baselines_both_telemetry_tables_without_repeating_ddl() -> None:
    # Given
    connection = _Connection(
        applied_migrations=set(MIGRATION_IDS[:-3]),
        existing_tables={"pipeline_telemetry_executions", "pipeline_telemetry_buckets"},
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == (
        "011_pipeline_telemetry_timeseries",
        "012_pipeline_telemetry_input_identity",
        "013_r1_stream_position_close_ledger",
    )
    assert not any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
    )
    _assert_migration_lock_precedes_history_table(connection)


@pytest.mark.parametrize("table", ["pipeline_telemetry_executions", "pipeline_telemetry_buckets"])
def test_rejects_partial_telemetry_schema(table: str) -> None:
    # Given
    connection = _Connection(applied_migrations=set(MIGRATION_IDS[:-3]), existing_tables={table})

    # When
    with pytest.raises(RuntimeError, match="partial 011_pipeline_telemetry_timeseries schema"):
        apply_migrations(connection)

    # Then
    assert "011_pipeline_telemetry_timeseries" not in connection.applied_migrations
    assert not any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
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
    assert not any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries
    )


def test_first_cycle_compatibility_entry_point_only_applies_first_migration() -> None:
    # Given
    connection = _Connection()

    # When
    applied = apply_first_cycle_migration(connection)

    # Then
    assert applied is True
    assert connection.applied_migrations == {"001_first_cycle"}
    _assert_migration_lock_precedes_history_table(connection)
    assert not any(
        "CREATE TABLE fusion_stopping_traces" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE decision_runtime_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE fusion_runtime_config_snapshots" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_runtime_status" in query for query, _ in connection.queries
    )
    assert not any(
        "CREATE TABLE pipeline_telemetry_executions" in query for query, _ in connection.queries
    )


def test_main_uses_connection_managed_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _ContextConnection(applied_migrations=set(MIGRATION_IDS))
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


def _assert_migration_lock_precedes_history_table(connection: _Connection) -> None:
    assert connection.queries[0] == (
        migrate._MIGRATION_ADVISORY_LOCK_SQL,
        (migrate._MIGRATION_ADVISORY_LOCK_KEY,),
    )
    assert "CREATE TABLE IF NOT EXISTS schema_migrations" in connection.queries[1][0]


def test_applies_the_position_close_ledger_after_the_event_time_ledger() -> None:
    # Given
    connection = _Connection(applied_migrations=set(MIGRATION_IDS[:-1]))

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("013_r1_stream_position_close_ledger",)
    assert any("CREATE TABLE r1_stream_position_closes" in query for query, _ in connection.queries)
    assert apply_migrations(connection) == ()


def test_baselines_an_existing_position_close_ledger_without_repeating_ddl() -> None:
    # Given
    connection = _Connection(
        applied_migrations=set(MIGRATION_IDS[:-1]),
        existing_tables={"r1_stream_position_closes"},
    )

    # When
    applied = apply_migrations(connection)

    # Then
    assert applied == ("013_r1_stream_position_close_ledger",)
    assert not any(
        "CREATE TABLE r1_stream_position_closes" in query for query, _ in connection.queries
    )
