"""Apply versioned PostgreSQL migrations for the First Cycle runtime."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol

import psycopg

from incident_awareness.storage.config import DatabaseConfig

_LOGGER = logging.getLogger(__name__)
_FIRST_CYCLE_MIGRATION_ID = "001_first_cycle"
_MIGRATION_ADVISORY_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))"
_MIGRATION_ADVISORY_LOCK_KEY = "incident_awareness_engine:migrations"
_INPUT_IDENTITY_MIGRATION_ID = "012_pipeline_telemetry_input_identity"
_POSITION_CLOSE_MIGRATION_ID = "013_r1_stream_position_close_ledger"
# Table baselines cannot identify an ALTER migration. Require all 012 artifacts;
# partial columns/constraints/trigger must not be silently recorded as applied.
_INPUT_IDENTITY_BASELINE_SQL = """
SELECT
    EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pipeline_telemetry_executions')
            AND attname = 'input_identity_kind' AND NOT attisdropped),
    EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('pipeline_telemetry_executions')
            AND attname = 'input_identity_sha256' AND NOT attisdropped),
    EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = to_regclass('pipeline_telemetry_executions')
            AND conname = 'pipeline_telemetry_input_identity_pair' AND convalidated AND contype = 'c'),
    EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = to_regclass('pipeline_telemetry_executions')
            AND conname = 'pipeline_telemetry_input_identity_payload' AND convalidated AND contype = 'c'),
    to_regprocedure('guard_pipeline_telemetry_input_identity()') IS NOT NULL,
    EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = to_regclass('pipeline_telemetry_executions')
            AND tgname = 'pipeline_telemetry_input_identity_immutable'
            AND tgfoid = to_regprocedure('guard_pipeline_telemetry_input_identity()')
            AND NOT tgisinternal AND tgenabled = 'O')
"""
_POSITION_CLOSE_BASELINE_SQL = """
SELECT
    to_regclass('r1_stream_position_closes') IS NOT NULL,
    (SELECT COUNT(*) = 12 AND NOT EXISTS (
        SELECT 1
        FROM (VALUES
            ('ledger_entry_id', 'bigint', 'a'),
            ('run_id', 'text', ''),
            ('host_id', 'text', ''),
            ('source', 'text', ''),
            ('source_channel', 'text', ''),
            ('close_id', 'text', ''),
            ('content_sha256', 'text', ''),
            ('lower_record_id', 'bigint', ''),
            ('upper_record_id', 'bigint', ''),
            ('covered_through_chunk_sequence', 'integer', ''),
            ('covered_chunks_sha256', 'text', ''),
            ('accepted_at', 'timestamp with time zone', '')
        ) AS expected(attname, data_type, identity_kind)
        LEFT JOIN pg_attribute attribute
          ON attribute.attrelid = to_regclass('r1_stream_position_closes')
         AND attribute.attname = expected.attname
         AND NOT attribute.attisdropped
        WHERE attribute.attname IS NULL
           OR NOT attribute.attnotnull
           OR format_type(attribute.atttypid, attribute.atttypmod) <> expected.data_type
           OR attribute.attidentity::text <> expected.identity_kind
    ) FROM pg_attribute
       WHERE attrelid = to_regclass('r1_stream_position_closes')
         AND attnum > 0 AND NOT attisdropped),
    NOT EXISTS (
        SELECT 1
        FROM (VALUES
            ('r1_stream_position_closes_pkey', 'p'),
            ('r1_stream_position_closes_run_close_unique', 'u'),
            ('r1_stream_position_closes_run_unique', 'u'),
            ('r1_stream_position_closes_run_id_nonblank', 'c'),
            ('r1_stream_position_closes_host_id_nonblank', 'c'),
            ('r1_stream_position_closes_source_nonblank', 'c'),
            ('r1_stream_position_closes_source_channel_nonblank', 'c'),
            ('r1_stream_position_closes_close_id_nonblank', 'c'),
            ('r1_stream_position_closes_content_sha256_format', 'c'),
            ('r1_stream_position_closes_record_id_bounds', 'c'),
            ('r1_stream_position_closes_covered_sequence_positive', 'c'),
            ('r1_stream_position_closes_covered_chunks_sha256_format', 'c')
        ) AS expected(conname, contype)
        LEFT JOIN pg_constraint constraint_row
          ON constraint_row.conrelid = to_regclass('r1_stream_position_closes')
         AND constraint_row.conname = expected.conname
         AND constraint_row.contype::text = expected.contype
        WHERE constraint_row.oid IS NULL OR NOT constraint_row.convalidated
    ),
    to_regprocedure('reject_r1_stream_position_close_change()') IS NOT NULL,
    EXISTS (
        SELECT 1 FROM pg_proc
        WHERE oid = to_regprocedure('reject_r1_stream_position_close_change()')
          AND prosrc LIKE '%r1_stream_position_closes is append-only%'
    ),
    EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = to_regclass('r1_stream_position_closes')
          AND tgname = 'r1_stream_position_closes_append_only'
          AND tgfoid = to_regprocedure('reject_r1_stream_position_close_change()')
          AND NOT tgisinternal AND tgenabled = 'O'
    )
"""
_MIGRATION_BASELINE_TABLES = {
    _FIRST_CYCLE_MIGRATION_ID: frozenset(
        {
            "runs",
            "events",
            "fusion_results",
            "detection_results",
            "decisions",
        }
    ),
    "002_fusion_stopping_trace": frozenset({"fusion_stopping_traces"}),
    "003_decision_runtime_snapshot": frozenset({"decision_runtime_snapshots"}),
    "004_fusion_runtime_config_snapshot": frozenset({"fusion_runtime_config_snapshots"}),
    "005_pipeline_runtime_status": frozenset({"pipeline_runtime_status"}),
    "006_s3_object_receipts": frozenset({"s3_object_receipts"}),
    "007_r1_archive_publications": frozenset({"r1_archive_publications"}),
    "008_r1_stream_delivery_ledger": frozenset(
        {"r1_stream_chunks", "r1_stream_watermarks", "r1_stream_run_closes"}
    ),
    "009_r1_stream_close_watermark_binding": frozenset(),
    "010_r1_stream_event_delivery_ledger": frozenset({"r1_stream_events"}),
    "011_pipeline_telemetry_timeseries": frozenset(
        {"pipeline_telemetry_executions", "pipeline_telemetry_buckets"}
    ),
}
_MIGRATIONS_DIRECTORY = Path(__file__).resolve().parents[3] / "infra" / "postgres" / "migrations"


class MigrationCursor(Protocol):
    """Minimal query result surface used to identify an applied migration."""

    def fetchone(self) -> tuple[object, ...] | None: ...


class MigrationConnection(Protocol):
    """Minimal PostgreSQL connection surface required by the migration runner."""

    def execute(self, query: str, params: tuple[object, ...] = ()) -> MigrationCursor: ...


def apply_first_cycle_migration(connection: MigrationConnection) -> bool:
    """Apply the First Cycle schema once and return whether this call applied it."""
    return bool(_apply_migration_paths(connection, (_migration_path(),)))


def apply_migrations(connection: MigrationConnection) -> tuple[str, ...]:
    """Apply pending migrations in filename order and return their identifiers."""
    return _apply_migration_paths(connection, _migration_paths())


def _apply_migration_paths(
    connection: MigrationConnection,
    paths: tuple[Path, ...],
) -> tuple[str, ...]:
    connection.execute(
        _MIGRATION_ADVISORY_LOCK_SQL,
        (_MIGRATION_ADVISORY_LOCK_KEY,),
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    applied_migration_ids: list[str] = []

    for path in paths:
        migration_id = path.stem
        if _is_migration_applied(connection, migration_id):
            continue

        if migration_id == _INPUT_IDENTITY_MIGRATION_ID:
            artifacts = connection.execute(_INPUT_IDENTITY_BASELINE_SQL).fetchone()
            if artifacts is None:
                raise RuntimeError("PostgreSQL input identity baseline query returned no row")
            if any(artifacts):
                if not all(artifacts):
                    raise RuntimeError("partial 012 input identity schema cannot be baselined")
                _record_migration(connection, migration_id)
                applied_migration_ids.append(migration_id)
                continue

        if migration_id == _POSITION_CLOSE_MIGRATION_ID:
            artifacts = connection.execute(_POSITION_CLOSE_BASELINE_SQL).fetchone()
            if artifacts is None:
                raise RuntimeError("PostgreSQL position close baseline query returned no row")
            if any(artifacts):
                if not all(artifacts):
                    raise RuntimeError("partial 013 position close schema cannot be baselined")
                _record_migration(connection, migration_id)
                applied_migration_ids.append(migration_id)
                continue

        baseline_tables = _MIGRATION_BASELINE_TABLES.get(migration_id)
        if baseline_tables is not None:
            existing_tables = _existing_baseline_tables(connection, baseline_tables)
            if existing_tables:
                if existing_tables != baseline_tables:
                    missing_tables = sorted(baseline_tables - existing_tables)
                    migration_name = (
                        "First Cycle" if migration_id == _FIRST_CYCLE_MIGRATION_ID else migration_id
                    )
                    raise RuntimeError(
                        f"partial {migration_name} schema cannot be baselined; "
                        f"missing tables: {', '.join(missing_tables)}"
                    )

                _record_migration(connection, migration_id)
                applied_migration_ids.append(migration_id)
                continue

        connection.execute(path.read_text(encoding="utf-8"))
        _record_migration(connection, migration_id)
        applied_migration_ids.append(migration_id)

    return tuple(applied_migration_ids)


def _is_migration_applied(connection: MigrationConnection, migration_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM schema_migrations WHERE migration_id = %s",
            (migration_id,),
        ).fetchone()
        is not None
    )


def _existing_baseline_tables(
    connection: MigrationConnection,
    baseline_tables: frozenset[str],
) -> frozenset[str]:
    existing_tables: set[str] = set()

    for table_name in sorted(baseline_tables):
        row = connection.execute("SELECT to_regclass(%s)", (table_name,)).fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL to_regclass query returned no row")
        if row[0] is not None:
            existing_tables.add(table_name)

    return frozenset(existing_tables)


def _record_migration(connection: MigrationConnection, migration_id: str) -> None:
    connection.execute(
        "INSERT INTO schema_migrations (migration_id) VALUES (%s)",
        (migration_id,),
    )


def main() -> int:
    """Apply all pending migrations using the configured runtime database."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url, autocommit=False) as connection:
        applied = apply_migrations(connection)

    if applied:
        _LOGGER.info("Applied PostgreSQL migrations: %s", ", ".join(applied))
    else:
        _LOGGER.info("PostgreSQL migrations are already up to date")
    return 0


def _migration_path() -> Path:
    path = _MIGRATIONS_DIRECTORY / f"{_FIRST_CYCLE_MIGRATION_ID}.sql"
    if not path.is_file():
        raise FileNotFoundError(f"First Cycle migration is missing: {path}")
    return path


def _migration_paths() -> tuple[Path, ...]:
    paths = tuple(sorted(_MIGRATIONS_DIRECTORY.glob("[0-9][0-9][0-9]_*.sql")))
    if not paths:
        raise FileNotFoundError(f"PostgreSQL migrations are missing: {_MIGRATIONS_DIRECTORY}")
    return paths


if __name__ == "__main__":
    raise SystemExit(main())
