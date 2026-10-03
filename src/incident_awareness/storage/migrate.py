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
