"""Apply versioned PostgreSQL migrations for the First Cycle runtime."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol

import psycopg

from incident_awareness.storage.config import DatabaseConfig

_LOGGER = logging.getLogger(__name__)
_FIRST_CYCLE_MIGRATION_ID = "001_first_cycle"
_MIGRATIONS_DIRECTORY = Path(__file__).resolve().parents[3] / "infra" / "postgres" / "migrations"


class MigrationCursor(Protocol):
    """Minimal query result surface used to identify an applied migration."""

    def fetchone(self) -> tuple[object, ...] | None: ...


class MigrationConnection(Protocol):
    """Minimal PostgreSQL connection surface required by the migration runner."""

    def execute(self, query: str, params: tuple[object, ...] = ()) -> MigrationCursor: ...


def apply_first_cycle_migration(connection: MigrationConnection) -> bool:
    """Apply the First Cycle schema once and return whether this call applied it."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    applied = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE migration_id = %s",
        (_FIRST_CYCLE_MIGRATION_ID,),
    ).fetchone()
    if applied is not None:
        return False

    migration = _migration_path().read_text(encoding="utf-8")
    connection.execute(migration)
    connection.execute(
        "INSERT INTO schema_migrations (migration_id) VALUES (%s)",
        (_FIRST_CYCLE_MIGRATION_ID,),
    )
    return True


def main() -> int:
    """Apply the First Cycle migration using the configured runtime database."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url, autocommit=False) as connection:
        applied = apply_first_cycle_migration(connection)

    if applied:
        _LOGGER.info("Applied PostgreSQL migration: %s", _FIRST_CYCLE_MIGRATION_ID)
    else:
        _LOGGER.info("PostgreSQL migration already applied: %s", _FIRST_CYCLE_MIGRATION_ID)
    return 0


def _migration_path() -> Path:
    path = _MIGRATIONS_DIRECTORY / f"{_FIRST_CYCLE_MIGRATION_ID}.sql"
    if not path.is_file():
        raise FileNotFoundError(f"First Cycle migration is missing: {path}")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
