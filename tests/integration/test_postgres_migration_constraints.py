import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.errors import CheckViolation
from psycopg.types.json import Jsonb

from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "001_first_cycle.sql"
)
RUN_ID = "RUN-20260912-998"
TIMESTAMP = datetime(2026, 9, 12, 1, tzinfo=UTC)


@pytest.fixture
def database_url() -> str:
    if DATABASE_URL_ENV not in os.environ:
        pytest.skip(f"{DATABASE_URL_ENV}가 설정된 PostgreSQL에서만 실행합니다.")

    return DatabaseConfig.from_environment().url


@pytest.fixture
def migration_connection(database_url: str) -> psycopg.Connection[tuple[object, ...]]:
    schema_name = f"migration_constraint_{uuid4().hex}"
    connection = psycopg.connect(database_url)
    schema = sql.Identifier(schema_name)

    try:
        connection.execute(sql.SQL("CREATE SCHEMA {} ").format(schema))
        connection.execute(sql.SQL("SET search_path TO {} ").format(schema))
        connection.execute(MIGRATION_PATH.read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO runs (
                run_id,
                scenario_id,
                run_type,
                target_host,
                start_time,
                metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                RUN_ID,
                "migration-constraint-test",
                "attack",
                "WIN-01",
                TIMESTAMP,
                Jsonb({"run_id": RUN_ID}),
            ),
        )
        connection.commit()
        yield connection
    finally:
        connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
        connection.commit()
        connection.close()


@pytest.mark.parametrize("payload", [{}, {"event_id": None, "run_id": None}])
def test_events_reject_missing_or_null_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO events (event_id, run_id, timestamp, host_id, event_type, payload)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        ("evt-001", RUN_ID, TIMESTAMP, "WIN-01", "process_create", Jsonb(payload)),
    )


@pytest.mark.parametrize("payload", [{}, {"run_id": None, "entity_id": None}])
def test_fusion_results_reject_missing_or_null_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO fusion_results (run_id, entity_id, fusion_status, fusion_time, payload)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (RUN_ID, "WIN-01", "miss", None, Jsonb(payload)),
    )


@pytest.mark.parametrize("payload", [{}, {"run_id": None, "entity_id": None}])
def test_detection_results_reject_missing_or_null_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO detection_results (
            run_id,
            entity_id,
            detector_status,
            detector_time,
            detector_id,
            payload
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (RUN_ID, "WIN-01", "detected", TIMESTAMP, "hayabusa", Jsonb(payload)),
    )


@pytest.mark.parametrize(
    "payload",
    [{}, {"decision_id": None, "run_id": None, "entity_id": None}],
)
def test_decisions_reject_missing_or_null_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO decisions (
            decision_id,
            run_id,
            entity_id,
            fast_status,
            fusion_status,
            payload
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        ("DEC-001", RUN_ID, "WIN-01", "miss", "miss", Jsonb(payload)),
    )


def _assert_check_violation(
    connection: psycopg.Connection[tuple[object, ...]],
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    with pytest.raises(CheckViolation), connection.transaction():
        connection.execute(statement, parameters)
