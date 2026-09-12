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
EVENT_ID = "evt-001"
ENTITY_ID = "WIN-01"
DECISION_ID = "DEC-001"
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


@pytest.mark.parametrize(
    "payload",
    [
        {"run_id": RUN_ID},
        {"event_id": None, "run_id": RUN_ID},
        {"event_id": "evt-other", "run_id": RUN_ID},
        {"event_id": EVENT_ID},
        {"event_id": EVENT_ID, "run_id": None},
        {"event_id": EVENT_ID, "run_id": "RUN-20260912-997"},
    ],
    ids=(
        "event_id-missing",
        "event_id-null",
        "event_id-mismatch",
        "run_id-missing",
        "run_id-null",
        "run_id-mismatch",
    ),
)
def test_events_reject_invalid_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str | None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO events (event_id, run_id, timestamp, host_id, event_type, payload)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (EVENT_ID, RUN_ID, TIMESTAMP, ENTITY_ID, "process_create", Jsonb(payload)),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"entity_id": ENTITY_ID},
        {"run_id": None, "entity_id": ENTITY_ID},
        {"run_id": "RUN-20260912-997", "entity_id": ENTITY_ID},
        {"run_id": RUN_ID},
        {"run_id": RUN_ID, "entity_id": None},
        {"run_id": RUN_ID, "entity_id": "WIN-02"},
    ],
    ids=(
        "run_id-missing",
        "run_id-null",
        "run_id-mismatch",
        "entity_id-missing",
        "entity_id-null",
        "entity_id-mismatch",
    ),
)
def test_fusion_results_reject_invalid_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str | None],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO fusion_results (run_id, entity_id, fusion_status, fusion_time, payload)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (RUN_ID, ENTITY_ID, "miss", None, Jsonb(payload)),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"entity_id": ENTITY_ID},
        {"run_id": None, "entity_id": ENTITY_ID},
        {"run_id": "RUN-20260912-997", "entity_id": ENTITY_ID},
        {"run_id": RUN_ID},
        {"run_id": RUN_ID, "entity_id": None},
        {"run_id": RUN_ID, "entity_id": "WIN-02"},
    ],
    ids=(
        "run_id-missing",
        "run_id-null",
        "run_id-mismatch",
        "entity_id-missing",
        "entity_id-null",
        "entity_id-mismatch",
    ),
)
def test_detection_results_reject_invalid_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str | None],
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
        (RUN_ID, ENTITY_ID, "detected", TIMESTAMP, "hayabusa", Jsonb(payload)),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": None, "run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": "DEC-OTHER", "run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": DECISION_ID, "entity_id": ENTITY_ID},
        {"decision_id": DECISION_ID, "run_id": None, "entity_id": ENTITY_ID},
        {
            "decision_id": DECISION_ID,
            "run_id": "RUN-20260912-997",
            "entity_id": ENTITY_ID,
        },
        {"decision_id": DECISION_ID, "run_id": RUN_ID},
        {"decision_id": DECISION_ID, "run_id": RUN_ID, "entity_id": None},
        {"decision_id": DECISION_ID, "run_id": RUN_ID, "entity_id": "WIN-02"},
    ],
    ids=(
        "decision_id-missing",
        "decision_id-null",
        "decision_id-mismatch",
        "run_id-missing",
        "run_id-null",
        "run_id-mismatch",
        "entity_id-missing",
        "entity_id-null",
        "entity_id-mismatch",
    ),
)
def test_decisions_reject_invalid_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str | None],
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
        (DECISION_ID, RUN_ID, ENTITY_ID, "miss", "miss", Jsonb(payload)),
    )


@pytest.mark.parametrize(
    ("fast_status", "fusion_status", "detector_time", "fusion_time"),
    [
        ("detected", "miss", None, None),
        ("miss", "detected", None, None),
    ],
)
def test_decisions_reject_statuses_without_required_times(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    fast_status: str,
    fusion_status: str,
    detector_time: datetime | None,
    fusion_time: datetime | None,
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
            detector_time,
            fusion_time,
            payload
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            "DEC-002",
            RUN_ID,
            "WIN-01",
            fast_status,
            fusion_status,
            detector_time,
            fusion_time,
            Jsonb({"decision_id": "DEC-002", "run_id": RUN_ID, "entity_id": "WIN-01"}),
        ),
    )


def _assert_check_violation(
    connection: psycopg.Connection[tuple[object, ...]],
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    with pytest.raises(CheckViolation), connection.transaction():
        connection.execute(statement, parameters)
