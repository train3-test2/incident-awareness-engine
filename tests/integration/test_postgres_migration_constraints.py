import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from queue import Queue
from threading import Barrier
from time import monotonic, sleep
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.errors import CheckViolation
from psycopg.types.json import Jsonb

from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import (
    _MIGRATION_ADVISORY_LOCK_KEY,
    _MIGRATION_ADVISORY_LOCK_SQL,
    apply_migrations,
)

FIRST_MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "001_first_cycle.sql"
)
SECOND_MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "002_fusion_stopping_trace.sql"
)
THIRD_MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "003_decision_runtime_snapshot.sql"
)
RUN_ID = "RUN-20260912-998"
EVENT_ID = "evt-001"
ENTITY_ID = "WIN-01"
DECISION_ID = "DEC-001"
SNAPSHOT_DECISION_ID = "DEC-SNAPSHOT-001"
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
        connection.execute(FIRST_MIGRATION_PATH.read_text(encoding="utf-8"))
        connection.execute(SECOND_MIGRATION_PATH.read_text(encoding="utf-8"))
        connection.execute(THIRD_MIGRATION_PATH.read_text(encoding="utf-8"))
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
        connection.execute(
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
            (
                SNAPSHOT_DECISION_ID,
                RUN_ID,
                ENTITY_ID,
                "miss",
                "miss",
                Jsonb(
                    {
                        "decision_id": SNAPSHOT_DECISION_ID,
                        "run_id": RUN_ID,
                        "entity_id": ENTITY_ID,
                    }
                ),
            ),
        )
        connection.commit()
        yield connection
    finally:
        connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
        connection.commit()
        connection.close()


def test_baselines_migrations_applied_by_docker_initdb(
    migration_connection: psycopg.Connection[tuple[object, ...]],
) -> None:
    # Given
    assert migration_connection.execute("SELECT to_regclass('schema_migrations')").fetchone() == (
        None,
    )

    # When
    applied = apply_migrations(migration_connection)

    # Then
    assert applied == (
        "001_first_cycle",
        "002_fusion_stopping_trace",
        "003_decision_runtime_snapshot",
    )
    migration_ids = migration_connection.execute(
        "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
    ).fetchall()
    assert migration_ids == [
        ("001_first_cycle",),
        ("002_fusion_stopping_trace",),
        ("003_decision_runtime_snapshot",),
    ]
    existing_tables = migration_connection.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name IN (
              'runs',
              'events',
              'fusion_results',
              'detection_results',
              'decisions',
              'fusion_stopping_traces',
              'decision_runtime_snapshots'
          )
        ORDER BY table_name
        """
    ).fetchall()
    assert existing_tables == [
        ("decision_runtime_snapshots",),
        ("decisions",),
        ("detection_results",),
        ("events",),
        ("fusion_results",),
        ("fusion_stopping_traces",),
        ("runs",),
    ]


def test_serializes_concurrent_migration_runners(database_url: str) -> None:
    # Given
    schema_name = f"migration_concurrency_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    worker_start = Barrier(3)
    worker_pid_queue: Queue[int] = Queue()
    setup_connection = psycopg.connect(database_url)

    try:
        setup_connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        setup_connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        setup_connection.execute(FIRST_MIGRATION_PATH.read_text(encoding="utf-8"))
        setup_connection.execute(
            """
            CREATE TABLE schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        setup_connection.execute(
            "INSERT INTO schema_migrations (migration_id) VALUES (%s)",
            ("001_first_cycle",),
        )
        setup_connection.commit()

        setup_connection.execute(
            _MIGRATION_ADVISORY_LOCK_SQL,
            (_MIGRATION_ADVISORY_LOCK_KEY,),
        )
        holder_pid_row = setup_connection.execute("SELECT pg_backend_pid()").fetchone()
        assert holder_pid_row is not None
        holder_pid = holder_pid_row[0]
        assert isinstance(holder_pid, int)

        def run_migrations() -> tuple[str, ...]:
            with psycopg.connect(database_url) as connection:
                connection.execute(sql.SQL("SET search_path TO {}").format(schema))
                worker_pid_row = connection.execute("SELECT pg_backend_pid()").fetchone()
                assert worker_pid_row is not None
                worker_pid = worker_pid_row[0]
                assert isinstance(worker_pid, int)
                worker_pid_queue.put(worker_pid)
                worker_start.wait(timeout=10)
                return apply_migrations(connection)

        # When
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run_migrations) for _ in range(2)]
            try:
                worker_start.wait(timeout=10)
                worker_pids = {worker_pid_queue.get(timeout=1) for _ in range(2)}
                assert len(worker_pids) == 2

                deadline = monotonic() + 10
                waiting_pids: set[int] = set()
                with psycopg.connect(database_url) as monitoring_connection:
                    while monotonic() < deadline:
                        waiting_rows = monitoring_connection.execute(
                            """
                            SELECT DISTINCT waiter.pid
                            FROM pg_locks AS holder
                            JOIN pg_locks AS waiter
                              ON waiter.locktype = holder.locktype
                             AND waiter.database IS NOT DISTINCT FROM holder.database
                             AND waiter.classid IS NOT DISTINCT FROM holder.classid
                             AND waiter.objid IS NOT DISTINCT FROM holder.objid
                             AND waiter.objsubid IS NOT DISTINCT FROM holder.objsubid
                            WHERE holder.pid = %s
                              AND holder.locktype = 'advisory'
                              AND holder.granted
                              AND waiter.pid IN (%s, %s)
                              AND NOT waiter.granted
                            """,
                            (holder_pid, *sorted(worker_pids)),
                        ).fetchall()
                        waiting_pids = {int(row[0]) for row in waiting_rows}
                        if waiting_pids == worker_pids:
                            break
                        sleep(0.05)
                    else:
                        pytest.fail(
                            "both migration workers did not wait on the holder advisory lock; "
                            f"expected={sorted(worker_pids)!r}, observed={sorted(waiting_pids)!r}"
                        )
            finally:
                setup_connection.commit()

            applied_results = [future.result(timeout=10) for future in futures]

        # Then
        assert sorted(applied_results, key=len) == [
            (),
            (
                "002_fusion_stopping_trace",
                "003_decision_runtime_snapshot",
            ),
        ]
        with psycopg.connect(database_url) as verification_connection:
            verification_connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            table_counts = verification_connection.execute(
                """
                SELECT table_name, count(*)
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name IN (
                      'fusion_stopping_traces',
                      'decision_runtime_snapshots'
                  )
                GROUP BY table_name
                ORDER BY table_name
                """
            ).fetchall()
            migration_counts = verification_connection.execute(
                """
                SELECT migration_id, count(*)
                FROM schema_migrations
                WHERE migration_id IN (%s, %s)
                GROUP BY migration_id
                ORDER BY migration_id
                """,
                (
                    "002_fusion_stopping_trace",
                    "003_decision_runtime_snapshot",
                ),
            ).fetchall()

        assert table_counts == [
            ("decision_runtime_snapshots", 1),
            ("fusion_stopping_traces", 1),
        ]
        assert migration_counts == [
            ("002_fusion_stopping_trace", 1),
            ("003_decision_runtime_snapshot", 1),
        ]
    finally:
        setup_connection.rollback()
        setup_connection.close()
        with psycopg.connect(database_url) as cleanup_connection:
            cleanup_connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))


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
        {
            "run_id": "RUN-20260912-997",
            "entity_id": ENTITY_ID,
            "scoring_config_version": "v1",
        },
        {
            "run_id": RUN_ID,
            "entity_id": "WIN-02",
            "scoring_config_version": "v1",
        },
        {
            "run_id": RUN_ID,
            "entity_id": ENTITY_ID,
            "scoring_config_version": "v2",
        },
    ],
    ids=("run-id-mismatch", "entity-id-mismatch", "config-version-mismatch"),
)
def test_fusion_stopping_traces_reject_payload_identifier_mismatch(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str],
) -> None:
    _assert_check_violation(
        migration_connection,
        """
        INSERT INTO fusion_stopping_traces (
            run_id,
            entity_id,
            scoring_config_version,
            payload
        )
        VALUES (%s, %s, %s, %s)
        """,
        (RUN_ID, ENTITY_ID, "v1", Jsonb(payload)),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": None, "run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": "DEC-OTHER", "run_id": RUN_ID, "entity_id": ENTITY_ID},
        {"decision_id": SNAPSHOT_DECISION_ID, "entity_id": ENTITY_ID},
        {"decision_id": SNAPSHOT_DECISION_ID, "run_id": None, "entity_id": ENTITY_ID},
        {
            "decision_id": SNAPSHOT_DECISION_ID,
            "run_id": "RUN-20260912-997",
            "entity_id": ENTITY_ID,
        },
        {"decision_id": SNAPSHOT_DECISION_ID, "run_id": RUN_ID},
        {"decision_id": SNAPSHOT_DECISION_ID, "run_id": RUN_ID, "entity_id": None},
        {"decision_id": SNAPSHOT_DECISION_ID, "run_id": RUN_ID, "entity_id": "WIN-02"},
    ],
    ids=(
        "decision-id-missing",
        "decision-id-null",
        "decision-id-mismatch",
        "run-id-missing",
        "run-id-null",
        "run-id-mismatch",
        "entity-id-missing",
        "entity-id-null",
        "entity-id-mismatch",
    ),
)
def test_decision_runtime_snapshots_reject_invalid_payload_identifiers(
    migration_connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, str | None],
) -> None:
    # Given
    statement = """
        INSERT INTO decision_runtime_snapshots (
            decision_id,
            run_id,
            entity_id,
            payload
        )
        VALUES (%s, %s, %s, %s)
        """
    parameters = (SNAPSHOT_DECISION_ID, RUN_ID, ENTITY_ID, Jsonb(payload))

    # When
    with pytest.raises(CheckViolation) as exc_info, migration_connection.transaction():
        migration_connection.execute(statement, parameters)

    # Then
    assert exc_info.type is CheckViolation


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
