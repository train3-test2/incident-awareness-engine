import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from threading import Barrier
from time import monotonic, sleep
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.errors import CheckViolation, ForeignKeyViolation, RaiseException
from psycopg.types.json import Jsonb

from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetryInputIdentity,
    PipelineTelemetrySnapshot,
    TelemetryObservationIssue,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_telemetry_reader
from incident_awareness.dashboard.telemetry_read_model import (
    DashboardTelemetryReader,
    TelemetryQuery,
)
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector
from incident_awareness.storage import migrate
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.repositories import (
    pipeline_telemetry_repository as repository_module,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryIntegrityError,
    PipelineTelemetryRepository,
)

START = datetime(2026, 10, 14, 1, tzinfo=UTC)
MIGRATIONS = tuple(
    sorted(
        (Path(__file__).resolve().parents[2] / "infra/postgres/migrations").glob(
            "[0-9][0-9][0-9]_*.sql"
        )
    )
)


@pytest.fixture
def database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for real PostgreSQL telemetry tests")
    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})
    database_name = unquote(urlparse(url).path).strip("/").lower()
    if (
        "test" not in database_name
        and os.environ.get("INCIDENT_AWARENESS_TEST_DATABASE", "").lower() != "true"
    ):
        pytest.skip("a test database or INCIDENT_AWARENESS_TEST_DATABASE=true is required")
    return url


@pytest.fixture
def schema_connection(database_url: str) -> Iterator[psycopg.Connection]:
    schema = sql.Identifier(f"telemetry_test_{uuid4().hex}")
    connection = psycopg.connect(database_url, autocommit=False, connect_timeout=2)
    try:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        connection.commit()
        yield connection
    finally:
        connection.rollback()
        connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
        connection.commit()
        connection.close()


@pytest.fixture
def connection(schema_connection: psycopg.Connection) -> psycopg.Connection:
    migrate.apply_migrations(schema_connection)
    schema_connection.commit()
    return schema_connection


def _snapshots(
    execution_id: str = "execution-001", entity_id: str = "WIN-01"
) -> tuple[PipelineTelemetrySnapshot, ...]:
    wall, elapsed = [START], [0]
    collector = PipelineTelemetryCollector(
        execution_id=execution_id,
        run_id="RUN-20261014-001",
        entity_id=entity_id,
        input_identity=PipelineTelemetryInputIdentity(
            kind="file_content_sha256_v1", sha256="a" * 64
        ),
        clock=lambda: wall[0],
        monotonic_clock=lambda: elapsed[0],
    )
    empty = collector.snapshot()
    collector.accept_batch(3)
    admitted = collector.snapshot()
    with collector.measure_record(1):
        elapsed[0] = 7
    first = collector.snapshot()
    with collector.measure_record(2):
        wall[0] += timedelta(seconds=20)
        elapsed[0] = 30
    return empty, admitted, first, collector.snapshot()


def _read_telemetry(connection: psycopg.Connection, *, end: datetime | None = None, **scope: str):
    end = end or START + timedelta(seconds=21)
    return DashboardTelemetryReader(
        PipelineTelemetryRepository(connection), clock=lambda: end + timedelta(milliseconds=500)
    ).get_telemetry(TelemetryQuery(**scope))


def test_postgres_read_api_uses_saved_revision_without_duplicates(
    connection: psycopg.Connection,
) -> None:
    # Given
    _, admitted, _, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)
    connection.commit()

    # When
    before = _read_telemetry(connection, scope="execution", execution_id=latest.execution_id)
    repository.save_snapshot(latest)
    connection.commit()
    repository.save_snapshot(latest)  # Revision-idempotent retry.
    connection.commit()
    after = _read_telemetry(connection, scope="execution", execution_id=latest.execution_id)

    # Then
    assert before.recent_60s_summary.processing_completed_count == 0
    assert after.recent_60s_summary.input_accepted_count == 3
    assert after.recent_60s_summary.processing_completed_count == 2
    assert after.recent_60s_summary.processing_latency_sum_ns == 30
    assert after.recent_60s_summary.processing_latency_sample_count == 2
    assert after.recent_60s_summary.processing_latency_mean_ms == 0.000015
    assert len(after.points) == 2
    assert after.persisted_at is not None


def test_postgres_multiple_attempts_entities_and_reported_scope(
    connection: psycopg.Connection,
) -> None:
    # Given
    repository = PipelineTelemetryRepository(connection)
    for execution_id, entity in (
        ("attempt-A", "WIN-A"),
        ("attempt-B", "WIN-A"),
        ("attempt-C", "WIN-B"),
    ):
        repository.save_snapshot(_snapshots(execution_id, entity)[-1])
    connection.commit()

    # When
    run = _read_telemetry(connection, scope="run", run_id="RUN-20261014-001")
    entity = _read_telemetry(connection, scope="run", run_id="RUN-20261014-001", entity_id="WIN-A")
    reported = _read_telemetry(connection, scope="reported")

    # Then
    assert run.executions_count == reported.executions_count == 3
    assert run.points == reported.points
    assert run.recent_60s_summary.processing_completed_count == 6
    assert entity.executions_count == 2
    assert entity.recent_60s_summary.processing_completed_count == 4
    assert [point.executions_count for point in reported.points] == [3, 3]
    assert reported.recent_60s_summary.input_accepted_count == 9


def test_postgres_completed_300_and_60_second_boundaries_exclude_current_bucket(
    connection: psycopg.Connection,
) -> None:
    # Given
    wall = [START - timedelta(seconds=1)]
    collector = PipelineTelemetryCollector(
        execution_id="boundary",
        run_id="RUN-BOUNDARY",
        entity_id="WIN-A",
        clock=lambda: wall[0],
        monotonic_clock=lambda: 0,
    )
    collector.accept_batch(4)
    for ordinal, second in enumerate((0, 239, 240, 300), 1):
        wall[0] = START + timedelta(seconds=second)
        with collector.measure_record(ordinal):
            pass
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(collector.snapshot())
    connection.commit()
    end = START + timedelta(seconds=300)

    # When
    result = _read_telemetry(connection, end=end, scope="execution", execution_id="boundary")

    # Then
    assert [point.bucket_start for point in result.points] == [
        START,
        START + timedelta(seconds=239),
        START + timedelta(seconds=240),
    ]
    assert result.recent_60s_summary.processing_completed_count == 1
    assert result.recent_60s_summary.processing_latency_sample_count == 1
    assert result.recent_60s_summary.processing_latency_mean_ms == 0.0  # Actual measured zero.
    assert result.recent_60s_summary.missing_bucket_count == 59
    assert result.range_start == START


def test_postgres_reported_does_not_include_out_of_range_or_unobserved_executions(
    connection: psycopg.Connection,
) -> None:
    # Given
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(_snapshots("old")[-1])
    repository.save_snapshot(_snapshots("unobserved")[0])
    connection.commit()

    # When
    reported = _read_telemetry(connection, end=START + timedelta(hours=1), scope="reported")
    run = _read_telemetry(
        connection, end=START + timedelta(hours=1), scope="run", run_id="RUN-20261014-001"
    )

    # Then
    assert reported.points == ()
    assert reported.executions_count == 0
    assert reported.recent_60s_summary.input_accepted_count is None
    assert run.executions_count == 2
    assert run.observation_quality.unavailable_executions == 1
    assert run.freshness.status == "stale"
    assert run.freshness.process_liveness == "unknown"


def test_postgres_quality_and_record_failures_do_not_become_successful_latency(
    connection: psycopg.Connection,
) -> None:
    # Given
    collector = PipelineTelemetryCollector(
        execution_id="failed-collection",
        run_id="RUN-A",
        entity_id="WIN-A",
        clock=lambda: START,
        monotonic_clock=lambda: 7,
    )
    collector.accept_batch(2)
    token = collector.begin_record(1)
    collector.record_failure(token)
    collector.mark_observation_issue(TelemetryObservationIssue.BUFFER_LIMIT, disable=True)
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(collector.snapshot())
    connection.commit()

    # When
    result = _read_telemetry(connection, scope="execution", execution_id="failed-collection")

    # Then
    assert result.recent_60s_summary.processing_failed_count == 1
    assert result.recent_60s_summary.processing_completed_count == 0
    assert result.recent_60s_summary.processing_latency_mean_ms is None
    assert result.observation_quality.status == "partial"
    assert result.observation_quality.observation_issues == (
        TelemetryObservationIssue.BUFFER_LIMIT,
    )
    assert result.observation_quality.disabled_executions == 1


def test_postgres_reader_sees_committed_snapshot_metadata_and_buckets_together(
    connection: psycopg.Connection, database_url: str
) -> None:
    # Given
    _, admitted, _, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)
    connection.commit()
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    repository.save_snapshot(latest)  # Both metadata and bucket writes still uncommitted.

    # When
    with psycopg.connect(database_url, autocommit=False) as reader_connection:
        reader_connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        before = _read_telemetry(
            reader_connection, scope="execution", execution_id=latest.execution_id
        )
        connection.commit()
        after = _read_telemetry(
            reader_connection, scope="execution", execution_id=latest.execution_id
        )

    # Then
    assert before.last_observed_at == admitted.last_observed_at
    assert before.recent_60s_summary.processing_completed_count == 0
    assert after.last_observed_at == latest.last_observed_at
    assert after.recent_60s_summary.processing_completed_count == 2
    assert after.recent_60s_summary.processing_latency_sum_ns == 30


def test_postgres_http_response_reads_real_saved_snapshot_in_read_only_transaction(
    connection: psycopg.Connection,
) -> None:
    # Given
    snapshot = _snapshots()[-1]
    PipelineTelemetryRepository(connection).save_snapshot(snapshot)
    connection.commit()
    connection.execute("SET TRANSACTION READ ONLY")
    reader = DashboardTelemetryReader(
        PipelineTelemetryRepository(connection), clock=lambda: START + timedelta(seconds=21)
    )
    app = create_app()
    app.dependency_overrides[get_dashboard_telemetry_reader] = lambda: reader

    # When
    with TestClient(app) as client:
        response = client.get(
            "/operations/telemetry",
            params={
                "scope": "execution",
                "execution_id": snapshot.execution_id,
                "end_at": "2026-10-14T01:00:21.000Z",
            },
        )

    # Then
    assert response.status_code == 200
    assert response.json()["recent_60s_summary"]["processing_completed_count"] == 2
    assert response.json()["last_observed_at"] == "2026-10-14T01:00:20.000Z"
    assert response.json()["observation_quality"]["continuous_coverage"] is False


def test_postgres_worker_latency_is_weighted_by_actual_samples(
    connection: psycopg.Connection,
) -> None:
    # Given
    repository = PipelineTelemetryRepository(connection)
    for execution, durations in (("worker-A", (500_000, 500_000)), ("worker-B", (2_000_000,))):
        elapsed = [0]
        collector = PipelineTelemetryCollector(
            execution_id=execution,
            run_id="RUN-WORKERS",
            entity_id="WIN-A",
            input_identity=PipelineTelemetryInputIdentity(
                kind="file_content_sha256_v1", sha256="a" * 64
            ),
            clock=lambda: START,
            monotonic_clock=lambda elapsed=elapsed: elapsed[0],
        )
        collector.accept_batch(len(durations))
        for ordinal, duration in enumerate(durations, 1):
            with collector.measure_record(ordinal):
                elapsed[0] += duration
        repository.save_snapshot(collector.snapshot())
    connection.commit()

    # When
    response = _read_telemetry(connection, scope="run", run_id="RUN-WORKERS")

    # Then
    assert response.recent_60s_summary.processing_latency_sample_count == 3
    assert response.recent_60s_summary.processing_latency_sum_ns == 3_000_000
    assert response.recent_60s_summary.processing_latency_mean_ms == 1.0
    assert response.points[0].processing_latency_mean_ms == 1.0


def test_postgres_read_is_utc_even_when_session_timezone_is_not_utc(
    connection: psycopg.Connection,
) -> None:
    # Given
    snapshot = _snapshots()[-1]
    PipelineTelemetryRepository(connection).save_snapshot(snapshot)
    connection.commit()
    connection.execute("SET LOCAL TIME ZONE 'Asia/Seoul'")

    # When
    result = _read_telemetry(connection, scope="execution", execution_id=snapshot.execution_id)

    # Then
    assert result.last_observed_at == snapshot.last_observed_at
    assert result.points[0].bucket_start == START
    assert result.persisted_at.utcoffset() == timedelta(0)
    assert result.model_dump(mode="json")["points"][0]["bucket_start"] == "2026-10-14T01:00:00.000Z"


def test_postgres_snapshot_round_trip_and_retry_are_exact(connection: psycopg.Connection) -> None:
    # Given
    snapshot = _snapshots()[-1]
    repository = PipelineTelemetryRepository(connection)

    # When
    saved = repository.save_snapshot(snapshot)
    connection.commit()
    repeated = repository.save_snapshot(snapshot)
    restored = repository.get_execution(snapshot.execution_id)
    buckets = repository.list_buckets(snapshot.execution_id)

    # Then
    assert saved and not repeated
    assert restored == snapshot
    assert buckets == list(snapshot.buckets)
    assert sum(bucket.processing_completed_count for bucket in buckets) == 2
    assert sum(bucket.latency_sum_ns for bucket in buckets) == 30
    assert connection.execute("SELECT count(*) FROM runs").fetchone() == (0,)


def test_postgres_revisions_and_sparse_time_query(connection: psycopg.Connection) -> None:
    # Given
    _, admitted, first, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)

    # When
    repository.save_snapshot(first)
    repository.save_snapshot(latest)
    stale = repository.save_snapshot(admitted)
    gap = repository.list_buckets(
        latest.execution_id, start=START + timedelta(seconds=1), end=START + timedelta(seconds=20)
    )
    final_bucket = repository.list_buckets(
        latest.execution_id, start=START + timedelta(seconds=20), end=START + timedelta(seconds=21)
    )

    # Then
    assert not stale
    assert repository.get_execution(latest.execution_id) == latest
    assert gap == []
    assert final_bucket == [latest.buckets[-1]]
    assert connection.execute("SELECT count(*) FROM pipeline_telemetry_buckets").fetchone() == (2,)


@pytest.mark.parametrize("bucket_conflict", [False, True])
def test_postgres_same_revision_conflicts_are_atomic(
    connection: psycopg.Connection, bucket_conflict: bool
) -> None:
    # Given
    original = _snapshots()[2]
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(original)
    connection.commit()
    values = original.model_dump()
    values["buckets"][0]["latency_sum_ns"] += 1
    if bucket_conflict:
        values["revision"] += 1
    conflict = PipelineTelemetrySnapshot.model_validate(values)

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="revision"):
        repository.save_snapshot(conflict)
    connection.commit()

    # Then
    assert repository.get_execution(original.execution_id) == original


def test_postgres_quality_and_unavailable_snapshots_preserve_missing_data(
    connection: psycopg.Connection,
) -> None:
    # Given
    empty, admitted, _, _ = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(empty)
    empty_restored = repository.get_execution(empty.execution_id)
    partial = admitted.model_copy(
        update={
            "revision": 2,
            "observation_status": "partial",
            "observation_issues": (TelemetryObservationIssue.INTERNAL_ERROR,),
            "collection_disabled": True,
        }
    )

    # When
    repository.save_snapshot(partial)
    restored = repository.get_execution(partial.execution_id)

    # Then
    assert empty_restored == empty
    assert empty_restored.buckets == ()
    assert restored == partial
    assert restored.buckets[0].revision == admitted.buckets[0].revision
    assert restored.collection_disabled


def test_postgres_same_run_keeps_execution_and_entity_scopes_separate(
    connection: psycopg.Connection,
) -> None:
    # Given
    repository = PipelineTelemetryRepository(connection)
    snapshots = [_snapshots("first")[-1], _snapshots("retry")[1], _snapshots("other", "WIN-02")[2]]

    # When
    for snapshot in snapshots:
        repository.save_snapshot(snapshot)

    # Then
    assert {
        item.execution_id for item in repository.list_executions("RUN-20261014-001", "WIN-01")
    } == {"first", "retry"}
    for snapshot in snapshots:
        assert repository.get_execution(snapshot.execution_id) == snapshot
        assert repository.list_buckets(snapshot.execution_id) == list(snapshot.buckets)
    assert repository.get_execution("missing") is None


def test_postgres_second_bucket_failure_rolls_back_all_writes_and_allows_retry(
    connection: psycopg.Connection,
) -> None:
    # Given
    _, admitted, _, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)
    connection.execute("""
        CREATE FUNCTION reject_later_bucket() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.bucket_start >= '2026-10-14T01:00:20Z'::timestamptz THEN
                RAISE EXCEPTION 'injected second-bucket write failure';
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER reject_later_bucket BEFORE INSERT OR UPDATE
        ON pipeline_telemetry_buckets FOR EACH ROW EXECUTE FUNCTION reject_later_bucket();
    """)
    connection.commit()

    # When
    with pytest.raises(RaiseException, match="second-bucket write failure"):
        repository.save_snapshot(latest)
    rolled_back = repository.get_execution(latest.execution_id)
    connection.execute("DROP TRIGGER reject_later_bucket ON pipeline_telemetry_buckets")
    repository.save_snapshot(latest)
    connection.commit()

    # Then
    assert rolled_back == admitted
    assert repository.get_execution(latest.execution_id) == latest


def test_postgres_save_leaves_commit_and_rollback_to_caller(connection: psycopg.Connection) -> None:
    # Given
    snapshot = _snapshots()[-1]
    repository = PipelineTelemetryRepository(connection)

    # When
    repository.save_snapshot(snapshot)
    connection.rollback()
    rolled_back = repository.get_execution(snapshot.execution_id)
    repository.save_snapshot(snapshot)
    connection.commit()

    # Then
    assert rolled_back is None
    assert repository.get_execution(snapshot.execution_id) == snapshot


@pytest.mark.parametrize("race", ["identical", "newer", "conflict", "input_identity"])
@pytest.mark.parametrize("existing_execution", [False, True])
def test_postgres_serializes_snapshot_revision_races(
    connection: psycopg.Connection, database_url: str, race: str, existing_execution: bool
) -> None:
    # Given
    _, admitted, first, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    if existing_execution:
        repository.save_snapshot(admitted)
    schema_name = connection.execute("SELECT current_schema()").fetchone()[0]
    connection.commit()  # Publish setup before workers start.
    candidates = [first, first if race == "identical" else latest]
    if race == "conflict":
        values = first.model_dump()
        values["buckets"][0]["latency_sum_ns"] += 1
        candidates[1] = PipelineTelemetrySnapshot.model_validate(values)
    elif race == "input_identity":
        candidates[1] = latest.model_copy(
            update={
                "input_identity": PipelineTelemetryInputIdentity(
                    kind="s3_object_sha256_v1", sha256="b" * 64
                )
            }
        )
    start = Barrier(3)
    pids: Queue[int] = Queue()
    connection.execute(
        repository_module._TELEMETRY_ADVISORY_LOCK_SQL,
        (repository_module._telemetry_lock_key(first.execution_id),),
    )
    holder_pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]

    def save(candidate: PipelineTelemetrySnapshot) -> bool | str:
        with psycopg.connect(database_url, autocommit=False, connect_timeout=2) as worker:
            worker.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name)))
            worker.execute("SET statement_timeout = '10s'")
            pids.put(worker.execute("SELECT pg_backend_pid()").fetchone()[0])
            start.wait(timeout=5)
            try:
                return PipelineTelemetryRepository(worker).save_snapshot(candidate)
            except PipelineTelemetryIntegrityError:
                return "conflict"

    # When
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(save, candidate) for candidate in candidates]
        try:
            start.wait(timeout=5)
            worker_pids = {pids.get(timeout=1) for _ in range(2)}
            assert len(worker_pids) == 2
            deadline = monotonic() + 5
            with psycopg.connect(database_url, connect_timeout=2) as monitor:
                while monotonic() < deadline:
                    rows = monitor.execute(
                        """
                        SELECT DISTINCT waiter.pid
                        FROM pg_locks holder JOIN pg_locks waiter
                          ON waiter.database IS NOT DISTINCT FROM holder.database
                         AND waiter.classid = holder.classid
                         AND waiter.objid = holder.objid
                         AND waiter.objsubid = holder.objsubid
                        WHERE holder.pid = %s AND holder.locktype = 'advisory' AND holder.granted
                          AND waiter.locktype = 'advisory' AND NOT waiter.granted
                          AND waiter.pid IN (%s, %s)
                    """,
                        (holder_pid, *sorted(worker_pids)),
                    ).fetchall()
                    if {row[0] for row in rows} == worker_pids:
                        break
                    sleep(0.05)
                else:
                    pytest.fail(
                        "both telemetry writers must wait on the same execution advisory lock"
                    )
        finally:
            connection.commit()  # Release even on assertion failure; never strand workers.
        results = [future.result(timeout=12) for future in futures]

    # Then
    restored = repository.get_execution(first.execution_id)
    if race == "identical":
        assert sorted(results) == [False, True]
        assert restored == first
    elif race == "newer":
        assert results[1] is True
        assert restored == latest
    else:
        assert results.count(True) == results.count("conflict") == 1
        assert restored in candidates
    assert len(repository.list_buckets(first.execution_id)) == len(restored.buckets)


def test_postgres_reader_sees_only_whole_committed_snapshots(
    connection: psycopg.Connection, database_url: str
) -> None:
    # Given
    _, admitted, _, latest = _snapshots()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)
    schema_name = connection.execute("SELECT current_schema()").fetchone()[0]
    connection.commit()

    # When
    repository.save_snapshot(latest)
    with psycopg.connect(database_url, connect_timeout=2) as reader_connection:
        reader_connection.execute(
            sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name))
        )
        reader = PipelineTelemetryRepository(reader_connection)
        before_commit = reader.get_execution(latest.execution_id)
        connection.commit()
        after_commit = reader.get_execution(latest.execution_id)

    # Then
    assert before_commit == admitted
    assert after_commit == latest


@pytest.mark.parametrize(
    "field,value",
    [
        ("processing_completed_count", -1),
        ("latency_sample_count", 1),
        ("latency_sum_ns", 1),
        ("bucket_start", START + timedelta(milliseconds=1)),
        ("bucket_end", START + timedelta(seconds=2)),
        ("last_observed_at", START + timedelta(seconds=1)),
        ("first_observed_at", START + timedelta(microseconds=1)),
    ],
)
def test_postgres_bucket_constraints_reject_invalid_raw_rows(
    connection: psycopg.Connection, field: str, value: object
) -> None:
    # Given
    admitted = _snapshots()[1]
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(admitted)
    payload = admitted.buckets[0].model_dump(mode="json")
    payload[field] = value.isoformat() if isinstance(value, datetime) else value
    query = sql.SQL(
        "UPDATE pipeline_telemetry_buckets SET {} = %s, payload = %s WHERE execution_id = %s"
    ).format(sql.Identifier(field))

    # When
    with pytest.raises(CheckViolation), connection.transaction():
        connection.execute(query, (value, Jsonb(payload), admitted.execution_id))

    # Then
    assert repository.get_execution(admitted.execution_id) == admitted


def test_postgres_bucket_requires_telemetry_execution_not_business_run(
    connection: psycopg.Connection,
) -> None:
    # Given
    bucket = _snapshots()[1].buckets[0]

    # When
    with pytest.raises(ForeignKeyViolation), connection.transaction():
        connection.execute(
            repository_module._UPSERT_BUCKET,
            (
                "missing-execution",
                bucket.bucket_start,
                bucket.bucket_end,
                bucket.revision,
                bucket.input_accepted_count,
                bucket.processing_completed_count,
                bucket.processing_failed_count,
                bucket.latency_sample_count,
                bucket.latency_sum_ns,
                bucket.first_observed_at,
                bucket.last_observed_at,
                Jsonb(bucket.model_dump(mode="json")),
            ),
        )

    # Then
    assert connection.execute("SELECT count(*) FROM pipeline_telemetry_buckets").fetchone() == (0,)


def test_postgres_migration_fresh_database_and_reexecution(
    schema_connection: psycopg.Connection,
) -> None:
    # Given
    connection = schema_connection

    # When
    applied = migrate.apply_migrations(connection)
    connection.commit()
    reapplied = migrate.apply_migrations(connection)

    # Then
    assert applied == tuple(path.stem for path in MIGRATIONS)
    assert reapplied == ()
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations WHERE migration_id = '011_pipeline_telemetry_timeseries'"
    ).fetchone() == (1,)


def test_postgres_migration_existing_database_preserves_runtime_table(
    schema_connection: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    connection = schema_connection
    with monkeypatch.context() as context:
        context.setattr(migrate, "_migration_paths", lambda: MIGRATIONS[:10])
        migrate.apply_migrations(connection)
    original_oid = connection.execute("SELECT 'pipeline_runtime_status'::regclass::oid").fetchone()[
        0
    ]
    connection.commit()

    # When
    applied = migrate.apply_migrations(connection)

    # Then
    assert applied == tuple(path.stem for path in MIGRATIONS[10:])
    assert connection.execute("SELECT 'pipeline_runtime_status'::regclass::oid").fetchone() == (
        original_oid,
    )


def test_postgres_migration_baselines_already_initialized_telemetry_tables(
    schema_connection: psycopg.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = schema_connection
    with monkeypatch.context() as context:
        context.setattr(migrate, "_migration_paths", lambda: MIGRATIONS[:10])
        migrate.apply_migrations(connection)
    connection.execute(MIGRATIONS[10].read_text(encoding="utf-8"))
    original = connection.execute(
        "SELECT 'pipeline_telemetry_executions'::regclass::oid, 'pipeline_telemetry_buckets'::regclass::oid"
    ).fetchone()
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations WHERE migration_id = '011_pipeline_telemetry_timeseries'"
    ).fetchone() == (0,)

    # When
    applied = migrate.apply_migrations(connection)

    # Then
    assert applied == tuple(path.stem for path in MIGRATIONS[10:])
    assert (
        connection.execute(
            "SELECT 'pipeline_telemetry_executions'::regclass::oid, 'pipeline_telemetry_buckets'::regclass::oid"
        ).fetchone()
        == original
    )
    assert migrate.apply_migrations(connection) == ()


def test_postgres_migration_partial_telemetry_schema_is_rejected(
    schema_connection: psycopg.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    connection = schema_connection
    with monkeypatch.context() as context:
        context.setattr(migrate, "_migration_paths", lambda: MIGRATIONS[:10])
        migrate.apply_migrations(connection)
    execution_ddl = (
        MIGRATIONS[10]
        .read_text(encoding="utf-8")
        .split("CREATE TABLE pipeline_telemetry_buckets")[0]
    )
    connection.execute(execution_ddl)
    connection.commit()

    # When
    with pytest.raises(RuntimeError, match="partial 011_pipeline_telemetry_timeseries schema"):
        migrate.apply_migrations(connection)

    # Then
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations WHERE migration_id = '011_pipeline_telemetry_timeseries'"
    ).fetchone() == (0,)


def _http_telemetry(connection: psycopg.Connection):
    reader = DashboardTelemetryReader(
        PipelineTelemetryRepository(connection), clock=lambda: START + timedelta(seconds=21)
    )
    app = create_app()
    app.dependency_overrides[get_dashboard_telemetry_reader] = lambda: reader
    with TestClient(app) as client:
        return client.get("/operations/telemetry", params={"end_at": "2026-10-14T01:00:21.000Z"})


def test_postgres_missing_telemetry_schema_is_a_500_read_defect(
    schema_connection: psycopg.Connection,
) -> None:
    # Given: Migration 011 is not applied to this schema.

    # When
    response = _http_telemetry(schema_connection)

    # Then
    assert (response.status_code, response.json()) == (500, {"detail": "Telemetry read failed"})
    assert "pipeline_telemetry" not in response.text


def test_postgres_statement_timeout_behind_a_lock_is_a_503_unavailability(
    connection: psycopg.Connection,
    database_url: str,
) -> None:
    # Given
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    holder = psycopg.connect(database_url, autocommit=False, connect_timeout=2)
    try:
        holder.execute(
            sql.SQL("LOCK TABLE {}.pipeline_telemetry_executions IN ACCESS EXCLUSIVE MODE").format(
                sql.Identifier(schema)
            )
        )
        connection.execute("SET statement_timeout = 200")

        # When
        response = _http_telemetry(connection)
    finally:
        holder.rollback()
        holder.close()
        connection.rollback()

    # Then
    assert (response.status_code, response.json()) == (
        503,
        {"detail": "Telemetry database is unavailable"},
    )
