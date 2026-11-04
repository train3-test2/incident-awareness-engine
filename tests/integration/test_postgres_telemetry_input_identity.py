from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
from test_postgres_pipeline_telemetry import MIGRATIONS
from test_postgres_pipeline_telemetry import (
    connection as connection,  # noqa: PLC0414 - pytest fixture
)
from test_postgres_pipeline_telemetry import (
    database_url as database_url,  # noqa: PLC0414 - pytest fixture
)
from test_postgres_pipeline_telemetry import (
    schema_connection as schema_connection,  # noqa: PLC0414 - pytest fixture
)

from incident_awareness.common.models.pipeline_telemetry import PipelineTelemetryInputIdentity
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_telemetry_reader
from incident_awareness.dashboard.telemetry_read_model import DashboardTelemetryReader
from incident_awareness.pipeline.telemetry_input import s3_input_identity
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector
from incident_awareness.storage import migrate
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryIntegrityError,
    PipelineTelemetryRepository,
)

# Reuse the TEST_DATABASE_URL-only, UUID schema fixtures; never use public.
END = datetime(2026, 10, 14, 1, 5, tzinfo=UTC)
FILE_A = PipelineTelemetryInputIdentity(kind="file_content_sha256_v1", sha256="a" * 64)
FILE_B = PipelineTelemetryInputIdentity(kind="file_content_sha256_v1", sha256="b" * 64)


def _snapshot(execution: str, identity, *, when=END - timedelta(seconds=1), entity="WIN-A"):
    collector = PipelineTelemetryCollector(
        execution_id=execution,
        run_id="RUN-INPUT",
        entity_id=entity,
        input_identity=identity,
        clock=lambda: when,
        monotonic_clock=lambda: 7,
    )
    collector.accept_batch(1)
    with collector.measure_record(1):
        pass
    return collector.snapshot()


def _request(connection, *, scope="run", **parameters):
    reader = DashboardTelemetryReader(PipelineTelemetryRepository(connection), clock=lambda: END)
    app = create_app()
    app.dependency_overrides[get_dashboard_telemetry_reader] = lambda: reader
    query = {"scope": scope, "end_at": END.isoformat(), **parameters}
    if scope == "run":
        query["run_id"] = "RUN-INPUT"
    with TestClient(app) as client:
        return client.get("/operations/telemetry", params=query)


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (FILE_A, FILE_A, 200),
        (FILE_A, FILE_B, 409),
        (None, None, 409),
        (None, FILE_A, 409),
        (FILE_A, None, 409),
        (FILE_A, PipelineTelemetryInputIdentity(kind="s3_object_sha256_v1", sha256="a" * 64), 409),
        (
            s3_input_identity("bucket", "A", "same-content"),
            s3_input_identity("bucket", "B", "same-content"),
            409,
        ),
        (s3_input_identity("bucket", "A", "v1"), s3_input_identity("bucket", "A", "v2"), 409),
        (s3_input_identity("bucket", "A", "v1"), s3_input_identity("bucket", "A", "v1"), 200),
    ],
)
def test_postgres_run_input_identity_matches_or_conflicts(connection, first, second, expected):
    # Given
    repository = PipelineTelemetryRepository(connection)
    for execution, identity in (("A", first), ("B", second)):
        repository.save_snapshot(_snapshot(execution, identity))
    connection.commit()

    # When
    response = _request(connection)
    execution = _request(connection, scope="execution", execution_id="A")
    reported = _request(connection, scope="reported")

    # Then
    assert response.status_code == expected
    if expected == 200:
        assert response.json()["executions_count"] == 2
        assert response.json()["recent_60s_summary"]["input_accepted_count"] == 2
    else:
        assert set(response.json()) == {"detail"}
        assert "s3://" not in response.text and "SQL" not in response.text
    assert execution.status_code == reported.status_code == 200
    assert execution.json()["executions_count"] == 1
    assert reported.json()["recent_60s_summary"]["input_accepted_count"] == 2


def test_postgres_single_legacy_execution_remains_readable(connection):
    # Given
    PipelineTelemetryRepository(connection).save_snapshot(_snapshot("legacy", None))
    connection.commit()

    # When
    response = _request(connection)

    # Then
    assert response.status_code == 200
    assert response.json()["executions_count"] == 1


@pytest.mark.parametrize("identity", [FILE_B, None])
def test_postgres_conflict_outside_time_and_entity_filter_is_not_hidden(connection, identity):
    # Given
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(
        _snapshot("old", identity, when=END - timedelta(days=1), entity="WIN-B")
    )
    repository.save_snapshot(_snapshot("new", FILE_A))
    connection.commit()

    # When
    response = _request(connection, entity_id="WIN-A")

    # Then
    assert response.status_code == 409
    assert _request(connection, scope="execution", execution_id="new").status_code == 200
    reported = _request(connection, scope="reported")
    assert reported.status_code == 200
    assert reported.json()["executions_count"] == 1


@pytest.mark.parametrize("previous", [None, FILE_A])
def test_postgres_input_identity_is_immutable_at_repository_and_database_boundaries(
    connection, previous
):
    # Given
    snapshot = _snapshot("identity", previous)
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(snapshot)
    connection.commit()
    changed = snapshot.model_copy(
        update={"revision": snapshot.revision + 1, "input_identity": FILE_B}
    )

    # When
    with pytest.raises(PipelineTelemetryIntegrityError):
        repository.save_snapshot(changed)
    with pytest.raises(psycopg.IntegrityError), connection.transaction():
        connection.execute(
            "UPDATE pipeline_telemetry_executions SET input_identity_kind = %s, input_identity_sha256 = %s, payload = %s WHERE execution_id = %s",
            (
                FILE_B.kind,
                FILE_B.sha256,
                Jsonb(changed.model_dump(mode="json", exclude={"buckets"})),
                "identity",
            ),
        )

    # Then
    assert repository.get_execution("identity") == snapshot
    assert repository.save_snapshot(snapshot) is False


def _apply_through_011(connection, monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(migrate, "_migration_paths", lambda: MIGRATIONS[:11])
        migrate.apply_migrations(connection)
    connection.commit()


def test_postgres_011_to_012_preserves_legacy_payload_revision_and_buckets(
    schema_connection, monkeypatch
):
    # Given
    connection = schema_connection
    _apply_through_011(connection, monkeypatch)
    snapshot = _snapshot("legacy", None)
    payload = snapshot.model_dump(mode="json", exclude={"buckets", "input_identity"})
    connection.execute(
        """
        INSERT INTO pipeline_telemetry_executions (
            execution_id, snapshot_id, run_id, entity_id, aggregation_basis, latency_scope,
            revision, input_total, input_accepted_at, last_observed_at,
            observation_status, collection_disabled, payload
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """,
        (
            snapshot.execution_id,
            snapshot.snapshot_id,
            snapshot.run_id,
            snapshot.entity_id,
            snapshot.aggregation_basis,
            snapshot.latency_scope,
            snapshot.revision,
            snapshot.input_total,
            snapshot.input_accepted_at,
            snapshot.last_observed_at,
            snapshot.observation_status,
            snapshot.collection_disabled,
            Jsonb(payload),
        ),
    )
    bucket = snapshot.buckets[0]
    from incident_awareness.storage.repositories.pipeline_telemetry_repository import _UPSERT_BUCKET

    connection.execute(
        _UPSERT_BUCKET,
        (
            snapshot.execution_id,
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
    before = connection.execute(
        "SELECT payload, revision, created_at, updated_at FROM pipeline_telemetry_executions"
    ).fetchone()
    connection.commit()

    # When
    applied = migrate.apply_migrations(connection)
    connection.commit()
    after = connection.execute(
        "SELECT payload, revision, created_at, updated_at FROM pipeline_telemetry_executions"
    ).fetchone()
    restored = PipelineTelemetryRepository(connection).get_execution("legacy")

    # Then
    assert applied == tuple(path.stem for path in MIGRATIONS[11:])
    assert before == after
    assert restored == snapshot
    assert "input_identity" not in after[0]
    assert connection.execute(
        "SELECT input_identity_kind, input_identity_sha256 FROM pipeline_telemetry_executions"
    ).fetchone() == (None, None)
    assert _request(connection).status_code == 200


def test_postgres_012_initdb_without_history_baselines_and_preserves_table(
    schema_connection, monkeypatch
):
    # Given
    connection = schema_connection
    _apply_through_011(connection, monkeypatch)
    connection.execute(MIGRATIONS[11].read_text(encoding="utf-8"))
    oid = connection.execute("SELECT 'pipeline_telemetry_executions'::regclass::oid").fetchone()
    connection.commit()

    # When
    applied = migrate.apply_migrations(connection)
    connection.commit()

    # Then
    assert applied == tuple(path.stem for path in MIGRATIONS[11:])
    assert migrate.apply_migrations(connection) == ()
    assert (
        connection.execute("SELECT 'pipeline_telemetry_executions'::regclass::oid").fetchone()
        == oid
    )


@pytest.mark.parametrize(
    "drop",
    [
        "ALTER TABLE pipeline_telemetry_executions DROP CONSTRAINT pipeline_telemetry_input_identity_pair",
        "ALTER TABLE pipeline_telemetry_executions DROP CONSTRAINT pipeline_telemetry_input_identity_payload",
        "DROP TRIGGER pipeline_telemetry_input_identity_immutable ON pipeline_telemetry_executions",
    ],
)
def test_postgres_partial_012_cannot_be_baselined(connection, drop):
    # Given
    connection.execute(
        "DELETE FROM schema_migrations WHERE migration_id = '012_pipeline_telemetry_input_identity'"
    )
    connection.execute(drop)
    connection.commit()

    # When
    with pytest.raises(RuntimeError, match="partial 012"):
        migrate.apply_migrations(connection)

    # Then
    assert (
        connection.execute(
            "SELECT 1 FROM schema_migrations WHERE migration_id = '012_pipeline_telemetry_input_identity'"
        ).fetchone()
        is None
    )
