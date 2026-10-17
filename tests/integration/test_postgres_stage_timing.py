"""Only an explicitly provisioned random disposable DB is accepted, never dev/test."""

import importlib.util
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_stage_timing import PipelineStageTimingSnapshot
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_stage_timing_reader
from incident_awareness.dashboard.stage_timing_read_model import DashboardStageTimingReader
from incident_awareness.pipeline.runner import _run_stage
from incident_awareness.pipeline.stage_timing import (
    PipelineStageTimingCollector,
    start_stage_timing,
)
from incident_awareness.pipeline.stage_timing_storage import PostgresPipelineStageTimingObserver
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
    StageTimingIntegrityError,
)

NOW = datetime(2026, 10, 17, 1, 2, 3, 456000, tzinfo=UTC)


@pytest.fixture
def database_url() -> str:
    value = os.environ.get("STAGE_TIMING_DISPOSABLE_DATABASE_URL")
    if not value:
        pytest.skip("An explicitly provisioned disposable stage timing DB is required")
    info = conninfo_to_dict(value)
    if not re.fullmatch(r"iae_stage_timing_test_[a-f0-9]{32}", info.get("dbname", "")):
        pytest.fail(
            "Refusing stage timing writes outside an owned disposable database", pytrace=False
        )
    if info.get("host") != "127.0.0.1" or info.get("port") != "54329":
        pytest.fail("Refusing nonlocal PostgreSQL test target", pytrace=False)
    return value


@pytest.fixture
def connection(database_url):
    schema = "stage_test_" + uuid4().hex
    with psycopg.connect(database_url, autocommit=False, connect_timeout=2) as conn:
        assert conn.info.dbname.startswith("iae_stage_timing_test_")
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        applied = apply_migrations(conn)
        assert applied[-1] == "013_pipeline_stage_timings"
        conn.commit()
        try:
            yield conn
        finally:
            conn.rollback()
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
            conn.commit()


def snapshots(*, execution="execution-1", stages=None, failure=None):
    ticks = iter([0, 17, 20, 37, 40, 57, 60, 77, 80, 97, 100, 117])
    observed = []
    collector = start_stage_timing(
        PipelineStageTimingCollector(
            clock=lambda: NOW,
            monotonic_clock=lambda: next(ticks),
            observer=observed.append,
        )
    )
    for stage in stages or list(PipelineStage):
        collector.finish(collector.begin(stage), failed=stage is failure)
        if stage is PipelineStage.ARTIFACT_VALIDATION:
            collector.bind(execution_id=execution, run_id="RUN-FIXTURE", entity_id="WIN-01")
        if stage is failure:
            break
    return collector, observed


def client(connection):
    app = create_app()
    app.dependency_overrides[get_dashboard_stage_timing_reader] = lambda: (
        DashboardStageTimingReader(PipelineStageTimingRepository(connection))
    )
    return TestClient(app)


def save(connection, snapshot):
    result = PipelineStageTimingRepository(connection).save_snapshot(snapshot)
    connection.commit()
    return result


def test_real_migration_roundtrip_order_and_idempotency(connection):
    # Given
    collector, observed = snapshots()
    repository = PipelineStageTimingRepository(connection)

    # When
    for snapshot in observed:
        assert save(connection, snapshot)
    restored, persisted_at, known = repository.read_execution("execution-1")
    before = persisted_at
    assert not save(connection, collector.snapshot())
    again, persisted_at, _ = repository.read_execution("execution-1")

    # Then
    assert known and restored == again == collector.snapshot()
    assert [r.stage for r in restored.records] == list(PipelineStage)
    assert [r.duration_ns for r in restored.records] == [17] * 6
    assert persisted_at == before and persisted_at.tzinfo is not None
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_records").fetchone()[0] == 6
    )


def test_real_api_exact_large_integer_and_utc_without_coverage_inference(connection):
    # Given
    collector, _ = snapshots()
    data = collector.snapshot().model_dump()
    data["records"][0]["duration_ns"] = 2**100 + 17
    snapshot = PipelineStageTimingSnapshot.model_validate(data)
    save(connection, snapshot)

    # When
    response = client(connection).get("/operations/stage-timings?execution_id=execution-1")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["snapshot"]["records"][0]["duration_ns"] == str(2**100 + 17)
    assert payload["snapshot"]["records"][0]["started_at"] == "2026-10-17T01:02:03.456Z"
    assert (
        payload["coverage_status"] == "not_evaluable" and payload["execution_outcome"] == "unknown"
    )
    assert payload["unmeasured_stages"] == []
    assert PipelineStageTimingRepository(connection).read_execution("execution-1")[0] == snapshot


@pytest.mark.parametrize("kind", ["record", "same_revision", "removed", "identity", "stale_record"])
def test_conflicts_are_rejected_without_rewriting_immutable_history(connection, kind):
    # Given
    collector, _ = snapshots()
    original = collector.snapshot()
    save(connection, original)
    data = original.model_dump()
    if kind != "same_revision":
        data["revision"] += 1
    if kind in {"record", "stale_record"}:
        data["records"][0]["duration_ns"] += 1
        if kind == "stale_record":
            data["revision"] = 1
    elif kind == "same_revision":
        data["issues"] = ("internal_error",)
        data["quality_status"] = "partial"
    elif kind == "removed":
        data["records"] = data["records"][:-1]
    else:
        data["entity_id"] = "OTHER-HOST"

    # When / Then
    with pytest.raises(StageTimingIntegrityError):
        PipelineStageTimingRepository(connection).save_snapshot(
            PipelineStageTimingSnapshot.model_validate(data)
        )
    connection.rollback()
    assert PipelineStageTimingRepository(connection).read_execution("execution-1")[0] == original


def test_stale_unbound_delivery_is_noop_and_same_execution_cannot_bind_another_attempt(connection):
    # Given
    collector, observed = snapshots()
    save(connection, collector.snapshot())

    # When / Then
    assert not save(connection, observed[0])
    second, _ = snapshots()
    with pytest.raises(StageTimingIntegrityError):
        PipelineStageTimingRepository(connection).save_snapshot(second.snapshot())
    connection.rollback()
    assert (
        PipelineStageTimingRepository(connection).read_execution("execution-1")[0]
        == collector.snapshot()
    )


def test_same_run_separate_executions_and_entities_are_not_combined(connection):
    # Given
    first, _ = snapshots()
    second, _ = snapshots(execution="retry-2")
    data = second.snapshot().model_dump()
    data["entity_id"] = "WIN-02"

    # When
    save(connection, first.snapshot())
    save(connection, PipelineStageTimingSnapshot.model_validate(data))

    # Then
    repository = PipelineStageTimingRepository(connection)
    assert repository.read_execution("execution-1")[0].entity_id == "WIN-01"
    assert repository.read_execution("retry-2")[0].entity_id == "WIN-02"
    assert len(repository.read_execution("execution-1")[0].records) == 6


def test_failed_stage_and_unbound_artifact_failure_are_preserved(connection):
    # Given
    failed, _ = snapshots(failure=PipelineStage.FUSION)
    unbound, _ = snapshots(failure=PipelineStage.ARTIFACT_VALIDATION)
    # The generator's binding is intentionally not used: real validation failure stays unbound.
    raw = unbound.snapshot().model_dump()
    raw.update(execution_id=None, run_id=None, entity_id=None)

    # When
    save(connection, failed.snapshot())
    save(connection, PipelineStageTimingSnapshot.model_validate(raw))
    response = client(connection).get("/operations/stage-timings?execution_id=execution-1")

    # Then
    assert response.json()["operation_failure_recorded"] is True
    assert PipelineStageTimingRepository(connection).read_attempt(
        raw["attempt_id"]
    ) == PipelineStageTimingSnapshot.model_validate(raw)
    assert [r["stage"] for r in response.json()["snapshot"]["records"]] == [
        "artifact_validation",
        "normalization",
        "fusion",
    ]
    assert (
        connection.execute(
            "SELECT count(*) FROM pipeline_stage_timing_attempts WHERE execution_id IS NULL AND run_id IS NULL"
        ).fetchone()[0]
        == 1
    )


def test_active_operation_has_no_synthetic_duration_and_standalone_has_only_five_records(
    connection,
):
    # Given
    collector, _ = snapshots(stages=[PipelineStage.ARTIFACT_VALIDATION])
    collector.begin(PipelineStage.NORMALIZATION)
    standalone, _ = snapshots(
        execution="standalone",
        stages=[s for s in PipelineStage if s is not PipelineStage.FAST_HANDOFF],
    )

    # When
    save(connection, collector.snapshot())
    save(connection, standalone.snapshot())
    first = client(connection).get("/operations/stage-timings?execution_id=execution-1").json()
    second = client(connection).get("/operations/stage-timings?execution_id=standalone").json()

    # Then
    assert first["snapshot"]["active_stage"] == "normalization"
    assert first["ended_invocation_count"] == 1
    assert second["ended_invocation_count"] == 5 and second["unmeasured_stages"] == ["fast_handoff"]
    assert second["missing_stage_meaning"] == "not_observed_not_proof_of_not_run"


@pytest.mark.parametrize("bad", [-1, 1.5, "not-an-integer"])
def test_database_constraints_and_function_atomic_rollback(connection, bad):
    # Given
    collector, _ = snapshots()
    data = collector.snapshot().model_dump(mode="json")
    data["records"][0]["duration_ns"] = bad

    # When
    with pytest.raises(psycopg.Error):
        connection.execute("SELECT save_pipeline_stage_timing(%s)", (Jsonb(data),))
    connection.rollback()

    # Then
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_attempts").fetchone()[0] == 0
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE pipeline_stage_timing_records SET duration_ns=99",
        "DELETE FROM pipeline_stage_timing_records",
        "DELETE FROM pipeline_stage_timing_attempts",
    ],
)
def test_database_rejects_direct_history_mutations(connection, statement):
    # Given
    collector, _ = snapshots()
    save(connection, collector.snapshot())
    # When / Then
    with pytest.raises(psycopg.Error):
        connection.execute(statement)
    connection.rollback()
    assert (
        len(PipelineStageTimingRepository(connection).read_execution("execution-1")[0].records) == 6
    )


def test_unknown_execution_vs_runtime_without_stage_timing(connection):
    # Given
    connection.execute(
        "INSERT INTO pipeline_runtime_status(run_id,entity_id,execution_id,status,current_stage,started_at,updated_at,payload) VALUES('fixture','host','known','running','fusion',%s,%s,%s)",
        (
            NOW,
            NOW,
            Jsonb(
                {
                    "execution_id": "known",
                    "run_id": "fixture",
                    "entity_id": "host",
                    "status": "running",
                    "current_stage": "fusion",
                }
            ),
        ),
    )
    connection.commit()
    # When / Then
    assert (
        client(connection).get("/operations/stage-timings?execution_id=missing").status_code == 404
    )
    response = client(connection).get("/operations/stage-timings?execution_id=known")
    assert response.status_code == 200 and response.json()["availability"] == "no_stage_timings"
    assert response.json()["snapshot"] is None


def test_real_concurrent_duplicate_publications_are_serialized(connection, database_url):
    # Given
    collector, _ = snapshots()
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    barrier = Barrier(4)

    def publish(_):
        with psycopg.connect(
            database_url, options=f"-c search_path={schema} -c statement_timeout=5000"
        ) as writer:
            barrier.wait(timeout=5)
            return PipelineStageTimingRepository(writer).save_snapshot(collector.snapshot())

    # When
    with ThreadPoolExecutor(max_workers=4) as pool:
        saved = list(pool.map(publish, range(4)))

    # Then
    assert sorted(saved) == [False, False, False, True]
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_records").fetchone()[0] == 6
    )


def test_real_read_only_session_and_actual_pipeline_storage(
    connection, database_url, tmp_path, monkeypatch
):
    # Given
    schema = connection.execute("SELECT current_schema()").fetchone()[0]

    def writer_factory(_):
        return psycopg.connect(
            database_url,
            autocommit=False,
            options=f"-c search_path={schema} -c statement_timeout=2000",
        )

    observer = PostgresPipelineStageTimingObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=writer_factory,
    )
    timing = PipelineStageTimingCollector(observer=observer)
    spec = importlib.util.spec_from_file_location(
        "actual_fixture", Path("tests/pipeline/test_first_cycle_fixture.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PipelineStageTimingCollector", lambda: timing)

    # When
    module.test_first_cycle_fixture_runs_through_the_assembled_pipeline(tmp_path)
    observer.close()
    execution = timing.snapshot().execution_id
    with psycopg.connect(
        database_url,
        options=f"-c search_path={schema} -c default_transaction_read_only=on -c statement_timeout=5000",
    ) as reader:
        response = client(reader).get(f"/operations/stage-timings?execution_id={execution}")
        assert reader.execute("SHOW transaction_read_only").fetchone()[0] == "on"
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            reader.execute("CREATE TABLE forbidden(value INTEGER)")
        reader.rollback()

    # Then
    assert response.status_code == 200 and response.json()["ended_invocation_count"] == 6
    assert timing.snapshot().quality_status == "observed"
    assert response.json()["snapshot"]["records"][-1]["stage"] == "persistence"
    evidence_dir = os.environ.get("STAGE_TIMING_EVIDENCE_DIR")
    if evidence_dir:
        expected = (
            Path(__file__).resolve().parents[2] / "build/view2-reference/stage-timing-storage"
        )
        assert Path(evidence_dir).resolve() == expected.resolve()
        (expected / "read-api-example.json").write_text(
            json.dumps(
                {
                    "fixture_only": True,
                    "operational_measurement": False,
                    "stage_timing_database": "Real disposable local PostgreSQL; no dev/test writes",
                    "pipeline_business_database": "Existing fixture fake connection",
                    "http_status": response.status_code,
                    "response": response.json(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def test_invalid_stored_payload_is_an_api_error_not_empty_data(connection):
    # Given
    collector, _ = snapshots()
    data = collector.snapshot().model_dump(mode="json")
    data.pop("records")
    data["unexpected_contract_field"] = True
    connection.execute(
        "INSERT INTO pipeline_stage_timing_attempts(attempt_id,execution_id,run_id,entity_id,revision,payload) VALUES(%s,%s,%s,%s,%s,%s)",
        (
            data["attempt_id"],
            data["execution_id"],
            data["run_id"],
            data["entity_id"],
            data["revision"],
            Jsonb(data),
        ),
    )
    connection.commit()
    # When / Then
    response = client(connection).get("/operations/stage-timings?execution_id=execution-1")
    assert response.status_code == 500 and response.json() == {
        "detail": "Stored stage timing is invalid"
    }


def test_partial_transaction_failure_then_retry_preserves_previous_records(connection):
    # Given
    collector, observed = snapshots()
    save(connection, observed[1])
    bad = collector.snapshot().model_dump(mode="json")
    bad["records"][-1]["duration_ns"] = -1

    # When
    with pytest.raises(psycopg.Error):
        connection.execute("SELECT save_pipeline_stage_timing(%s)", (Jsonb(bad),))
    connection.rollback()
    restored = PipelineStageTimingRepository(connection).read_execution("execution-1")[0]
    assert restored == observed[1]
    assert save(connection, collector.snapshot())

    # Then
    assert (
        PipelineStageTimingRepository(connection).read_execution("execution-1")[0]
        == collector.snapshot()
    )
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_records").fetchone()[0] == 6
    )


@pytest.mark.parametrize("bad", ["order", "duplicate", "active"])
def test_direct_sql_rejects_invalid_invocation_order_or_active_boundary(connection, bad):
    # Given
    collector, _ = snapshots()
    data = collector.snapshot().model_dump(mode="json")
    if bad == "order":
        data["records"].reverse()
    elif bad == "duplicate":
        data["records"].append(data["records"][0])
    else:
        data["active_stage"] = "fusion"
        data["active_invocation_index"] = 1
    # When / Then
    with pytest.raises(psycopg.Error):
        connection.execute("SELECT save_pipeline_stage_timing(%s)", (Jsonb(data),))
    connection.rollback()
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_attempts").fetchone()[0] == 0
    )


def test_partial_clock_data_and_measured_zero_roundtrip_without_filling_missing_stages(connection):
    # Given
    timing = start_stage_timing(
        PipelineStageTimingCollector(clock=lambda: None, monotonic_clock=lambda: 0)
    )
    _run_stage(PipelineStage.FUSION, lambda: None, stage_timing=timing)
    timing.bind(execution_id="zero-partial", run_id="fixture", entity_id="host")
    # When
    save(connection, timing.snapshot())
    response = client(connection).get("/operations/stage-timings?execution_id=zero-partial").json()
    # Then
    assert (
        PipelineStageTimingRepository(connection).read_execution("zero-partial")[0]
        == timing.snapshot()
    )
    record = response["snapshot"]["records"][0]
    assert (
        record["duration_ns"] == "0" and record["started_at"] is None and record["ended_at"] is None
    )
    assert response["snapshot"]["quality_status"] == "partial"
    assert response["ended_invocation_count"] == 1


def test_session_timezone_is_normalized_to_utc_at_read_boundary(connection):
    # Given
    timing, _ = snapshots()
    save(connection, timing.snapshot())
    connection.execute("SET TIME ZONE 'Asia/Seoul'")
    # When
    response = client(connection).get("/operations/stage-timings?execution_id=execution-1")
    # Then
    assert response.status_code == 200
    assert response.json()["persisted_at"].endswith("Z")


@pytest.mark.parametrize("business_fails", [False, True])
def test_actual_business_transaction_is_never_committed_or_rolled_back_by_observer(
    connection, database_url, business_fails
):
    # Given
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    connection.execute("CREATE TABLE business_probe(value INTEGER)")
    connection.commit()

    def writer_factory(_):
        return psycopg.connect(
            database_url,
            autocommit=False,
            options=f"-c search_path={schema} -c statement_timeout=2000",
        )

    observer = PostgresPipelineStageTimingObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=writer_factory,
    )
    timing = start_stage_timing(PipelineStageTimingCollector(observer=observer))
    timing.bind(execution_id="business-isolation", run_id="fixture", entity_id="host")
    error = ValueError("original business failure")

    def operation():
        connection.execute("INSERT INTO business_probe VALUES(1)")
        if business_fails:
            raise error
        return "result"

    # When
    if business_fails:
        with pytest.raises(ValueError) as caught:
            _run_stage(PipelineStage.PERSISTENCE, operation, stage_timing=timing)
        assert caught.value is error
    else:
        assert _run_stage(PipelineStage.PERSISTENCE, operation, stage_timing=timing) == "result"
    with writer_factory(None) as outsider:
        assert outsider.execute("SELECT count(*) FROM business_probe").fetchone()[0] == 0
    assert connection.execute("SELECT count(*) FROM business_probe").fetchone()[0] == 1
    if business_fails:
        connection.rollback()
    else:
        connection.commit()
    observer.close()

    # Then
    assert connection.execute("SELECT count(*) FROM business_probe").fetchone()[0] == (
        0 if business_fails else 1
    )
    restored = PipelineStageTimingRepository(connection).read_execution("business-isolation")[0]
    assert restored.records[0].outcome == ("failed" if business_fails else "completed")


def test_actual_observer_write_error_does_not_abort_business_transaction(connection, database_url):
    # Given
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    connection.execute("CREATE TABLE business_probe(value INTEGER)")
    connection.commit()

    def read_only_writer(_):
        return psycopg.connect(
            database_url,
            autocommit=False,
            options=f"-c search_path={schema} -c default_transaction_read_only=on",
        )

    observer = PostgresPipelineStageTimingObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=read_only_writer,
    )
    timing = start_stage_timing(PipelineStageTimingCollector(observer=observer))
    # When
    assert _run_stage(
        PipelineStage.PERSISTENCE,
        lambda: connection.execute("INSERT INTO business_probe VALUES(1)"),
        stage_timing=timing,
    )
    connection.commit()
    observer.close()
    # Then
    assert connection.execute("SELECT count(*) FROM business_probe").fetchone()[0] == 1
    assert (
        connection.execute("SELECT count(*) FROM pipeline_stage_timing_records").fetchone()[0] == 0
    )
    assert timing.snapshot().issues == ("observer_error",)
    assert observer.pending_snapshot is not None


def test_bound_empty_snapshot_is_not_reported_as_measured_stage_data(connection):
    # Given
    timing = start_stage_timing(PipelineStageTimingCollector())
    timing.bind(execution_id="empty-bound", run_id="fixture", entity_id="host")
    # When
    save(connection, timing.snapshot())
    response = client(connection).get("/operations/stage-timings?execution_id=empty-bound").json()
    # Then
    assert (
        response["availability"] == "no_stage_timings" and response["ended_invocation_count"] == 0
    )
    assert response["snapshot"]["quality_status"] == "unavailable"


def test_real_api_dependency_runs_read_only_sql_and_closes_connection(
    connection, database_url, monkeypatch
):
    # Given
    from incident_awareness.dashboard.api import dependencies

    timing, _ = snapshots()
    save(connection, timing.snapshot())
    schema = connection.execute("SELECT current_schema()").fetchone()[0]
    original_connect = psycopg.connect
    sessions = []
    settings = []
    monkeypatch.setattr(
        dependencies.DatabaseConfig, "from_environment", lambda: DatabaseConfig(database_url)
    )

    def connect(url, **kwargs):
        kwargs["options"] += f" -c search_path={schema}"
        conn = original_connect(url, **kwargs)
        settings.append(
            conn.execute(
                "SELECT current_setting('transaction_read_only'), current_setting('statement_timeout'),current_setting('TimeZone')"
            ).fetchone()
        )
        sessions.append(conn)
        return conn

    monkeypatch.setattr(dependencies.psycopg, "connect", connect)
    # When
    response = TestClient(create_app()).get("/operations/stage-timings?execution_id=execution-1")
    # Then
    assert response.status_code == 200 and response.json()["ended_invocation_count"] == 6
    assert settings == [("on", "5s", "UTC")]
    assert sessions[0].closed
