import hashlib
import json
import os
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import Connection, sql

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_telemetry_reader,
    get_database_connection,
)
from incident_awareness.dashboard.telemetry_read_model import DashboardTelemetryReader
from incident_awareness.pipeline import event_evidence, runner, sqs_worker
from incident_awareness.pipeline import standalone as standalone_module
from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.runner import run_first_cycle_pipeline
from incident_awareness.pipeline.runtime_telemetry import PostgresPipelineRuntimeObserver
from incident_awareness.pipeline.standalone import run_standalone_sysmon_jsonl
from incident_awareness.pipeline.timeseries_observer import PostgresPipelineTelemetryObserver
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)
from incident_awareness.storage.repositories.s3_object_receipt_repository import (
    S3ObjectReceiptRepository,
)

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"
FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "pipeline" / "first_cycle"
FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")


@pytest.fixture
def database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_DATABASE_URL_ENV} is required for PostgreSQL integration tests")

    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})
    database_name = unquote(urlparse(url).path).strip("/").lower()
    explicitly_marked = os.environ.get(TEST_DATABASE_MARKER_ENV, "").lower() == "true"
    if "test" not in database_name and not explicitly_marked:
        pytest.skip(
            "PostgreSQL integration requires a database containing 'test' in its name or "
            f"{TEST_DATABASE_MARKER_ENV}=true"
        )
    return url


def test_first_cycle_runtime_is_available_through_dashboard_api(
    database_url: str,
    tmp_path: Path,
) -> None:
    # Given
    schema = sql.Identifier(f"pipeline_runtime_e2e_{uuid4().hex}")
    fixture_root = tmp_path / "inputs"
    shutil.copytree(FIXTURE_ROOT, fixture_root)
    _rewrite_trace_paths_for_local_fixture(fixture_root)
    inputs = parse_cli_args(
        [
            "--run-metadata",
            str(fixture_root / "run_metadata.json"),
            "--manifest",
            str(fixture_root / "manifest.json"),
            "--sysmon-jsonl",
            str(fixture_root / "sysmon-0001.jsonl"),
            "--fast-hits",
            str(fixture_root / "fast" / "hits.jsonl"),
            "--fast-trace",
            str(fixture_root / "fast" / "trace.json"),
            "--fast-selection",
            str(fixture_root / "fast" / "selection.json"),
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--entity-id",
            "WIN-01",
            "--decision-id",
            "D-FIXTURE-001",
            "--decision-config-version",
            "parallel-v0.2",
        ]
    )
    schema_created = False

    def connect_to_schema(url: str) -> Connection[tuple[object, ...]]:
        connection = psycopg.connect(url)
        connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        return connection

    def get_test_database_connection() -> Iterator[Connection[tuple[object, ...]]]:
        connection = connect_to_schema(database_url)
        try:
            yield connection
        finally:
            connection.close()

    try:
        with psycopg.connect(database_url) as setup_connection:
            setup_connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
            schema_created = True
            setup_connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            apply_migrations(setup_connection)
            setup_connection.commit()

        with (
            psycopg.connect(database_url) as business_connection,
            PostgresPipelineRuntimeObserver(
                database_config_factory=lambda: DatabaseConfig(database_url),
                connection_factory=connect_to_schema,
                progress_write_interval_seconds=0.0,
            ) as runtime_observer,
        ):
            business_connection.execute(sql.SQL("SET search_path TO {}").format(schema))

            # When
            summary = run_first_cycle_pipeline(
                inputs,
                connection=business_connection,
                runtime_observer=runtime_observer,
            )

        # Then
        assert summary.run_id == "RUN-20260920-001"
        assert summary.entity_id == "WIN-01"
        assert summary.normalized_event_count == 2
        assert summary.evidence_count == 2
        assert summary.fusion_status == "detected"
        assert summary.detector_status == "detected"
        assert summary.decision_path == "fast_and_fusion"

        app = create_app()
        app.dependency_overrides[get_database_connection] = get_test_database_connection

        # When
        with TestClient(app) as client:
            completed_response = client.get("/operations/runtime?status=completed")
            failed_response = client.get("/operations/runtime?status=failed")

        # Then
        assert completed_response.status_code == 200
        completed_items = completed_response.json()["items"]
        assert len(completed_items) == 1
        runtime_item = completed_items[0]
        assert runtime_item["run_id"] == "RUN-20260920-001"
        assert runtime_item["entity_id"] == "WIN-01"
        assert runtime_item["status"] == "completed"
        assert runtime_item["current_stage"] is None
        assert runtime_item["input_total"] == 2
        assert runtime_item["normalization_processed_count"] == 2
        assert runtime_item["remaining_count"] == 0
        assert runtime_item["completed_at"] is not None
        assert runtime_item["failed_stage"] is None
        assert runtime_item["has_error"] is False
        assert runtime_item["is_stale"] is False
        assert runtime_item["execution_id"].strip()

        started_at = _parse_api_datetime(runtime_item["started_at"])
        updated_at = _parse_api_datetime(runtime_item["updated_at"])
        completed_at = _parse_api_datetime(runtime_item["completed_at"])
        assert started_at <= updated_at
        assert completed_at <= updated_at

        assert failed_response.status_code == 200
        assert failed_response.json() == {"items": []}

        parsed_url = urlparse(database_url)
        secret_markers = {
            DATABASE_URL_ENV,
            TEST_DATABASE_URL_ENV,
            "postgresql://",
            "password",
            "Traceback",
            "SELECT",
            database_url,
            parsed_url.password,
            parsed_url.hostname,
        }
        for response in (completed_response, failed_response):
            for marker in secret_markers:
                if marker:
                    assert marker not in response.text
    finally:
        if schema_created:
            with psycopg.connect(database_url) as cleanup_connection:
                cleanup_connection.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema)
                )
                cleanup_connection.commit()


def _rewrite_trace_paths_for_local_fixture(fixture_root: Path) -> None:
    trace_path = fixture_root / "fast" / "trace.json"
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["input_csv"] = str((fixture_root / "fast" / "handoff.csv").resolve())
    trace["config_path"] = str((fixture_root / "fast" / "config.json").resolve())
    trace_path.write_text(json.dumps(trace), encoding="utf-8")


def _parse_api_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


@pytest.fixture
def telemetry_database(database_url: str):
    """Only migrate an owned temporary schema in the explicitly selected test database."""
    schema = sql.Identifier(f"pipeline_timeseries_e2e_{uuid4().hex}")
    original_connect = psycopg.connect
    with original_connect(database_url, autocommit=False) as setup:
        setup.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        setup.execute(sql.SQL("SET search_path TO {}").format(schema))
        apply_migrations(setup)

    def connect(url, **kwargs):
        if url != database_url:
            raise ValueError("E2E connections must use the selected test database")
        kwargs.setdefault("autocommit", False)
        connection = original_connect(url, **kwargs)
        connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        return connection

    try:
        yield connect
    finally:
        with original_connect(database_url, autocommit=False) as cleanup:
            cleanup.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))


def _telemetry_inputs(tmp_path):
    fixture = tmp_path / "inputs"
    shutil.copytree(FIXTURE_ROOT, fixture)
    _rewrite_trace_paths_for_local_fixture(fixture)
    return parse_cli_args(
        [
            "--run-metadata",
            str(fixture / "run_metadata.json"),
            "--manifest",
            str(fixture / "manifest.json"),
            "--sysmon-jsonl",
            str(fixture / "sysmon-0001.jsonl"),
            "--fast-hits",
            str(fixture / "fast/hits.jsonl"),
            "--fast-trace",
            str(fixture / "fast/trace.json"),
            "--fast-selection",
            str(fixture / "fast/selection.json"),
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--entity-id",
            "WIN-01",
            "--decision-id",
            "D-FIXTURE-001",
            "--decision-config-version",
            "parallel-v0.2",
        ]
    )


@pytest.mark.parametrize("execution_path", ["first_cycle", "standalone", "sqs_worker"])
def test_pipeline_timeseries_matches_runtime_and_business_results(
    database_url,
    telemetry_database,
    tmp_path,
    monkeypatch,
    execution_path,
) -> None:
    # Given
    connect = telemetry_database
    inputs = _telemetry_inputs(tmp_path)
    if execution_path == "sqs_worker":
        monkeypatch.setenv(DATABASE_URL_ENV, database_url)
        monkeypatch.setenv("INCIDENT_AWARENESS_SQS_QUEUE_URL", "test-queue")
        monkeypatch.setenv("INCIDENT_AWARENESS_S3_INPUT_BUCKET", "test-inputs")
        monkeypatch.setattr(sqs_worker.psycopg, "connect", connect)
        body = json.dumps(
            {
                "Records": [
                    {
                        "eventSource": "aws:s3",
                        "eventName": "ObjectCreated:Put",
                        "s3": {
                            "bucket": {"name": "test-inputs"},
                            "object": {
                                "key": "incoming/first-cycle/sysmon/ING-550e8400-e29b-41d4-a716-446655440000/sysmon.jsonl",
                                "eTag": "immutable-test-version",
                                "sequencer": "001",
                            },
                        },
                    }
                ]
            }
        )

        class Queue:
            def __init__(self):
                self.deleted = []

            def receive_message(self, **kwargs):
                return {"Messages": [{"Body": body, "ReceiptHandle": "test-receipt"}]}

            def delete_message(self, **kwargs):
                self.deleted.append(kwargs["ReceiptHandle"])
                return {}

        class S3:
            def download_file(self, bucket, key, filename):
                shutil.copyfile(inputs.sysmon_jsonl_path, filename)

        queue = Queue()
        monkeypatch.setattr(
            sqs_worker.boto3, "client", lambda name: queue if name == "sqs" else S3()
        )

        # When
        assert sqs_worker.main(["--once"]) == 0
        assert sqs_worker.main(["--once"]) == 0  # Successful Receipt suppresses reprocessing.
    else:
        runtime = PostgresPipelineRuntimeObserver(
            database_config_factory=lambda: DatabaseConfig(database_url),
            connection_factory=connect,
        )
        telemetry = PostgresPipelineTelemetryObserver(
            database_config_factory=lambda: DatabaseConfig(database_url),
            connection_factory=connect,
        )

        # When
        with connect(database_url) as business, runtime, telemetry:
            if execution_path == "first_cycle":
                summary = run_first_cycle_pipeline(
                    inputs,
                    connection=business,
                    runtime_observer=runtime,
                    telemetry_observer=telemetry,
                )
            else:
                execution = run_standalone_sysmon_jsonl(
                    sysmon_jsonl_path=inputs.sysmon_jsonl_path,
                    output_root=tmp_path / "output",
                    connection=business,
                    runtime_observer=runtime,
                    telemetry_observer=telemetry,
                )
                business.commit()
                execution.complete_runtime()
                summary = execution.summary

    # Then
    with connect(database_url) as verification:
        rows = verification.execute(
            "SELECT execution_id FROM pipeline_telemetry_executions"
        ).fetchall()
        assert len(rows) == 1
        repository = PipelineTelemetryRepository(verification)
        snapshot = repository.get_execution(rows[0][0])
        assert snapshot.input_identity is not None
        if execution_path == "sqs_worker":
            assert snapshot.input_identity.kind == "s3_object_sha256_v1"
        else:
            assert snapshot.input_identity.kind == "file_content_sha256_v1"
            assert (
                snapshot.input_identity.sha256
                == hashlib.sha256(inputs.sysmon_jsonl_path.read_bytes()).hexdigest()
            )
        status = PipelineRuntimeStatusRepository(verification).get(
            snapshot.run_id, snapshot.entity_id
        )
        assert status.execution_id == snapshot.execution_id
        assert status.status.value == "completed"
        assert (
            snapshot.input_total == status.input_total == status.normalization_processed_count == 2
        )
        assert sum(bucket.input_accepted_count for bucket in snapshot.buckets) == 2
        assert sum(bucket.processing_completed_count for bucket in snapshot.buckets) == 2
        assert sum(bucket.processing_failed_count for bucket in snapshot.buckets) == 0
        assert sum(bucket.latency_sample_count for bucket in snapshot.buckets) == 2
        assert sum(bucket.latency_sum_ns for bucket in snapshot.buckets) > 0
        assert snapshot.observation_status == "observed"
        assert verification.execute("SELECT count(*) FROM events").fetchone() == (2,)
        assert verification.execute("SELECT count(*) FROM decisions").fetchone() == (1,)
        assert not repository.save_snapshot(snapshot)
        if execution_path != "first_cycle":
            assert verification.execute(
                "SELECT detector_status FROM detection_results"
            ).fetchone() == ("not_evaluated",)
        if execution_path == "sqs_worker":
            assert verification.execute("SELECT count(*) FROM s3_object_receipts").fetchone() == (
                1,
            )
            assert queue.deleted == ["test-receipt", "test-receipt"]
        else:
            assert summary.normalized_event_count == 2
            assert summary.run_id == snapshot.run_id


def test_failed_normalization_persists_partial_work_and_original_exception(
    database_url,
    telemetry_database,
    tmp_path,
    monkeypatch,
) -> None:
    # Given
    connect = telemetry_database
    inputs = _telemetry_inputs(tmp_path)
    error = RuntimeError("original Evidence failure")
    extract = event_evidence.extract_evidence
    calls = [0]

    def fail_second(event):
        calls[0] += 1
        if calls[0] == 2:
            raise error
        return extract(event)

    monkeypatch.setattr(event_evidence, "extract_evidence", fail_second)
    runtime = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )
    telemetry = PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )

    # When
    with (
        connect(database_url) as business,
        runtime,
        telemetry,
        pytest.raises(RuntimeError) as exc_info,
    ):
        run_first_cycle_pipeline(
            inputs,
            connection=business,
            runtime_observer=runtime,
            telemetry_observer=telemetry,
        )

    # Then
    assert exc_info.value is error
    with connect(database_url) as verification:
        identity = verification.execute(
            "SELECT execution_id FROM pipeline_telemetry_executions"
        ).fetchone()[0]
        snapshot = PipelineTelemetryRepository(verification).get_execution(identity)
        status = PipelineRuntimeStatusRepository(verification).get(
            snapshot.run_id, snapshot.entity_id
        )
        assert status.status.value == "failed"
        assert status.failed_stage.value == "normalization"
        assert status.normalization_processed_count == 1
        assert sum(bucket.processing_completed_count for bucket in snapshot.buckets) == 1
        assert sum(bucket.processing_failed_count for bucket in snapshot.buckets) == 1
        assert sum(bucket.latency_sample_count for bucket in snapshot.buckets) == 1
        assert verification.execute("SELECT count(*) FROM runs").fetchone() == (0,)


def test_pipeline_recovers_from_telemetry_db_error_without_changing_business(
    database_url,
    telemetry_database,
    tmp_path,
) -> None:
    # Given
    connect = telemetry_database
    inputs = _telemetry_inputs(tmp_path)
    writer_connections = []

    def writer_connect(url):
        connection = connect(url)
        writer_connections.append(connection)
        if len(writer_connections) == 1:
            connection.execute(
                sql.SQL("SET search_path TO {}").format(
                    sql.Identifier(f"missing_telemetry_schema_{uuid4().hex}")
                )
            )
        return connection

    runtime = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )
    telemetry = PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=writer_connect,
    )

    # When
    with connect(database_url) as business, runtime, telemetry:
        summary = run_first_cycle_pipeline(
            inputs,
            connection=business,
            runtime_observer=runtime,
            telemetry_observer=telemetry,
        )

    # Then
    assert len(writer_connections) == 2
    assert all(connection.closed for connection in writer_connections)
    with connect(database_url) as verification:
        snapshot = PipelineTelemetryRepository(verification).list_executions(
            summary.run_id, summary.entity_id
        )[0]
        status = PipelineRuntimeStatusRepository(verification).get(
            summary.run_id, summary.entity_id
        )
        assert status.status.value == "completed"
        assert snapshot.execution_id == status.execution_id
        assert snapshot.observation_status == "partial"
        assert [issue.value for issue in snapshot.observation_issues] == ["storage_error"]
        assert not snapshot.collection_disabled
        assert sum(bucket.processing_completed_count for bucket in snapshot.buckets) == 2
        assert sum(bucket.latency_sample_count for bucket in snapshot.buckets) == 2
        assert verification.execute("SELECT count(*) FROM decisions").fetchone() == (1,)


def test_business_persistence_failure_does_not_erase_processing_observations(
    database_url,
    telemetry_database,
    tmp_path,
    monkeypatch,
) -> None:
    # Given
    connect = telemetry_database
    inputs = _telemetry_inputs(tmp_path)
    error = RuntimeError("original Business persistence failure")

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(runner, "persist_s0_results", fail)
    runtime = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )
    telemetry = PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )

    # When
    with (
        connect(database_url) as business,
        runtime,
        telemetry,
        pytest.raises(RuntimeError) as exc_info,
    ):
        run_first_cycle_pipeline(
            inputs,
            connection=business,
            runtime_observer=runtime,
            telemetry_observer=telemetry,
        )

    # Then
    assert exc_info.value is error
    with connect(database_url) as verification:
        identity = verification.execute(
            "SELECT execution_id FROM pipeline_telemetry_executions"
        ).fetchone()[0]
        snapshot = PipelineTelemetryRepository(verification).get_execution(identity)
        status = PipelineRuntimeStatusRepository(verification).get(
            snapshot.run_id, snapshot.entity_id
        )
        assert status.status.value == "failed"
        assert status.failed_stage.value == "persistence"
        assert snapshot.observation_status == "observed"
        assert sum(bucket.processing_completed_count for bucket in snapshot.buckets) == 2
        assert sum(bucket.processing_failed_count for bucket in snapshot.buckets) == 0
        assert verification.execute("SELECT count(*) FROM runs").fetchone() == (0,)


def _s3_event_body(key: str, e_tag: str) -> str:
    return json.dumps(
        {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {"name": "test-inputs"},
                        "object": {"key": key, "eTag": e_tag, "sequencer": "001"},
                    },
                }
            ]
        }
    )


@pytest.mark.parametrize("failed_step", ["business_persistence", "receipt_commit"])
def test_run_scope_does_not_combine_a_rolled_back_input_with_the_next_input(
    database_url,
    telemetry_database,
    tmp_path,
    monkeypatch,
    failed_step,
) -> None:
    """Reproduce P2-1 through the SQS Worker; preconditions fail loudly if the flow changes."""
    # Given
    connect = telemetry_database
    run_id = "RUN-20261014-001"
    source = (FIXTURE_ROOT / "sysmon-0001.jsonl").read_text(encoding="utf-8")
    input_a = "incoming/first-cycle/sysmon/ING-11111111-1111-4111-8111-111111111111/sysmon.jsonl"
    input_b = "incoming/first-cycle/sysmon/ING-22222222-2222-4222-8222-222222222222/sysmon.jsonl"
    objects = {input_a: source, input_b: source.splitlines(keepends=True)[0]}
    deliveries = [
        (input_a, "input-a-version", "receipt-a"),
        (input_b, "input-b-version", "receipt-b"),
    ]
    monkeypatch.setenv(DATABASE_URL_ENV, database_url)
    monkeypatch.setenv("INCIDENT_AWARENESS_SQS_QUEUE_URL", "test-queue")
    monkeypatch.setenv("INCIDENT_AWARENESS_S3_INPUT_BUCKET", "test-inputs")
    monkeypatch.setattr(sqs_worker.psycopg, "connect", connect)

    class Queue:
        def __init__(self):
            self.deleted = []

        def receive_message(self, **kwargs):
            key, e_tag, handle = deliveries.pop(0)
            return {"Messages": [{"Body": _s3_event_body(key, e_tag), "ReceiptHandle": handle}]}

        def delete_message(self, **kwargs):
            self.deleted.append(kwargs["ReceiptHandle"])
            return {}

    class S3:
        def download_file(self, bucket, key, filename):
            Path(filename).write_text(objects[key], encoding="utf-8", newline="")

    queue = Queue()
    monkeypatch.setattr(sqs_worker.boto3, "client", lambda name: queue if name == "sqs" else S3())
    allocate = standalone_module._allocate_identifiers
    monkeypatch.setattr(
        standalone_module,
        "_allocate_identifiers",
        lambda connection, output_root: allocate(
            connection, output_root, now=datetime(2026, 10, 14, 1, tzinfo=UTC)
        ),
    )
    failures = []
    if failed_step == "business_persistence":
        persist = standalone_module.persist_s0_results

        def fail_once(*args, **kwargs):
            if not failures:
                failures.append(failed_step)
                raise RuntimeError("injected Business persistence failure")
            return persist(*args, **kwargs)

        monkeypatch.setattr(standalone_module, "persist_s0_results", fail_once)
    else:
        save_success = S3ObjectReceiptRepository.save_success

        def fail_once(self, **kwargs):
            if not failures:
                failures.append(failed_step)
                raise psycopg.OperationalError("injected Receipt failure before commit")
            return save_success(self, **kwargs)

        monkeypatch.setattr(S3ObjectReceiptRepository, "save_success", fail_once)

    # When
    assert sqs_worker.main(["--once"]) == 0  # Input A is rolled back and retained in SQS.
    assert sqs_worker.main(["--once"]) == 0  # Different input B is committed.

    # Then
    with connect(database_url) as verification:
        attempts = verification.execute(
            "SELECT execution_id, run_id, input_total FROM pipeline_telemetry_executions "
            "ORDER BY input_accepted_at, execution_id"
        ).fetchall()
        committed_runs = verification.execute("SELECT run_id FROM runs").fetchall()
        receipts = verification.execute(
            "SELECT object_key, run_id FROM s3_object_receipts"
        ).fetchall()
        runtime = PipelineRuntimeStatusRepository(verification).list_for_run(run_id)
        _start, end = verification.execute(
            "SELECT min(bucket_start), max(bucket_end) FROM pipeline_telemetry_buckets"
        ).fetchone()
        reader = DashboardTelemetryReader(
            PipelineTelemetryRepository(verification), clock=lambda: end.astimezone(UTC)
        )
        app = create_app()
        app.dependency_overrides[get_dashboard_telemetry_reader] = lambda: reader
        with TestClient(app) as client:
            response = client.get(
                "/operations/telemetry",
                params={
                    "scope": "run",
                    "run_id": run_id,
                    "end_at": end.astimezone(UTC).isoformat(),
                },
            )
        identities = verification.execute(
            "SELECT input_identity_kind, input_identity_sha256 FROM pipeline_telemetry_executions"
        ).fetchall()
    assert failures == [failed_step]
    assert [(row[1], row[2]) for row in attempts] == [(run_id, 2), (run_id, 1)]
    assert committed_runs == [(run_id,)]
    assert receipts == [(input_b, run_id)]
    assert queue.deleted == ["receipt-b"]
    assert [status.execution_id for status in runtime] == [attempts[1][0]]
    assert response.status_code == 409
    assert response.json() == {
        "detail": "Run telemetry input identity is conflicting or unknown across executions"
    }
    assert len(set(identities)) == 2
    assert {row[0] for row in identities} == {"s3_object_sha256_v1"}
    assert input_a not in response.text and input_b not in response.text


def test_missing_telemetry_schema_disables_only_timeseries_after_three_attempts(
    database_url,
    telemetry_database,
    tmp_path,
) -> None:
    # Given
    connect = telemetry_database
    inputs = _telemetry_inputs(tmp_path)
    writer_connections = []
    missing_schema = sql.Identifier(f"missing_telemetry_schema_{uuid4().hex}")

    def writer_connect(url):
        connection = connect(url)
        connection.execute(sql.SQL("SET search_path TO {}").format(missing_schema))
        writer_connections.append(connection)
        return connection

    runtime = PostgresPipelineRuntimeObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=connect,
    )
    telemetry = PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig(database_url),
        connection_factory=writer_connect,
    )

    # When
    with connect(database_url) as business, runtime, telemetry:
        summary = run_first_cycle_pipeline(
            inputs,
            connection=business,
            runtime_observer=runtime,
            telemetry_observer=telemetry,
        )

    # Then
    assert len(writer_connections) == 3
    assert all(connection.closed for connection in writer_connections)
    assert telemetry.is_disabled
    with connect(database_url) as verification:
        status = PipelineRuntimeStatusRepository(verification).get(
            summary.run_id, summary.entity_id
        )
        assert status.status.value == "completed"
        assert verification.execute(
            "SELECT count(*) FROM pipeline_telemetry_executions"
        ).fetchone() == (0,)
        assert verification.execute("SELECT count(*) FROM decisions").fetchone() == (1,)
