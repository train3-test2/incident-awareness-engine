import json
import os
import shutil
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import Connection, sql

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_database_connection
from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.runner import run_first_cycle_pipeline
from incident_awareness.pipeline.runtime_telemetry import PostgresPipelineRuntimeObserver
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations

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
