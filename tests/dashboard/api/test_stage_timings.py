from datetime import UTC, datetime

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.dashboard.api import dependencies
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_stage_timing_reader
from incident_awareness.dashboard.stage_timing_read_model import DashboardStageTimingReader
from incident_awareness.pipeline.stage_timing import (
    PipelineStageTimingCollector,
    start_stage_timing,
)
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
)


class Connection:
    def __init__(self, row=(None, None, False), error=None):
        self.row = row
        self.error = error
        self.calls = []
        self.closed = False

    def execute(self, query, params=()):
        self.calls.append((query, params))
        if self.error:
            raise self.error
        return self

    def fetchone(self):
        return self.row

    def close(self):
        self.closed = True


def client(connection):
    app = create_app()
    app.dependency_overrides[get_dashboard_stage_timing_reader] = lambda: (
        DashboardStageTimingReader(PipelineStageTimingRepository(connection))
    )
    return TestClient(app)


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?execution_id=",
        "?execution_id=%20",
        "?execution_id=%20x",
        "?execution_id=x&run_id=y",
        "?execution_id=" + "x" * 513,
    ],
)
def test_invalid_query_does_not_open_database(monkeypatch, query):
    # Given
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid query must not connect")

    monkeypatch.setattr(dependencies.psycopg, "connect", forbidden)
    # When / Then
    assert TestClient(create_app()).get("/operations/stage-timings" + query).status_code == 422


@pytest.mark.parametrize("known,expected", [(False, 404), (True, 200)])
def test_unknown_execution_is_distinct_from_known_execution_without_timing(known, expected):
    # Given
    connection = Connection((None, None, known))
    # When
    response = client(connection).get("/operations/stage-timings?execution_id=fixture")
    # Then
    assert response.status_code == expected
    assert connection.calls[0][1] == ("fixture",) * 3
    if known:
        assert response.json()["availability"] == "no_stage_timings"
        assert response.json()["snapshot"] is None


@pytest.mark.parametrize(
    "error,status",
    [
        (psycopg.OperationalError("password=private"), 503),
        (psycopg.errors.UndefinedTable("private SQL"), 500),
        (psycopg.errors.InsufficientPrivilege("private role"), 500),
    ],
)
def test_read_failures_are_not_empty_data_and_do_not_leak_details(error, status):
    # Given
    connection = Connection(error=error)
    # When
    response = client(connection).get("/operations/stage-timings?execution_id=fixture")
    # Then
    assert response.status_code == status
    assert "private" not in response.text


def test_dependency_uses_read_only_bounded_session_and_always_closes(monkeypatch):
    # Given
    connection = Connection()
    calls = []
    monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", "postgresql://test/database")

    def connect(*args, **kwargs):
        calls.append(kwargs)
        return connection

    monkeypatch.setattr(dependencies.psycopg, "connect", connect)
    # When
    response = TestClient(create_app()).get("/operations/stage-timings?execution_id=fixture")
    # Then
    assert response.status_code == 404 and connection.closed
    assert calls[0]["connect_timeout"] == 2 and calls[0]["autocommit"] is False
    assert "default_transaction_read_only=on" in calls[0]["options"]
    assert "statement_timeout=5000" in calls[0]["options"]


@pytest.mark.parametrize("failure", ["missing_config", "connect"])
def test_dependency_configuration_and_connection_failures_are_sanitized(monkeypatch, failure):
    # Given
    monkeypatch.delenv("INCIDENT_AWARENESS_DATABASE_URL", raising=False)
    if failure == "connect":
        monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", "postgresql://test/database")

        def fail(*args, **kwargs):
            raise psycopg.OperationalError("private password URL")

        monkeypatch.setattr(dependencies.psycopg, "connect", fail)
    # When
    response = TestClient(create_app()).get("/operations/stage-timings?execution_id=fixture")
    # Then
    assert response.status_code == (503 if failure == "connect" else 500)
    assert "private" not in response.text


def test_invalid_stored_model_and_wrong_execution_are_errors():
    # Given
    timing = start_stage_timing(PipelineStageTimingCollector())
    timing.finish(timing.begin(PipelineStage.FUSION), failed=True)
    timing.bind(execution_id="another", run_id="fixture", entity_id="host")
    # When / Then
    for payload in [{"schema_version": "invalid"}, timing.snapshot().model_dump(mode="json")]:
        response = client(Connection((payload, datetime.now(UTC), True))).get(
            "/operations/stage-timings?execution_id=fixture"
        )
        assert response.status_code == 500


def test_actual_record_model_is_restored_without_duration_or_failure_inference():
    # Given
    timing = start_stage_timing(PipelineStageTimingCollector())
    timing.finish(timing.begin(PipelineStage.FUSION), failed=True)
    timing.bind(execution_id="fixture", run_id="run", entity_id="host")
    payload = timing.snapshot().model_dump(mode="json")
    # When
    response = client(Connection((payload, datetime(2026, 10, 17, tzinfo=UTC), True))).get(
        "/operations/stage-timings?execution_id=fixture"
    )
    # Then
    assert response.status_code == 200
    result = response.json()
    assert result["operation_failure_recorded"] is True
    assert result["snapshot"]["records"][0]["outcome"] == "failed"
    assert result["snapshot"]["records"][0]["duration_ns"] == str(
        payload["records"][0]["duration_ns"]
    )
    assert result["execution_outcome"] == "unknown" and result["coverage_status"] == "not_evaluable"
