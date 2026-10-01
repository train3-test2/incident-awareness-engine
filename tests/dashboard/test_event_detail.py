from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.app import app, get_queries
from incident_awareness.dashboard.queries import DashboardQueries, MissingResource


class Cursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return self.value


class Database:
    def __init__(self, *rows):
        self.rows = iter(rows)
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))
        return Cursor(next(self.rows))


def test_event_binds_both_identifiers_and_selects_only_provenance():
    row = {
        "event_id": "E",
        "run_id": "R",
        "timestamp": datetime(2026, 10, 1, tzinfo=UTC),
        "host_id": "WIN-01",
        "event_type": "process_create",
        "provenance": {},
    }
    db = Database({"run_id": "R"}, row)
    result = DashboardQueries(db).event("R", "E")
    assert result["timestamp"] == "2026-10-01T00:00:00Z"
    sql, params = db.calls[-1]
    assert params == ("R", "E")
    assert "WHERE run_id = %s AND event_id = %s" in sql
    assert "jsonb_build_object" in sql
    assert "payload," not in sql
    for field in ("command_line", "user", "network", "process"):
        assert field not in sql


def test_missing_run():
    with pytest.raises(MissingResource, match="RUN_NOT_FOUND"):
        DashboardQueries(Database(None)).event("R", "E")


def test_event_from_another_run_is_not_returned():
    db = Database({"run_id": "R"}, None)
    with pytest.raises(MissingResource, match="EVENT_NOT_FOUND"):
        DashboardQueries(db).event("R", "E-from-other-run")
    assert db.calls[-1][1] == ("R", "E-from-other-run")


def test_event_http_auth_and_missing(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(
        Database({"run_id": "R"}, None)
    )
    try:
        with TestClient(app) as client:
            assert client.get("/api/runs/R/events/E").status_code == 401
            response = client.get(
                "/api/runs/R/events/E", headers={"Authorization": "Bearer test-token"}
            )
            assert response.status_code == 404
            assert response.json()["error"]["code"] == "EVENT_NOT_FOUND"
    finally:
        app.dependency_overrides.clear()
