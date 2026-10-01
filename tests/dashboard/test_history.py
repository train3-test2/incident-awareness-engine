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

    def fetchall(self):
        return self.value


class Database:
    def __init__(self, *values):
        self.values = iter(values)
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))
        return Cursor(next(self.values))


def row(identifier, supersedes=None):
    return {
        "created_at": datetime(2026, 10, 1, tzinfo=UTC),
        "payload": {
            "run_id": "RUN-20260927-002",
            "decision_id": identifier,
            "entity_id": "WIN-01",
            "fast_status": "miss",
            "fusion_status": "miss",
            "detector_time": None,
            "fusion_time": None,
            "t_e": None,
            "decision_path": "none",
            "winning_path": "none",
            "decision_reason": "fixture",
            "config_version": "v1",
            "supersedes_decision_id": supersedes,
        },
    }


def test_history_binds_run_and_page_preserves_explicit_replacement():
    run = "RUN-20260927-002"
    db = Database({"run_id": run}, {"count": 30}, [row("D-002", "D-001"), row("D-001")])
    result = DashboardQueries(db).decisions(run, 2, 20)
    assert result["total"] == 30
    assert result["offset"] == 20
    assert result["items"][0]["supersedes_decision_id"] == "D-001"
    assert result["items"][1]["supersedes_decision_id"] is None
    assert result["items"][0]["created_at"] == "2026-10-01T00:00:00Z"
    assert db.calls[-1][1] == (run, 2, 20)
    assert "ORDER BY created_at DESC, decision_id DESC" in db.calls[-1][0]
    assert all(params[0] == run for _, params in db.calls)


def test_missing_run_is_not_empty_history():
    with pytest.raises(MissingResource, match="RUN_NOT_FOUND"):
        DashboardQueries(Database(None)).decisions("unknown", 20, 0)


def test_existing_run_without_history():
    result = DashboardQueries(Database({"run_id": "R"}, {"count": 0}, [])).decisions("R", 20, 0)
    assert result == {"items": [], "total": 0, "limit": 20, "offset": 0}


def test_history_http_auth_page_validation_and_response(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(
        Database({"run_id": "R"}, {"count": 0}, [])
    )
    headers = {"Authorization": "Bearer test-token"}
    try:
        with TestClient(app) as client:
            assert client.get("/api/runs/R/decisions").status_code == 401
            for query in ("limit=0", "limit=101", "offset=-1"):
                assert (
                    client.get(f"/api/runs/R/decisions?{query}", headers=headers).status_code == 400
                )
            result = client.get("/api/runs/R/decisions", headers=headers)
            assert result.status_code == 200
            assert result.json()["items"] == []
    finally:
        app.dependency_overrides.clear()
