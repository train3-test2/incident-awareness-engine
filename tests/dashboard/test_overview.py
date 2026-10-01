from fastapi.testclient import TestClient

from incident_awareness.dashboard.app import app, get_queries
from incident_awareness.dashboard.queries import DashboardQueries


class Cursor:
    def __init__(self, value):
        self.value = value

    def fetchall(self):
        return self.value

    def fetchone(self):
        return self.value


class Database:
    def __init__(self, groups, event_count):
        self.groups = groups
        self.event_count = event_count
        self.calls = []

    def execute(self, sql):
        self.calls.append(sql)
        return Cursor(self.groups if "LATERAL" in sql else {"count": self.event_count})


def group(fast, fusion, path, count=1, exists=True):
    return {
        "has_decision": exists,
        "fast_status": fast,
        "fusion_status": fusion,
        "decision_path": path,
        "count": count,
    }


def test_overview_preserves_missing_and_unevaluated_without_pagination():
    db = Database(
        [
            group(None, None, None, 7, False),
            group("not_evaluated", "detected", None, 4),
            group("miss", "miss", "none", 9),
            group("detected", "detected", "fast_and_fusion", 11),
            group("detected", "miss", "fast", 2),
            group("miss", "detected", "fusion", 3),
        ],
        500,
    )
    result = DashboardQueries(db).overview()
    assert result["total_runs"] == 36
    assert result["runs_without_decision"] == 7
    assert result["runs_with_decision"] == 29
    assert result["fast"] == {"detected": 13, "miss": 12, "not_evaluated": 4, "missing": 7}
    assert result["fusion"] == {"detected": 18, "miss": 11, "not_evaluated": 0, "missing": 7}
    assert result["decision_paths"]["not_evaluated"] == 4
    assert result["decision_paths"]["none"] == 9
    for key in ("fast", "fusion", "decision_paths"):
        assert sum(result[key].values()) == 36
    assert result["total_events"] == 500
    assert "ORDER BY created_at DESC, decision_id DESC LIMIT 1" in db.calls[0]
    assert "LEFT JOIN LATERAL" in db.calls[0]


def test_empty_overview_returns_zero_counts():
    result = DashboardQueries(Database([], 0)).overview()
    assert result["total_runs"] == result["total_events"] == 0
    assert all(value == 0 for value in result["decision_paths"].values())


def test_overview_http_auth_and_response(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(Database([], 0))
    try:
        with TestClient(app) as client:
            assert client.get("/api/overview").status_code == 401
            response = client.get("/api/overview", headers={"Authorization": "Bearer test-token"})
            assert response.status_code == 200
            assert response.json()["scope"] == "all_runs"
            assert response.headers["cache-control"] == "no-store"
    finally:
        app.dependency_overrides.clear()
