from datetime import UTC, datetime

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.app import app, get_queries
from incident_awareness.dashboard.queries import (
    DashboardQueries,
    MissingResource,
    decision,
    timeline,
)


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

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        return Cursor(next(self.values))


RUN = {
    "run_id": "RUN-20260901-001",
    "scenario_id": "S0",
    "run_type": "attack",
    "target_host": "WIN-01",
    "start_time": datetime(2026, 9, 1, tzinfo=UTC),
    "end_time": None,
}


def payload():
    return {
        "run_id": RUN["run_id"],
        "decision_id": "D-001",
        "entity_id": "WIN-01",
        "fast_status": "miss",
        "fusion_status": "miss",
        "fusion_time": None,
        "detector_time": None,
        "t_e": None,
        "decision_path": "none",
        "winning_path": "none",
        "decision_reason": "Both missed",
        "config_version": "v0.2",
    }


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(Database())
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_authentication_required(client):
    assert client.get("/api/runs").status_code == 401
    assert client.get("/api/runs", headers={"Authorization": "Bearer wrong"}).status_code == 401


@pytest.mark.parametrize(
    "url",
    [
        "/api/runs?limit=101",
        "/api/runs?offset=-1",
        "/api/runs?limit=abc",
        "/api/runs/x?event_limit=201",
        "/api/runs/x?decision_id=",
    ],
)
def test_invalid_pagination(client, url):
    response = client.get(url, headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_QUERY"


def test_empty_list_and_no_cache(client):
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(Database({"count": 0}, []))
    response = client.get("/api/runs", headers={"Authorization": "Bearer test-token"})
    assert response.json() == {"items": [], "total": 0, "limit": 20, "offset": 0}
    assert response.headers["cache-control"] == "no-store"


def test_database_error_does_not_expose_details(client):
    def fail():
        raise psycopg.OperationalError("postgresql://secret:password@private-db")

    app.dependency_overrides[get_queries] = fail
    response = client.get("/api/runs", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 503
    assert "password" not in response.text


def test_missing_run(client):
    app.dependency_overrides[get_queries] = lambda: DashboardQueries(Database(None))
    response = client.get("/api/runs/unknown", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "RUN_NOT_FOUND"


def test_list_preserves_missing_decision_and_stable_sort():
    db = Database({"count": 1}, [RUN], None)
    result = DashboardQueries(db).runs(10, 2)
    assert result["items"][0]["latest_decision"] is None
    assert result["items"][0]["has_decision"] is False
    assert "start_time DESC, run_id DESC" in db.calls[1][0]
    assert db.calls[1][1] == (10, 2)
    assert "created_at DESC, decision_id DESC" in db.calls[2][0]


def test_detail_without_decision_does_not_guess_entity():
    db = Database(RUN, None, {"count": 0}, [])
    result = DashboardQueries(db).detail(RUN["run_id"], None, 50, 0)
    assert result["current_entity_results"] is None
    assert result["evidence"]["availability"] == "not_available"
    assert len(db.calls) == 4


def test_explicit_decision_is_scoped_to_run_and_bound():
    db = Database(RUN, None)
    with pytest.raises(MissingResource, match="DECISION_NOT_FOUND"):
        DashboardQueries(db).detail(RUN["run_id"], "' OR 1=1 --", 50, 0)
    assert db.calls[1][1] == (RUN["run_id"], "' OR 1=1 --")
    assert "AND decision_id = %s" in db.calls[1][0]


def test_historical_decision_current_results_and_event_page_are_separate():
    row = {"payload": payload(), "created_at": RUN["start_time"]}
    db = Database(RUN, row, None, None, {"count": 8}, [])
    result = DashboardQueries(db).detail(RUN["run_id"], "D-001", 2, 4)
    assert result["selected_decision"]["fast_status"] == "miss"
    assert result["current_entity_results"]["fast"] == {"availability": "missing", "value": None}
    assert result["current_entity_results"]["relation_to_selected_decision"] == "unverified"
    assert result["timeline"]["total_event_count"] == 8
    assert result["timeline"]["event_scope"] == "returned_page"
    assert db.calls[-1][1] == (RUN["run_id"], 2, 4)


def test_not_evaluated_is_not_miss():
    value = payload()
    value.update(fast_status="not_evaluated", decision_path=None, winning_path=None)
    result = decision({"payload": value, "created_at": RUN["start_time"]})
    assert result["fast_status"] == "not_evaluated"
    assert result["decision_path"] is None


def test_timeline_sorts_instants_with_different_fraction_precision():
    run = {"run_id": "R", "start_time": "2026-09-01T00:00:00Z", "end_time": None}
    selected = {
        "decision_id": "D",
        "detector_time": "2026-09-01T00:00:00.1Z",
        "fusion_time": None,
        "t_e": "2026-09-01T00:00:00.1Z",
    }
    result = timeline(run, selected, [])
    assert result[0]["kind"] == "run_start"
    assert len(result) == 3


def test_database_dependency_uses_read_only_snapshot(monkeypatch):
    from contextlib import contextmanager

    calls = []

    class Connection:
        @contextmanager
        def transaction(self):
            calls.append("begin")
            yield
            calls.append("end")

        def execute(self, sql):
            calls.append(sql)

    @contextmanager
    def connect(dsn, **kwargs):
        assert dsn == "test-dsn"
        yield Connection()

    monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", "test-dsn")
    monkeypatch.setattr(psycopg, "connect", connect)
    dependency = get_queries()
    assert isinstance(next(dependency), DashboardQueries)
    with pytest.raises(StopIteration):
        next(dependency)
    assert calls == [
        "begin",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
        "SET LOCAL statement_timeout = '5s'",
        "end",
    ]
