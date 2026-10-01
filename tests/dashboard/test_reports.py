from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from incident_awareness.dashboard.app import app, get_report_store
from incident_awareness.dashboard.queries import MissingResource
from incident_awareness.dashboard.reports import (
    ReportConflict,
    ReportFields,
    ReportStore,
    SaveReport,
)


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class DB:
    def __init__(self, *rows):
        self.rows = iter(rows)
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))
        return Cursor(next(self.rows))


def source():
    return {
        "created_at": datetime(2026, 10, 1, tzinfo=UTC),
        "payload": {
            "run_id": "RUN-20260927-002",
            "decision_id": "D-1",
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
        },
    }


@pytest.mark.parametrize("value", [123, "123", "2026-10-01T12:00:00"])
def test_awareness_requires_explicit_time_zone(value):
    with pytest.raises(ValidationError):
        ReportFields(awareness_at=value)


def test_awareness_converts_kst_and_does_not_default_consent():
    fields = ReportFields(awareness_at="2026-10-01T12:00:00+09:00")
    assert fields.awareness_at == datetime(2026, 10, 1, 3, tzinfo=UTC)
    assert fields.personal_data_consent is None
    assert fields.technical_support_consent is None
    assert fields.occurred_at is None


@pytest.mark.parametrize(
    "fields",
    [
        {"t_e": "2026-10-01T00:00:00Z"},
        {"personal_data_consent": "true"},
        {"affected_pc_count": -1},
        {"affected_pc_count": True},
        {"incident_type": "unknown"},
        {"company_name": "x" * 501},
    ],
)
def test_invalid_fields_rejected(fields):
    with pytest.raises(ValidationError):
        ReportFields(**fields)


def test_missing_draft_returns_empty_fields_not_inferred_times():
    db = DB(source(), None)
    result = ReportStore(db).get("RUN-20260927-002", "D-1")
    assert result["revision"] == 0
    assert result["availability"] == "missing"
    assert result["fields"]["awareness_at"] is None
    assert result["status"] == "draft"


def test_cross_run_decision_fails_before_write():
    db = DB(None)
    with pytest.raises(MissingResource):
        ReportStore(db).save("other", "D-1", SaveReport(expected_revision=0, fields={}))
    assert len(db.calls) == 1
    assert db.calls[0][1] == ("other", "D-1")


def test_new_report_has_source_snapshot_and_conflict_is_not_overwritten():
    db = DB(source(), None)
    with pytest.raises(ReportConflict):
        ReportStore(db).save("R", "D-1", SaveReport(expected_revision=0, fields={}))
    sql, params = db.calls[-1]
    assert "DO NOTHING" in sql
    assert params[3].obj["decision_id"] == "D-1"


def test_update_requires_revision_and_preserves_snapshot():
    db = DB(source(), None)
    with pytest.raises(ReportConflict):
        ReportStore(db).save(
            "R", "D-1", SaveReport(expected_revision=2, fields={"company_name": "demo"})
        )
    sql, params = db.calls[-1]
    assert "AND revision = %s" in sql
    assert params[1:] == ("R", "D-1", 2)
    assert "source_decision =" not in sql
    assert params[0].obj["company_name"] == "demo"


def test_successful_save_returns_persisted_revision():
    saved = {
        "revision": 3,
        "fields": {"company_name": "demo"},
        "source_decision": {},
        "updated_at": datetime(2026, 10, 1, tzinfo=UTC),
    }
    result = ReportStore(DB(source(), saved)).save(
        "R", "D-1", SaveReport(expected_revision=2, fields={})
    )
    assert result["revision"] == 3
    assert result["updated_at"] == "2026-10-01T00:00:00Z"


def test_report_http_auth_validation_and_conflict(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    app.dependency_overrides[get_report_store] = lambda: ReportStore(DB(source(), None))
    url = "/api/runs/R/decisions/D-1/report"
    headers = {"Authorization": "Bearer test-token"}
    try:
        with TestClient(app) as client:
            assert client.put(url, json={}).status_code == 401
            invalid = client.put(
                url, headers=headers, json={"expected_revision": 0, "fields": {"t_e": "fake"}}
            )
            assert invalid.status_code == 400
            assert invalid.json()["error"]["code"] == "INVALID_REPORT"
            conflict = client.put(url, headers=headers, json={"expected_revision": 0, "fields": {}})
            assert conflict.status_code == 409
            result = client.get(url, headers=headers)
            assert result.status_code == 200
            assert result.json()["availability"] == "missing"
    finally:
        app.dependency_overrides.clear()


def test_commit_failure_does_not_return_success(monkeypatch):
    import psycopg

    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")

    class Store:
        def save(self, *args):
            return {"revision": 1}

    def fails_on_commit():
        yield Store()
        raise psycopg.OperationalError("commit failed with private connection details")

    app.dependency_overrides[get_report_store] = fails_on_commit
    try:
        with TestClient(app) as client:
            response = client.put(
                "/api/runs/R/decisions/D/report",
                headers={"Authorization": "Bearer test-token"},
                json={"expected_revision": 0, "fields": {}},
            )
            assert response.status_code == 503
            assert "private" not in response.text
    finally:
        app.dependency_overrides.clear()
