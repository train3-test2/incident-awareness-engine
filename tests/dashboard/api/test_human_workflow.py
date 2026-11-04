from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import human_workflow as api
from incident_awareness.dashboard.api.app import create_app


@pytest.mark.parametrize(
    "mode,host,origin,status",
    [
        ("0", "testserver", None, 403),
        ("1", "external.example", None, 403),
        ("1", "testserver", "http://evil.example", 403),
        ("1", "testserver", "null", 403),
    ],
)
def test_actor_boundary(monkeypatch, mode, host, origin, status):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", mode)

    def forbidden():
        raise AssertionError("Rejected clients must not open a DB connection")

    monkeypatch.setattr(api, "repository", forbidden)
    headers = {"origin": origin} if origin else {}
    response = TestClient(create_app(), base_url=f"http://{host}").post(
        "/human-workflow/runs/RUN-20261019-007/sync", headers=headers
    )
    assert response.status_code == status


def test_unavailable_database_is_actionable_and_does_not_expose_secrets(monkeypatch):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_DATABASE_URL", "postgresql://test:secret@127.0.0.1:1/test"
    )
    response = TestClient(create_app()).get("/human-workflow/runs/R/alerts")
    assert response.status_code == 503
    assert "secret" not in response.text


def test_missing_input_rejected_before_repository(monkeypatch):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")

    def forbidden():
        raise AssertionError("Invalid requests must not open a DB connection")

    monkeypatch.setattr(api, "repository", forbidden)
    response = TestClient(create_app()).post("/human-workflow/alerts/A/actions", json={})
    assert response.status_code == 422


class _ReadOnlyAlerts:
    def __init__(self, alerts):
        self.alerts = alerts
        self.calls = []

    def read(self, run_ids):
        self.calls.append(run_ids)
        return [{"run_id": run_id, "alerts": self.alerts.get(run_id, [])} for run_id in run_ids]

    def synchronize(self, *_args, **_kwargs):
        raise AssertionError("List summaries must never create alerts")


def _stored_alert(run_id):
    return {
        "alert_id": "HWA-1",
        "run_id": run_id,
        "entity_id": "WIN-01",
        "detection_kind": "fusion",
        "issued_at": "2026-10-21T04:47:24.084884Z",
        "state": {"version": 4, "report_choice": "proceed"},
        "source_key": "decision:DEC-1",
        "source_snapshot": {"evidence_ids": ["E-A"]},
        "audit": [{"version": 4, "command": {"reason": "검토"}}],
        "operational_24h": {"status": "within_24h"},
    }


def test_alert_summaries_read_listed_runs_without_sync_or_audit(monkeypatch):
    # Given
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    repo = _ReadOnlyAlerts({"RUN-20261021-901": [_stored_alert("RUN-20261021-901")]})

    @contextmanager
    def read_only():
        yield repo

    monkeypatch.setattr(api, "read_only_repository", read_only)
    monkeypatch.setattr(api, "repository", lambda: pytest.fail("Summaries use the read-only path"))
    # When
    response = TestClient(create_app()).get(
        "/human-workflow/alert-summaries",
        params=[("run_id", "RUN-20261021-901"), ("run_id", "RUN-20261021-902")],
    )
    # Then: an unselected Run simply has no stored alert yet.
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "human_workflow_alert_summaries_v1"
    assert repo.calls == [["RUN-20261021-901", "RUN-20261021-902"]]
    assert payload["items"][1] == {"run_id": "RUN-20261021-902", "alerts": []}
    alert = payload["items"][0]["alerts"][0]
    assert set(alert) == {"alert_id", "run_id", "entity_id", "detection_kind", "issued_at", "state"}
    assert alert["state"] == {"version": 4, "report_choice": "proceed"}


@pytest.mark.parametrize(
    "params", [[], [("run_id", "R")] * 2, [("run_id", f"R-{i}") for i in range(21)]]
)
def test_alert_summaries_reject_unbounded_scopes_before_database(monkeypatch, params):
    # Given
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setattr(api, "read_only_repository", lambda: pytest.fail("No DB on invalid scope"))
    # When
    response = TestClient(create_app()).get("/human-workflow/alert-summaries", params=params)
    # Then
    assert response.status_code == 422


def test_alert_summaries_keep_the_local_actor_boundary(monkeypatch):
    # Given
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "0")
    monkeypatch.setattr(api, "read_only_repository", lambda: pytest.fail("Rejected before DB"))
    # When
    response = TestClient(create_app()).get(
        "/human-workflow/alert-summaries", params={"run_id": "RUN-20261021-901"}
    )
    # Then
    assert response.status_code == 403


def test_alert_summary_transaction_is_read_only(monkeypatch):
    # Given
    options, statements = [], []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, statement, *_args):
            statements.append(statement)

    def connect(_url, **kwargs):
        options.append(kwargs["options"])
        return Connection()

    monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", "postgresql://t:t@127.0.0.1:1/t")
    monkeypatch.setattr(api.psycopg, "connect", connect)
    # When
    with api.read_only_repository():
        pass
    # Then
    assert "default_transaction_read_only=on" in options[0]
    assert statements == ["SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"]


def test_alert_summary_reader_uses_one_query_without_detail_audit_or_sync():
    # Given
    statements = []
    stored = _stored_alert("R2")

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, statement, params):
            statements.append((statement, params))
            return self

        def fetchall(self):
            return [
                {key: stored[key] for key in api.ALERT_SUMMARY_KEYS},
                {
                    "alert_id": "A0",
                    "run_id": "R1",
                    "entity_id": "H1",
                    "detection_kind": "fusion",
                    "issued_at": stored["issued_at"],
                    "state": None,
                },
            ]

    class Connection:
        def cursor(self, **kwargs):
            return Cursor()

    # When
    items = api.StoredAlertSummaryReader(Connection()).read(["R1", "R2", "R3"])

    # Then
    assert len(statements) == 1
    statement, params = statements[0]
    assert params == (["R1", "R2", "R3"], 100)
    assert "ANY(%s)" in statement
    assert "ORDER BY version DESC LIMIT 1" in statement
    assert "PARTITION BY run_id" in statement
    assert "source_snapshot" not in statement and "command" not in statement
    assert [item["run_id"] for item in items] == ["R1", "R2", "R3"]
    assert items[0]["alerts"][0]["state"]["version"] == 0
    assert items[1]["alerts"][0]["state"] == stored["state"]
    assert items[2]["alerts"] == []
