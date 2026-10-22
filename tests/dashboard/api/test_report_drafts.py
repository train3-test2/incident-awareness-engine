from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import report_drafts as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.reporting.store import ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv("IAE_MONOROUTER_ENABLED", "0")
    app = create_app()
    app.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(
        tmp_path / "drafts.sqlite3"
    )
    source = synthetic_report_input()
    monkeypatch.setattr(api, "load_report_input", lambda alert_id: source)
    return TestClient(app), source, tmp_path


def request(client, version=1, key=None, **extra):
    return client.post(
        "/human-workflow/alerts/SYNTHETIC-ALERT-001/report-drafts",
        json={"expected_version": version, "idempotency_key": str(key or uuid4()), **extra},
    )


def test_api_draft_generation_and_new_process_store_restore(client, monkeypatch):
    http, source, tmp_path = client
    key = uuid4()
    response = request(http, key=key)
    assert response.status_code == 200, response.text
    assert response.json()["method"] == "jinja2_fallback"
    assert response.json()["submission_status"] == "not_submitted"
    assert request(http, key=key).json()["draft_id"] == response.json()["draft_id"]

    @contextmanager
    def repository():
        yield SimpleNamespace(detail=lambda alert_id: {"state": source.human_state})

    monkeypatch.setattr(api, "repository", repository)
    fresh = create_app()
    fresh.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(
        tmp_path / "drafts.sqlite3"
    )
    result = TestClient(fresh).get("/human-workflow/alerts/SYNTHETIC-ALERT-001/report-drafts")
    assert result.status_code == 200
    assert result.json()["items"][0]["draft"]["draft_id"] == response.json()["draft_id"]
    source.human_state["report_choice"] = "hold"
    result = TestClient(fresh).get("/human-workflow/alerts/SYNTHETIC-ALERT-001/report-drafts")
    assert not result.json()["items"][0]["current"]


def test_stale_workflow_version_is_409(client):
    http, _, _ = client
    assert request(http, version=2).status_code == 409


@pytest.mark.parametrize("choice", [None, "hold", "do_not_proceed"])
def test_actual_database_read_gate_prevents_generation(client, monkeypatch, choice):
    http, source, _ = client
    source.human_state["report_choice"] = choice
    # Exercise the real API loader, not the fixture override.
    monkeypatch.undo()
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")

    @contextmanager
    def repository():
        yield SimpleNamespace(detail=lambda alert_id: {"state": source.human_state})

    monkeypatch.setattr(api, "repository", repository)
    response = request(http)
    assert response.status_code == 409


@pytest.mark.parametrize(
    "extra",
    [
        {"synthetic": True},
        {"api_key": "forged"},
        {"report_input": {}},
        {"endpoint": "https://example.org"},
    ],
)
def test_browser_cannot_supply_classification_secrets_or_provider_settings(client, extra):
    http, _, _ = client
    assert request(http, **extra).status_code == 422


def test_remote_actor_cannot_access_drafts(client, monkeypatch):
    http, _, _ = client
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "0")
    assert request(http).status_code == 403
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    result = http.post(
        "/human-workflow/alerts/A/report-drafts",
        headers={"Origin": "https://evil.example"},
        json={},
    )
    assert result.status_code == 403


@pytest.mark.parametrize("consent", [None, False, 1, "true"])
def test_synthetic_requires_explicit_boolean_consent_before_storage(client, consent):
    http, _, path = client
    body = {"expected_version": 1, "idempotency_key": str(uuid4())}
    if consent is not None:
        body["allow_external_synthetic"] = consent
    response = http.post("/human-workflow/reporting/synthetic/ANCHOR/drafts", json=body)
    assert response.status_code == 422
    assert not (path / "drafts.sqlite3").exists()


def test_synthetic_server_gate_and_stale_anchor(client):
    http, _, path = client
    body = {
        "expected_version": 1,
        "idempotency_key": str(uuid4()),
        "allow_external_synthetic": True,
    }
    route = "/human-workflow/reporting/synthetic/ANCHOR/drafts"
    assert http.post(route, json=body).status_code == 409
    assert http.post(route, json={**body, "expected_version": 2}).status_code == 409
    assert not (path / "drafts.sqlite3").exists()


def test_synthetic_route_uses_only_code_owned_fixture_and_persists_consent(client, monkeypatch):
    from incident_awareness.dashboard.human_workflow import fingerprint

    http, anchor, path = client
    anchor = anchor.model_copy(deep=True)
    anchor.run_id = "PRIVATE-ANCHOR-RUN"
    anchor.human_state["report_reason"] = "PRIVATE-REASON"
    monkeypatch.setattr(api, "load_report_input", lambda _: anchor)
    monkeypatch.setattr(api, "reporting_status", lambda _: {"synthetic_transmission_enabled": True})
    calls = []
    original = api.GroundedReportService

    def service(store):
        instance = original(store)
        generate = instance.generate

        def checked(source, key, version, reload):
            assert source.model_dump(mode="json") == synthetic_report_input().model_dump(
                mode="json"
            )
            assert "PRIVATE" not in source.model_dump_json()
            calls.append(source)
            return generate(source, key, version, reload)

        instance.generate = checked
        return instance

    monkeypatch.setattr(api, "GroundedReportService", service)
    body = {
        "expected_version": 1,
        "idempotency_key": str(uuid4()),
        "allow_external_synthetic": True,
    }
    route = "/human-workflow/reporting/synthetic/ANCHOR/drafts"
    first = http.post(route, json=body)
    assert first.status_code == 200
    assert http.post(route, json=body).json() == first.json()
    assert len(calls) == 2
    store = ReportDraftStore(path / "drafts.sqlite3")
    with store.connect() as connection:
        rows = connection.execute("SELECT * FROM report_external_consents").fetchall()
    assert len(rows) == 1
    assert rows[0]["actor_id"] == "local-demo-analyst"
    assert rows[0]["fixture_sha256"] == fingerprint(
        synthetic_report_input().model_dump(mode="json")
    )


def test_status_separates_historical_verification_from_transmission(client, monkeypatch):
    from incident_awareness.reporting.contracts import CallMetadata, canonical_output
    from incident_awareness.reporting.monorouter import ProviderResult

    http, source, path = client
    store = ReportDraftStore(path / "history.sqlite3")

    class VerifiedAdapter:
        def generate(self, source, record_attempt):
            return ProviderResult(
                CallMetadata(
                    status="success",
                    http_status=200,
                    actual_model="claude-haiku-4-5-20251001",
                    requested_at="2026-10-20T00:00:00Z",
                    input_tokens=10,
                    output_tokens=20,
                ),
                canonical_output(source).model_dump_json(),
            )

    api.GroundedReportService(store, VerifiedAdapter()).generate(source, uuid4(), 1, lambda: source)
    monkeypatch.setenv("IAE_MONOROUTER_VERIFICATION_STORE_PATH", str(store.path))
    monkeypatch.setenv("IAE_MONOROUTER_API_KEY", "SYNTHETIC-SECRET-NOT-REAL")
    result = http.get("/human-workflow/reporting/status")
    assert result.status_code == 200
    status = result.json()
    assert status["adapter"] == "configured"
    assert status["connection_verification"]["actual_model"] == "claude-haiku-4-5-20251001"
    assert not status["synthetic_transmission_enabled"]
    assert not status["actual_workflow_transmission_allowed"]
    assert status["verification_meaning"] == "historical_synthetic_request_not_live_health"
    assert "SYNTHETIC-SECRET" not in result.text and "history.sqlite3" not in result.text
