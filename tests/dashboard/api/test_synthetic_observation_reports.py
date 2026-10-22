"""Synthetic DOCX requires a saved consent linked to a current local human decision."""

from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import report_drafts as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.reporting import service
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.store import ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input
from tests.reporting.test_monorouter_reports import Response, Session, envelope, settings
from tests.reporting.test_observation_prose import response_output


def test_synthetic_consent_anchor_docx_version_and_restart(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("IAE_MONOROUTER_ENABLED", "1")
    monkeypatch.setenv("IAE_MONOROUTER_API_KEY", "SYNTHETIC-KEY")
    source = synthetic_report_input()
    source.human_state["version"] = 4
    monkeypatch.setattr(api, "load_report_input", lambda _: source)

    @contextmanager
    def repository():
        yield SimpleNamespace(detail=lambda _: {"state": source.human_state})

    monkeypatch.setattr(api, "repository", repository)
    payload = envelope()
    payload["content"][0]["text"] = json.dumps(response_output())
    session = Session(Response(payload))
    monkeypatch.setattr(
        service, "MonoRouterAdapter", lambda _: MonoRouterAdapter(settings(), lambda: session)
    )
    store = ReportDraftStore(tmp_path / "isolated.sqlite3")
    app = create_app()
    app.dependency_overrides[api.get_draft_store] = lambda: store
    http = TestClient(app)
    body = {
        "expected_version": 4,
        "idempotency_key": str(uuid4()),
        "allow_external_synthetic": True,
        "fixture": "verified_observations_v1",
    }
    url = "/human-workflow/reporting/synthetic/LOCAL-ANCHOR/drafts"
    result = http.post(url, json=body)
    assert result.status_code == 200, result.text
    draft = result.json()
    assert http.post(url, json=body).json() == draft
    assert len(session.calls) == 1
    base = f"/human-workflow/alerts/{draft['alert_id']}/report-drafts/{draft['draft_id']}"
    assert http.get(base + "/kisa-forms").status_code == 200
    command = {
        "expected_workflow_version": 1,
        "expected_form_version": 0,
        "idempotency_key": str(uuid4()),
        "incident_type": "other_hacking",
        "classification_reason": "Explicit synthetic test type selection",
    }
    saved = http.post(base + "/kisa-forms", json=command)
    assert saved.status_code == 200, saved.text
    form = saved.json()
    assert form["narrative"] == draft["narrative"]
    doc = base + f"/kisa-forms/{form['form_id']}/docx"
    assert http.post(doc).status_code == 200
    first = http.get(doc)
    assert first.status_code == 200
    fresh = create_app()
    fresh.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(store.path)
    restored = TestClient(fresh).get(doc)
    assert restored.content == first.content
    assert restored.headers["x-document-sha256"] == first.headers["x-document-sha256"]
    items = http.get(url).json()["items"]
    assert len(items) == 1 and items[0]["current"]
    source.human_state["version"] = 5
    assert (
        http.post(
            base + "/kisa-forms",
            json={**command, "idempotency_key": str(uuid4()), "expected_form_version": 1},
        ).status_code
        == 409
    )
    assert http.get(url).json()["items"][0]["current"] is False
    # Saved historical downloads remain available; no provider retry on reads/restarts.
    assert http.get(doc).content == first.content
    assert len(session.calls) == 1
    source.human_state["version"] = 4
    newer = http.post(url, json={**body, "idempotency_key": str(uuid4())})
    assert newer.status_code == 200
    assert newer.json()["document_version"] == 2
    assert newer.json()["draft_id"] != draft["draft_id"]
    assert store.load(draft["draft_id"]) == draft
    assert http.get(doc).content == first.content
    assert len(session.calls) == 2
