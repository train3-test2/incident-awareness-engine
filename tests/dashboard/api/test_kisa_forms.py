from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import kisa_forms as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv("IAE_MONOROUTER_ENABLED", "0")
    source = synthetic_report_input()
    source.alert_id = "TEST-API-ALERT"
    source.run_id = "RUN-20261019-007"
    for field in source.fields:
        field.value = "UNKNOWN"
        field.references = []
    store = ReportDraftStore(tmp_path / "reports.sqlite3")
    draft = GroundedReportService(store, MonoRouterAdapter(MonoRouterSettings())).generate(
        source, uuid4(), 1, lambda: source
    )
    state = {"version": 1, "report_choice": "proceed"}

    @contextmanager
    def repository():
        yield SimpleNamespace(detail=lambda _: {"state": state})

    monkeypatch.setattr(api, "repository", repository)
    app = create_app()
    app.dependency_overrides[api.get_draft_store] = lambda: store
    return TestClient(app), store, draft, state


def route(draft):
    return (
        f"/human-workflow/alerts/{draft['alert_id']}/report-drafts/{draft['draft_id']}/kisa-forms"
    )


def test_unsaved_assessment_is_read_only_and_lists_human_inputs(client):
    http, store, draft, _ = client
    original = store.load(draft["draft_id"])
    response = http.get(route(draft))
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == [] and body["unsaved_preview"]["preview_only"]
    preview = body["unsaved_preview"]
    assert preview["fields"]["company_name"]["input_state"] == "missing_input"
    assert preview["fields"]["affected_ip"]["input_state"] == "unknown"
    assert preview["fields"]["company_name"]["actor_id"] is None
    assert preview["fields"]["t_h"]["utc_value"] is None
    assert {"company_name", "reporter_name", "reporter_phone", "t_h", "privacy_collection"} <= set(
        preview["readiness"]["blockers"]
    )
    assert store.load(draft["draft_id"]) == original
    from incident_awareness.reporting.kisa_store import KISAFormStore

    with KISAFormStore(store.path).connect() as connection:
        assert connection.execute("SELECT count(*) FROM kisa_form_versions").fetchone()[0] == 0


def test_generated_document_does_not_change_submission_readiness(client):
    http, _store, draft, _ = client
    saved = http.post(route(draft), json=body()).json()
    endpoint = route(draft) + f"/{saved['form_id']}/docx"
    assert http.post(endpoint).status_code == 200
    restored = http.get(route(draft)).json()
    assert restored["items"][0] == saved
    assert not restored["readiness_assessments"][saved["form_id"]]["submission_ready"]
    assert "company_name" in restored["readiness_assessments"][saved["form_id"]]["missing_inputs"]


def body(**changes):
    return {
        "expected_workflow_version": 1,
        "expected_form_version": 0,
        "idempotency_key": str(uuid4()),
        "incident_type": "other_hacking",
        "classification_reason": "TEST FIXTURE: development form",
        **changes,
    }


def test_saved_inputs_docx_download_hash_and_fresh_process_restore(client):
    import hashlib

    from incident_awareness.reporting.kisa_docx import template_path

    if not template_path().is_file():
        pytest.skip("User KISA template not installed")
    http, store, draft, _ = client
    before = store.load(draft["draft_id"])
    request = body()
    saved = http.post(route(draft), json=request)
    assert saved.status_code == 200, saved.text
    form = saved.json()
    assert (
        form["fields"]["t_h"]["utc_value"] is None
        and form["consents"]["privacy_collection"] is None
    )
    assert http.post(route(draft), json=request).json() == form
    assert (
        http.post(route(draft), json={**request, "classification_reason": "different"}).status_code
        == 409
    )
    artifact = route(draft) + f"/{form['form_id']}/docx"
    assert http.get(artifact).status_code == 404
    generated = http.post(artifact)
    assert generated.status_code == 200
    download = http.get(artifact)
    assert download.status_code == 200 and download.content.startswith(b"PK")
    assert download.headers["x-document-sha256"] == hashlib.sha256(download.content).hexdigest()
    assert "filename*=UTF-8''" in download.headers["content-disposition"]
    assert download.headers["x-draft-sha256"] == form["source_snapshot_sha256"]
    assert (
        http.post(artifact, json={"company_name": "UNSAVED FORGED VALUE"}).json()
        == generated.json()
    )
    assert store.load(draft["draft_id"]) == before
    fresh = create_app()
    fresh.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(store.path)
    with TestClient(fresh) as restarted:
        assert restarted.get(route(draft)).json()["items"][0] == form
        assert restarted.get(artifact).content == download.content
    evidence = http.get(route(draft) + f"/{form['form_id']}/technical-evidence")
    assert (
        evidence.status_code == 200
        and not evidence.json()["technical_attachment"]["evidence_archive_verified"]
    )


def test_undetermined_and_stale_workflow_cannot_generate_new_selected_form(client):
    http, _, draft, state = client
    saved = http.post(
        route(draft), json=body(incident_type="undetermined", classification_reason="")
    ).json()
    assert "incident_type" in saved["readiness"]["blockers"]
    assert http.post(route(draft) + f"/{saved['form_id']}/docx").status_code == 409
    state["version"] = 2
    assert (
        http.post(
            route(draft), json=body(expected_workflow_version=2, expected_form_version=1)
        ).status_code
        == 409
    )
    assert http.get(route(draft)).json()["items"][0] == saved


@pytest.mark.parametrize(
    "changes",
    [
        {"fields": {"t_h": {"value": "forged", "confirmation": "confirmed"}}},
        {"consents": {"privacy_collection": "true"}},
        {"actor_id": "authenticated-admin"},
        {
            "fields": {
                "incident_occurred_at": {
                    "value": "2026-10-20T09:00:00",
                    "confirmation": "confirmed",
                }
            }
        },
    ],
)
def test_client_cannot_forge_actor_awareness_or_implicit_consent(client, changes):
    http, _, draft, _ = client
    assert http.post(route(draft), json=body(**changes)).status_code == 422
    assert http.get(route(draft)).json()["items"] == []


def test_cross_alert_export_and_remote_actor_denied(client, monkeypatch):
    http, _, draft, _ = client
    assert http.get(route(draft).replace(draft["alert_id"], "OTHER")).status_code == 404
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "0")
    assert http.get(route(draft)).status_code == 403
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    assert (
        http.post(route(draft), json=body(), headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
