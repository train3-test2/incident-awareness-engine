"""Isolated SQLite and server-owned raw-verified fixture; HTTP transport is mocked."""

import json
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import kisa_forms
from incident_awareness.dashboard.api import report_drafts as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.reporting import service
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.store import ReportDraftStore
from tests.evidence import test_evidence_resolution as raw_fixtures
from tests.evidence.test_evidence_resolution import analysis, report_input
from tests.reporting.test_approved_snapshot import prose
from tests.reporting.test_monorouter_reports import Response, Session, envelope, settings

archive = raw_fixtures.archive


@pytest.fixture
def setup(archive, tmp_path, monkeypatch):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("IAE_MONOROUTER_ENABLED", "1")
    source = report_input(archive, analysis(archive))
    monkeypatch.setattr(api, "load_report_input", lambda _: source)

    @contextmanager
    def repository():
        yield SimpleNamespace(detail=lambda _: {"state": source.human_state})

    monkeypatch.setattr(api, "repository", repository)
    monkeypatch.setattr(kisa_forms, "repository", repository)
    store = ReportDraftStore(tmp_path / "new.sqlite3")
    app = create_app()
    app.dependency_overrides[api.get_draft_store] = lambda: store
    return TestClient(app), source, store


def test_preview_approval_generation_word_and_restart(setup, monkeypatch):
    http, source, store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot = http.get(base + "/report-snapshot")
    assert snapshot.status_code == 200
    assert not store.path.exists()  # Read preview has no ledger side effect.
    snapshot = snapshot.json()
    assert snapshot["external_transmission"] == "not_sent"
    approval = {
        "expected_version": 3,
        "idempotency_key": str(uuid4()),
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "approve_external": True,
    }
    blocked = http.post(
        base + "/ai-report-drafts",
        json={"expected_version": 3, "idempotency_key": str(uuid4()), "consent_id": str(uuid4())},
    )
    assert blocked.status_code == 409
    grant = http.post(base + "/report-snapshot-approvals", json=approval)
    assert grant.status_code == 200
    assert http.post(base + "/report-snapshot-approvals", json=approval).json() == grant.json()
    payload = envelope()
    payload["content"][0]["text"] = json.dumps(prose(snapshot), ensure_ascii=False)
    session = Session(Response(payload))
    monkeypatch.setattr(
        service, "MonoRouterAdapter", lambda _: MonoRouterAdapter(settings(), lambda: session)
    )
    command = {
        "expected_version": 3,
        "idempotency_key": str(uuid4()),
        "consent_id": grant.json()["consent_id"],
    }
    result = http.post(base + "/ai-report-drafts", json=command)
    assert result.status_code == 200, result.text
    draft = result.json()
    assert draft["method"] == "monorouter_grounded"
    assert "source" not in draft["approved_input"]
    assert "prose" not in draft["approved_input"]
    assert http.post(base + "/ai-report-drafts", json=command).json() == draft
    docbase = base + f"/report-drafts/{draft['draft_id']}"
    form = http.post(
        docbase + "/kisa-forms",
        json={
            "expected_workflow_version": 3,
            "expected_form_version": 0,
            "idempotency_key": str(uuid4()),
            "incident_type": "other_hacking",
            "classification_reason": "Synthetic QA",
        },
    )
    assert form.status_code == 200, form.text
    assert form.json()["narrative"]["validation"]["status"] == "passed"
    url = docbase + f"/kisa-forms/{form.json()['form_id']}/docx"
    assert http.post(url).status_code == 200
    content = http.get(url).content
    assert content.startswith(b"PK")
    fresh = create_app()
    fresh.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(store.path)
    assert TestClient(fresh).get(url).content == content
    assert len(session.calls) == 1


@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_strict_explicit_approval(setup, value):
    http, source, store = setup
    response = http.post(
        f"/human-workflow/alerts/{source.alert_id}/report-snapshot-approvals",
        json={
            "expected_version": 3,
            "idempotency_key": str(uuid4()),
            "snapshot_sha256": "a" * 64,
            "approve_external": value,
        },
    )
    assert response.status_code == 422
    assert not store.path.exists()


def test_changed_input_needs_new_preview_and_no_cross_origin_approval(setup):
    http, source, store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    preview = http.get(base + "/report-snapshot").json()
    command = {
        "expected_version": 3,
        "idempotency_key": str(uuid4()),
        "snapshot_sha256": preview["snapshot_sha256"],
        "approve_external": True,
    }
    assert (
        http.post(
            base + "/report-snapshot-approvals",
            json=command,
            headers={"Origin": "https://foreign.example"},
        ).status_code
        == 403
    )
    source.human_state["version"] += 1
    assert http.post(base + "/report-snapshot-approvals", json=command).status_code == 409
    assert not store.path.exists()


def test_automatic_word_reuses_only_explicit_human_fields_and_never_consents(setup, monkeypatch):
    http, source, _store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    # Existing fallback draft and explicitly entered form are local prerequisites only.
    old = http.post(
        base + "/report-drafts", json={"expected_version": 3, "idempotency_key": str(uuid4())}
    ).json()
    oldbase = base + f"/report-drafts/{old['draft_id']}"
    form = http.post(
        oldbase + "/kisa-forms",
        json={
            "expected_workflow_version": 3,
            "expected_form_version": 0,
            "idempotency_key": str(uuid4()),
            "incident_type": "other_hacking",
            "classification_reason": "Human selected synthetic QA type",
            "fields": {
                "company_name": {
                    "confirmation": "confirmed",
                    "value": "SYNTHETIC PRIVATE ORGANIZATION",
                },
                "reporter_email": {"confirmation": "confirmed", "value": "reporter@example.test"},
            },
            "consents": {"privacy_collection": True},
        },
    )
    assert form.status_code == 200
    snapshot = http.get(base + "/report-snapshot").json()
    assert snapshot["word_reuse"]["form_id"] == form.json()["form_id"]
    assert "SYNTHETIC PRIVATE ORGANIZATION" not in snapshot["request_body"]
    grant = http.post(
        base + "/report-snapshot-approvals",
        json={
            "expected_version": 3,
            "idempotency_key": str(uuid4()),
            "approve_external": True,
            "snapshot_sha256": snapshot["snapshot_sha256"],
        },
    ).json()
    payload = envelope()
    payload["content"][0]["text"] = json.dumps(prose(snapshot))
    session = Session(Response(payload))
    monkeypatch.setattr(
        service, "MonoRouterAdapter", lambda _: MonoRouterAdapter(settings(), lambda: session)
    )
    command = {
        "expected_version": 3,
        "idempotency_key": str(uuid4()),
        "consent_id": grant["consent_id"],
        "reuse_form_id": form.json()["form_id"],
    }
    result = http.post(base + "/ai-report-drafts", json=command)
    assert result.status_code == 200, result.text
    draft = result.json()
    assert draft["word_result"]["status"] == "ready"
    assert http.post(base + "/ai-report-drafts", json=command).json() == draft
    saved = http.get(base + f"/report-drafts/{draft['draft_id']}/kisa-forms").json()["items"][0]
    assert saved["fields"]["company_name"]["value"] == "SYNTHETIC PRIVATE ORGANIZATION"
    assert all(v is None for v in saved["consents"].values())
    assert len(session.calls) == 1
    assert "SYNTHETIC PRIVATE ORGANIZATION" not in json.dumps(session.calls[0][1]["json"])
