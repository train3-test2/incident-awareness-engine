"""No external calls: approval, wire privacy, grounding, DOCX and ledger replay."""

import json
from copy import deepcopy
from io import BytesIO
from uuid import uuid4

import pytest
import requests
from docx import Document

from incident_awareness.reporting.approved_snapshot import (
    CHECKS,
    DAMAGE,
    ENDINGS,
    PREFIXES,
    RESPONSE,
    preview,
    validate_prose,
)
from incident_awareness.reporting.kisa_contracts import KISAFormCommand
from incident_awareness.reporting.kisa_docx import generate_docx
from incident_awareness.reporting.kisa_service import create_form
from incident_awareness.reporting.kisa_store import KISAFormStore
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore
from incident_awareness.reporting.synthetic_observations import synthetic_observation_input
from tests.evidence import test_evidence_resolution as raw_fixtures
from tests.evidence.test_evidence_resolution import analysis, report_input
from tests.reporting.test_monorouter_reports import Response, Session, envelope, settings

archive = raw_fixtures.archive


def prose(snapshot):
    facts = json.loads(snapshot["request"]["messages"][0]["content"])["observations"]
    sentences = [
        {"reference": f["reference"], "text": PREFIXES[1] + f["fact_phrase"] + ENDINGS[1]}
        for f in facts
    ]
    return {
        "sentences": sentences,
        "incident_content": " ".join(s["text"] for s in sentences),
        "confirmed_damage": DAMAGE,
        "confirmed_response": RESPONSE,
        "further_checks": CHECKS,
    }


def approved(tmp_path, source, output=None, *, error=None, status=200):
    snapshot = preview(source, settings())
    payload = envelope()
    payload["content"][0]["text"] = json.dumps(output or prose(snapshot), ensure_ascii=False)
    session = Session(Response(payload, status=status), error=error)
    store = ReportDraftStore(tmp_path / "isolated.sqlite3")
    grant = store.approve_snapshot(
        source.alert_id,
        uuid4(),
        source.human_state["version"],
        "actor",
        snapshot["snapshot_sha256"],
    )
    service = GroundedReportService(store, MonoRouterAdapter(settings(), lambda: session))
    return service, grant, session, snapshot


def generate(service, grant, source, *, key=None, reload_input=None):
    return service.generate(
        source,
        key or uuid4(),
        source.human_state["version"],
        reload_input or (lambda: source),
        approval=grant["consent_id"],
        actor_id="actor",
    )


def test_verified_real_shaped_source_is_deidentified_before_wire_and_docx(archive, tmp_path):
    source = report_input(archive, analysis(archive))
    service, grant, session, snapshot = approved(tmp_path, source)
    # Both real-shaped predicates are reconstructed through raw proof and extractor checks.
    assert len(source.verified_observations) == 2
    body = snapshot["request_body"]
    for identity in [
        source.run_id,
        source.entity_id,
        source.alert_id,
        source.human_action_id,
        *(o.evidence_id for o in source.verified_observations),
        *(o.observation_id for o in source.verified_observations),
    ]:
        assert identity not in body
    assert all(
        key not in body
        for key in (
            "raw_ref",
            "behavior_summary",
            "source_event_id",
            "203.0.113.10",
            "actor_id",
            "observed_at",
        )
    )
    key = uuid4()
    draft = generate(service, grant, source, key=key)
    assert draft["method"] == "monorouter_grounded"
    assert draft["narrative"]["validation"]["status"] == "passed"
    assert all(f["value"] == "UNKNOWN" for f in draft["output"]["fields"])
    prepared = requests.Request(
        "POST", settings().endpoint, json=session.calls[0][1]["json"]
    ).prepare()
    assert prepared.body == body.encode("utf-8")
    assert len(session.calls) == 1
    restored = GroundedReportService(ReportDraftStore(service.store.path), service.adapter)
    assert generate(restored, grant, source, key=key) == draft
    forms = KISAFormStore(service.store.path)
    command = KISAFormCommand(
        expected_workflow_version=source.human_state["version"],
        expected_form_version=0,
        idempotency_key=uuid4(),
        incident_type="other_hacking",
        classification_reason="Fixture QA",
    )
    form = create_form(service.store, forms, draft, command, lambda: draft)
    saved = generate_docx(forms, form)
    document = Document(BytesIO(saved["docx_bytes"]))
    text = " ".join(c.text for t in document.tables for r in t.rows for c in r.cells)
    assert draft["approved_input"]["prose"]["incident_content"] in text
    assert len(session.calls) == 1  # No second LLM call on Word generation.
    assert all(v is None for v in form["consents"].values())
    fresh = generate_docx(KISAFormStore(service.store.path), form)
    assert fresh["docx_bytes"] == saved["docx_bytes"]


@pytest.mark.parametrize("change", ["source", "model", "actor", "grant", "version"])
def test_missing_or_stale_approval_never_opens_transport(tmp_path, change):
    source = synthetic_observation_input()
    service, grant, session, _ = approved(tmp_path, source)
    actor = "actor"
    if change == "source":
        source.human_state["note"] = "changed"
    elif change == "model":
        service.adapter = MonoRouterAdapter(settings(model="claude-different"), lambda: session)
    elif change == "actor":
        actor = "other"
    elif change == "grant":
        grant["consent_id"] = str(uuid4())
    else:
        source.human_state["version"] += 1
    with pytest.raises((DraftConflict, ValueError)):
        service.generate(
            source,
            uuid4(),
            source.human_state["version"],
            lambda: source,
            approval=grant["consent_id"],
            actor_id=actor,
        )
    assert session.calls == []


def test_source_changed_before_send_is_rejected_without_transport(tmp_path):
    source = synthetic_observation_input()
    service, grant, session, _ = approved(tmp_path, source)
    changed = deepcopy(source)
    changed.human_state["note"] = "new input"
    with pytest.raises((DraftConflict, ValueError)):
        generate(service, grant, source, reload_input=lambda: changed)
    assert session.calls == []


@pytest.mark.parametrize(
    "claim",
    [
        "감염되었습니다",
        "개인정보 유출",
        "격리 완료",
        "원인 확정",
        "2026-01-01",
        "관측되지 않았습니다",
        "신고의무 확정",
    ],
)
def test_unsupported_provider_assertions_fail_closed(tmp_path, claim):
    source = synthetic_observation_input()
    snapshot = preview(source, settings())
    value = prose(snapshot)
    value["sentences"][0]["text"] = claim
    value["incident_content"] = " ".join(s["text"] for s in value["sentences"])
    with pytest.raises(ValueError):
        validate_prose(json.dumps(value), snapshot["request"])
    service, grant, _session, _ = approved(tmp_path, source, value)
    draft = generate(service, grant, source)
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["status"] == "invalid_output"
    assert "prose" not in draft["approved_input"]


@pytest.mark.parametrize(
    "status,error,expected",
    [
        (429, None, "rate_limited"),
        (500, None, "http_error"),
        (200, requests.Timeout("PRIVATE"), "timeout"),
    ],
)
def test_provider_failure_is_explicit_not_ai(tmp_path, status, error, expected):
    source = synthetic_observation_input()
    service, grant, _session, _ = approved(tmp_path, source, status=status, error=error)
    draft = generate(service, grant, source)
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["status"] == expected
    assert "PRIVATE" not in json.dumps(draft)


def test_unverified_source_has_no_outbound_preview(archive):
    with pytest.raises(ValueError):
        preview(report_input(archive, analysis(archive, raw=False)), settings())


def test_snapshot_preview_does_not_open_or_create_ledger(tmp_path):
    path = tmp_path / "not-created.sqlite3"
    preview(synthetic_observation_input(), settings())
    assert not path.exists()


def test_approval_records_are_append_only_and_have_no_secret_material(tmp_path):
    import sqlite3

    source = synthetic_observation_input()
    service, grant, _, _ = approved(tmp_path, source)
    with service.store.snapshot_connection() as connection:
        for statement in (
            "UPDATE report_snapshot_consents SET actor_id='other'",
            "DELETE FROM report_snapshot_consents",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
        row = dict(connection.execute("SELECT * FROM report_snapshot_consents").fetchone())
        assert row["consent_id"] == grant["consent_id"]
        assert set(row) == {
            "consent_id",
            "alert_id",
            "actor_id",
            "snapshot_sha256",
            "workflow_version",
            "recorded_at",
            "idempotency_key",
        }


@pytest.mark.parametrize("field", ["output", "analysis", "entity_id", "prose"])
def test_saved_ai_narrative_is_revalidated_before_word(tmp_path, field):
    from incident_awareness.reporting.approved_snapshot import saved_narrative

    source = synthetic_observation_input()
    service, grant, _, _ = approved(tmp_path, source)
    draft = generate(service, grant, source)
    broken = deepcopy(draft)
    if field == "prose":
        broken["approved_input"]["prose"]["confirmed_damage"] = "확정 피해"
    elif field == "output":
        broken["output"]["fields"][0]["value"] = "2026-01-01"
    elif field == "analysis":
        broken["analysis"] = {"injected": True}
    else:
        broken["entity_id"] = "other"
    with pytest.raises(ValueError):
        saved_narrative(broken)
