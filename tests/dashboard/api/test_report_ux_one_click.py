"""One operator request -> approved Claude draft -> review-only KISA DOCX.

Isolated SQLite, the server-owned raw-verified archive fixture and a mocked HTTP
transport. No real provider, database or running dashboard is used.
"""

import json
import re
from contextlib import contextmanager
from io import BytesIO
from types import SimpleNamespace
from uuid import uuid4
from zipfile import ZipFile

import pytest
from docx import Document
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import kisa_forms
from incident_awareness.dashboard.api import report_drafts as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.reporting import service
from incident_awareness.reporting.kisa_docx import TEMPLATE_SHA256
from incident_awareness.reporting.kisa_narrative import (
    LOCAL_DETAILS_HEADING,
    local_observation_details,
)
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.store import ReportDraftStore
from tests.evidence import test_evidence_resolution as raw_fixtures
from tests.evidence.test_evidence_resolution import HOST, analysis, report_input
from tests.reporting.test_approved_snapshot import prose
from tests.reporting.test_monorouter_reports import Response, Session, envelope, settings

archive = raw_fixtures.archive
REASON = "담당자가 대시보드에서 '그 밖의 해킹' 양식을 직접 선택함."
HUMAN_ONLY = (
    "company_name",
    "business_number",
    "reporter_name",
    "reporter_email",
    "reporter_phone",
)


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
    store = ReportDraftStore(tmp_path / "one-click.sqlite3")
    app = create_app()
    app.dependency_overrides[api.get_draft_store] = lambda: store
    return TestClient(app), source, store


def provider(monkeypatch, text):
    payload = envelope()
    payload["content"][0]["text"] = text
    session = Session(Response(payload))
    monkeypatch.setattr(
        service, "MonoRouterAdapter", lambda _: MonoRouterAdapter(settings(), lambda: session)
    )
    return session


def approve(http, base):
    snapshot = http.get(base + "/report-snapshot").json()
    grant = http.post(
        base + "/report-snapshot-approvals",
        json={
            "expected_version": 3,
            "idempotency_key": str(uuid4()),
            "snapshot_sha256": snapshot["snapshot_sha256"],
            "approve_external": True,
        },
    )
    assert grant.status_code == 200, grant.text
    return snapshot, grant.json()["consent_id"]


def one_click(consent_id, incident_type="other_hacking", reason=REASON):
    # The exact body the dashboard sends: no organization, reporter or consent values.
    return {
        "expected_version": 3,
        "idempotency_key": str(uuid4()),
        "consent_id": consent_id,
        "word_inputs": {
            "expected_workflow_version": 3,
            "expected_form_version": 0,
            "idempotency_key": str(uuid4()),
            "incident_type": incident_type,
            "classification_reason": reason,
        },
    }


def docx_text(content):
    document = Document(BytesIO(content))
    tables = [
        [[cell.text for cell in row.cells] for row in table.rows] for table in document.tables
    ]
    with ZipFile(BytesIO(content)) as package:
        footer = package.read("word/footerKisaDraft.xml").decode("utf-8")
        body = "".join(
            re.findall(
                r"<w:t[^>]*>([^<]*)</w:t>", package.read("word/document.xml").decode("utf-8")
            )
        )
    # Text following each checked box, in document order.
    checked = [body[index + 1 :].lstrip() for index, char in enumerate(body) if char == "☑"]
    return tables, footer, checked


def test_one_request_returns_review_docx_with_blank_human_fields(setup, monkeypatch):
    # Given
    http, source, _store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot, consent_id = approve(http, base)
    session = provider(monkeypatch, json.dumps(prose(snapshot), ensure_ascii=False))
    observations = source.verified_observations

    # When
    result = http.post(base + "/ai-report-drafts", json=one_click(consent_id))

    # Then
    assert result.status_code == 200, result.text
    draft = result.json()
    assert draft["method"] == "monorouter_grounded"
    assert draft["word_result"]["status"] == "ready"
    assert len(session.calls) == 1
    sent = json.dumps(session.calls[0][1]["json"], ensure_ascii=False)
    for private in (
        HOST,
        REASON,
        *(o.evidence_id for o in observations),
        *(o.observed_at for o in observations),
    ):
        assert private not in sent
    listed = http.get(base + f"/report-drafts/{draft['draft_id']}/kisa-forms").json()
    form = listed["items"][0]
    assert listed["exports"][form["form_id"]]["docx_sha256"] == draft["word_result"]["docx_sha256"]
    assert form["classification"]["basis"] == "explicit_human_form_selection"
    assert all(form["fields"][key]["input_state"] == "missing_input" for key in HUMAN_ONLY)
    assert all(value is None for value in form["consents"].values())
    assert form["fields"]["incident_occurred_at"]["value"] == "확인불가"
    assert form["fields"]["incident_occurred_at"]["confirmation_status"] == "UNCONFIRMED"
    assert form["readiness"]["submission_ready"] is False
    download = http.get(draft["word_result"]["download_url"])
    assert download.status_code == 200
    assert download.headers["X-Template-SHA256"] == TEMPLATE_SHA256
    tables, footer, checked = docx_text(download.content)
    common = "\n".join(cell for row in tables[1] for cell in row)
    for label in ("기업명", "사업자번호", "이름", "메일", "연락처"):
        assert f"- {label} : 미입력" in common
    occurred = tables[1][10][-1]
    assert "☑ 확인불가" in occurred
    assert all(o.observed_at not in occurred for o in observations)
    content = tables[1][15][-1]
    assert draft["approved_input"]["snapshot_sha256"] == snapshot["snapshot_sha256"]
    assert prose(snapshot)["incident_content"] in content
    assert LOCAL_DETAILS_HEADING in content
    for observation in observations:
        assert observation.behavior_summary in content
        assert observation.evidence_id in content
    assert "UNKNOWN: 실제 수행된 담당자 대응조치는 확인되지 않았습니다." in tables[1][18][-1]
    # Only the chosen form section and explicit "unconfirmed" boxes; no consent/truth checks.
    expected = ["그 밖의 해킹", "확인불가", "확인불가", "확인불가"]
    assert len(checked) == len(expected)
    assert all(text.startswith(label) for text, label in zip(checked, expected, strict=True))
    assert "검토용 초안" in footer and "실제 외부 제출되지 않음" in footer


@pytest.mark.parametrize(
    ("incident_type", "reason"),
    [("undetermined", ""), ("other_hacking", ""), ("other_hacking", " ")],
)
def test_type_confirmation_is_required_before_any_transmission(
    setup, monkeypatch, incident_type, reason
):
    # Given
    http, source, store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot, consent_id = approve(http, base)
    session = provider(monkeypatch, json.dumps(prose(snapshot), ensure_ascii=False))

    # When
    result = http.post(
        base + "/ai-report-drafts", json=one_click(consent_id, incident_type, reason)
    )

    # Then
    assert result.status_code == 422
    assert session.calls == []
    assert store.list_for_alert(source.alert_id) == []


def test_unverified_ai_wording_never_reaches_word(setup, monkeypatch):
    # Given
    http, source, _store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot, consent_id = approve(http, base)
    output = prose(snapshot)
    output["confirmed_damage"] = "개인정보 유출이 확인되었습니다."
    session = provider(monkeypatch, json.dumps(output, ensure_ascii=False))

    # When
    draft = http.post(base + "/ai-report-drafts", json=one_click(consent_id)).json()

    # Then
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["status"] == "invalid_output"
    assert draft["word_result"]["status"] == "not_prepared"
    listed = http.get(base + f"/report-drafts/{draft['draft_id']}/kisa-forms").json()
    assert listed["items"] == [] and listed["exports"] == {}
    assert "개인정보 유출이 확인" not in json.dumps(draft, ensure_ascii=False)
    assert len(session.calls) == 1


def test_lost_response_retry_and_restart_restore_the_same_documents(setup, monkeypatch):
    # Given
    http, source, store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot, consent_id = approve(http, base)
    session = provider(monkeypatch, json.dumps(prose(snapshot), ensure_ascii=False))
    command = one_click(consent_id)
    first = http.post(base + "/ai-report-drafts", json=command).json()

    # When
    retried = http.post(base + "/ai-report-drafts", json=command).json()
    fresh = create_app()
    fresh.dependency_overrides[api.get_draft_store] = lambda: ReportDraftStore(store.path)
    restarted = TestClient(fresh)
    drafts = restarted.get(base + "/report-drafts").json()["items"]
    listed = restarted.get(base + f"/report-drafts/{first['draft_id']}/kisa-forms").json()

    # Then
    assert retried["word_result"] == first["word_result"]
    assert len(session.calls) == 1
    assert [item["draft_id"] for item in drafts] == [first["draft_id"]]
    assert len(listed["items"]) == 1
    assert listed["items"][0]["form_id"] == first["word_result"]["form_id"]
    assert (
        listed["exports"][first["word_result"]["form_id"]]["docx_sha256"]
        == (first["word_result"]["docx_sha256"])
    )
    assert (
        restarted.get(first["word_result"]["download_url"]).content
        == http.get(first["word_result"]["download_url"]).content
    )


def test_saved_forms_are_scoped_to_their_own_incident(setup, monkeypatch):
    # Given
    http, source, _store = setup
    base = f"/human-workflow/alerts/{source.alert_id}"
    snapshot, consent_id = approve(http, base)
    provider(monkeypatch, json.dumps(prose(snapshot), ensure_ascii=False))
    draft = http.post(base + "/ai-report-drafts", json=one_click(consent_id)).json()

    # When
    other = http.get(
        f"/human-workflow/alerts/OTHER-ALERT/report-drafts/{draft['draft_id']}/kisa-forms"
    )
    word = http.get(draft["word_result"]["download_url"].replace(source.alert_id, "OTHER-ALERT"))

    # Then
    assert other.status_code == 404
    assert word.status_code == 404


def test_local_details_come_only_from_the_matching_verified_provenance(archive):
    # Given
    source = report_input(archive, analysis(archive))
    draft = {
        "run_id": source.run_id,
        "entity_id": source.entity_id,
        "analysis": source.analysis,
        "verified_observations": [o.model_dump(mode="json") for o in source.verified_observations],
    }

    # When
    details, references = local_observation_details(draft)

    # Then
    assert details == [
        f"- {o.behavior_summary} (Evidence {o.evidence_id})" for o in source.verified_observations
    ]
    assert references == list(dict.fromkeys(o.evidence_id for o in source.verified_observations))
    assert local_observation_details({**draft, "analysis": {}}) == ([], [])
    with pytest.raises(ValueError):
        local_observation_details(
            {**draft, "verified_observations": draft["verified_observations"][:1]}
        )
    with pytest.raises(ValueError):
        local_observation_details({**draft, "entity_id": "OTHER-HOST"})
