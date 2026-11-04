"""No external calls. All evidence and credentials in these tests are synthetic."""

import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from uuid import uuid4

import pytest
import requests
from pydantic import SecretStr

from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.contracts import canonical_output
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input

TEST_KEY = "SYNTHETIC-API-KEY-NOT-A-REAL-CREDENTIAL"


class Response:
    def __init__(self, payload=None, status=200, raw=None):
        self.status_code = status
        self.raw = raw if raw is not None else json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def iter_content(self, chunk_size):
        yield self.raw


class Session:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []
        self.trust_env = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def envelope():
    return {
        "type": "message",
        "model": "claude-haiku-4-5-20251001",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 200, "output_tokens": 120},
        "content": [
            {"type": "text", "text": canonical_output(synthetic_report_input()).model_dump_json()}
        ],
    }


def settings(**changes):
    return MonoRouterSettings(
        enabled=True, development=True, api_key=SecretStr(TEST_KEY), **changes
    )


def adapter(session, config=None):
    return MonoRouterAdapter(config or settings(), session_factory=lambda: session)


def service(tmp_path, session, config=None):
    return GroundedReportService(
        ReportDraftStore(tmp_path / "drafts.sqlite3"), adapter(session, config)
    )


def generate(service, key=None, reload_input=synthetic_report_input):
    return service.generate(synthetic_report_input(), key or uuid4(), 1, reload_input)


def operational_unknown_input():
    report = synthetic_report_input()
    report.alert_id = "LOCAL-EXISTING-WORKFLOW"
    for field in report.fields:
        field.value = "UNKNOWN"
        field.references = []
    report.human_state["report_reason"] = "PRIVATE ORGANIZATION DATA MUST STAY LOCAL"
    return report


def test_exact_messages_protocol_and_safe_accounting(tmp_path, caplog):
    session = Session(Response(envelope()))
    draft = generate(service(tmp_path, session))
    assert draft["method"] == "monorouter_grounded"
    metadata = draft["call_metadata"]
    assert metadata["requested_model"] == "claude-haiku-4.5"
    assert metadata["actual_model"] == "claude-haiku-4-5-20251001"
    assert metadata["requested_at"] and metadata["completed_at"]
    assert (metadata["input_tokens"], metadata["output_tokens"]) == (200, 120)
    _, request = session.calls[0]
    assert request["headers"]["x-api-key"] == TEST_KEY
    assert request["headers"]["anthropic-version"] == "2023-06-01"
    assert request["json"]["model"] == "claude-haiku-4.5"
    assert request["json"]["max_tokens"] == 1200
    assert request["timeout"] == (3, 25)
    assert not request["allow_redirects"] and request["verify"] and not session.trust_env
    prompt = request["json"]["messages"][0]["content"]
    for forbidden in ["raw_ref", "human_state", "report_reason", "SYNTHETIC-RUN-001"]:
        assert forbidden not in prompt
    assert TEST_KEY not in caplog.text + json.dumps(draft) + repr(settings())


@pytest.mark.parametrize("enabled,development", [(False, True), (True, False), (False, False)])
def test_explicit_development_gates_prevent_network(tmp_path, enabled, development):
    session = Session(error=AssertionError("Network must not open"))
    config = MonoRouterSettings(
        enabled=enabled, development=development, api_key=SecretStr(TEST_KEY)
    )
    draft = generate(service(tmp_path, session, config))
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["requested_at"] is None
    assert session.calls == []


def test_real_workflow_data_cannot_be_relabelled_as_synthetic(tmp_path):
    session = Session(error=AssertionError("Sensitive input must not leave this process"))
    report = operational_unknown_input()
    report.human_state["context"] = "synthetic_fixture"
    draft = service(tmp_path, session).generate(report, uuid4(), 1, lambda: report)
    assert draft["call_metadata"]["status"] == "blocked_data"
    assert "PRIVATE ORGANIZATION" not in json.dumps(draft)
    assert session.calls == []


@pytest.mark.parametrize(
    "error,status",
    [
        (requests.Timeout("secret response or key must not be logged"), "timeout"),
        (requests.ConnectionError("private endpoint details"), "transport_error"),
    ],
)
def test_transport_failures_fall_back_without_exception_details(tmp_path, caplog, error, status):
    draft = generate(service(tmp_path, Session(error=error)))
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["status"] == status
    assert "private endpoint" not in caplog.text + json.dumps(draft)
    assert draft["call_metadata"]["requested_at"]


@pytest.mark.parametrize(
    "http_status,status",
    [(429, "rate_limited"), (500, "http_error"), (401, "http_error"), (302, "http_error")],
)
def test_http_errors_do_not_retry_or_log_body(tmp_path, http_status, status):
    session = Session(Response(status=http_status, raw=TEST_KEY.encode()))
    draft = generate(service(tmp_path, session))
    assert draft["call_metadata"]["status"] == status
    assert TEST_KEY not in json.dumps(draft)
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    "mutation", ["bad_json", "oversized", "model", "usage", "truncated", "tool", "key_echo"]
)
def test_invalid_provider_envelopes_use_template(tmp_path, mutation):
    payload = envelope()
    raw = None
    if mutation == "bad_json":
        raw = b"not json"
    if mutation == "oversized":
        raw = b"x" * (128 * 1024 + 1)
    if mutation == "model":
        payload["model"] = "untrusted-model"
    if mutation == "usage":
        payload["usage"]["input_tokens"] = "200"
    if mutation == "truncated":
        payload["stop_reason"] = "max_tokens"
    if mutation == "tool":
        payload["content"][0]["type"] = "tool_use"
    if mutation == "key_echo":
        payload["content"][0]["text"] = TEST_KEY
    draft = generate(service(tmp_path, Session(Response(payload, raw=raw))))
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["status"] == "invalid_response"
    assert TEST_KEY not in json.dumps(draft)


@pytest.mark.parametrize(
    "mutation", ["cause", "damage", "exfiltration", "reference", "missing", "duplicate", "extra"]
)
def test_hallucinations_and_broken_provenance_are_rejected(tmp_path, mutation):
    result = canonical_output(synthetic_report_input()).model_dump(mode="json")
    if mutation == "cause":
        result["fields"][1]["value"] = "malware confirmed"
    if mutation == "damage":
        result["fields"][2]["value"] = "10000 users affected"
    if mutation == "exfiltration":
        result["fields"][2]["value"] = "personal data exfiltrated"
    if mutation == "reference":
        result["fields"][0]["evidence_ids"] = ["INVENTED"]
    if mutation == "missing":
        result["fields"].pop()
    if mutation == "duplicate":
        result["fields"][1] = deepcopy(result["fields"][0])
    if mutation == "extra":
        result["summary"] = "unverified assertion"
    payload = envelope()
    payload["content"][0]["text"] = json.dumps(result)
    draft = generate(service(tmp_path, Session(Response(payload))))
    assert draft["call_metadata"]["status"] == "invalid_output"
    assert draft["call_metadata"]["actual_model"] == "claude-haiku-4-5-20251001"
    assert draft["call_metadata"]["output_tokens"] == 120
    assert draft["method"] == "jinja2_fallback"
    assert draft["output"]["fields"][1]["value"] == "UNKNOWN"
    assert "유출 여부: UNKNOWN" in draft["text"]


def test_unverified_input_and_missing_proceed_are_rejected_before_network(tmp_path):
    session = Session(error=AssertionError("No network"))
    svc = service(tmp_path, session)
    report = operational_unknown_input()
    report.fields[1].value = "Unverified cause"
    with pytest.raises(ValueError):
        svc.generate(report, uuid4(), 1, lambda: report)
    report = synthetic_report_input()
    report.human_state["report_choice"] = "hold"
    with pytest.raises(ValueError):
        svc.generate(report, uuid4(), 1, lambda: report)
    assert session.calls == []


def test_model_drift_uses_fallback_and_preserves_actual_model_and_usage(tmp_path):
    payload = envelope()
    payload["model"] = "claude-unexpected-version"
    draft = generate(service(tmp_path, Session(Response(payload))))
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["actual_model"] == "claude-unexpected-version"
    assert draft["call_metadata"]["output_tokens"] == 120


def test_duplicate_request_and_restart_reuse_persisted_draft(tmp_path):
    session = Session(Response(envelope()))
    svc = service(tmp_path, session)
    key = uuid4()
    draft = generate(svc, key)
    assert generate(svc, key) == draft
    fresh = service(tmp_path, Session(error=AssertionError("Restart must read stored draft")))
    assert generate(fresh, key) == draft
    assert len(session.calls) == 1
    row = fresh.store.list_for_alert(synthetic_report_input().alert_id)[0]
    assert row["draft"]["call_metadata"] == draft["call_metadata"]


def test_same_idempotency_key_with_different_source_is_conflict(tmp_path):
    svc = service(tmp_path, Session(Response(envelope())))
    key = uuid4()
    generate(svc, key)
    changed = synthetic_report_input()
    changed.human_state["version"] = 2
    # Keep only operational UNKNOWN fields so grounding still passes.
    for field in changed.fields:
        field.value = "UNKNOWN"
        field.references = []
    with pytest.raises(DraftConflict):
        svc.generate(changed, key, 2, lambda: changed)


def test_changed_workflow_invalidates_result_but_retains_usage(tmp_path):
    svc = service(tmp_path, Session(Response(envelope())))
    changed = synthetic_report_input()
    changed.human_state["version"] = 2
    for field in changed.fields:
        field.value = "UNKNOWN"
        field.references = []
    with pytest.raises(DraftConflict):
        generate(svc, reload_input=lambda: changed)
    row = svc.store.list_for_alert(synthetic_report_input().alert_id)[0]
    assert row["status"] == "stale" and row["draft"] is None
    assert row["call_metadata"]["output_tokens"] == 120


def test_concurrent_claims_cannot_duplicate_provider_call(tmp_path):
    store = ReportDraftStore(tmp_path / "claims.sqlite3")
    source = synthetic_report_input()
    key = str(uuid4())

    def claim(_):
        try:
            return store.claim(source, key, "same-hash")[0]
        except DraftConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))
    assert results.count("conflict") == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint": "http://monogpt.kr/api"},
        {"endpoint": "https://evil.example/messages"},
        {"endpoint": "https://monogpt.kr/api/monorouter/v1/anthropic/v1/messages?key=private"},
        {"max_tokens": 0},
        {"read_timeout": 60},
        {"connect_timeout": float("nan")},
    ],
)
def test_invalid_server_configuration_is_not_used(changes):
    with pytest.raises(ValueError):
        MonoRouterSettings(**changes)


@pytest.mark.parametrize("outcome", ["success", "timeout", "rate_limited"])
def test_synthetic_narrative_transport_accounting_and_safe_fallback(tmp_path, outcome):
    import requests

    from incident_awareness.reporting.kisa_contracts import KISAFormCommand
    from incident_awareness.reporting.kisa_mapping import build_form_data
    from incident_awareness.reporting.kisa_narrative import generate_narrative, synthetic_narrative
    from incident_awareness.reporting.kisa_store import KISAFormStore

    fixture = synthetic_report_input()
    drafts = ReportDraftStore(tmp_path / "synthetic.sqlite3")
    draft = GroundedReportService(drafts, MonoRouterAdapter(MonoRouterSettings())).generate(
        fixture, uuid4(), 1, lambda: fixture
    )
    body = KISAFormCommand.model_validate(
        {
            "idempotency_key": str(uuid4()),
            "expected_workflow_version": 1,
            "expected_form_version": 0,
            "incident_type": "other_hacking",
            "classification_reason": "Synthetic layout fixture selection",
        }
    )
    form = build_form_data(draft, 1, body, action_id="TEST", actor_id="fixture", recorded_at="TEST")
    expected = synthetic_narrative()
    payload = envelope()
    payload["content"][0]["text"] = "```json\n" + expected.model_dump_json() + "\n```"
    session = Session(
        Response(payload, status=429 if outcome == "rate_limited" else 200),
        error=requests.Timeout("PRIVATE DETAILS") if outcome == "timeout" else None,
    )
    forms = KISAFormStore(drafts.path)
    result = generate_narrative(
        draft,
        form,
        adapter(session),
        lambda meta: forms.record_attempt("TEST", draft["draft_id"], meta),
    )
    assert result["call_metadata"]["status"] == outcome
    assert result["output"] == expected.model_dump()
    assert result["method"] == (
        "monorouter_grounded" if outcome == "success" else "jinja2_fallback"
    )
    assert result["call_metadata"]["requested_at"] and result["call_metadata"]["completed_at"]
    sent = json.loads(session.calls[0][1]["json"]["messages"][0]["content"])
    assert sent["facts"] == expected.model_dump()
    assert set(expected.supporting_reference_ids) <= {
        r.evidence_id for r in fixture.candidate_evidence
    }
    assert expected.response_actions == form["fields"]["response_actions"]["value"]
    for field in ("incident_occurred_at", "response_actions"):
        pointer = form["fields"][field]["source_references"][0].split("#/", 1)[1]
        item = draft
        for part in pointer.split("/"):
            item = item[int(part)] if isinstance(item, list) else item[part]
        assert item["value"] == form["fields"][field]["value"]
    with forms.connect() as connection:
        rows = [
            json.loads(r[0])
            for r in connection.execute(
                "SELECT call_metadata FROM kisa_narrative_attempts ORDER BY rowid"
            )
        ]
    assert [row["status"] for row in rows] == ["requesting", outcome]
    assert "PRIVATE DETAILS" not in json.dumps(rows)
