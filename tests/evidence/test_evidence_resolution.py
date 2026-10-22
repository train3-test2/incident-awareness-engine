"""Synthetic provenance records; actual Run 007 is audited separately without writes."""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from docx import Document
from fastapi.testclient import TestClient

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.evidence_provenance import get_provenance_connection
from incident_awareness.dashboard.grounded_report_contract import build_report_input
from incident_awareness.dashboard.provenance_read_model import read_provenance
from incident_awareness.evidence.extractor import EXTRACTOR_VERSION, extract_evidence
from incident_awareness.evidence.provenance import resolve_evidence
from incident_awareness.evidence.raw_verification import RawArtifactVerifier
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.contracts import CallMetadata, canonical_output
from incident_awareness.reporting.kisa_contracts import KISAFormCommand
from incident_awareness.reporting.kisa_docx import KISADocxRenderer
from incident_awareness.reporting.kisa_mapping import build_form_data
from incident_awareness.reporting.kisa_narrative import (
    canonical_narrative,
    generate_narrative,
    verify_narrative,
)
from incident_awareness.reporting.monorouter import MonoRouterAdapter, ProviderResult
from incident_awareness.reporting.observations import snapshot_observations
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore

RUN = "RUN-20990101-991"  # Reserved synthetic fixture; never persisted in the source database.
HOST = "SYNTHETIC-HOST"


@pytest.fixture
def archive(tmp_path, monkeypatch):
    monkeypatch.setenv("INCIDENT_AWARENESS_EVENT_TYPES_PATH", "configs/event_types_v0.2.yaml")
    monkeypatch.delenv("IAE_PROVENANCE_ARCHIVE_ROOT", raising=False)
    records = [
        {
            "EventId": 1,
            "RecordId": 9001,
            "Computer": HOST,
            "TimeCreated": "2026-01-01T00:00:00.123Z",
            "EventData": {
                "UtcTime": "2026-01-01 00:00:00.123",
                "Image": "C:\\Synthetic\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand QQ==",
                "ProcessId": "42",
            },
        },
        {
            "EventId": 3,
            "RecordId": 9002,
            "Computer": HOST,
            "TimeCreated": "2026-01-01T00:00:02.123Z",
            "EventData": {
                "UtcTime": "2026-01-01 00:00:01.123",
                "Image": "C:\\Synthetic\\powershell.exe",
                "ProcessId": "42",
                "Protocol": "tcp",
                "SourceIp": "192.0.2.1",
                "SourcePort": "54321",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "443",
            },
        },
    ]
    context = SysmonNormalizationContext(RUN, f"RAW-{RUN}-SYSMON-001", 1)
    events = [
        normalizer(SysmonJsonlRecord(index, record), context=context)
        for index, record, normalizer in zip(
            (1, 2),
            records,
            (normalize_sysmon_process_create, normalize_sysmon_network_connection),
            strict=True,
        )
    ]
    raw = ("\n".join(json.dumps(record) for record in records) + "\n").encode()
    directory = tmp_path / RUN
    (directory / "telemetry").mkdir(parents=True)
    raw_path = directory / "telemetry/sysmon-0001.jsonl"
    raw_path.write_bytes(raw)
    manifest = {
        "run_id": RUN,
        "items": [
            {
                "raw_log_id": context.raw_log_id,
                "path": f"raw/{RUN}/telemetry/sysmon-0001.jsonl",
                "source": "sysmon",
                "layer": "raw_telemetry",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        ],
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf8")
    return {
        "root": tmp_path,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "raw": raw,
        "raw_path": raw_path,
        "events": events,
        "evidences": [e for event in events for e in extract_evidence(event)],
    }


def resolve(archive, *, raw=True, evidence=None, events=None, **kwargs):
    return resolve_evidence(
        evidence or archive["evidences"][0],
        events if events is not None else {e.event_id: e for e in archive["events"]},
        run_id=RUN,
        entity_id=HOST,
        raw_verifier=RawArtifactVerifier(archive["root"] if raw else None),
        **kwargs,
    )


def test_exact_deterministic_ids_are_distinct_from_original_rule_attestation(archive):
    for event, evidence in zip(archive["events"], archive["evidences"], strict=True):
        assert extract_evidence(event)[0] == evidence
        assert evidence.extractor_version == EXTRACTOR_VERSION
        result = resolve(archive, evidence=evidence)
        assert result.resolution_status == "raw_verified"
        assert result.evidence_origin == "current_extractor_reconstruction"
        assert not result.historical_extractor_verified
    result = resolve(archive, expected_extractor_version="s0-historical-different")
    assert result.resolution_status == "unresolved"
    assert result.unresolved_reason == "extractor_version_mismatch"


def test_missing_archive_verifies_events_without_inventing_behavior(archive):
    result = resolve(archive, raw=False)
    assert result.resolution_status == "event_verified"
    assert result.source_event_ids == ("9001",)
    assert result.raw_references[0].record_no == 1  # Not source_record_id 9001.
    assert result.unresolved_reason == "run_manifest_unavailable"
    assert not result.observed_behavior


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"run_id": "OTHER-RUN"}, "event_scope_mismatch"),
        ({"host_id": "OTHER-HOST"}, "event_scope_mismatch"),
        ({"event_id": "OTHER-ID"}, "evidence_event_id_mismatch"),
        ({"source_layer": "detector_output"}, "event_source_layer_mismatch"),
        ({"timestamp": datetime(2026, 1, 2, tzinfo=UTC)}, "evidence_event_timestamp_mismatch"),
    ],
)
def test_reject_wrong_event_even_when_similar_or_nearby(archive, change, reason):
    original = archive["events"][0]
    result = resolve(archive, events={original.event_id: original.model_copy(update=change)})
    assert result.resolution_status == "unresolved"
    assert result.unresolved_reason == reason
    assert not result.observed_behavior


@pytest.mark.parametrize(
    "change,reason",
    [
        ("run", "manifest_run_mismatch"),
        ("raw_id", "manifest_raw_mapping_mismatch"),
        ("segment", "manifest_raw_mapping_mismatch"),
        ("duplicate", "manifest_raw_mapping_mismatch"),
        ("source", "manifest_source_mismatch"),
        ("sha", "raw_sha256_mismatch"),
        ("etag_as_sha", "manifest_sha256_missing"),
        ("path", "raw_archive_invalid"),
    ],
)
def test_manifest_or_hash_mismatch_cannot_promote(archive, change, reason):
    manifest = archive["manifest"]
    item = manifest["items"][0]
    if change == "run":
        manifest["run_id"] = "OTHER-RUN"
    if change == "raw_id":
        item["raw_log_id"] = "OTHER-RAW"
    if change == "segment":
        item["segment_no"] = 2
    if change == "duplicate":
        manifest["items"].append(deepcopy(item))
    if change == "source":
        item["source"] = "other"
    if change == "sha":
        item["sha256"] = "0" * 64
    if change == "etag_as_sha":
        item["sha256"] = "a" * 32
    if change == "path":
        item["path"] = "raw/../telemetry/sysmon-0001.jsonl"
    archive["manifest_path"].write_text(json.dumps(manifest), encoding="utf8")
    result = resolve(archive)
    assert result.resolution_status == "event_verified"
    assert result.unresolved_reason == reason
    assert not result.observed_behavior


@pytest.mark.parametrize(
    "change,reason",
    [
        ("missing", "raw_record_missing"),
        ("record_id", "source_record_id_mismatch"),
        ("host", "raw_normalized_event_mismatch"),
        ("process", "raw_normalized_event_mismatch"),
        ("time", "raw_normalized_event_mismatch"),
        ("type", "raw_archive_invalid"),
    ],
)
def test_record_must_match_beyond_file_integrity(archive, change, reason):
    records = [json.loads(line) for line in archive["raw"].splitlines()]
    if change == "missing":
        records = []
    elif change == "record_id":
        records[0]["RecordId"] = 42
    elif change == "host":
        records[0]["Computer"] = "OTHER"
    elif change == "process":
        records[0]["EventData"]["CommandLine"] = "powershell.exe -NoProfile"
    elif change == "time":
        records[0]["EventData"]["UtcTime"] = "2026-01-01 01:00:00.123"
    elif change == "type":
        records[0]["EventId"] = 3
    raw = ("\n".join(json.dumps(row) for row in records)).encode()
    archive["raw_path"].write_bytes(raw)
    archive["manifest"]["items"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    archive["manifest_path"].write_text(json.dumps(archive["manifest"]), encoding="utf8")
    result = resolve(archive)
    assert result.resolution_status == "event_verified"
    assert result.unresolved_reason == reason
    assert not result.observed_behavior


def test_multi_event_evidence_requires_all_references(archive):
    first, second = archive["events"]
    evidence = archive["evidences"][0].model_copy(
        update={"event_ids": [first.event_id, second.event_id]}
    )
    result = resolve(archive, evidence=evidence)
    assert result.resolution_status == "raw_verified"
    assert result.source_event_ids == ("9001", "9002")
    assert len(result.raw_references) == 2
    assert not result.observed_behavior  # No human-readable rule for invented multi-Event type.
    partial = resolve(archive, evidence=evidence, events={first.event_id: first})
    assert partial.resolution_status == "unresolved"


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class ReadConnection:
    def __init__(self, events, fusion):
        self.events, self.fusion, self.calls = events, fusion, []

    def execute(self, query, params=()):
        self.calls.append((query, params))
        assert query.startswith("SELECT "), "Provenance may not mutate the database"
        if "to_regclass" in query:
            return Cursor([(None,)])
        if "SELECT 1 FROM runs" in query:
            return Cursor([(1,)])
        if "FROM fusion_results" in query:
            return Cursor([(self.fusion,)])
        assert "FROM events" in query and params[0] == RUN
        return Cursor(
            [
                (
                    e.event_id,
                    e.run_id,
                    e.host_id,
                    e.timestamp,
                    e.event_type,
                    e.model_dump(mode="json"),
                )
                for e in self.events
            ]
        )


def connection(archive, status="detected"):
    fusion = json.loads(Path("tests/fixtures/human_workflow/reference-results.json").read_text())[
        0
    ]["fusion_results"]
    fusion.update(
        run_id=RUN,
        entity_id=HOST,
        fusion_time="2026-01-01T00:00:02.123Z",
        contributing_evidence_ids=[e.evidence_id for e in archive["evidences"]],
    )
    for episode in fusion["fusion_episodes"]:
        episode.update(
            run_id=RUN,
            entity_id=HOST,
            start_time="2026-01-01T00:00:02.123Z",
            end_time="2026-01-01T00:05:00.123Z",
            contributing_evidence_ids=fusion["contributing_evidence_ids"],
        )
    if status != "detected":
        fusion.update(
            fusion_status=status,
            fusion_time=None,
            fusion_episodes=[],
            contributing_evidence_ids=[],
            score_at_decision=0.0 if status == "miss" else None,
        )
    return ReadConnection(archive["events"], fusion)


def analysis(archive, *, raw=True):
    provenance = read_provenance(
        connection(archive), RUN, raw_verifier=RawArtifactVerifier(archive["root"] if raw else None)
    )
    return {
        "run_metadata": {"run_id": RUN, "scenario_id": "SYNTHETIC"},
        "event_statistics": {
            "normalized_event_count": 2,
            "by_type": {"process_create": 1, "network_connection": 1},
        },
        "fusion": connection(archive).fusion,
        "detection": {"t_e": None},
        "hybrid_status": "not_evaluated",
        "times": {
            "technical_detection_at": "2026-01-01T00:00:02Z",
            "alert_issued_at": "2026-01-01T00:00:03Z",
            "t_h": None,
        },
        "human_state": {"report_choice": "proceed", "t_h": None},
        "human_history": [],
        "evidence": [
            {
                **item,
                "verification": "VERIFIED"
                if item["resolution_status"] == "raw_verified"
                else "UNRESOLVED",
            }
            for item in provenance["items"]
        ],
        "evidence_link_note": "Synthetic provenance validation only",
        "evidence_provenance": provenance,
        "verified_observations": provenance["verified_observations"],
    }


@pytest.mark.parametrize("status", ["miss", "not_evaluated"])
def test_no_contributing_evidence_for_normal_or_unevaluated(archive, status):
    c = connection(archive, status)
    result = read_provenance(c, RUN)
    assert result["items"] == result["verified_observations"] == []
    assert not any("FROM events" in query for query, _ in c.calls)


def test_api_is_local_read_only_and_no_browser_archive_overrides(archive, monkeypatch):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    app = create_app()
    c = connection(archive)
    app.dependency_overrides[get_provenance_connection] = lambda: c
    http = TestClient(app)
    response = http.get(f"/runs/{RUN}/evidence-provenance")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["summary"]["event_verified"] == 2
    denied = http.get(
        f"/runs/{RUN}/evidence-provenance", headers={"Origin": "https://untrusted.invalid"}
    )
    assert denied.status_code == 403
    assert http.post(f"/runs/{RUN}/evidence-provenance", json={"verified": True}).status_code == 405


@pytest.mark.parametrize(
    "change", ["text", "evidence_id", "event", "proof", "scope", "level", "missing_proof"]
)
def test_report_rejects_poisoned_observation_snapshot(archive, change):
    snapshot = analysis(archive)
    assert len(snapshot_observations(snapshot, run_id=RUN, entity_id=HOST)) == 2
    p = snapshot["evidence_provenance"]
    if change == "text":
        p["items"][0]["observed_behavior"][0]["behavior_summary"] += " 유출 확정"
    if change == "evidence_id":
        p["items"][0]["evidence_id"] = "OTHER"
    if change == "event":
        p["source_events"][0]["process"]["name"] = "forged.exe"
    if change == "proof":
        p["items"][0]["validation_details"]["raw_checks"][0]["verified"] = False
    if change == "scope":
        p["run_id"] = "OTHER"
    if change == "level":
        p["items"][0]["resolution_status"] = "event_verified"
    if change == "missing_proof":
        del p["items"][0]["validation_details"]["raw_checks"]
    with pytest.raises(ValueError):
        snapshot_observations(snapshot, run_id=RUN, entity_id=HOST)


def report_input(archive, snapshot):
    detail = {
        "state": {"version": 3, "report_choice": "proceed", "t_h": None},
        "alert_id": "SYNTHETIC-ALERT",
        "run_id": RUN,
        "entity_id": HOST,
        "decision_id": None,
        "audit": [{"action": "decide_reporting", "action_id": "SYNTHETIC-ACTION", "version": 3}],
        "source_snapshot": {"evidence_ids": [e.evidence_id for e in archive["evidences"]]},
    }
    return build_report_input(detail, snapshot)


def test_new_provenance_creates_new_report_and_docx_without_rewriting_old(archive, tmp_path):
    before, after = analysis(archive, raw=False), analysis(archive)
    store = ReportDraftStore(tmp_path / "reports.sqlite3")

    def forbidden_network():
        raise AssertionError("Actual Run must never open an external session")

    adapter = MonoRouterAdapter(
        MonoRouterSettings(enabled=True, development=True, api_key="TEST-ONLY"),
        session_factory=forbidden_network,
    )
    service = GroundedReportService(store, adapter)
    first_input = report_input(archive, before)
    second_input = report_input(archive, after)
    key = uuid4()
    first = service.generate(first_input, key, 3, lambda: first_input)
    original_bytes = json.dumps(store.load(first["draft_id"]), sort_keys=True)
    with pytest.raises(DraftConflict):
        service.generate(second_input, key, 3, lambda: second_input)
    second = service.generate(second_input, uuid4(), 3, lambda: second_input)
    assert store.load(first["draft_id"])["document_version"] == 1
    assert second["document_version"] == 2
    assert json.dumps(store.load(first["draft_id"]), sort_keys=True) == original_bytes
    assert (
        first["output"] == second["output"] == canonical_output(first_input).model_dump(mode="json")
    )
    assert all(f["value"] == "UNKNOWN" for f in second["output"]["fields"])
    assert second["call_metadata"]["status"] == "blocked_data"
    cmd = KISAFormCommand(
        expected_workflow_version=3,
        expected_form_version=0,
        idempotency_key=uuid4(),
        incident_type="other_hacking",
        classification_reason="Synthetic layout fixture only",
    )
    form = build_form_data(
        second,
        2,
        cmd,
        action_id="SYNTHETIC-FORM-ACTION",
        actor_id="local-demo-analyst",
        recorded_at="2026-01-01T00:00:03Z",
    )
    old_narrative = canonical_narrative(first, form)
    narrative = canonical_narrative(second, form)
    assert "상세 행위 미확인" in old_narrative.observed_indicators
    assert "인코딩된 PowerShell 실행 옵션" in narrative.observed_indicators
    assert "공인 IP" in narrative.observed_indicators
    assert "192.0.2.1" not in narrative.observed_indicators  # No need to quote internal/source IP.
    assert "QQ==" not in narrative.observed_indicators  # No raw command in prose.
    poisoned = narrative.model_dump()
    poisoned["observed_indicators"] += " C2 서버와 통신하여 개인정보 유출 확정."
    with pytest.raises(ValueError):
        verify_narrative(json.dumps(poisoned), narrative)
    form["narrative"] = {"method": "jinja2_fallback", "output": narrative.model_dump(mode="json")}
    form["report_version"] = 1
    content = KISADocxRenderer().render(form)
    document = Document(BytesIO(content))
    text = "\n".join(c.text for table in document.tables for row in table.rows for c in row.cells)
    assert "인코딩된 PowerShell 실행 옵션" in text and "공인 IP" in text
    assert "원인" in narrative.unconfirmed_items[1] or "사고 원인" in narrative.unconfirmed_items


def test_network_record_fields_and_parser_version_are_checked(archive):
    evidence = archive["evidences"][1]
    event = archive["events"][1]
    changed = event.model_copy(
        update={"network": event.network.model_copy(update={"dst_port": 8443})}
    )
    result = resolve(archive, evidence=evidence, events={event.event_id: changed})
    assert result.unresolved_reason == "raw_normalized_event_mismatch"
    changed = event.model_copy(
        update={"raw_ref": event.raw_ref.model_copy(update={"parser_version": "unknown-version"})}
    )
    result = resolve(archive, evidence=evidence, events={event.event_id: changed})
    assert result.unresolved_reason == "parser_version_unsupported"
    assert not result.observed_behavior


def test_full_id_can_stay_same_while_evidence_content_and_snapshot_change(archive):
    old = analysis(archive)
    event = archive["events"][0]
    records = [json.loads(line) for line in archive["raw"].splitlines()]
    records[0]["EventData"]["CommandLine"] = "powershell.exe -enc QQ=="
    raw = ("\n".join(json.dumps(row) for row in records) + "\n").encode()
    archive["raw_path"].write_bytes(raw)
    archive["manifest"]["items"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    archive["manifest_path"].write_text(json.dumps(archive["manifest"]), encoding="utf8")
    archive["events"][0] = normalize_sysmon_process_create(
        SysmonJsonlRecord(1, records[0]),
        context=SysmonNormalizationContext(RUN, event.raw_ref.raw_log_id, 1),
    )
    archive["evidences"][0] = extract_evidence(archive["events"][0])[0]
    new = analysis(archive)
    assert (
        old["evidence_provenance"]["items"][0]["evidence_id"]
        == new["evidence_provenance"]["items"][0]["evidence_id"]
    )
    assert (
        old["verified_observations"][0]["observation_id"]
        != new["verified_observations"][0]["observation_id"]
    )
    assert snapshot_observations(
        old, run_id=RUN, entity_id=HOST
    )  # Old immutable facts still valid.


def test_mock_llm_accepts_only_canonical_observation_sentences(archive):
    snapshot = analysis(archive)
    draft = {
        "analysis": snapshot,
        "draft_id": "SYNTHETIC-DRAFT",
        "run_id": RUN,
        "entity_id": HOST,
        "alert_id": "SYNTHETIC-ALERT",
        "workflow_version": 3,
        "output": {"fields": []},
    }
    cmd = KISAFormCommand(
        expected_workflow_version=3, expected_form_version=0, idempotency_key=uuid4()
    )
    form = build_form_data(
        draft, 1, cmd, action_id="TEST", actor_id="TEST", recorded_at="2026-01-01T00:00:03Z"
    )
    expected = canonical_narrative(draft, form)

    class MockAdapter:
        poison = False

        def generate_kisa_narrative(self, facts, record_attempt):
            assert facts == expected.model_dump(mode="json")
            if self.poison:
                facts["observed_indicators"] += " 악성코드 감염 및 유출 확정"
            return ProviderResult(
                CallMetadata(status="success"), json.dumps(facts, ensure_ascii=False)
            )

    adapter = MockAdapter()
    assert generate_narrative(draft, form, adapter)["method"] == "monorouter_grounded"
    adapter.poison = True
    fallback = generate_narrative(draft, form, adapter)
    assert fallback["method"] == "jinja2_fallback"
    assert fallback["call_metadata"]["status"] == "invalid_output"
    assert fallback["output"] == expected.model_dump(mode="json")
