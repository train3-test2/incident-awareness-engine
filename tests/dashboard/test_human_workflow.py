"""Reference analysis facts, explicit human times, and fail-closed report inputs."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.dashboard.grounded_report_contract import (
    GroundedReportField,
    ReportEvidenceReference,
    build_report_input,
)
from incident_awareness.dashboard.human_workflow import (
    WorkflowCommand,
    WorkflowConflict,
    apply_command,
    initial_state,
    notification_candidate,
    operational_clock,
)

REFERENCE = json.loads(Path("tests/fixtures/human_workflow/reference-results.json").read_text())
NOW = datetime(2026, 10, 20, 4, tzinfo=UTC)


def command(action, version=0, **fields):
    return WorkflowCommand(
        action=action, expected_version=version, idempotency_key=uuid4(), **fields
    )


@pytest.mark.parametrize("index,detected", [(0, True), (1, False), (2, False)])
def test_reference_detection_classification(index, detected):
    item = REFERENCE[index]
    candidate = notification_candidate(
        FusionResult.model_validate(item["fusion_results"]),
        DecisionResult.model_validate(item["decisions"]),
        local_demo=True,
    )
    assert bool(candidate) is detected
    if detected:
        assert candidate["source_snapshot"]["hybrid_status"] == "not_evaluated"
        assert candidate["source_snapshot"]["decision"]["t_e"] is None
        assert candidate["source_snapshot"]["context"] == "local_historical_development"
        assert candidate["detected_at"] < NOW


def test_new_decision_version_has_distinct_identity():
    item = REFERENCE[0]
    fusion = FusionResult.model_validate(item["fusion_results"])
    decision = DecisionResult.model_validate(item["decisions"])
    old = notification_candidate(fusion, decision, local_demo=True)
    new = notification_candidate(
        fusion,
        decision.model_copy(
            update={"decision_id": "DEC-NEW", "supersedes_decision_id": decision.decision_id}
        ),
        local_demo=True,
    )
    assert old["source_key"] != new["source_key"]


def test_eligible_hybrid_and_standalone_fusion():
    item = REFERENCE[0]
    fusion = FusionResult.model_validate(item["fusion_results"])
    assert notification_candidate(fusion, None, local_demo=True)["decision_id"] is None
    miss = FusionResult.model_validate(REFERENCE[1]["fusion_results"])
    d = DecisionResult.model_validate(
        {
            **REFERENCE[1]["decisions"],
            "fast_status": "detected",
            "detector_time": "2026-09-27T07:22:01.275Z",
            "t_e": "2026-09-27T07:22:01.275Z",
            "decision_path": "fast",
            "winning_path": "fast",
        }
    )
    candidate = notification_candidate(miss, d, local_demo=True)
    assert candidate["detection_kind"] == "hybrid"
    assert candidate["source_snapshot"]["hybrid_status"] == "detected"
    assert candidate["source_snapshot"]["source_path"] == "decisions.payload"


@pytest.mark.parametrize(
    "fields",
    [
        {"action": "record_awareness", "reason": "test"},
        {"action": "record_awareness", "t_h": "2026-10-20T01:00:00", "reason": "test"},
        {"action": "record_awareness", "t_h": 1, "reason": "test"},
        {"action": "record_awareness", "t_h": "123", "reason": "test"},
        {"action": "decide_reporting", "report_choice": "proceed", "reason": " "},
        {"action": "acknowledge", "actor_id": "forged"},
        {"action": "acknowledge", "report_choice": "hold"},
    ],
)
def test_invalid_or_forged_human_command(fields):
    with pytest.raises(ValidationError):
        WorkflowCommand(expected_version=0, idempotency_key=uuid4(), **fields)


def test_acknowledgment_does_not_infer_awareness():
    state = apply_command(initial_state(), command("acknowledge"), NOW)
    assert state["analyst_ack_time"] == NOW.isoformat()
    assert state["t_h"] is None and state["t_h_recorded_at"] is None
    assert operational_clock(state, NOW)["status"] == "no_awareness"
    with pytest.raises(WorkflowConflict):
        apply_command(state, command("acknowledge", 1), NOW)


def test_awareness_correction_and_reporting_have_separate_times():
    state = apply_command(initial_state(), command("review_evidence"), NOW)
    state = apply_command(state, command("acknowledge", 1), NOW)
    th = NOW - timedelta(hours=4)
    old = apply_command(state, command("record_awareness", 2, t_h=th, reason="담당자 입력"), NOW)
    corrected = apply_command(
        old,
        command("record_awareness", 3, t_h=th - timedelta(hours=25), reason="과거 인지시각 정정"),
        NOW,
    )
    assert old["t_h"] == th.isoformat()
    assert corrected["t_h_recorded_at"] == NOW.isoformat()
    assert operational_clock(corrected, NOW)["status"] == "over_24h"
    final = apply_command(
        corrected,
        command("decide_reporting", 4, report_choice="proceed", reason="내부 검토"),
        NOW + timedelta(minutes=1),
    )
    assert final["report_decided_at"] != final["t_h_recorded_at"]
    assert final["t_h"] == corrected["t_h"]
    with pytest.raises(WorkflowConflict):
        apply_command(
            final, command("decide_reporting", 4, report_choice="hold", reason="stale"), NOW
        )
    with pytest.raises(ValueError):
        apply_command(
            final,
            command("record_awareness", 5, t_h=NOW + timedelta(hours=1), reason="future"),
            NOW,
        )


def test_awareness_requires_explicit_review_and_acknowledgment():
    with pytest.raises(WorkflowConflict):
        apply_command(initial_state(), command("record_awareness", t_h=NOW, reason="test"), NOW)


def test_report_fields_stay_unknown_without_verified_evidence():
    detail = {
        "alert_id": "A",
        "run_id": "R",
        "entity_id": "E",
        "decision_id": "D",
        "state": {"report_choice": "hold"},
        "audit": [],
        "source_snapshot": {},
    }
    with pytest.raises(ValueError):
        build_report_input(detail)
    detail.update(
        state={"report_choice": "proceed"},
        audit=[{"action": "decide_reporting", "action_id": uuid4(), "version": 3}],
        source_snapshot={"evidence_ids": ["UNRESOLVED-EVIDENCE"]},
    )
    report = build_report_input(detail)
    assert all(f.value == "UNKNOWN" and f.references == [] for f in report.fields)
    assert report.candidate_evidence[0].source_event_id is None
    assert report.candidate_evidence[0].raw_ref is None


def test_report_contract_rejects_incomplete_chain_and_unbacked_values():
    with pytest.raises(ValidationError):
        ReportEvidenceReference(evidence_id="E1", verification="VERIFIED")
    with pytest.raises(ValidationError):
        GroundedReportField(report_field_id="incident_cause", value="An invented cause")


def test_report_contract_accepts_complete_verified_structural_reference():
    reference = ReportEvidenceReference(
        evidence_id="E1",
        source_event_id="EV1",
        verification="VERIFIED",
        raw_ref={"raw_log_id": "RAW1", "segment_no": 1, "record_no": 2},
    )
    field = GroundedReportField(
        report_field_id="incident_cause", value="Test fixture claim", references=[reference]
    )
    assert field.references[0].raw_ref.record_no == 2


def test_one_click_awareness_uses_single_server_millisecond_capture():
    state = apply_command(initial_state(), command("review_evidence"), NOW)
    state = apply_command(state, command("acknowledge", 1), NOW - timedelta(minutes=1))
    captured = NOW.replace(microsecond=123000)
    result = apply_command(state, command("record_awareness", 2, awareness_mode="now"), captured)
    assert result["t_h"] == result["t_h_recorded_at"] == "2026-10-20T04:00:00.123+00:00"
    assert result["t_h"] != result["analyst_ack_time"]
    with pytest.raises(WorkflowConflict):
        apply_command(
            result, command("record_awareness", 3, awareness_mode="now"), NOW + timedelta(hours=1)
        )


def test_browser_time_cannot_override_now_awareness():
    with pytest.raises(ValidationError):
        command("record_awareness", awareness_mode="now", t_h=NOW)
