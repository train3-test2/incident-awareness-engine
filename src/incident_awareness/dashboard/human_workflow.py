"""Human decisions remain separate from immutable technical result snapshots."""

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult

DEMO_ACTOR = {"actor_id": "local-demo-analyst", "actor_kind": "unauthenticated_local_demo"}


class WorkflowConflict(ValueError):
    """A stale version, conflicting retry, or invalid transition."""


class WorkflowCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    action: Literal["acknowledge", "review_evidence", "record_awareness", "decide_reporting"]
    expected_version: int = Field(ge=0, strict=True)
    idempotency_key: UUID
    reason: str | None = Field(default=None, min_length=1, max_length=4000)
    t_h: AwareDatetime | None = None
    awareness_mode: Literal["manual", "now"] = "manual"
    report_choice: Literal["proceed", "hold", "do_not_proceed"] | None = None

    @field_validator("t_h", mode="before")
    @classmethod
    def timestamp_is_explicit(cls, value):
        if value is not None and not isinstance(value, (str, datetime)):
            raise ValueError("t_h requires an explicit timestamp with timezone")
        if isinstance(value, str) and not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
        ):
            raise ValueError("t_h requires an RFC3339 timestamp with timezone")
        return value

    @model_validator(mode="after")
    def validate_action_fields(self):
        if self.action == "record_awareness":
            if self.awareness_mode == "now" and self.t_h is not None:
                raise ValueError("Current awareness uses only the server reception time")
            if self.awareness_mode == "manual" and (self.t_h is None or not self.reason):
                raise ValueError("t_h and reason are required")
        elif self.t_h is not None:
            raise ValueError("Only record_awareness accepts t_h")
        if self.action != "record_awareness" and self.awareness_mode != "manual":
            raise ValueError("awareness_mode is only valid for awareness records")
        if self.action == "decide_reporting":
            if self.report_choice is None or not self.reason:
                raise ValueError("report_choice and reason are required")
        elif self.report_choice is not None:
            raise ValueError("Only decide_reporting accepts report_choice")
        return self


def fingerprint(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def notification_candidate(
    fusion: FusionResult, decision: DecisionResult | None, *, local_demo: bool
) -> dict | None:
    """Select only a positive, scoped result. t_e=null never becomes Hybrid detection."""
    if decision and (fusion.run_id, fusion.entity_id) != (decision.run_id, decision.entity_id):
        raise ValueError("Decision and Fusion scopes differ")
    if decision and (fusion.fusion_status, fusion.fusion_time) != (
        decision.fusion_status,
        decision.fusion_time,
    ):
        raise ValueError("Decision and Fusion detection facts differ")
    hybrid = (
        decision is not None
        and decision.t_e is not None
        and decision.decision_path in {"fast", "fusion", "fast_and_fusion"}
    )
    if fusion.fusion_status != "detected" and not hybrid:
        return None
    kind = "fusion" if fusion.fusion_status == "detected" else "hybrid"
    fusion_payload = fusion.model_dump(mode="json")
    decision_payload = decision.model_dump(mode="json") if decision else None
    source_key = (
        "decision:" + decision.decision_id if decision else "fusion:" + fingerprint(fusion_payload)
    )
    return {
        "alert_id": "HWA-" + hashlib.sha256(source_key.encode()).hexdigest(),
        "source_key": source_key,
        "run_id": fusion.run_id,
        "entity_id": fusion.entity_id,
        "decision_id": decision.decision_id if decision else None,
        "detection_kind": kind,
        "detected_at": fusion.fusion_time if kind == "fusion" else decision.t_e,
        "source_snapshot": {
            "source_path": (
                "decisions.payload"
                if kind == "hybrid"
                else "decision_runtime_snapshots.fusion_result"
                if decision
                else "fusion_results.payload"
            ),
            "decision_source_path": "decisions.payload" if decision else None,
            "fusion": fusion_payload,
            "decision": decision_payload,
            "hybrid_status": "detected"
            if hybrid
            else "not_evaluated"
            if decision is None or decision.t_e is None
            else "miss",
            "evidence_ids": fusion.contributing_evidence_ids,
            "source_hit_ids": decision.source_hit_ids if decision else [],
            "context": "local_historical_development" if local_demo else "stored_analysis",
            "legal_obligation": "UNDETERMINED",
        },
    }


def initial_state() -> dict:
    return {
        "version": 0,
        "analyst_ack_time": None,
        "evidence_reviewed_at": None,
        "t_h": None,
        "t_h_recorded_at": None,
        "report_choice": None,
        "report_decided_at": None,
        "report_reason": None,
    }


def apply_command(state: dict, command: WorkflowCommand, now: datetime) -> dict:
    if state["version"] != command.expected_version:
        raise WorkflowConflict("동시 수정 충돌: 최신 기록을 조회한 뒤 다시 입력하세요.")
    stamp = now.astimezone(UTC).isoformat(
        timespec="milliseconds" if command.awareness_mode == "now" else "auto"
    )
    result = {**state, "version": state["version"] + 1}
    if command.action == "acknowledge":
        if state["analyst_ack_time"]:
            raise WorkflowConflict("알림 확인은 이미 기록되었습니다.")
        result["analyst_ack_time"] = stamp
    elif command.action == "review_evidence":
        if state["evidence_reviewed_at"]:
            raise WorkflowConflict("근거 검토는 이미 기록되었습니다.")
        result["evidence_reviewed_at"] = stamp
    else:
        if not state["analyst_ack_time"] or not state["evidence_reviewed_at"]:
            raise WorkflowConflict("알림 확인과 근거 검토 기록이 먼저 필요합니다.")
        if command.action == "record_awareness":
            if command.awareness_mode == "now" and state["t_h"] is not None:
                raise WorkflowConflict(
                    "인지시각은 이미 기록되었습니다. 별도 정정 기능을 사용하세요."
                )
            awareness = now if command.awareness_mode == "now" else command.t_h
            if awareness > now:
                raise ValueError("내부 인지시각은 미래 시각일 수 없습니다.")
            result.update(
                t_h=stamp
                if command.awareness_mode == "now"
                else awareness.astimezone(UTC).isoformat(),
                t_h_recorded_at=stamp,
            )
        else:
            result.update(
                report_choice=command.report_choice,
                report_decided_at=stamp,
                report_reason=command.reason,
            )
    return result


def operational_clock(state: dict, now: datetime) -> dict:
    if not state["t_h"]:
        return {"status": "no_awareness", "due_at": None, "remaining_seconds": None}
    due = datetime.fromisoformat(state["t_h"]) + timedelta(hours=24)
    remaining = (due - now).total_seconds()
    return {
        "status": "within_24h" if remaining > 0 else "over_24h",
        "due_at": due.isoformat(),
        "remaining_seconds": remaining,
        "meaning": "internal_operations_only",
        "legal_obligation": "UNDETERMINED",
    }
