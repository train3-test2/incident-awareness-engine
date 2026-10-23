"""KISA values keep their exact ReportDraft or explicit human provenance."""

from datetime import datetime
from zoneinfo import ZoneInfo

from incident_awareness.dashboard.human_workflow import fingerprint
from incident_awareness.reporting.kisa_contracts import COMMON_FIELDS, TYPE_FIELDS
from incident_awareness.reporting.kisa_readiness import HUMAN_INPUT_FIELDS, assess_readiness

UNKNOWN = "확인불가"


def kst_minute(value):
    time = datetime.fromisoformat(value)
    if time.tzinfo is None or time.utcoffset() is None:
        raise ValueError("Stored awareness time must have an explicit timezone")
    time = time.astimezone(ZoneInfo("Asia/Seoul"))
    return (
        f"{time.year}년 {time.month:02d}월 {time.day:02d}일 {time.hour:02d}시 {time.minute:02d}분"
    )


def build_form_data(draft, source_version, command, *, action_id, actor_id, recorded_at):
    digest = fingerprint(draft)
    base = f"report-draft:{draft['draft_id']}"
    mapped = {}
    for key, label in (COMMON_FIELDS | TYPE_FIELDS[command.incident_type]).items():
        item = command.fields.get(key)
        mapped[key] = {
            "report_field_id": key,
            "label": label,
            "value": item.value if item and item.confirmation == "confirmed" else UNKNOWN,
            "input_state": "confirmed"
            if item and item.confirmation == "confirmed"
            else "unknown"
            if item and item.confirmation == "unknown"
            else "missing_input"
            if key in HUMAN_INPUT_FIELDS or (item and item.confirmation == "missing_input")
            else "unknown",
            "confirmation_status": "HUMAN_CONFIRMED"
            if item and item.confirmation == "confirmed"
            else "CONFIRMED_UNKNOWN"
            if item and item.confirmation == "unknown"
            else "UNCONFIRMED",
            "source_references": [f"human-input:{action_id}/{key}"] if item else [],
            "actor_id": actor_id if item else None,
            "human_action_id": action_id if item else None,
            "source_snapshot_sha256": digest,
        }
    # Reuse saved, grounded statutory fields if there is no human supplement.
    source_fields = {v["report_field_id"]: (i, v) for i, v in enumerate(draft["output"]["fields"])}
    for target, source_key in [
        ("incident_occurred_at", "incident_occurred_at"),
        ("response_actions", "response_measures"),
    ]:
        source = source_fields.get(source_key)
        index, stored = source if source else (None, None)
        if target not in command.fields and stored and stored["value"] != "UNKNOWN":
            mapped[target].update(
                value=stored["value"],
                confirmation_status="STORED_REPORT_FACT",
                input_state="confirmed",
                source_references=[f"{base}#/output/fields/{index}"],
            )
    analysis = draft.get("analysis") or {}
    state = analysis.get("human_state") or {}
    times = analysis.get("times") or {}
    th = times.get("t_h") or state.get("t_h")
    mapped["t_h"] = {
        "report_field_id": "t_h",
        "label": "사고인지시점 (담당자가 기록한 내부 인지시각)",
        "value": kst_minute(th) if th else "미기록 (필수 미완료)",
        "confirmation_status": "RECORDED_HUMAN_AWARENESS" if th else "NOT_RECORDED",
        "input_state": "confirmed" if th else "missing_input",
        "utc_value": th,
        "t_h_recorded_at": times.get("t_h_recorded_at") or state.get("t_h_recorded_at"),
        "source_references": [f"{base}#/analysis/times/t_h"] if th else [],
        "awareness_audit": [
            a for a in analysis.get("human_history", []) if a.get("action") == "record_awareness"
        ],
        "source_snapshot_sha256": digest,
    }
    confirmations = command.consents.model_dump(mode="json")
    result = {
        "schema_version": "kisa_form_data_v2",
        "source_draft_id": draft["draft_id"],
        "source_report_version": source_version,
        "source_snapshot_sha256": digest,
        "source_call_metadata": draft.get("call_metadata"),
        "run_id": draft.get("run_id", "UNKNOWN"),
        "alert_id": draft["alert_id"],
        "workflow_version": draft["workflow_version"],
        "context": draft.get("context", "local_development"),
        "submission_status": "not_submitted",
        "incident_type": command.incident_type,
        "classification_reason": command.classification_reason,
        "classification": {
            "incident_type": command.incident_type,
            "reason": command.classification_reason,
            "basis": "explicit_human_form_selection",
            "actor_id": actor_id,
            "action_id": action_id,
            "recorded_at": recorded_at,
            "source_snapshot_sha256": digest,
        },
        "human_action_id": action_id,
        "actor_id": actor_id,
        "actor_kind": "local_demo",
        "recorded_at": recorded_at,
        "inputs": command.model_dump(
            mode="json",
            exclude={"idempotency_key", "expected_form_version", "expected_workflow_version"},
        ),
        "fields": mapped,
        "consents": confirmations,
        "technical_attachment": {
            "source_draft_id": draft["draft_id"],
            "source_snapshot_sha256": digest,
            "analysis": analysis,
            "source_call_metadata": draft.get("call_metadata"),
            "evidence_archive_verified": bool(
                (analysis.get("evidence_provenance") or {}).get("historical_extractor_verified")
            ),
            "raw_verification_summary": (analysis.get("evidence_provenance") or {}).get("summary"),
        },
    }
    result["readiness"] = assess_readiness(result)
    return result
