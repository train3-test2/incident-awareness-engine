"""Read-only assessments for old and new saved forms; never rewrite an audit snapshot."""

from incident_awareness.reporting.kisa_contracts import CONSENT_LABELS

HUMAN_INPUT_FIELDS = {
    "company_name",
    "business_number",
    "industry",
    "company_size",
    "company_address",
    "reporter_name",
    "reporter_email",
    "reporter_phone",
    "t_h",
}


def input_state(key, field):
    if field.get("input_state") in {"unknown", "missing_input", "confirmed"}:
        return field["input_state"]
    status = field["confirmation_status"]
    if status in {"HUMAN_CONFIRMED", "STORED_REPORT_FACT", "RECORDED_HUMAN_AWARENESS"}:
        return "confirmed"
    if status == "CONFIRMED_UNKNOWN":
        return "unknown"
    return "missing_input" if key in HUMAN_INPUT_FIELDS else "unknown"


def assess_readiness(form):
    items = []
    if form["incident_type"] == "undetermined":
        items.append(
            {
                "key": "incident_type",
                "label": "담당자의 사고 유형 선택·사유",
                "state": "missing_input",
                "target": "type",
            }
        )
    missing, unknown, unconfirmed = [], [], []
    for key, field in form["fields"].items():
        state = input_state(key, field)
        if state == "missing_input":
            missing.append(key)
        elif state == "unknown":
            unknown.append(key)
        if (
            field["confirmation_status"] in {"UNCONFIRMED", "NOT_RECORDED"}
            or state == "missing_input"
        ):
            unconfirmed.append(key)
            items.append(
                {
                    "key": key,
                    "label": field["label"],
                    "state": state,
                    "target": "awareness" if key == "t_h" else f"field:{key}",
                }
            )
    choices = []
    for key, value in form["consents"].items():
        if key == "technical_support" and form["incident_type"] == "ddos":
            continue
        if value is None or (
            key in {"privacy_collection", "truth_confirmation"} and value is not True
        ):
            choices.append(key)
            items.append(
                {
                    "key": key,
                    "label": CONSENT_LABELS[key],
                    "state": "missing_input" if value is None else "not_agreed",
                    "target": f"consent:{key}",
                }
            )
    return {
        "assessment_version": "kisa_readiness_v2",
        "submission_ready": False,
        "fields_complete": not items,
        "blockers": [item["key"] for item in items],
        "required_items": items,
        "missing_inputs": missing,
        "unknown_fields": unknown,
        "field_states": {key: input_state(key, field) for key, field in form["fields"].items()},
        "unconfirmed_fields": unconfirmed,
        "unconfirmed_consents": choices,
        "reason": "개발용 시나리오 검토 초안이며 자동 제출·법적 판단을 하지 않음",
    }
