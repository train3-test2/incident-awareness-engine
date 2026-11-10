"""Bounded factual sentences and strict JSON validation; ungrounded prose is rejected."""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.reporting.contracts import CallMetadata
from incident_awareness.reporting.kisa_observations import verified_observations
from incident_awareness.reporting.monorouter import ProviderResult


class KISANarrative(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    incident_summary: str = Field(max_length=2500)
    observed_indicators: str = Field(max_length=2500)
    response_actions: str = Field(max_length=2500)
    unconfirmed_items: list[str] = Field(max_length=40)
    supporting_reference_ids: list[str] = Field(max_length=80)


def canonical_narrative(draft, form):
    from incident_awareness.reporting.contracts import canonical_output
    from incident_awareness.reporting.synthetic import synthetic_report_input

    fixture = synthetic_report_input()
    if (
        draft.get("context") == "synthetic_development"
        and draft.get("run_id") == fixture.run_id
        and draft["alert_id"] == fixture.alert_id
        and draft["output"] == canonical_output(fixture).model_dump(mode="json")
        and not form["inputs"]["fields"]
    ):
        return synthetic_narrative()
    analysis = draft.get("analysis") or {}
    base = f"report-draft:{draft['draft_id']}"
    facts = ["개발용 침해 의심 사례입니다. 실제 사고·피해는 확정되지 않았습니다."]
    refs = [base]
    indicators, observation_refs = verified_observations(draft)
    refs.extend(observation_refs)
    if not indicators:
        indicators = ["상세 행위 미확인: Evidence 원문 연결이 검증되지 않았습니다."]
    if analysis.get("evidence") and not observation_refs:
        refs.append(f"{base}#/analysis/evidence")
    response = form["fields"]["response_actions"]
    response_text = (
        response["value"]
        if response["confirmation_status"] in {"HUMAN_CONFIRMED", "STORED_REPORT_FACT"}
        else "확인불가: 실제 수행된 대응조치가 확인되지 않았습니다."
    )
    if response["confirmation_status"] in {"HUMAN_CONFIRMED", "STORED_REPORT_FACT"}:
        refs.extend(response["source_references"])
    unknown = ["사고 원인", "피해 규모", "개인정보 유출 여부"]
    if not observation_refs:
        unknown.append("상세 행위 미확인")
    if form["fields"]["incident_occurred_at"]["value"] == "확인불가":
        unknown.insert(0, "실제 사고 발생시간")
    if form["fields"]["t_h"]["confirmation_status"] == "NOT_RECORDED":
        unknown.append("담당자가 기록한 조직 내부 인지시각")
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=StrictUndefined,
        autoescape=False,
    )
    raw = environment.get_template("kisa_narrative.json.j2").render(
        summary=" ".join(facts),
        indicators=" ".join(indicators) or "추가 기술적 징후 확인불가",
        response=response_text,
        unknown=unknown,
        refs=refs,
    )
    return KISANarrative.model_validate_json(raw)


def verify_narrative(text, expected):
    content = text.strip()
    # The Messages API may wrap its JSON in a single Markdown code block.
    # Strip only that exact envelope; prose or additional blocks still fail validation.
    if content.startswith("```json\n") and content.endswith("\n```"):
        content = content[8:-4]
    value = KISANarrative.model_validate_json(content)
    # References alone cannot prove a sentence. Accept only the source-grounded sentences
    # and their exact field roles; a novel cause/damage/action claim triggers fallback.
    for key in ("incident_summary", "observed_indicators", "response_actions"):
        if " ".join(getattr(value, key).split()) != " ".join(getattr(expected, key).split()):
            raise ValueError("Narrative conflicts with stored facts")
    if (
        value.unconfirmed_items != expected.unconfirmed_items
        or value.supporting_reference_ids != expected.supporting_reference_ids
    ):
        raise ValueError("Narrative grounding references do not match")
    return expected


def synthetic_narrative():
    """Only this code-owned, non-identifying fixture may use the external narrative path."""
    return KISANarrative(
        incident_summary="합성 개발용 침해 의심 사례입니다. 실제 운영 사고가 아닙니다.",
        observed_indicators="저장된 합성 Evidence 참조 SYNTHETIC-EVIDENCE-001이 있습니다.",
        response_actions="합성 테스트 호스트 격리 및 조사 중",
        unconfirmed_items=["사고 원인", "피해 규모", "개인정보 유출 여부"],
        supporting_reference_ids=["SYNTHETIC-EVIDENCE-001"],
    )


LOCAL_DETAILS_HEADING = (
    "관측 상세 (원본 검증된 로컬 기록 · 외부 AI 미전송 · 관측 시각은 사고 발생시각이 아님):"
)


def local_observation_details(draft):
    """Code-owned sentences re-derived from the draft's raw-verified provenance snapshot.

    These stay local: the approved provider request carries only deidentified predicates.
    """
    from incident_awareness.reporting.observations import snapshot_observations

    analysis = draft.get("analysis") or {}
    if "evidence_provenance" not in analysis:
        return [], []
    observations = snapshot_observations(
        analysis, run_id=draft.get("run_id"), entity_id=draft.get("entity_id")
    )
    if [o.model_dump(mode="json") for o in observations] != draft.get("verified_observations"):
        raise ValueError("Saved observations conflict with their verified provenance")
    details = [f"- {o.behavior_summary} (Evidence {o.evidence_id})" for o in observations]
    return details, list(dict.fromkeys(o.evidence_id for o in observations))


def generate_narrative(draft, form, adapter, record_attempt=lambda metadata: None):
    from copy import deepcopy

    from incident_awareness.reporting.synthetic_observations import (
        ALERT_ID,
        validated_saved_narrative,
    )

    if draft.get("approved_input", {}).get("prose") is not None:
        from incident_awareness.reporting.approved_snapshot import saved_narrative

        narrative = deepcopy(saved_narrative(draft))
        details, references = local_observation_details(draft)
        if details:
            narrative["output"]["observed_indicators"] += "\n".join(
                ["", LOCAL_DETAILS_HEADING, *details]
            )
            narrative["output"]["supporting_reference_ids"].extend(references)
        response = form["fields"]["response_actions"]
        if response["confirmation_status"] in {"HUMAN_CONFIRMED", "STORED_REPORT_FACT"}:
            narrative["output"]["response_actions"] = response["value"]
            narrative["output"]["supporting_reference_ids"].extend(response["source_references"])
        return narrative
    if draft.get("alert_id") == ALERT_ID and not draft.get("approved_input"):
        # Reuse the validated, versioned provider prose; never re-send human form inputs.
        narrative = deepcopy(validated_saved_narrative(draft))
        response = form["fields"]["response_actions"]
        if response["confirmation_status"] == "HUMAN_CONFIRMED":
            narrative["output"]["response_actions"] = response["value"]
            narrative["output"]["supporting_reference_ids"].extend(response["source_references"])
        return narrative
    expected = canonical_narrative(draft, form)
    result = (
        adapter.generate_kisa_narrative(expected.model_dump(mode="json"), record_attempt)
        if adapter
        else ProviderResult(CallMetadata(status="configuration_error"))
    )
    method = "jinja2_fallback"
    if result.text is not None:
        try:
            verify_narrative(result.text, expected)
            method = "monorouter_grounded"
        except (ValueError, TypeError):
            result.metadata.status = "invalid_output"
    record_attempt(result.metadata)
    return {
        "method": method,
        "call_metadata": result.metadata.model_dump(mode="json"),
        "output": json.loads(expected.model_dump_json()),
    }
