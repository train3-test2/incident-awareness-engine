"""Code-owned synthetic observations and a deliberately bounded Korean prose language.

These fixtures simulate verified references; they do not attest a collected Run or archive.
The provider chooses wording, but cannot introduce a new factual predicate or literal.
"""

import json
from itertools import product
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.dashboard.grounded_report_contract import (
    GroundedReportField,
    GroundedReportInput,
    ReportEvidenceReference,
)
from incident_awareness.dashboard.human_workflow import fingerprint
from incident_awareness.evidence.provenance import SupportingReference, VerifiedObservation, digest
from incident_awareness.reporting.contracts import FIELD_IDS

FIXTURE_ID = "synthetic_verified_observations_v1"
ALERT_ID = "SYNTHETIC-OBS-ALERT-001"
PREFIXES = ("합성 관측에서 ", "합성 테스트 데이터에서 ", "비식별 합성 데이터에서 ")
ENDINGS = ("이 관측되었습니다.", "이 확인되었습니다.")
PHRASES = (
    "PowerShell -EncodedCommand 옵션",
    "문서 예시 주소 203.0.113.10:443을 대상으로 한 테스트용 연결",
)


def synthetic_observation_input():
    observations = []
    for index, phrase in enumerate(PHRASES, 1):
        event_id = f"SYNTHETIC-OBS-EVENT-{index:03}"
        record = {"fixture": FIXTURE_ID, "event_id": event_id, "observation": phrase}
        record_hash = digest(record)
        reference = SupportingReference(
            event_id=event_id,
            source_event_id=f"SYNTHETIC-OBS-SOURCE-{index:03}",
            raw_ref={"raw_log_id": "SYNTHETIC-NOT-COLLECTED", "segment_no": 1, "record_no": index},
            manifest_sha256=digest({"fixture": FIXTURE_ID, "record_sha256": record_hash}),
            raw_sha256=record_hash,
            raw_record_sha256=record_hash,
        )
        observations.append(
            VerifiedObservation(
                observation_id=f"SYNTHETIC-OBS-{index:03}",
                observed_at="2026-01-01T00:00:00Z",
                evidence_id=f"SYNTHETIC-OBS-EVIDENCE-{index:03}",
                evidence_type="synthetic_fixture",
                event_ids=(event_id,),
                behavior_summary=phrase,
                supporting_references=(reference,),
            )
        )
    return GroundedReportInput(
        alert_id=ALERT_ID,
        run_id="SYNTHETIC-OBS-RUN-001",
        entity_id="SYNTHETIC-OBS-HOST-001",
        decision_id="SYNTHETIC-OBS-DECISION-001",
        human_action_id="00000000-0000-4000-8000-000000000002",
        human_action_version=1,
        human_state={"version": 1, "report_choice": "proceed", "context": FIXTURE_ID},
        fields=[GroundedReportField(report_field_id=key, value="UNKNOWN") for key in FIELD_IDS],
        candidate_evidence=[
            ReportEvidenceReference(
                evidence_id=o.evidence_id,
                source_event_id=o.supporting_references[0].source_event_id,
                raw_ref=o.supporting_references[0].raw_ref,
                verification="VERIFIED",
            )
            for o in observations
        ],
        verified_observations=observations,
    )


def is_observation_fixture(report):
    return report.model_dump(mode="json") == synthetic_observation_input().model_dump(mode="json")


class ObservationSentence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    observation_id: str = Field(max_length=80)
    evidence_id: str = Field(max_length=80)
    text: str = Field(min_length=1, max_length=400)


class ObservationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["grounded_observation_prose_v1"]
    sentences: list[ObservationSentence] = Field(min_length=2, max_length=2)


def transmission_payload(report):
    if not is_observation_fixture(report):
        raise ValueError("Only the exact code-owned observation fixture is permitted")
    return {
        "output_schema": ObservationOutput.model_json_schema(),
        "observations": [
            {
                "observation_id": o.observation_id,
                "evidence_id": o.evidence_id,
                "fact_phrase": o.behavior_summary,
            }
            for o in report.verified_observations
        ],
        "wording": {"prefixes": PREFIXES, "endings": ENDINGS},
        "limitations": "합성 데이터이며 실제 사건이 아님. 악성 여부·성공·감염·유출·원인·피해·조치는 UNKNOWN.",
    }


def validate_observation_output(text, report):
    if not is_observation_fixture(report):
        raise ValueError("Unapproved observation source")
    content = text.strip()
    if content.startswith("```json\n") and content.endswith("\n```"):
        content = content[8:-4]
    output = ObservationOutput.model_validate_json(content)
    seen = set()
    allowed = {o.observation_id: o for o in report.verified_observations}
    for sentence in output.sentences:
        observation = allowed.get(sentence.observation_id)
        if observation is None or sentence.observation_id in seen:
            raise ValueError("Unknown or duplicate observation")
        seen.add(sentence.observation_id)
        # Check the entire predicate and its polarity, not keywords or ID membership.
        accepted = {
            prefix + observation.behavior_summary + ending
            for prefix, ending in product(PREFIXES, ENDINGS)
        }
        if sentence.evidence_id != observation.evidence_id or sentence.text not in accepted:
            raise ValueError("Sentence is outside the source-grounded language")
    return output


def fallback_output(report):
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=StrictUndefined,
        autoescape=False,
    )
    return validate_observation_output(
        environment.get_template("observation_prose.json.j2").render(
            observations=report.verified_observations, prefix=PREFIXES[0], ending=ENDINGS[0]
        ),
        report,
    )


def narrative_output(output):
    from incident_awareness.reporting.kisa_narrative import KISANarrative

    return KISANarrative(
        incident_summary="비식별 합성 개발용 시나리오입니다. 실제 운영 사고가 아닙니다. 악성 여부와 공격 성공은 확인되지 않았습니다.",
        observed_indicators=" ".join(s.text for s in output.sentences),
        response_actions="UNKNOWN: 수행된 대응조치가 확인되지 않았습니다.",
        unconfirmed_items=[
            "사고 발생시각",
            "사고 원인",
            "피해 규모",
            "유출 여부",
            "대응조치",
            "t_h",
            "법적 신고의무",
        ],
        supporting_reference_ids=[
            ref for s in output.sentences for ref in (s.observation_id, s.evidence_id)
        ],
    ).model_dump(mode="json")


def validated_saved_narrative(draft):
    """Recheck saved prose and source identity before rendering, without another HTTP call."""
    fixture = synthetic_observation_input()
    if (
        draft.get("context") != "synthetic_development"
        or draft.get("alert_id") != ALERT_ID
        or draft.get("source_snapshot_sha256") != fingerprint(fixture.model_dump(mode="json"))
        or draft.get("verified_observations")
        != [o.model_dump(mode="json") for o in fixture.verified_observations]
    ):
        raise ValueError("Synthetic narrative source mismatch")
    narrative = draft["narrative"]
    output = validate_observation_output(json.dumps(narrative["observation_output"]), fixture)
    if narrative["output"] != narrative_output(output):
        raise ValueError("Saved narrative differs from validated sentences")
    if (
        narrative["method"] != draft["method"]
        or narrative["call_metadata"] != draft["call_metadata"]
    ):
        raise ValueError("Saved provider accounting mismatch")
    if draft["method"] == "monorouter_grounded" and (
        draft["call_metadata"]["status"] != "success"
        or draft["call_metadata"]["http_status"] != 200
    ):
        raise ValueError("LLM success requires validated HTTP success")
    return narrative
