"""Input boundary for a future grounded generator and a separate template renderer.

No provider calls or inferred evidence. A resolver must verify every complete chain
before a generator may replace UNKNOWN. Technical references alone are insufficient.
"""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_awareness.common.models.event import RawLogReference
from incident_awareness.evidence.provenance import VerifiedObservation


class ReportEvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: str = Field(min_length=1)
    source_event_id: str | None = Field(default=None, min_length=1)
    raw_ref: RawLogReference | None = None
    verification: Literal["UNRESOLVED", "VERIFIED"] = "UNRESOLVED"

    @model_validator(mode="after")
    def complete_verified_chain(self):
        if self.verification == "VERIFIED" and (not self.source_event_id or self.raw_ref is None):
            raise ValueError("Verified references require evidence -> source_event -> raw_ref")
        return self


class GroundedReportField(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_field_id: str
    value: str = "UNKNOWN"
    references: list[ReportEvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def known_values_require_grounding(self):
        if self.value != "UNKNOWN" and (
            not self.references or any(r.verification != "VERIFIED" for r in self.references)
        ):
            raise ValueError("Known report fields require verified evidence references")
        return self


class GroundedReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["grounded_report_input_v1"] = "grounded_report_input_v1"
    alert_id: str
    run_id: str
    entity_id: str
    decision_id: str | None
    human_action_id: str
    human_action_version: int
    human_state: dict
    fields: list[GroundedReportField]
    candidate_evidence: list[ReportEvidenceReference]
    legal_obligation: Literal["UNDETERMINED"] = "UNDETERMINED"
    analysis: dict | None = None
    verified_observations: list[VerifiedObservation] = Field(default_factory=list)


def build_report_input(detail: dict, analysis: dict | None = None) -> GroundedReportInput:
    from incident_awareness.reporting.observations import snapshot_observations

    state = detail["state"]
    if state["report_choice"] != "proceed":
        raise ValueError("신고 진행 결정이 있어야 Report 입력을 준비할 수 있습니다.")
    action = next(a for a in reversed(detail["audit"]) if a["action"] == "decide_reporting")
    return GroundedReportInput(
        alert_id=detail["alert_id"],
        run_id=detail["run_id"],
        entity_id=detail["entity_id"],
        decision_id=detail["decision_id"],
        human_action_id=str(action["action_id"]),
        human_action_version=action["version"],
        human_state=state,
        fields=[
            GroundedReportField(report_field_id=key)
            for key in (
                "incident_occurred_at",
                "incident_cause",
                "damage_description",
                "response_measures",
                "responsible_department",
                "contact_information",
            )
        ],
        candidate_evidence=_candidate_references(detail, analysis),
        analysis=analysis,
        verified_observations=snapshot_observations(
            analysis, run_id=detail["run_id"], entity_id=detail["entity_id"]
        ),
    )


def _candidate_references(detail, analysis):
    items = (analysis or {}).get("evidence_provenance", {}).get("items", [])
    candidates = []
    for evidence_id in detail["source_snapshot"]["evidence_ids"]:
        resolved = next((item for item in items if item["evidence_id"] == evidence_id), None)
        if resolved and resolved["resolution_status"] == "raw_verified":
            # Keep all source Events, including a multi-Event Evidence's references.
            candidates.extend(
                ReportEvidenceReference(
                    evidence_id=evidence_id,
                    source_event_id=source_id,
                    raw_ref=raw,
                    verification="VERIFIED",
                )
                for source_id, raw in zip(
                    resolved["source_event_ids"], resolved["raw_references"], strict=True
                )
            )
        else:
            candidates.append(ReportEvidenceReference(evidence_id=evidence_id))
    return candidates


class ReportGroundingResolver(Protocol):
    def resolve(self, report: GroundedReportInput) -> GroundedReportInput: ...


class GroundedReportGenerator(Protocol):
    def generate(self, report: GroundedReportInput) -> dict: ...


class ReportRenderer(Protocol):
    def render(self, report: dict) -> str: ...
