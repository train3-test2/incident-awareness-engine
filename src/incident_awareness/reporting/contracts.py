"""Conservative output validation: the provider cannot add ungrounded claims."""

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.dashboard.grounded_report_contract import GroundedReportInput

FIELD_IDS = (
    "incident_occurred_at",
    "incident_cause",
    "damage_description",
    "response_measures",
    "responsible_department",
    "contact_information",
)


class GeneratedField(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    report_field_id: str
    value: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)


class GroundedReportOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["grounded_report_output_v1"] = "grounded_report_output_v1"
    fields: list[GeneratedField] = Field(min_length=6, max_length=6)


class CallMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    status: Literal[
        "disabled",
        "blocked_data",
        "missing_key",
        "configuration_error",
        "requesting",
        "success",
        "timeout",
        "transport_error",
        "rate_limited",
        "http_error",
        "invalid_response",
        "invalid_output",
    ]
    requested_model: str | None = None
    actual_model: str | None = None
    requested_at: str | None = None
    completed_at: str | None = None
    elapsed_ms: int | None = Field(default=None, ge=0)
    http_status: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_creation_input_tokens: int | None = None
    cache_read_input_tokens: int | None = None


def canonical_output(report: GroundedReportInput) -> GroundedReportOutput:
    if len(report.fields) != 6 or {f.report_field_id for f in report.fields} != set(FIELD_IDS):
        raise ValueError("Report field contract mismatch")
    return GroundedReportOutput(
        fields=[
            GeneratedField(
                report_field_id=f.report_field_id,
                value=f.value,
                evidence_ids=[r.evidence_id for r in f.references],
            )
            for f in report.fields
        ]
    )


def verify_output(text: str, report: GroundedReportInput) -> GroundedReportOutput:
    content = text.strip()
    if content.startswith("```json\n") and content.endswith("\n```"):
        content = content[8:-4]
    result = GroundedReportOutput.model_validate(json.loads(content))
    expected = canonical_output(report)
    expected_fields = {f.report_field_id: f for f in expected.fields}
    if len({f.report_field_id for f in result.fields}) != 6:
        raise ValueError("Duplicate output fields")
    for generated in result.fields:
        source = expected_fields.get(generated.report_field_id)
        if source is None:
            raise ValueError("Unknown output field")
        value = "UNKNOWN" if generated.value in {"UNKNOWN", "조사 중"} else generated.value
        if value != source.value or generated.evidence_ids != source.evidence_ids:
            raise ValueError("Output conflicts with verified source facts")
    # Return canonical facts, never provider-written markup or unconstrained narrative.
    return expected
