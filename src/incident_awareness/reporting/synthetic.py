"""Code-owned, entirely synthetic fixture; never derived from existing S0 or Sysmon data."""

from incident_awareness.dashboard.grounded_report_contract import (
    GroundedReportField,
    GroundedReportInput,
    ReportEvidenceReference,
)
from incident_awareness.reporting.contracts import FIELD_IDS


def synthetic_report_input() -> GroundedReportInput:
    reference = ReportEvidenceReference(
        evidence_id="SYNTHETIC-EVIDENCE-001",
        source_event_id="SYNTHETIC-EVENT-001",
        raw_ref={"raw_log_id": "SYNTHETIC-NOT-A-REAL-LOG", "segment_no": 1, "record_no": 1},
        verification="VERIFIED",
    )
    facts = {
        "incident_occurred_at": "2026-01-01T00:00:00Z",
        "response_measures": "합성 테스트 호스트 격리 및 조사 중",
    }
    return GroundedReportInput(
        alert_id="SYNTHETIC-ALERT-001",
        run_id="SYNTHETIC-RUN-001",
        entity_id="SYNTHETIC-HOST-001",
        decision_id="SYNTHETIC-DECISION-001",
        human_action_id="00000000-0000-4000-8000-000000000001",
        human_action_version=1,
        human_state={"version": 1, "report_choice": "proceed", "context": "synthetic_fixture"},
        fields=[
            GroundedReportField(
                report_field_id=k,
                value=facts.get(k, "UNKNOWN"),
                references=[reference] if k in facts else [],
            )
            for k in FIELD_IDS
        ],
        candidate_evidence=[reference],
    )


def is_synthetic_fixture(report: GroundedReportInput) -> bool:
    from incident_awareness.reporting.synthetic_observations import is_observation_fixture

    # A browser flag, a Run label, or a caller's VERIFIED assertion is not authorization.
    return report.model_dump(mode="json") == synthetic_report_input().model_dump(
        mode="json"
    ) or is_observation_fixture(report)


def validate_source_input(report: GroundedReportInput) -> GroundedReportInput:
    from incident_awareness.reporting.observations import snapshot_observations

    validated = GroundedReportInput.model_validate(report.model_dump(mode="json"))
    if validated.human_state.get("report_choice") != "proceed":
        raise ValueError("A current human proceed decision is required")
    from incident_awareness.reporting.synthetic_observations import is_observation_fixture

    if not is_observation_fixture(
        validated
    ) and validated.verified_observations != snapshot_observations(
        validated.analysis, run_id=validated.run_id, entity_id=validated.entity_id
    ):
        raise ValueError("Observation input does not match the verified snapshot")
    if not is_synthetic_fixture(validated) and any(
        f.value != "UNKNOWN" or f.references for f in validated.fields
    ):
        raise ValueError("Source facts require a verified archive resolver")
    return validated
