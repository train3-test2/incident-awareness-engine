"""R1 whole-episode Evidence를 causal replay 입력으로 변환한다."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evidence.r1_approved_lineage_policy import (
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import load_r1_evidence_artifacts

R1_CAUSAL_AVAILABILITY_CONTRACT_VERSION = "v0.1"
R1_CAUSAL_WATERMARK_BASIS = "authoritative_run_end"


class R1CausalPolicyIdentity(BaseModel):
    """Causal replay 입력을 만든 selector 또는 approved policy identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: StrictStr
    version: StrictStr
    config_hash: StrictStr

    @field_validator("policy_id", "version", "config_hash")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("policy identity values must be non-blank and unpadded")
        return value


class R1CausalEvidenceAvailability(BaseModel):
    """기존 Evidence와 별도로 보존하는 event-time availability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: StrictStr
    timestamp: datetime
    available_at: datetime
    event_ids: tuple[StrictStr, ...] = Field(min_length=1)
    context_event_ids: tuple[StrictStr, ...] = ()

    @field_validator("evidence_id")
    @classmethod
    def validate_evidence_id(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("evidence_id must be non-blank and unpadded")
        return value

    @field_validator("event_ids", "context_event_ids")
    @classmethod
    def validate_event_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() or value != value.strip() for value in values):
            raise ValueError("Event IDs must be non-blank and unpadded")
        if len(values) != len(set(values)):
            raise ValueError("Event IDs must be unique within each provenance field")
        return values

    @field_validator("timestamp", "available_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime(value)

    @field_validator("timestamp", "available_at")
    @classmethod
    def validate_utc_datetime(cls, value: datetime) -> datetime:
        _validate_utc_datetime(value, field_name="causal Evidence time")
        return value


class R1CausalAvailabilityEnvelope(BaseModel):
    """#232가 Evidence와 결정적으로 결합할 Run 단위 availability 계약."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["v0.1"]
    run_id: StrictStr
    entity_id: StrictStr
    run_start: datetime
    run_end: datetime
    watermark_at: datetime
    watermark_basis: Literal["authoritative_run_end"]
    selector_policy_identity: R1CausalPolicyIdentity
    approved_policy_identity: R1CausalPolicyIdentity
    source_extractor_version: StrictStr
    source_evidence_count: StrictInt = Field(ge=0)
    source_evidence_artifact_sha256: StrictStr
    source_extraction_summary_sha256: StrictStr
    evidences: tuple[R1CausalEvidenceAvailability, ...]

    @field_validator("run_id", "entity_id", "source_extractor_version")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("causal envelope identity values must be non-blank and unpadded")
        return value

    @field_validator("source_evidence_artifact_sha256", "source_extraction_summary_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _is_sha256(value):
            raise ValueError("source artifact hashes must be lowercase SHA-256")
        return value

    @field_validator("run_start", "run_end", "watermark_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime(value)

    @field_validator("run_start", "run_end", "watermark_at")
    @classmethod
    def validate_utc_datetime(cls, value: datetime) -> datetime:
        _validate_utc_datetime(value, field_name="causal envelope time")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> "R1CausalAvailabilityEnvelope":
        if self.run_end < self.run_start:
            raise ValueError("run_end must not be earlier than run_start")
        if self.watermark_at != self.run_end:
            raise ValueError("whole-episode watermark_at must equal authoritative run_end")
        if self.source_evidence_count != len(self.evidences):
            raise ValueError("source_evidence_count must match availability records")
        if self.evidences != tuple(sorted(self.evidences, key=r1_causal_availability_sort_key)):
            raise ValueError("availability records must use canonical ordering")
        if len({item.evidence_id for item in self.evidences}) != len(self.evidences):
            raise ValueError("availability records must contain unique evidence_id values")
        for item in self.evidences:
            if item.timestamp < self.run_start:
                raise ValueError(
                    "Evidence timestamp must not be earlier than authoritative run_start"
                )
            if item.timestamp > self.run_end:
                raise ValueError("Evidence timestamp must not exceed authoritative run_end")
            if item.available_at != self.run_end:
                raise ValueError("R1 whole-episode Evidence available_at must equal run_end")
        return self


def build_r1_causal_availability_envelope(
    artifact_directory: Path,
    *,
    run_metadata: RunMetadata,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
) -> R1CausalAvailabilityEnvelope:
    """검증된 R1 artifact와 authoritative Run 경계로 replay envelope를 만든다."""
    if not isinstance(run_metadata, RunMetadata):
        raise TypeError("run_metadata must be a RunMetadata")
    if not isinstance(selector_policy, R1SelectorPolicy):
        raise TypeError("selector_policy must be an R1SelectorPolicy")
    if not isinstance(approved_policy, ApprovedLineagePolicy):
        raise TypeError("approved_policy must be an ApprovedLineagePolicy")
    if run_metadata.end_time is None:
        raise ValueError("causal availability requires authoritative RunMetadata.end_time")
    if run_metadata.family_id is None:
        raise ValueError("causal availability requires RunMetadata.family_id")
    validate_r1_policy_family_binding(run_metadata.family_id, approved_policy)

    artifact_run = load_r1_evidence_artifacts(artifact_directory)
    summary = artifact_run.summary
    if summary.run_id != run_metadata.run_id:
        raise ValueError("Evidence artifact run_id must match RunMetadata run_id")
    if summary.diagnostics:
        raise ValueError("causal availability requires an artifact without extraction diagnostics")

    selector = summary.selector
    if selector is None:
        raise ValueError(
            "manual or legacy artifact without selector provenance is not causal input"
        )
    if selector.status != "selected":
        raise ValueError("causal availability requires a selected whole-episode lineage")
    expected_selector_identity = _selector_identity(selector_policy)
    actual_selector_identity = R1CausalPolicyIdentity(
        policy_id=selector.policy_id,
        version=selector.version,
        config_hash=selector.config_hash,
    )
    if actual_selector_identity != expected_selector_identity:
        raise ValueError("selector provenance does not match the supplied selector policy")

    lineage_inputs = summary.lineage_inputs
    if lineage_inputs is None or len(lineage_inputs) != 1:
        raise ValueError("causal availability requires one selected lineage provenance input")
    lineage_provenance = lineage_inputs[0]
    expected_approved_identity = _approved_policy_identity(approved_policy)
    actual_approved_identity = R1CausalPolicyIdentity(
        policy_id=lineage_provenance.policy_id,
        version=lineage_provenance.policy_version,
        config_hash=lineage_provenance.policy_config_hash,
    )
    if actual_approved_identity != expected_approved_identity:
        raise ValueError("approved policy provenance does not match the supplied policy")
    evidence_artifact_sha256 = summary.evidence_artifact_sha256
    if evidence_artifact_sha256 is None:
        raise ValueError("completed Evidence artifact must include its validated SHA-256")

    run_end = run_metadata.end_time
    availability_records: list[R1CausalEvidenceAvailability] = []
    for evidence in artifact_run.evidences:
        if evidence.run_id != run_metadata.run_id:
            raise ValueError("Evidence run_id must match RunMetadata run_id")
        if evidence.entity_id != run_metadata.target_host:
            raise ValueError("Evidence entity_id must match RunMetadata target_host")
        if evidence.timestamp < run_metadata.start_time:
            raise ValueError("Evidence timestamp must not be earlier than authoritative run_start")
        if evidence.timestamp > run_end:
            raise ValueError("Evidence timestamp must not exceed authoritative run_end")
        availability_records.append(
            R1CausalEvidenceAvailability(
                evidence_id=evidence.evidence_id,
                timestamp=evidence.timestamp,
                available_at=run_end,
                event_ids=tuple(evidence.event_ids),
                context_event_ids=lineage_provenance.context_event_ids,
            )
        )

    return R1CausalAvailabilityEnvelope(
        contract_version=R1_CAUSAL_AVAILABILITY_CONTRACT_VERSION,
        run_id=run_metadata.run_id,
        entity_id=run_metadata.target_host,
        run_start=run_metadata.start_time,
        run_end=run_end,
        watermark_at=run_end,
        watermark_basis=R1_CAUSAL_WATERMARK_BASIS,
        selector_policy_identity=actual_selector_identity,
        approved_policy_identity=actual_approved_identity,
        source_extractor_version=summary.extractor_version,
        source_evidence_count=len(artifact_run.evidences),
        source_evidence_artifact_sha256=evidence_artifact_sha256,
        source_extraction_summary_sha256=artifact_run.summary_artifact_sha256,
        evidences=tuple(sorted(availability_records, key=r1_causal_availability_sort_key)),
    )


def r1_causal_availability_sort_key(
    availability: R1CausalEvidenceAvailability,
) -> tuple[datetime, datetime, str]:
    """#232에서 공유할 available_at, timestamp, evidence_id 순서다."""
    return availability.available_at, availability.timestamp, availability.evidence_id


def _selector_identity(policy: R1SelectorPolicy) -> R1CausalPolicyIdentity:
    return R1CausalPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
    )


def _approved_policy_identity(policy: ApprovedLineagePolicy) -> R1CausalPolicyIdentity:
    return R1CausalPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
    )


def _validate_utc_datetime(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")


def _reject_numeric_datetime(value: object) -> object:
    if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
        raise ValueError("datetime에 숫자형 Unix timestamp를 사용할 수 없습니다.")

    return value


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False

    return True


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= frozenset("0123456789abcdef")


__all__ = [
    "R1_CAUSAL_AVAILABILITY_CONTRACT_VERSION",
    "R1_CAUSAL_WATERMARK_BASIS",
    "R1CausalAvailabilityEnvelope",
    "R1CausalEvidenceAvailability",
    "R1CausalPolicyIdentity",
    "build_r1_causal_availability_envelope",
    "r1_causal_availability_sort_key",
]
