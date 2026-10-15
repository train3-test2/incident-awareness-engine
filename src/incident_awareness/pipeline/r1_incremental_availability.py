"""R1 incremental causal availability v0.2 and replay linkage."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
)
from incident_awareness.collection.r1_role2_verified_close_proof import (
    role2_verified_close_proof_sha256,
)
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evidence.r1_approved_lineage_policy import (
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalEvidenceAvailability,
    R1CausalPolicyIdentity,
    r1_causal_availability_sort_key,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    R1IncrementalEvidenceCheckpoint,
    incremental_checkpoint_sha256,
)
from incident_awareness.pipeline.r1_incremental_evidence import (
    R1IncrementalEvidenceSnapshot,
)

R1_INCREMENTAL_CAUSAL_AVAILABILITY_CONTRACT_VERSION = "v0.2"
R1_INCREMENTAL_WATERMARK_BASIS = "accepted_final_stream_close_and_verified_candidate_proof"


class R1IncrementalAvailabilityFrontier(BaseModel):
    """All durable facts whose validated maximum defines v0.2 availability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_close_id: StrictStr
    accepted_run_closed_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    input_close_emitted_at: datetime
    candidate_boundary_at: datetime
    verified_seal_at: datetime
    proof_id: StrictStr
    proof_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    proof_created_at: datetime
    proof_validated_at: datetime
    latest_input_ingest_at: datetime

    @field_validator(
        "input_close_emitted_at",
        "candidate_boundary_at",
        "verified_seal_at",
        "proof_created_at",
        "proof_validated_at",
        "latest_input_ingest_at",
        mode="before",
    )
    @classmethod
    def reject_numeric_time(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("incremental availability time must not be a numeric Unix timestamp")
        return value

    @field_validator(
        "input_close_emitted_at",
        "candidate_boundary_at",
        "verified_seal_at",
        "proof_created_at",
        "proof_validated_at",
        "latest_input_ingest_at",
    )
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        _validate_utc(value)
        return value

    @model_validator(mode="after")
    def validate_frontier(self) -> R1IncrementalAvailabilityFrontier:
        predecessors = (
            self.input_close_emitted_at,
            self.candidate_boundary_at,
            self.verified_seal_at,
            self.proof_created_at,
            self.latest_input_ingest_at,
        )
        if self.proof_validated_at < max(predecessors):
            raise ValueError("proof validation must not precede a finalization input")
        return self


class R1IncrementalCausalAvailabilityEnvelope(BaseModel):
    """Versioned early availability without changing whole-episode v0.1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["v0.2"]
    run_id: StrictStr
    entity_id: StrictStr
    run_start: datetime
    run_end: datetime
    watermark_at: datetime
    watermark_basis: Literal["accepted_final_stream_close_and_verified_candidate_proof"]
    selector_policy_identity: R1CausalPolicyIdentity
    approved_policy_identity: R1CausalPolicyIdentity
    candidate_policy_identity: R1CausalPolicyIdentity
    required_partition_contract_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    source_state_checkpoint_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    source_verified_close_proof_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    source_evidence_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    source_evidence_count: StrictInt = Field(ge=0)
    frontier: R1IncrementalAvailabilityFrontier
    evidences: tuple[R1CausalEvidenceAvailability, ...]

    @field_validator("run_id", "entity_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("incremental availability identities must be non-blank and unpadded")
        return value

    @field_validator("run_start", "run_end", "watermark_at", mode="before")
    @classmethod
    def reject_numeric_time(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("incremental availability time must not be a numeric Unix timestamp")
        return value

    @field_validator("run_start", "run_end", "watermark_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        _validate_utc(value)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> R1IncrementalCausalAvailabilityEnvelope:
        if self.run_end < self.run_start:
            raise ValueError("run_end must not precede run_start")
        if not self.run_start <= self.watermark_at <= self.run_end:
            raise ValueError("incremental watermark must be inside authoritative Run bounds")
        if not self.run_start <= self.frontier.proof_validated_at <= self.run_end:
            raise ValueError("incremental causal frontier must be inside authoritative Run bounds")
        if self.source_evidence_count != len(self.evidences):
            raise ValueError("source_evidence_count must match availability records")
        if self.evidences != tuple(sorted(self.evidences, key=r1_causal_availability_sort_key)):
            raise ValueError("availability records must use canonical ordering")
        if len({item.evidence_id for item in self.evidences}) != len(self.evidences):
            raise ValueError("availability evidence_id values must be unique")
        for item in self.evidences:
            if not self.run_start <= item.timestamp <= self.run_end:
                raise ValueError("Evidence timestamp must be inside authoritative Run bounds")
            if item.available_at != self.frontier.proof_validated_at:
                raise ValueError("Evidence available_at must equal the validated causal frontier")
            if not item.timestamp <= item.available_at <= self.run_end:
                raise ValueError("incremental Evidence availability must be causal and in-Run")
        return self


def build_r1_incremental_causal_availability_envelope(
    snapshot: R1IncrementalEvidenceSnapshot,
    checkpoint: R1IncrementalEvidenceCheckpoint,
    *,
    run_metadata: RunMetadata,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
    candidate_policy: R1CandidateGenerationPolicy,
) -> R1IncrementalCausalAvailabilityEnvelope:
    """Bind finalized Evidence to proof, checkpoint, policies and Run bounds."""

    if not isinstance(snapshot, R1IncrementalEvidenceSnapshot):
        raise TypeError("snapshot must be an R1IncrementalEvidenceSnapshot")
    if not isinstance(checkpoint, R1IncrementalEvidenceCheckpoint):
        raise TypeError("checkpoint must be an R1IncrementalEvidenceCheckpoint")
    checkpoint = R1IncrementalEvidenceCheckpoint.model_validate(
        checkpoint.model_dump(by_alias=True),
    )
    if not isinstance(run_metadata, RunMetadata):
        raise TypeError("run_metadata must be a RunMetadata")
    if not isinstance(selector_policy, R1SelectorPolicy):
        raise TypeError("selector_policy must be an R1SelectorPolicy")
    if not isinstance(approved_policy, ApprovedLineagePolicy):
        raise TypeError("approved_policy must be an ApprovedLineagePolicy")
    if not isinstance(candidate_policy, R1CandidateGenerationPolicy):
        raise TypeError("candidate_policy must be an R1CandidateGenerationPolicy")
    if snapshot.status != "finalized" or snapshot.close_mode != "verified_close_proof":
        raise ValueError("v0.2 availability requires a finalized verified-proof snapshot")
    if snapshot.availability_contract_version != "v0.2":
        raise ValueError("snapshot does not carry incremental availability v0.2")
    if run_metadata.end_time is None or run_metadata.family_id is None:
        raise ValueError("v0.2 availability requires authoritative RunMetadata bounds/family")
    if (checkpoint.run_id, checkpoint.entity_id) != (
        run_metadata.run_id,
        run_metadata.target_host,
    ):
        raise ValueError("checkpoint scope must match RunMetadata")
    if checkpoint.run_start != run_metadata.start_time:
        raise ValueError("checkpoint run_start must match RunMetadata")
    if checkpoint.scenario_family_id != run_metadata.family_id:
        raise ValueError("checkpoint scenario family must match RunMetadata")
    validate_r1_policy_family_binding(run_metadata.family_id, approved_policy)
    _validate_policy_identities(checkpoint, selector_policy, approved_policy, candidate_policy)
    proof = checkpoint.verified_close_proof
    run_closed = checkpoint.accepted_run_closed
    if proof is None or run_closed is None or checkpoint.proof_validated_at is None:
        raise ValueError("checkpoint is missing verified close proof provenance")
    if snapshot.verified_close_proof_sha256 != role2_verified_close_proof_sha256(proof):
        raise ValueError("snapshot proof identity does not match checkpoint proof")
    if snapshot.available_at != checkpoint.proof_validated_at:
        raise ValueError("snapshot availability does not match checkpoint validation time")
    selection = snapshot.selector_result.selection
    if selection is None or (selection.run_id, selection.entity_id) != (
        run_metadata.run_id,
        run_metadata.target_host,
    ):
        raise ValueError("snapshot selector scope must match RunMetadata")
    all_events = tuple(event for chunk in checkpoint.accepted_chunks for event in chunk.events)
    latest_input_ingest_at = max(
        (event.ingest_time for event in all_events),
        default=run_metadata.start_time,
    )
    frontier = R1IncrementalAvailabilityFrontier(
        input_close_id=proof.input_close_id,
        accepted_run_closed_content_sha256=proof.accepted_run_closed_content_sha256,
        input_close_emitted_at=proof.input_close_emitted_at,
        candidate_boundary_at=proof.candidate_boundary_at,
        verified_seal_at=proof.verified_seal_at,
        proof_id=proof.proof_id,
        proof_content_sha256=role2_verified_close_proof_sha256(proof),
        proof_created_at=proof.proof_created_at,
        proof_validated_at=checkpoint.proof_validated_at,
        latest_input_ingest_at=latest_input_ingest_at,
    )
    evidences = tuple(sorted(snapshot.availability, key=r1_causal_availability_sort_key))
    evidence_by_id = {evidence.evidence_id: evidence for evidence in snapshot.evidences}
    if len(evidence_by_id) != len(snapshot.evidences):
        raise ValueError("snapshot Evidence IDs must be unique")
    if {item.evidence_id for item in evidences} != evidence_by_id.keys():
        raise ValueError("snapshot Evidence and availability identities must match")
    context_event_ids = (
        snapshot.lineage_input.context_event_ids if snapshot.lineage_input is not None else ()
    )
    for item in evidences:
        evidence = evidence_by_id[item.evidence_id]
        if evidence.run_id != run_metadata.run_id or evidence.entity_id != run_metadata.target_host:
            raise ValueError("incremental Evidence scope must match RunMetadata")
        if item.timestamp != evidence.timestamp:
            raise ValueError("incremental availability timestamp must match Evidence timestamp")
        if item.event_ids != tuple(evidence.event_ids):
            raise ValueError("incremental availability event_ids must match Evidence event_ids")
        if item.context_event_ids != context_event_ids:
            raise ValueError("incremental availability context provenance must match lineage input")
    required_partition_identities = {
        (item.source, item.source_channel)
        for item in checkpoint.required_partition_contract.required_partitions
    }
    target_watermarks = tuple(
        item
        for item in proof.sealed_partitions
        if item.partition.run_id == run_metadata.run_id
        and item.partition.host_id == run_metadata.target_host
        and (item.partition.source, item.partition.source_channel) in required_partition_identities
    )
    if len(target_watermarks) != len(required_partition_identities):
        raise ValueError("proof does not contain every required target partition watermark")
    return R1IncrementalCausalAvailabilityEnvelope(
        contract_version=R1_INCREMENTAL_CAUSAL_AVAILABILITY_CONTRACT_VERSION,
        run_id=run_metadata.run_id,
        entity_id=run_metadata.target_host,
        run_start=run_metadata.start_time,
        run_end=run_metadata.end_time,
        watermark_at=max(item.watermark_at for item in target_watermarks),
        watermark_basis=R1_INCREMENTAL_WATERMARK_BASIS,
        selector_policy_identity=_selector_identity(selector_policy),
        approved_policy_identity=_approved_identity(approved_policy),
        candidate_policy_identity=_candidate_identity(candidate_policy),
        required_partition_contract_sha256=required_partition_contract_sha256(
            checkpoint.required_partition_contract
        ),
        source_state_checkpoint_sha256=incremental_checkpoint_sha256(checkpoint),
        source_verified_close_proof_sha256=role2_verified_close_proof_sha256(proof),
        source_evidence_sha256=_evidence_set_sha256(snapshot.evidences),
        source_evidence_count=len(snapshot.evidences),
        frontier=frontier,
        evidences=evidences,
    )


def write_r1_incremental_causal_availability_envelope(
    path: Path,
    envelope: R1IncrementalCausalAvailabilityEnvelope,
) -> None:
    """Publish a finalized envelope once; overwrite is forbidden."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    content = _serialize_envelope(envelope)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
        staged = Path(stream.name)
    try:
        os.link(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def incremental_availability_envelope_sha256(
    envelope: R1IncrementalCausalAvailabilityEnvelope,
) -> str:
    if not isinstance(envelope, R1IncrementalCausalAvailabilityEnvelope):
        raise TypeError("envelope must be an R1IncrementalCausalAvailabilityEnvelope")
    return hashlib.sha256(_serialize_envelope(envelope)).hexdigest()


def _serialize_envelope(envelope: R1IncrementalCausalAvailabilityEnvelope) -> bytes:
    return (
        json.dumps(
            envelope.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def load_r1_incremental_causal_availability_envelope(
    path: Path,
) -> R1IncrementalCausalAvailabilityEnvelope:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        return R1IncrementalCausalAvailabilityEnvelope.model_validate(payload)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ) as error:
        raise ValueError("R1 incremental availability envelope is invalid") from error


def required_partition_contract_sha256(contract: R1RequiredPartitionContract) -> str:
    return _canonical_sha256(contract.model_dump(mode="json", by_alias=True))


def _validate_policy_identities(checkpoint, selector, approved, candidate) -> None:
    if checkpoint.selector_policy_identity != checkpoint.selector_policy_identity.__class__(
        **_selector_identity(selector).model_dump(),
        lineage_event_count=selector.lineage_event_count,
    ):
        raise ValueError("selector policy does not match checkpoint")
    approved_identity = checkpoint.approved_policy_identity
    if (
        approved_identity.policy_id,
        approved_identity.version,
        approved_identity.config_hash,
        approved_identity.family_id,
        approved_identity.lifecycle,
    ) != (
        approved.policy_id,
        approved.version,
        approved.config_hash,
        approved.family_id,
        approved.lifecycle,
    ):
        raise ValueError("approved policy does not match checkpoint")
    if checkpoint.candidate_policy_identity != _candidate_identity(candidate):
        raise ValueError("candidate policy does not match checkpoint")


def _selector_identity(policy: R1SelectorPolicy) -> R1CausalPolicyIdentity:
    return R1CausalPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
    )


def _approved_identity(policy: ApprovedLineagePolicy) -> R1CausalPolicyIdentity:
    return R1CausalPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
    )


def _candidate_identity(policy: R1CandidateGenerationPolicy) -> R1CausalPolicyIdentity:
    return R1CausalPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
    )


def _evidence_set_sha256(evidences: tuple[Evidence, ...]) -> str:
    payload = [
        evidence.model_dump(mode="json", by_alias=True)
        for evidence in sorted(evidences, key=lambda item: item.evidence_id)
    ]
    return _canonical_sha256(payload)


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("incremental availability times must include timezone information")
    if value.utcoffset() != timedelta(0):
        raise ValueError("incremental availability times must be UTC")


def _is_numeric_string(value: str) -> bool:
    try:
        float(value.strip())
    except ValueError:
        return False
    return bool(value.strip())


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


__all__ = [
    "R1_INCREMENTAL_CAUSAL_AVAILABILITY_CONTRACT_VERSION",
    "R1_INCREMENTAL_WATERMARK_BASIS",
    "R1IncrementalAvailabilityFrontier",
    "R1IncrementalCausalAvailabilityEnvelope",
    "build_r1_incremental_causal_availability_envelope",
    "incremental_availability_envelope_sha256",
    "load_r1_incremental_causal_availability_envelope",
    "required_partition_contract_sha256",
    "write_r1_incremental_causal_availability_envelope",
]
