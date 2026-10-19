"""Role2-safe proof of a Role4 seal over an accepted R1 RecordId position close.

This is a separate proof contract.  ``r1-role2-verified-close-proof/v0.1`` still binds
only an event-time ``run_closed`` and is not extended.

Role4 issues the proof from a validated position seal, the Role3-accepted position close
and its ledger receipt, and the trusted projection digest that Role4 recorded in an
``r1-position-seal-projection-record`` when it validated the seal.  Role2 validates the
proof against the close and receipt it loaded from the Role3 export and against the
projection digest it received through its own trusted channel.

``verified_seal_at``, ``proof_created_at`` and ``proof_validated_at`` are provenance
only.  None of them, nor the close or reconciliation time, is Evidence ``available_at``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
    R1CandidatePolicyIdentity,
    _validate_utc_milliseconds,
)
from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.collection.r1_position_candidate_generation_seal import (
    R1PositionCandidateGenerationSeal,
    R1PositionSealProjectionRecord,
    R1VerifiedPositionCandidateBoundary,
    position_candidate_generation_seal_sha256,
    position_seal_projection_record_sha256,
    role2_safe_position_seal_projection_payload,
    role2_safe_position_seal_projection_sha256,
)
from incident_awareness.common.models.r1_record_bounded_snapshot import (
    PositiveCount,
    Sha256,
    UtcMilliseconds,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
    R1RecordPositionFrontier,
    record_position_close_receipt_sha256,
    record_position_close_sha256,
    require_receipt_binds_close,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition
from incident_awareness.common.models.run import RunMetadata

R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_SCHEMA = "r1-role2-verified-position-close-proof"
R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_CONTRACT_VERSION = "v0.1"


class R1Role2VerifiedPositionCloseProof(BaseModel):
    """Ground-Truth-free proof whose every binding Role2 can re-check."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-role2-verified-position-close-proof"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["role2_verified_position_close_proof"]
    proof_id: StrictStr = Field(min_length=1)
    run_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    family_id: StrictStr = Field(min_length=1)
    candidate_policy: R1CandidatePolicyIdentity
    source_seal_id: StrictStr = Field(min_length=1)
    source_seal_projection_sha256: Sha256
    source_seal_projection_record_sha256: Sha256
    input_position_close_id: StrictStr = Field(min_length=1)
    accepted_position_close_content_sha256: Sha256
    position_close_receipt: R1AcceptedRecordPositionCloseReceipt
    sealed_partition: R1StreamPartition
    position_frontier: R1RecordPositionFrontier
    covered_through_chunk_sequence: PositiveCount
    covered_chunks_sha256: Sha256
    post_commit_ack_count: PositiveCount
    source_reconciliation_sha256: Sha256
    required_partition_contract_sha256: Sha256
    candidate_boundary_at: UtcMilliseconds
    verified_seal_at: UtcMilliseconds
    proof_created_at: UtcMilliseconds
    non_guarantees: tuple[StrictStr, ...] = Field(min_length=1)
    proof_content_sha256: Sha256

    @field_validator("proof_id", "host_id", "source_seal_id", "input_position_close_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _unpadded("position close proof identity", value)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("family_id")
    @classmethod
    def validate_family_id(cls, value: str) -> str:
        return validate_family_id(value)

    @field_validator("non_guarantees")
    @classmethod
    def validate_non_guarantees(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != R1_RECORD_POSITION_FINALITY_NON_GUARANTEES:
            raise ValueError(
                "non_guarantees must list exactly the position-finality non-guarantees"
            )
        return value

    @model_validator(mode="after")
    def validate_scope_and_hash(self) -> R1Role2VerifiedPositionCloseProof:
        receipt = self.position_close_receipt
        if self.sealed_partition.run_id != self.run_id:
            raise ValueError("sealed_partition must belong to the proof run_id")
        if self.sealed_partition.host_id != self.host_id:
            raise ValueError("proof host_id must be the sealed partition host")
        if (receipt.run_id, receipt.close_id, receipt.partition) != (
            self.run_id,
            self.input_position_close_id,
            self.sealed_partition,
        ):
            raise ValueError("proof receipt does not match the sealed position close")
        if receipt.close_content_sha256 != self.accepted_position_close_content_sha256:
            raise ValueError("proof receipt does not bind the accepted close content")
        if self.post_commit_ack_count != self.covered_through_chunk_sequence:
            raise ValueError("every covered chunk must have exactly one post-commit ack")
        if self.verified_seal_at < receipt.accepted_at:
            raise ValueError("verified_seal_at must not precede the Role3 ledger acceptance")
        if self.verified_seal_at < self.candidate_boundary_at:
            raise ValueError("verified_seal_at must not precede the candidate boundary")
        if self.proof_created_at < self.verified_seal_at:
            raise ValueError("proof_created_at must not precede verified_seal_at")
        _require_proof_content_hash(self)
        return self


@dataclass(frozen=True, slots=True)
class R1Role2VerifiedPositionCloseProofValidation:
    """Strict Role2 validation result.  ``proof_validated_at`` is not ``available_at``."""

    proof: R1Role2VerifiedPositionCloseProof
    proof_validated_at: datetime


def issue_r1_role2_verified_position_close_proof(
    *,
    proof_id: str,
    host_id: str,
    verified_boundary: R1VerifiedPositionCandidateBoundary,
    source_seal: R1PositionCandidateGenerationSeal,
    accepted_position_close: R1RecordPositionClose,
    accepted_position_close_receipt: R1AcceptedRecordPositionCloseReceipt,
    trusted_seal_projection_record: R1PositionSealProjectionRecord,
    candidate_policy: R1CandidateGenerationPolicy,
    proof_created_at: datetime,
) -> R1Role2VerifiedPositionCloseProof:
    """Issue a proof from a validated seal and Role4's independently recorded projection."""

    validated_host_id = _unpadded("host_id", host_id)
    _validate_source_binding(
        verified_boundary=verified_boundary,
        source_seal=source_seal,
        accepted_position_close=accepted_position_close,
        accepted_position_close_receipt=accepted_position_close_receipt,
        candidate_policy=candidate_policy,
        host_id=validated_host_id,
    )
    _validate_trusted_projection_record(
        trusted_seal_projection_record,
        source_seal=source_seal,
        host_id=validated_host_id,
    )
    created_at = _validate_utc_milliseconds("proof_created_at", proof_created_at)
    payload: dict[str, object] = {
        "schema": R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_SCHEMA,
        "contract_version": R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_CONTRACT_VERSION,
        "message_type": "role2_verified_position_close_proof",
        "proof_id": proof_id,
        "run_id": source_seal.run_id,
        "host_id": validated_host_id,
        "family_id": source_seal.family_id,
        "candidate_policy": source_seal.candidate_policy.model_dump(mode="json"),
        "source_seal_id": source_seal.seal_id,
        "source_seal_projection_sha256": trusted_seal_projection_record.projection_sha256,
        "source_seal_projection_record_sha256": position_seal_projection_record_sha256(
            trusted_seal_projection_record
        ),
        "input_position_close_id": accepted_position_close.close_id,
        "accepted_position_close_content_sha256": record_position_close_sha256(
            accepted_position_close
        ),
        "position_close_receipt": accepted_position_close_receipt.model_dump(
            mode="json", by_alias=True
        ),
        "sealed_partition": accepted_position_close.partition.model_dump(mode="json"),
        "position_frontier": accepted_position_close.position_frontier.model_dump(mode="json"),
        "covered_through_chunk_sequence": accepted_position_close.covered_through_chunk_sequence,
        "covered_chunks_sha256": accepted_position_close.covered_chunks_sha256,
        "post_commit_ack_count": accepted_position_close.post_commit_ack_count,
        "source_reconciliation_sha256": (
            accepted_position_close.source_snapshot.reconciliation_sha256
        ),
        "required_partition_contract_sha256": (
            accepted_position_close.required_partition_contract.content_sha256
        ),
        "candidate_boundary_at": _datetime_json(verified_boundary.candidate_boundary_at),
        "verified_seal_at": _datetime_json(verified_boundary.verified_seal_at),
        "proof_created_at": _datetime_json(created_at),
        "non_guarantees": list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES),
    }
    payload["proof_content_sha256"] = _canonical_sha256(payload)
    try:
        return R1Role2VerifiedPositionCloseProof.model_validate(payload)
    except ValidationError as error:
        raise ValueError("position close proof bindings are invalid") from error


def validate_r1_role2_verified_position_close_proof(
    proof: R1Role2VerifiedPositionCloseProof,
    *,
    accepted_position_close: R1RecordPositionClose,
    accepted_position_close_receipt: R1AcceptedRecordPositionCloseReceipt,
    candidate_policy: R1CandidateGenerationPolicy,
    expected_run_id: str,
    expected_family_id: str,
    expected_selector_partition: R1StreamPartition,
    expected_required_partition_contract_sha256: str,
    accepted_source_seal_id: str,
    accepted_source_seal_projection_sha256: str,
    accepted_source_seal_projection_record_sha256: str,
    proof_validated_at: datetime,
) -> R1Role2VerifiedPositionCloseProofValidation:
    """Role2 check of every proof binding without Ground Truth or a Role4 object."""

    if not isinstance(proof, R1Role2VerifiedPositionCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedPositionCloseProof")
    if not isinstance(accepted_position_close, R1RecordPositionClose):
        raise TypeError("accepted_position_close must be an R1RecordPositionClose")
    if not isinstance(candidate_policy, R1CandidateGenerationPolicy):
        raise TypeError("candidate_policy must be an R1CandidateGenerationPolicy")
    if not isinstance(expected_selector_partition, R1StreamPartition):
        raise TypeError("expected_selector_partition must be an R1StreamPartition")
    require_receipt_binds_close(accepted_position_close_receipt, accepted_position_close)
    _require_proof_content_hash(proof)
    run_id = RunMetadata.validate_run_id(RunMetadata.validate_required_identifier(expected_run_id))
    family_id = validate_family_id(expected_family_id)
    seal_id = _unpadded("accepted_source_seal_id", accepted_source_seal_id)
    projection_sha256 = _sha256(
        "accepted_source_seal_projection_sha256", accepted_source_seal_projection_sha256
    )
    projection_record_sha256 = _sha256(
        "accepted_source_seal_projection_record_sha256",
        accepted_source_seal_projection_record_sha256,
    )
    contract_sha256 = _sha256(
        "expected_required_partition_contract_sha256",
        expected_required_partition_contract_sha256,
    )
    validated_at = _validate_utc_milliseconds("proof_validated_at", proof_validated_at)

    if proof.run_id != run_id or accepted_position_close.run_id != run_id:
        raise ValueError("proof and accepted position close must match expected_run_id")
    if expected_selector_partition != accepted_position_close.partition:
        raise ValueError("expected selector partition is not the closed partition")
    if proof.sealed_partition != expected_selector_partition:
        raise ValueError("proof sealed_partition does not match the expected selector partition")
    if proof.host_id != expected_selector_partition.host_id:
        raise ValueError("proof host_id does not match the expected selector partition")
    if proof.family_id != family_id or candidate_policy.family_id != family_id:
        raise ValueError("proof and candidate policy must match expected_family_id")
    if (
        proof.candidate_policy.policy_id,
        proof.candidate_policy.version,
        proof.candidate_policy.config_hash,
        proof.candidate_policy.config_path,
    ) != (
        candidate_policy.policy_id,
        candidate_policy.version,
        candidate_policy.config_hash,
        candidate_policy.canonical_path,
    ):
        raise ValueError("proof candidate policy identity does not match registered policy")
    if proof.source_seal_id != seal_id:
        raise ValueError("proof source_seal_id does not match the accepted source seal")
    if proof.source_seal_projection_sha256 != projection_sha256:
        raise ValueError("proof projection digest does not match the trusted projection digest")
    if proof.source_seal_projection_record_sha256 != projection_record_sha256:
        raise ValueError(
            "proof projection record digest does not match the trusted projection record digest"
        )
    if _proof_projection_sha256(proof) != projection_sha256:
        raise ValueError("proof fields do not match the trusted source seal projection digest")
    if proof.input_position_close_id != accepted_position_close.close_id:
        raise ValueError("proof input_position_close_id does not match the accepted close")
    if proof.accepted_position_close_content_sha256 != record_position_close_sha256(
        accepted_position_close
    ):
        raise ValueError("proof close content hash does not match the accepted close")
    if proof.position_close_receipt != accepted_position_close_receipt:
        raise ValueError("proof receipt does not match the Role3 ledger receipt")
    if (
        proof.position_frontier,
        proof.covered_through_chunk_sequence,
        proof.covered_chunks_sha256,
        proof.post_commit_ack_count,
    ) != (
        accepted_position_close.position_frontier,
        accepted_position_close.covered_through_chunk_sequence,
        accepted_position_close.covered_chunks_sha256,
        accepted_position_close.post_commit_ack_count,
    ):
        raise ValueError("proof RecordId frontier or covered chunks do not match the close")
    if proof.source_reconciliation_sha256 != (
        accepted_position_close.source_snapshot.reconciliation_sha256
    ):
        raise ValueError("proof source reconciliation hash does not match the accepted close")
    if not (
        proof.required_partition_contract_sha256
        == accepted_position_close.required_partition_contract.content_sha256
        == contract_sha256
    ):
        raise ValueError("proof required-partition contract does not match the expected contract")
    if proof.candidate_boundary_at != accepted_position_close.candidate_boundary_at:
        raise ValueError("proof candidate boundary does not match the freeze request boundary")
    if validated_at < proof.proof_created_at:
        raise ValueError("proof_validated_at must not precede proof_created_at")
    return R1Role2VerifiedPositionCloseProofValidation(
        proof=proof,
        proof_validated_at=validated_at,
    )


def role2_verified_position_close_proof_sha256(proof: R1Role2VerifiedPositionCloseProof) -> str:
    """Canonical digest of a complete serialized proof."""

    if not isinstance(proof, R1Role2VerifiedPositionCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedPositionCloseProof")
    return _canonical_sha256(proof.model_dump(mode="json", by_alias=True))


def validate_r1_role2_verified_position_close_proof_replay(
    existing: R1Role2VerifiedPositionCloseProof,
    incoming: R1Role2VerifiedPositionCloseProof,
) -> None:
    """Reject reuse of a proof identity with different canonical content."""

    if (existing.run_id, existing.proof_id) != (incoming.run_id, incoming.proof_id):
        raise ValueError("position close proof replay identity does not match")
    if role2_verified_position_close_proof_sha256(existing) != (
        role2_verified_position_close_proof_sha256(incoming)
    ):
        raise ValueError("position close proof identity was reused with different content")


def write_r1_role2_verified_position_close_proof(
    path: Path,
    proof: R1Role2VerifiedPositionCloseProof,
) -> None:
    """Write a proof with exclusive create so prior content is never overwritten."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    if not isinstance(proof, R1Role2VerifiedPositionCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedPositionCloseProof")
    text = json.dumps(
        proof.model_dump(mode="json", by_alias=True), ensure_ascii=False, indent=2, sort_keys=True
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text + "\n")


def load_r1_role2_verified_position_close_proof(path: Path) -> R1Role2VerifiedPositionCloseProof:
    """Load a proof while rejecting duplicate keys, schema drift and hash drift."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("R1 Role2 position close proof is not valid UTF-8 JSON") from error
    try:
        return R1Role2VerifiedPositionCloseProof.model_validate(payload)
    except ValidationError as error:
        raise ValueError("R1 Role2 position close proof does not match v0.1") from error


def _validate_source_binding(
    *,
    verified_boundary: R1VerifiedPositionCandidateBoundary,
    source_seal: R1PositionCandidateGenerationSeal,
    accepted_position_close: R1RecordPositionClose,
    accepted_position_close_receipt: R1AcceptedRecordPositionCloseReceipt,
    candidate_policy: R1CandidateGenerationPolicy,
    host_id: str,
) -> None:
    if not isinstance(verified_boundary, R1VerifiedPositionCandidateBoundary):
        raise TypeError("verified_boundary must be an R1VerifiedPositionCandidateBoundary")
    if not isinstance(source_seal, R1PositionCandidateGenerationSeal):
        raise TypeError("source_seal must be an R1PositionCandidateGenerationSeal")
    if not isinstance(accepted_position_close, R1RecordPositionClose):
        raise TypeError("accepted_position_close must be an R1RecordPositionClose")
    if not isinstance(candidate_policy, R1CandidateGenerationPolicy):
        raise TypeError("candidate_policy must be an R1CandidateGenerationPolicy")
    require_receipt_binds_close(accepted_position_close_receipt, accepted_position_close)
    if (
        verified_boundary.run_id,
        verified_boundary.seal_id,
        verified_boundary.input_position_close_id,
        verified_boundary.candidate_boundary_at,
        verified_boundary.verified_seal_at,
    ) != (
        source_seal.run_id,
        source_seal.seal_id,
        source_seal.input_position_close_id,
        source_seal.boundary.completed_at,
        source_seal.emitted_at,
    ):
        raise ValueError("verified boundary does not exactly match the source seal")
    if (
        source_seal.input_position_close_id,
        source_seal.input_position_close_content_sha256,
        source_seal.position_close_receipt,
        source_seal.sealed_partition,
        source_seal.position_frontier,
        source_seal.covered_chunks_sha256,
        source_seal.source_reconciliation_sha256,
    ) != (
        accepted_position_close.close_id,
        record_position_close_sha256(accepted_position_close),
        accepted_position_close_receipt,
        accepted_position_close.partition,
        accepted_position_close.position_frontier,
        accepted_position_close.covered_chunks_sha256,
        accepted_position_close.source_snapshot.reconciliation_sha256,
    ):
        raise ValueError("source seal does not bind the accepted position close and receipt")
    if source_seal.family_id != candidate_policy.family_id:
        raise ValueError("source seal family_id does not match candidate policy")
    if (
        source_seal.candidate_policy.policy_id,
        source_seal.candidate_policy.version,
        source_seal.candidate_policy.config_hash,
        source_seal.candidate_policy.config_path,
    ) != (
        candidate_policy.policy_id,
        candidate_policy.version,
        candidate_policy.config_hash,
        candidate_policy.canonical_path,
    ):
        raise ValueError("source seal candidate policy does not match registered policy")
    if source_seal.sealed_partition.host_id != host_id:
        raise ValueError("host_id is not the sealed partition host")
    if verified_boundary.candidate_boundary_at != accepted_position_close.candidate_boundary_at:
        raise ValueError("verified boundary does not match the freeze request boundary")


def _validate_trusted_projection_record(
    record: R1PositionSealProjectionRecord,
    *,
    source_seal: R1PositionCandidateGenerationSeal,
    host_id: str,
) -> None:
    """The trusted digest must come from Role4's record of this exact seal."""

    if not isinstance(record, R1PositionSealProjectionRecord):
        raise TypeError("trusted_seal_projection_record must be an R1PositionSealProjectionRecord")
    if (record.seal_id, record.run_id, record.host_id) != (
        source_seal.seal_id,
        source_seal.run_id,
        host_id,
    ):
        raise ValueError("trusted projection record is bound to another seal, run or host")
    if record.seal_content_sha256 != position_candidate_generation_seal_sha256(source_seal):
        raise ValueError("trusted projection record was not made from this source seal")
    if record.projection_sha256 != role2_safe_position_seal_projection_sha256(
        source_seal, host_id=host_id
    ):
        raise ValueError("trusted projection digest does not match the source seal projection")
    if record.recorded_at < source_seal.emitted_at:
        raise ValueError("trusted projection record precedes its source seal")


def _proof_projection_sha256(proof: R1Role2VerifiedPositionCloseProof) -> str:
    return _canonical_sha256(
        role2_safe_position_seal_projection_payload(
            source_seal_id=proof.source_seal_id,
            run_id=proof.run_id,
            host_id=proof.host_id,
            family_id=proof.family_id,
            candidate_policy=proof.candidate_policy,
            input_position_close_id=proof.input_position_close_id,
            input_position_close_content_sha256=proof.accepted_position_close_content_sha256,
            position_close_receipt_sha256=record_position_close_receipt_sha256(
                proof.position_close_receipt
            ),
            sealed_partition=proof.sealed_partition,
            position_frontier=proof.position_frontier,
            covered_through_chunk_sequence=proof.covered_through_chunk_sequence,
            covered_chunks_sha256=proof.covered_chunks_sha256,
            source_reconciliation_sha256=proof.source_reconciliation_sha256,
            required_partition_contract_sha256=proof.required_partition_contract_sha256,
            candidate_boundary_at=proof.candidate_boundary_at,
            verified_seal_at=proof.verified_seal_at,
        )
    )


def _require_proof_content_hash(proof: R1Role2VerifiedPositionCloseProof) -> None:
    payload = proof.model_dump(mode="json", by_alias=True)
    actual = payload.pop("proof_content_sha256")
    if actual != _canonical_sha256(payload):
        raise ValueError("proof_content_sha256 does not match canonical proof content")


def _sha256(field: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _unpadded(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be non-blank and unpadded")
    return value


def _datetime_json(value: datetime) -> str:
    # Match Pydantic's JSON representation of a UTC datetime exactly.
    return value.isoformat().replace("+00:00", "Z")


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


__all__ = [
    "R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_CONTRACT_VERSION",
    "R1_ROLE2_VERIFIED_POSITION_CLOSE_PROOF_SCHEMA",
    "R1Role2VerifiedPositionCloseProof",
    "R1Role2VerifiedPositionCloseProofValidation",
    "issue_r1_role2_verified_position_close_proof",
    "load_r1_role2_verified_position_close_proof",
    "role2_verified_position_close_proof_sha256",
    "validate_r1_role2_verified_position_close_proof",
    "validate_r1_role2_verified_position_close_proof_replay",
    "write_r1_role2_verified_position_close_proof",
]
