"""Role2-safe R1 candidate close proof contract.

The proof preserves the bindings that are intentionally absent from the older
``R1VerifiedCandidateBoundary``.  It does not define Evidence availability or
activate early close in the incremental Evidence state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    R1CandidateGenerationSeal,
    R1CandidatePolicyIdentity,
    R1VerifiedCandidateBoundary,
)
from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.common.models.r1_stream import (
    R1FinalPartitionWatermark,
    R1RunClosed,
    R1StreamPartition,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
)

R1_ROLE2_VERIFIED_CLOSE_PROOF_SCHEMA = "r1-role2-verified-close-proof"
R1_ROLE2_VERIFIED_CLOSE_PROOF_CONTRACT_VERSION = "v0.1"
R1_ROLE2_SOURCE_SEAL_PROJECTION_SCHEMA = "r1-role2-source-seal-projection"
R1_ROLE2_SOURCE_SEAL_PROJECTION_CONTRACT_VERSION = "v0.1"


class R1Role2VerifiedCloseProof(BaseModel):
    """Sanitized close proof whose bindings can be checked by Role2."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-role2-verified-close-proof"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["role2_verified_close_proof"]
    proof_id: StrictStr = Field(min_length=1)
    run_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    family_id: StrictStr = Field(min_length=1)
    candidate_policy: R1CandidatePolicyIdentity
    source_seal_id: StrictStr = Field(min_length=1)
    source_seal_projection_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    input_close_id: StrictStr = Field(min_length=1)
    accepted_run_closed_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    input_close_emitted_at: datetime
    candidate_boundary_at: datetime
    sealed_partitions: tuple[R1FinalPartitionWatermark, ...] = Field(min_length=1)
    verified_seal_at: datetime
    proof_created_at: datetime
    proof_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("proof_id", "host_id", "source_seal_id", "input_close_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _validate_unpadded("verified close proof identity", value)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("family_id")
    @classmethod
    def validate_family_id(cls, value: str) -> str:
        return validate_family_id(value)

    @field_validator(
        "input_close_emitted_at",
        "candidate_boundary_at",
        "verified_seal_at",
        "proof_created_at",
        mode="before",
    )
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("verified close proof datetime must not be a numeric Unix timestamp")
        return value

    @field_validator(
        "input_close_emitted_at",
        "candidate_boundary_at",
        "verified_seal_at",
        "proof_created_at",
    )
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_milliseconds("verified close proof timestamp", value)

    @model_validator(mode="after")
    def validate_scope_and_hash(self) -> R1Role2VerifiedCloseProof:
        partitions = tuple(_partition_key(item.partition) for item in self.sealed_partitions)
        if len(partitions) != len(set(partitions)):
            raise ValueError("sealed_partitions must not contain duplicate partitions")
        if any(item.partition.run_id != self.run_id for item in self.sealed_partitions):
            raise ValueError("every sealed partition run_id must match proof run_id")
        if not any(item.partition.host_id == self.host_id for item in self.sealed_partitions):
            raise ValueError("proof host_id must be present in sealed_partitions")
        if any(item.watermark_at < self.candidate_boundary_at for item in self.sealed_partitions):
            raise ValueError("every final watermark must cover the candidate boundary")
        if self.verified_seal_at < self.input_close_emitted_at:
            raise ValueError("verified_seal_at must not precede input_close_emitted_at")
        if self.proof_created_at < self.verified_seal_at:
            raise ValueError("proof_created_at must not precede verified_seal_at")
        _require_proof_content_hash(self)
        return self


@dataclass(frozen=True, slots=True)
class R1Role2VerifiedCloseProofValidation:
    """Strict Role2 validation result; neither timestamp is Evidence availability."""

    proof: R1Role2VerifiedCloseProof
    proof_validated_at: datetime


def issue_r1_role2_verified_close_proof(
    *,
    proof_id: str,
    host_id: str,
    verified_boundary: R1VerifiedCandidateBoundary,
    source_seal: R1CandidateGenerationSeal,
    accepted_run_closed: R1RunClosed,
    accepted_close_receipt: R1AcceptedRunCloseReceipt,
    candidate_policy: R1CandidateGenerationPolicy,
    proof_created_at: datetime,
) -> R1Role2VerifiedCloseProof:
    """Create a proof only from an already verified Role4 boundary and accepted close."""

    validated_host_id = _validate_unpadded("host_id", host_id)
    _validate_accepted_close_receipt(
        accepted_close_receipt,
        accepted_run_closed=accepted_run_closed,
    )
    _validate_source_binding(
        verified_boundary=verified_boundary,
        source_seal=source_seal,
        accepted_run_closed=accepted_run_closed,
        candidate_policy=candidate_policy,
        host_id=validated_host_id,
    )
    created_at = _validate_utc_milliseconds("proof_created_at", proof_created_at)
    payload: dict[str, object] = {
        "schema": R1_ROLE2_VERIFIED_CLOSE_PROOF_SCHEMA,
        "contract_version": R1_ROLE2_VERIFIED_CLOSE_PROOF_CONTRACT_VERSION,
        "message_type": "role2_verified_close_proof",
        "proof_id": proof_id,
        "run_id": source_seal.run_id,
        "host_id": validated_host_id,
        "family_id": source_seal.family_id,
        "candidate_policy": source_seal.candidate_policy.model_dump(mode="json"),
        "source_seal_id": source_seal.seal_id,
        "source_seal_projection_sha256": role2_safe_source_seal_projection_sha256(
            source_seal,
            host_id=validated_host_id,
        ),
        "input_close_id": accepted_run_closed.close_id,
        "accepted_run_closed_content_sha256": r1_run_closed_sha256(accepted_run_closed),
        "input_close_emitted_at": _datetime_json(accepted_run_closed.emitted_at),
        "candidate_boundary_at": _datetime_json(verified_boundary.candidate_boundary_at),
        "sealed_partitions": [
            item.model_dump(mode="json") for item in accepted_run_closed.final_watermarks
        ],
        "verified_seal_at": _datetime_json(verified_boundary.verified_seal_at),
        "proof_created_at": _datetime_json(created_at),
    }
    payload["proof_content_sha256"] = _canonical_sha256(payload)
    return R1Role2VerifiedCloseProof.model_validate(payload)


def validate_r1_role2_verified_close_proof(
    proof: R1Role2VerifiedCloseProof,
    *,
    accepted_run_closed: R1RunClosed,
    accepted_close_receipt: R1AcceptedRunCloseReceipt,
    candidate_policy: R1CandidateGenerationPolicy,
    expected_run_id: str,
    expected_family_id: str,
    expected_selector_partition: R1StreamPartition,
    accepted_source_seal_id: str,
    accepted_source_seal_projection_sha256: str,
    proof_validated_at: datetime,
) -> R1Role2VerifiedCloseProofValidation:
    """Strictly validate every Role2-visible proof binding without Ground Truth."""

    if not isinstance(proof, R1Role2VerifiedCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedCloseProof")
    if not isinstance(accepted_run_closed, R1RunClosed):
        raise TypeError("accepted_run_closed must be an R1RunClosed")
    _validate_accepted_close_receipt(
        accepted_close_receipt,
        accepted_run_closed=accepted_run_closed,
    )
    if not isinstance(candidate_policy, R1CandidateGenerationPolicy):
        raise TypeError("candidate_policy must be an R1CandidateGenerationPolicy")
    if not isinstance(expected_selector_partition, R1StreamPartition):
        raise TypeError("expected_selector_partition must be an R1StreamPartition")

    _require_proof_content_hash(proof)
    run_id = RunMetadata.validate_run_id(RunMetadata.validate_required_identifier(expected_run_id))
    family_id = validate_family_id(expected_family_id)
    source_seal_id = _validate_unpadded("accepted_source_seal_id", accepted_source_seal_id)
    source_projection_hash = _validate_sha256(
        "accepted_source_seal_projection_sha256",
        accepted_source_seal_projection_sha256,
    )
    validated_at = _validate_utc_milliseconds("proof_validated_at", proof_validated_at)

    if proof.run_id != run_id or accepted_run_closed.run_id != run_id:
        raise ValueError("proof and accepted run_closed must match expected_run_id")
    if expected_selector_partition.run_id != run_id:
        raise ValueError("expected selector partition run_id must match expected_run_id")
    if proof.host_id != expected_selector_partition.host_id:
        raise ValueError("proof host_id does not match expected selector partition")
    if proof.family_id != family_id or candidate_policy.family_id != family_id:
        raise ValueError("proof and candidate policy must match expected_family_id")
    if proof.source_seal_id != source_seal_id:
        raise ValueError("proof source_seal_id does not match the accepted source seal")
    if proof.source_seal_projection_sha256 != source_projection_hash:
        raise ValueError(
            "proof source seal projection digest does not match the accepted projection"
        )
    if _proof_source_seal_projection_sha256(proof) != source_projection_hash:
        raise ValueError("proof fields do not match the trusted source seal projection digest")
    if proof.input_close_id != accepted_run_closed.close_id:
        raise ValueError("proof input_close_id does not match accepted run_closed")
    if proof.accepted_run_closed_content_sha256 != r1_run_closed_sha256(accepted_run_closed):
        raise ValueError("proof run_closed content hash does not match accepted run_closed")
    if proof.input_close_emitted_at != accepted_run_closed.emitted_at:
        raise ValueError("proof input close emission does not match accepted run_closed")
    if proof.sealed_partitions != accepted_run_closed.final_watermarks:
        raise ValueError("proof sealed_partitions do not exactly match accepted run_closed")
    if expected_selector_partition not in tuple(item.partition for item in proof.sealed_partitions):
        raise ValueError("expected selector partition is absent from proof sealed_partitions")

    expected_policy = _policy_identity(candidate_policy)
    actual_policy = (
        proof.candidate_policy.policy_id,
        proof.candidate_policy.version,
        proof.candidate_policy.config_hash,
        proof.candidate_policy.config_path,
    )
    if actual_policy != expected_policy:
        raise ValueError("proof candidate policy identity does not match registered policy")
    if any(item.watermark_at < proof.candidate_boundary_at for item in proof.sealed_partitions):
        raise ValueError("proof final watermark does not cover candidate boundary")
    if proof.verified_seal_at < accepted_run_closed.emitted_at:
        raise ValueError("proof verified_seal_at precedes accepted run_closed")
    if validated_at < proof.proof_created_at:
        raise ValueError("proof_validated_at must not precede proof_created_at")
    return R1Role2VerifiedCloseProofValidation(
        proof=proof,
        proof_validated_at=validated_at,
    )


def r1_run_closed_sha256(run_closed: R1RunClosed) -> str:
    """Return the canonical content hash of an accepted ``run_closed`` message."""

    if not isinstance(run_closed, R1RunClosed):
        raise TypeError("run_closed must be an R1RunClosed")
    return _canonical_sha256(run_closed.model_dump(mode="json", by_alias=True))


def role2_safe_source_seal_projection_sha256(
    source_seal: R1CandidateGenerationSeal,
    *,
    host_id: str,
) -> str:
    """Hash only the Role2-safe source-seal fields exposed by the proof."""

    if not isinstance(source_seal, R1CandidateGenerationSeal):
        raise TypeError("source_seal must be an R1CandidateGenerationSeal")
    validated_host_id = _validate_unpadded("host_id", host_id)
    if not any(
        item.partition.host_id == validated_host_id for item in source_seal.sealed_partitions
    ):
        raise ValueError("host_id is absent from source seal partitions")
    return _canonical_sha256(
        _source_seal_projection_payload(
            source_seal_id=source_seal.seal_id,
            run_id=source_seal.run_id,
            host_id=validated_host_id,
            family_id=source_seal.family_id,
            candidate_policy=source_seal.candidate_policy,
            input_close_id=source_seal.input_close_id,
            candidate_boundary_at=source_seal.boundary.completed_at,
            sealed_partitions=source_seal.sealed_partitions,
            verified_seal_at=source_seal.emitted_at,
        )
    )


def role2_verified_close_proof_sha256(proof: R1Role2VerifiedCloseProof) -> str:
    """Return the canonical hash of the complete serialized proof."""

    if not isinstance(proof, R1Role2VerifiedCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedCloseProof")
    return _canonical_sha256(proof.model_dump(mode="json", by_alias=True))


def validate_r1_role2_verified_close_proof_replay(
    existing: R1Role2VerifiedCloseProof,
    incoming: R1Role2VerifiedCloseProof,
) -> None:
    """Reject reuse of a proof identity with different canonical content."""

    if existing.run_id != incoming.run_id or existing.proof_id != incoming.proof_id:
        raise ValueError("verified close proof replay identity does not match")
    if role2_verified_close_proof_sha256(existing) != role2_verified_close_proof_sha256(incoming):
        raise ValueError("verified close proof identity was reused with different content")


def write_r1_role2_verified_close_proof(
    path: Path,
    proof: R1Role2VerifiedCloseProof,
) -> None:
    """Write a proof using exclusive create so prior content is never overwritten."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    if not isinstance(proof, R1Role2VerifiedCloseProof):
        raise TypeError("proof must be an R1Role2VerifiedCloseProof")
    text = (
        json.dumps(
            proof.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def load_r1_role2_verified_close_proof(path: Path) -> R1Role2VerifiedCloseProof:
    """Load a proof while rejecting duplicate keys, schema drift, and hash drift."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("R1 Role2 verified close proof is not valid UTF-8 JSON") from error
    try:
        return R1Role2VerifiedCloseProof.model_validate(payload)
    except ValidationError as error:
        raise ValueError("R1 Role2 verified close proof does not match v0.1") from error


def _validate_source_binding(
    *,
    verified_boundary: R1VerifiedCandidateBoundary,
    source_seal: R1CandidateGenerationSeal,
    accepted_run_closed: R1RunClosed,
    candidate_policy: R1CandidateGenerationPolicy,
    host_id: str,
) -> None:
    if not isinstance(verified_boundary, R1VerifiedCandidateBoundary):
        raise TypeError("verified_boundary must be an R1VerifiedCandidateBoundary")
    if not isinstance(source_seal, R1CandidateGenerationSeal):
        raise TypeError("source_seal must be an R1CandidateGenerationSeal")
    if not isinstance(accepted_run_closed, R1RunClosed):
        raise TypeError("accepted_run_closed must be an R1RunClosed")
    if not isinstance(candidate_policy, R1CandidateGenerationPolicy):
        raise TypeError("candidate_policy must be an R1CandidateGenerationPolicy")
    if (
        verified_boundary.run_id,
        verified_boundary.seal_id,
        verified_boundary.input_close_id,
        verified_boundary.candidate_boundary_at,
        verified_boundary.verified_seal_at,
    ) != (
        source_seal.run_id,
        source_seal.seal_id,
        source_seal.input_close_id,
        source_seal.boundary.completed_at,
        source_seal.emitted_at,
    ):
        raise ValueError("verified boundary does not exactly match source seal")
    if source_seal.run_id != accepted_run_closed.run_id:
        raise ValueError("source seal run_id does not match accepted run_closed")
    if source_seal.input_close_id != accepted_run_closed.close_id:
        raise ValueError("source seal input_close_id does not match accepted run_closed")
    if source_seal.sealed_partitions != accepted_run_closed.final_watermarks:
        raise ValueError("source seal partitions do not exactly match accepted run_closed")
    if source_seal.family_id != candidate_policy.family_id:
        raise ValueError("source seal family_id does not match candidate policy")
    if (
        source_seal.candidate_policy.policy_id,
        source_seal.candidate_policy.version,
        source_seal.candidate_policy.config_hash,
        source_seal.candidate_policy.config_path,
    ) != _policy_identity(candidate_policy):
        raise ValueError("source seal candidate policy does not match registered policy")
    if not any(item.partition.host_id == host_id for item in source_seal.sealed_partitions):
        raise ValueError("host_id is absent from source seal partitions")
    if any(
        item.watermark_at < verified_boundary.candidate_boundary_at
        for item in source_seal.sealed_partitions
    ):
        raise ValueError("source seal final watermark does not cover candidate boundary")
    if verified_boundary.verified_seal_at < accepted_run_closed.emitted_at:
        raise ValueError("verified boundary precedes accepted run_closed")


def _validate_accepted_close_receipt(
    receipt: R1AcceptedRunCloseReceipt,
    *,
    accepted_run_closed: R1RunClosed,
) -> None:
    if not isinstance(receipt, R1AcceptedRunCloseReceipt):
        raise TypeError("accepted_close_receipt must be an R1AcceptedRunCloseReceipt")
    run_id = RunMetadata.validate_run_id(RunMetadata.validate_required_identifier(receipt.run_id))
    close_id = _validate_unpadded("accepted_close_receipt.close_id", receipt.close_id)
    content_sha256 = _validate_sha256(
        "accepted_close_receipt.content_sha256",
        receipt.content_sha256,
    )
    if run_id != accepted_run_closed.run_id:
        raise ValueError("accepted close receipt run_id does not match accepted run_closed")
    if close_id != accepted_run_closed.close_id:
        raise ValueError("accepted close receipt close_id does not match accepted run_closed")
    if content_sha256 != r1_run_closed_sha256(accepted_run_closed):
        raise ValueError("accepted close receipt content hash does not match accepted run_closed")


def _policy_identity(policy: R1CandidateGenerationPolicy) -> tuple[str, str, str, str]:
    return policy.policy_id, policy.version, policy.config_hash, policy.canonical_path


def _proof_source_seal_projection_sha256(proof: R1Role2VerifiedCloseProof) -> str:
    return _canonical_sha256(
        _source_seal_projection_payload(
            source_seal_id=proof.source_seal_id,
            run_id=proof.run_id,
            host_id=proof.host_id,
            family_id=proof.family_id,
            candidate_policy=proof.candidate_policy,
            input_close_id=proof.input_close_id,
            candidate_boundary_at=proof.candidate_boundary_at,
            sealed_partitions=proof.sealed_partitions,
            verified_seal_at=proof.verified_seal_at,
        )
    )


def _source_seal_projection_payload(
    *,
    source_seal_id: str,
    run_id: str,
    host_id: str,
    family_id: str,
    candidate_policy: R1CandidatePolicyIdentity,
    input_close_id: str,
    candidate_boundary_at: datetime,
    sealed_partitions: tuple[R1FinalPartitionWatermark, ...],
    verified_seal_at: datetime,
) -> dict[str, object]:
    return {
        "schema": R1_ROLE2_SOURCE_SEAL_PROJECTION_SCHEMA,
        "contract_version": R1_ROLE2_SOURCE_SEAL_PROJECTION_CONTRACT_VERSION,
        "source_seal_id": source_seal_id,
        "run_id": run_id,
        "host_id": host_id,
        "family_id": family_id,
        "candidate_policy": candidate_policy.model_dump(mode="json"),
        "input_close_id": input_close_id,
        "candidate_boundary_at": _datetime_json(candidate_boundary_at),
        "sealed_partitions": [item.model_dump(mode="json") for item in sealed_partitions],
        "verified_seal_at": _datetime_json(verified_seal_at),
    }


def _require_proof_content_hash(proof: R1Role2VerifiedCloseProof) -> None:
    payload = proof.model_dump(mode="json", by_alias=True)
    actual = payload.pop("proof_content_sha256")
    expected = _canonical_sha256(payload)
    if actual != expected:
        raise ValueError("proof_content_sha256 does not match canonical proof content")


def _validate_sha256(field: str, value: object) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _partition_key(partition: R1StreamPartition) -> tuple[str, str, str, str]:
    return partition.run_id, partition.host_id, partition.source, partition.source_channel


def _validate_unpadded(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be non-blank and unpadded")
    return value


def _validate_utc_milliseconds(field: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include timezone information")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be UTC")
    if value.microsecond % 1000 != 0:
        raise ValueError(f"{field} must use millisecond precision")
    return value.astimezone(UTC)


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _datetime_json(value: datetime) -> str:
    # Match Pydantic's canonical JSON representation exactly.  The value has
    # already been constrained to millisecond precision; forcing ``.000`` here
    # would differ from ``model_dump(mode="json")`` for whole-second values.
    return value.isoformat().replace("+00:00", "Z")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


__all__ = [
    "R1_ROLE2_SOURCE_SEAL_PROJECTION_CONTRACT_VERSION",
    "R1_ROLE2_SOURCE_SEAL_PROJECTION_SCHEMA",
    "R1_ROLE2_VERIFIED_CLOSE_PROOF_CONTRACT_VERSION",
    "R1_ROLE2_VERIFIED_CLOSE_PROOF_SCHEMA",
    "R1Role2VerifiedCloseProof",
    "R1Role2VerifiedCloseProofValidation",
    "issue_r1_role2_verified_close_proof",
    "load_r1_role2_verified_close_proof",
    "r1_run_closed_sha256",
    "role2_safe_source_seal_projection_sha256",
    "role2_verified_close_proof_sha256",
    "validate_r1_role2_verified_close_proof",
    "validate_r1_role2_verified_close_proof_replay",
    "write_r1_role2_verified_close_proof",
]
