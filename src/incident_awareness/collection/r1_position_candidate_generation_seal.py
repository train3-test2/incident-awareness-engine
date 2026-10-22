"""Role4 candidate-generation seal over an accepted R1 RecordId position close.

This is a separate versioned seal.  ``r1-candidate-generation-seal/v0.1`` keeps binding
an event-time ``run_closed`` and is not extended.  The position seal binds the accepted
``r1-record-position-close`` and its Role3 ledger receipt instead, and reuses the v0.1
scenario-boundary rules unchanged.

A seal is Role4 provenance only: it is not an event-time watermark, its ``emitted_at`` is
not Evidence ``available_at``, and it inherits every non-guarantee of the position close.

Role4 also records the Role2-safe projection digest of a validated seal in a separate
immutable ``r1-position-seal-projection-record``.  A proof binds the digest of that
record; it does not mint its own trusted digest.
"""

from __future__ import annotations

import hashlib
import json
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
    R1CandidateBoundaryAttestation,
    R1CandidateBoundaryCompletion,
    R1CandidateGenerationPolicy,
    R1CandidatePolicyIdentity,
    R1ScenarioAction,
    _validate_boundary_action_completion,
    _validate_boundary_attestation,
    _validate_boundary_within_run,
    _validate_scenario_boundary,
    _validate_utc_milliseconds,
)
from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.r1_record_bounded_snapshot import (
    PositiveCount,
    Sha256,
    UtcMilliseconds,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
    R1RecordPositionFrontier,
    record_position_close_receipt_sha256,
    record_position_close_sha256,
    require_receipt_binds_close,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition
from incident_awareness.common.models.run import RunMetadata, RunType

R1_POSITION_CANDIDATE_GENERATION_SEAL_SCHEMA = "r1-position-candidate-generation-seal"
R1_POSITION_SEAL_PROJECTION_RECORD_SCHEMA = "r1-position-seal-projection-record"
R1_ROLE2_POSITION_SEAL_PROJECTION_SCHEMA = "r1-role2-position-seal-projection"
R1_POSITION_SEAL_CONTRACT_VERSION = "v0.1"


class _Message(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


class R1PositionCandidateGenerationSeal(_Message):
    """Role4 boundary bound to one Role3-accepted RecordId position close."""

    schema_id: Literal["r1-position-candidate-generation-seal"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["position_candidate_generation_seal"]
    seal_id: StrictStr = Field(min_length=1)
    run_id: StrictStr = Field(min_length=1)
    family_id: StrictStr = Field(min_length=1)
    run_type: RunType
    input_position_close_id: StrictStr = Field(min_length=1)
    input_position_close_content_sha256: Sha256
    position_close_receipt: R1AcceptedRecordPositionCloseReceipt
    sealed_partition: R1StreamPartition
    position_frontier: R1RecordPositionFrontier
    covered_through_chunk_sequence: PositiveCount
    covered_chunks_sha256: Sha256
    source_reconciliation_sha256: Sha256
    required_partition_contract_sha256: Sha256
    candidate_policy: R1CandidatePolicyIdentity
    boundary: R1CandidateBoundaryAttestation
    emitted_at: UtcMilliseconds

    @field_validator("seal_id", "input_position_close_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _unpadded("position seal identity", value)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("family_id")
    @classmethod
    def validate_family(cls, value: str) -> str:
        return validate_family_id(value)

    @model_validator(mode="after")
    def validate_scope(self) -> R1PositionCandidateGenerationSeal:
        receipt = self.position_close_receipt
        if self.sealed_partition.run_id != self.run_id:
            raise ValueError("sealed_partition must belong to the seal run_id")
        if (receipt.run_id, receipt.close_id, receipt.partition) != (
            self.run_id,
            self.input_position_close_id,
            self.sealed_partition,
        ):
            raise ValueError("position seal receipt does not match the sealed close")
        if receipt.close_content_sha256 != self.input_position_close_content_sha256:
            raise ValueError("position seal receipt does not bind the sealed close content")
        if self.emitted_at < self.boundary.completed_at:
            raise ValueError("seal emitted_at must not precede boundary completion")
        if self.emitted_at < receipt.accepted_at:
            raise ValueError("a position seal must not precede the Role3 ledger acceptance")
        return self


class R1VerifiedPositionCandidateBoundary(BaseModel):
    """Ground-Truth-free boundary that Role4 hands to the proof issuer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: StrictStr = Field(min_length=1)
    seal_id: StrictStr = Field(min_length=1)
    input_position_close_id: StrictStr = Field(min_length=1)
    candidate_boundary_at: UtcMilliseconds
    verified_seal_at: UtcMilliseconds


class R1PositionSealProjectionRecord(_Message):
    """Role4's immutable record of a validated seal's Role2-safe projection digest."""

    schema_id: Literal["r1-position-seal-projection-record"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["position_seal_projection_record"]
    seal_id: StrictStr = Field(min_length=1)
    run_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    seal_content_sha256: Sha256
    projection_sha256: Sha256
    recorded_at: UtcMilliseconds
    record_content_sha256: Sha256

    @field_validator("seal_id", "host_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _unpadded("projection record identity", value)

    @model_validator(mode="after")
    def validate_content_hash(self) -> R1PositionSealProjectionRecord:
        payload = self.model_dump(mode="json", by_alias=True)
        actual = payload.pop("record_content_sha256")
        if actual != _canonical_sha256(payload):
            raise ValueError("record_content_sha256 does not match the projection record")
        return self


def issue_r1_position_candidate_generation_seal(
    *,
    seal_id: str,
    run_metadata: RunMetadata,
    position_close: R1RecordPositionClose,
    position_close_receipt: R1AcceptedRecordPositionCloseReceipt,
    scenario_actions: tuple[R1ScenarioAction, ...],
    boundary: R1CandidateBoundaryAttestation,
    boundary_action_record: ExecutionRecordRow,
    boundary_completion: R1CandidateBoundaryCompletion,
    policy: R1CandidateGenerationPolicy,
    emitted_at: datetime,
) -> R1PositionCandidateGenerationSeal:
    """Issue a seal only over a position close the Role3 ledger has committed."""

    if not isinstance(position_close, R1RecordPositionClose):
        raise TypeError("position_close must be an R1RecordPositionClose")
    require_receipt_binds_close(position_close_receipt, position_close)
    payload = {
        "schema": R1_POSITION_CANDIDATE_GENERATION_SEAL_SCHEMA,
        "contract_version": R1_POSITION_SEAL_CONTRACT_VERSION,
        "message_type": "position_candidate_generation_seal",
        "seal_id": seal_id,
        "run_id": run_metadata.run_id,
        "family_id": policy.family_id,
        "run_type": run_metadata.run_type.value,
        "input_position_close_id": position_close.close_id,
        "input_position_close_content_sha256": record_position_close_sha256(position_close),
        "position_close_receipt": position_close_receipt.model_dump(mode="json", by_alias=True),
        "sealed_partition": position_close.partition.model_dump(mode="json"),
        "position_frontier": position_close.position_frontier.model_dump(mode="json"),
        "covered_through_chunk_sequence": position_close.covered_through_chunk_sequence,
        "covered_chunks_sha256": position_close.covered_chunks_sha256,
        "source_reconciliation_sha256": position_close.source_snapshot.reconciliation_sha256,
        "required_partition_contract_sha256": (
            position_close.required_partition_contract.content_sha256
        ),
        "candidate_policy": {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "config_hash": policy.config_hash,
            "config_path": policy.canonical_path,
        },
        "boundary": boundary.model_dump(mode="json"),
        "emitted_at": emitted_at,
    }
    try:
        seal = R1PositionCandidateGenerationSeal.model_validate(payload)
    except ValidationError as error:
        raise ValueError("position candidate-generation seal bindings are invalid") from error
    validate_r1_position_candidate_generation_seal_binding(
        seal,
        run_metadata=run_metadata,
        position_close=position_close,
        position_close_receipt=position_close_receipt,
        scenario_actions=scenario_actions,
        boundary_action_record=boundary_action_record,
        boundary_completion=boundary_completion,
        policy=policy,
    )
    return seal


def validate_r1_position_candidate_generation_seal_binding(
    seal: R1PositionCandidateGenerationSeal,
    *,
    run_metadata: RunMetadata,
    position_close: R1RecordPositionClose,
    position_close_receipt: R1AcceptedRecordPositionCloseReceipt,
    scenario_actions: tuple[R1ScenarioAction, ...],
    boundary_action_record: ExecutionRecordRow,
    boundary_completion: R1CandidateBoundaryCompletion,
    policy: R1CandidateGenerationPolicy,
) -> R1VerifiedPositionCandidateBoundary:
    """Validate the Ground-Truth bindings in Role4 and return only a Ground-Truth-free boundary."""

    if not isinstance(seal, R1PositionCandidateGenerationSeal):
        raise TypeError("seal must be an R1PositionCandidateGenerationSeal")
    if not isinstance(position_close, R1RecordPositionClose):
        raise TypeError("position_close must be an R1RecordPositionClose")
    require_receipt_binds_close(position_close_receipt, position_close)
    if run_metadata.run_id != position_close.run_id or seal.run_id != position_close.run_id:
        raise ValueError("RunMetadata, seal and position close must share one run_id")
    if run_metadata.target_host != position_close.partition.host_id:
        raise ValueError("RunMetadata target_host does not match the position close host")
    if run_metadata.family_id != policy.family_id or seal.family_id != policy.family_id:
        raise ValueError("RunMetadata and seal family_id must match the candidate policy")
    if seal.run_type is not run_metadata.run_type:
        raise ValueError("seal run_type does not match RunMetadata")
    if (
        seal.input_position_close_id,
        seal.input_position_close_content_sha256,
        seal.position_close_receipt,
    ) != (
        position_close.close_id,
        record_position_close_sha256(position_close),
        position_close_receipt,
    ):
        raise ValueError("seal does not bind the accepted position close and its receipt")
    if (
        seal.sealed_partition,
        seal.position_frontier,
        seal.covered_through_chunk_sequence,
        seal.covered_chunks_sha256,
        seal.source_reconciliation_sha256,
        seal.required_partition_contract_sha256,
    ) != (
        position_close.partition,
        position_close.position_frontier,
        position_close.covered_through_chunk_sequence,
        position_close.covered_chunks_sha256,
        position_close.source_snapshot.reconciliation_sha256,
        position_close.required_partition_contract.content_sha256,
    ):
        raise ValueError("seal position frontier references do not exactly match the close")
    if (
        seal.candidate_policy.policy_id,
        seal.candidate_policy.version,
        seal.candidate_policy.config_hash,
        seal.candidate_policy.config_path,
    ) != (policy.policy_id, policy.version, policy.config_hash, policy.canonical_path):
        raise ValueError("seal candidate policy identity does not match registered policy")

    expected_boundary = (
        policy.attack_boundary if seal.run_type is RunType.ATTACK else policy.normal_boundary
    )
    expected_processes = (
        policy.attack_owned_processes
        if seal.run_type is RunType.ATTACK
        else policy.normal_owned_processes
    )
    _validate_scenario_boundary(scenario_actions, expected_boundary)
    _validate_boundary_attestation(seal.boundary, expected_boundary, expected_processes, policy)
    _validate_boundary_action_completion(
        seal.boundary,
        scenario_actions[-1],
        boundary_action_record,
        boundary_completion,
        run_metadata,
    )
    _validate_boundary_within_run(seal.boundary, run_metadata)
    if seal.boundary.completed_at != position_close.candidate_boundary_at:
        raise ValueError("seal boundary does not match the freeze request candidate boundary")
    if seal.emitted_at < position_close_receipt.accepted_at:
        raise ValueError("seal emitted_at must not precede the Role3 ledger acceptance")
    return R1VerifiedPositionCandidateBoundary(
        run_id=seal.run_id,
        seal_id=seal.seal_id,
        input_position_close_id=seal.input_position_close_id,
        candidate_boundary_at=seal.boundary.completed_at,
        verified_seal_at=seal.emitted_at,
    )


def position_candidate_generation_seal_sha256(seal: R1PositionCandidateGenerationSeal) -> str:
    """Canonical content digest of a position seal (it includes Ground Truth)."""

    if not isinstance(seal, R1PositionCandidateGenerationSeal):
        raise TypeError("seal must be an R1PositionCandidateGenerationSeal")
    return _canonical_sha256(seal.model_dump(mode="json", by_alias=True))


def role2_safe_position_seal_projection_payload(
    *,
    source_seal_id: str,
    run_id: str,
    host_id: str,
    family_id: str,
    candidate_policy: R1CandidatePolicyIdentity,
    input_position_close_id: str,
    input_position_close_content_sha256: str,
    position_close_receipt_sha256: str,
    sealed_partition: R1StreamPartition,
    position_frontier: R1RecordPositionFrontier,
    covered_through_chunk_sequence: int,
    covered_chunks_sha256: str,
    source_reconciliation_sha256: str,
    required_partition_contract_sha256: str,
    candidate_boundary_at: datetime,
    verified_seal_at: datetime,
) -> dict[str, object]:
    """Fields a proof exposes to Role2; ``run_type`` and process details are excluded."""

    return {
        "schema": R1_ROLE2_POSITION_SEAL_PROJECTION_SCHEMA,
        "contract_version": R1_POSITION_SEAL_CONTRACT_VERSION,
        "source_seal_id": source_seal_id,
        "run_id": run_id,
        "host_id": host_id,
        "family_id": family_id,
        "candidate_policy": candidate_policy.model_dump(mode="json"),
        "input_position_close_id": input_position_close_id,
        "input_position_close_content_sha256": input_position_close_content_sha256,
        "position_close_receipt_sha256": position_close_receipt_sha256,
        "sealed_partition": sealed_partition.model_dump(mode="json"),
        "position_frontier": position_frontier.model_dump(mode="json"),
        "covered_through_chunk_sequence": covered_through_chunk_sequence,
        "covered_chunks_sha256": covered_chunks_sha256,
        "source_reconciliation_sha256": source_reconciliation_sha256,
        "required_partition_contract_sha256": required_partition_contract_sha256,
        "candidate_boundary_at": _datetime_json(candidate_boundary_at),
        "verified_seal_at": _datetime_json(verified_seal_at),
    }


def role2_safe_position_seal_projection_sha256(
    seal: R1PositionCandidateGenerationSeal,
    *,
    host_id: str,
) -> str:
    """Role4 computation of the Role2-safe projection digest of a position seal."""

    if not isinstance(seal, R1PositionCandidateGenerationSeal):
        raise TypeError("seal must be an R1PositionCandidateGenerationSeal")
    if _unpadded("host_id", host_id) != seal.sealed_partition.host_id:
        raise ValueError("host_id is not the sealed partition host")
    return _canonical_sha256(
        role2_safe_position_seal_projection_payload(
            source_seal_id=seal.seal_id,
            run_id=seal.run_id,
            host_id=host_id,
            family_id=seal.family_id,
            candidate_policy=seal.candidate_policy,
            input_position_close_id=seal.input_position_close_id,
            input_position_close_content_sha256=seal.input_position_close_content_sha256,
            position_close_receipt_sha256=record_position_close_receipt_sha256(
                seal.position_close_receipt
            ),
            sealed_partition=seal.sealed_partition,
            position_frontier=seal.position_frontier,
            covered_through_chunk_sequence=seal.covered_through_chunk_sequence,
            covered_chunks_sha256=seal.covered_chunks_sha256,
            source_reconciliation_sha256=seal.source_reconciliation_sha256,
            required_partition_contract_sha256=seal.required_partition_contract_sha256,
            candidate_boundary_at=seal.boundary.completed_at,
            verified_seal_at=seal.emitted_at,
        )
    )


def issue_r1_position_seal_projection_record(
    *,
    seal: R1PositionCandidateGenerationSeal,
    verified_boundary: R1VerifiedPositionCandidateBoundary,
    host_id: str,
    recorded_at: datetime,
) -> R1PositionSealProjectionRecord:
    """Record the projection digest of a seal Role4 has already validated."""

    if not isinstance(seal, R1PositionCandidateGenerationSeal):
        raise TypeError("seal must be an R1PositionCandidateGenerationSeal")
    if not isinstance(verified_boundary, R1VerifiedPositionCandidateBoundary):
        raise TypeError("verified_boundary must be an R1VerifiedPositionCandidateBoundary")
    if (
        verified_boundary.run_id,
        verified_boundary.seal_id,
        verified_boundary.input_position_close_id,
        verified_boundary.candidate_boundary_at,
        verified_boundary.verified_seal_at,
    ) != (
        seal.run_id,
        seal.seal_id,
        seal.input_position_close_id,
        seal.boundary.completed_at,
        seal.emitted_at,
    ):
        raise ValueError("verified boundary does not exactly match the position seal")
    recorded = _utc_milliseconds("recorded_at", recorded_at)
    if recorded < seal.emitted_at:
        raise ValueError("a projection record must not precede its seal")
    payload: dict[str, object] = {
        "schema": R1_POSITION_SEAL_PROJECTION_RECORD_SCHEMA,
        "contract_version": R1_POSITION_SEAL_CONTRACT_VERSION,
        "message_type": "position_seal_projection_record",
        "seal_id": seal.seal_id,
        "run_id": seal.run_id,
        "host_id": host_id,
        "seal_content_sha256": position_candidate_generation_seal_sha256(seal),
        "projection_sha256": role2_safe_position_seal_projection_sha256(seal, host_id=host_id),
        "recorded_at": _datetime_json(recorded),
    }
    payload["record_content_sha256"] = _canonical_sha256(payload)
    return R1PositionSealProjectionRecord.model_validate(payload)


def position_seal_projection_record_sha256(record: R1PositionSealProjectionRecord) -> str:
    """Canonical content digest of a projection record."""

    if not isinstance(record, R1PositionSealProjectionRecord):
        raise TypeError("record must be an R1PositionSealProjectionRecord")
    return _canonical_sha256(record.model_dump(mode="json", by_alias=True))


def write_r1_position_message(path: Path, message: BaseModel) -> None:
    """Write a seal or projection record with exclusive create (never overwritten)."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    text = json.dumps(
        message.model_dump(mode="json", by_alias=True), ensure_ascii=False, indent=2, sort_keys=True
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text + "\n")


def load_r1_position_candidate_generation_seal(path: Path) -> R1PositionCandidateGenerationSeal:
    """Load a position seal, rejecting duplicate keys and schema drift."""

    return _load(path, R1PositionCandidateGenerationSeal)


def load_r1_position_seal_projection_record(path: Path) -> R1PositionSealProjectionRecord:
    """Load a projection record, rejecting duplicate keys, drift and hash changes."""

    return _load(path, R1PositionSealProjectionRecord)


def _load[MessageT: BaseModel](path: Path, model: type[MessageT]) -> MessageT:
    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{model.__name__} is not valid UTF-8 JSON") from error
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        raise ValueError(f"{model.__name__} does not match v0.1") from error


def _unpadded(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be non-blank without surrounding whitespace")
    return value


def _utc_milliseconds(field: str, value: datetime) -> datetime:
    return _validate_utc_milliseconds(field, value)


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
    "R1_POSITION_CANDIDATE_GENERATION_SEAL_SCHEMA",
    "R1_POSITION_SEAL_CONTRACT_VERSION",
    "R1_POSITION_SEAL_PROJECTION_RECORD_SCHEMA",
    "R1_ROLE2_POSITION_SEAL_PROJECTION_SCHEMA",
    "R1PositionCandidateGenerationSeal",
    "R1PositionSealProjectionRecord",
    "R1VerifiedPositionCandidateBoundary",
    "issue_r1_position_candidate_generation_seal",
    "issue_r1_position_seal_projection_record",
    "load_r1_position_candidate_generation_seal",
    "load_r1_position_seal_projection_record",
    "position_candidate_generation_seal_sha256",
    "position_seal_projection_record_sha256",
    "role2_safe_position_seal_projection_payload",
    "role2_safe_position_seal_projection_sha256",
    "validate_r1_position_candidate_generation_seal_binding",
    "write_r1_position_message",
]
