"""R1 Sysmon RecordId position close and its accepted Role3 ledger receipt (v0.1).

A record position close is a separate stream finality kind.  It closes one approved,
immutable RecordId-bounded canonical snapshot after the snapshot reconciliation has
verified it, and it is accepted only by the Role3 ledger.  It is neither a
``source_watermark`` nor a ``run_closed``: it carries no event-time frontier, and
``observation_boundary_at`` and ``candidate_boundary_at`` are provenance only.

The only guarantee is ``R1_RECORD_POSITION_FINALITY_GUARANTEE``.  Every item of
``R1_RECORD_POSITION_FINALITY_NON_GUARANTEES`` remains unproven.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    Identity,
    PositiveCount,
    RecordId,
    Sha256,
    TargetEventIds,
    UtcMilliseconds,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition
from incident_awareness.common.models.run import RunMetadata

R1_RECORD_POSITION_CLOSE_SCHEMA = "r1-record-position-close"
R1_RECORD_POSITION_CLOSE_RECEIPT_SCHEMA = "r1-record-position-close-receipt"
R1_RECORD_POSITION_CLOSE_CONTRACT_VERSION = "v0.1"
R1_RECORD_POSITION_FINALITY_KIND = "sysmon_record_id_position"
R1_RECORD_POSITION_FINALITY_GUARANTEE = (
    "every Event of the approved immutable RecordId-bounded canonical snapshot was "
    "delivered to the collector and committed by the Role3 ledger, and the snapshot "
    "is not modified any further"
)
R1_RECORD_POSITION_FINALITY_NON_GUARANTEES = (
    "sysmon_provider_queue_drain",
    "raw_source_completeness_outside_snapshot",
    "event_time_completeness",
    "absence_of_post_bound_events_with_earlier_timestamps",
    "early_close_before_candidate_boundary",
    "causal_confirmation_within_reference_plus_600s",
    "ttsd_or_online_eligibility",
)


def _require_non_guarantees(value: tuple[str, ...]) -> tuple[str, ...]:
    if value != R1_RECORD_POSITION_FINALITY_NON_GUARANTEES:
        raise ValueError("non_guarantees must list exactly the position-finality non-guarantees")
    return value


NonGuarantees = Annotated[tuple[str, ...], Field(min_length=1)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class R1RecordPositionFrontier(_Strict):
    """The closed RecordId position range of one Sysmon channel generation."""

    finality_kind: Literal["sysmon_record_id_position"]
    lower_record_id: RecordId
    upper_record_id: RecordId
    target_event_ids: TargetEventIds
    channel_generation_id: Sha256

    @model_validator(mode="after")
    def validate_bound(self) -> R1RecordPositionFrontier:
        if self.lower_record_id > self.upper_record_id:
            raise ValueError("lower_record_id must not exceed upper_record_id")
        return self


class R1RequiredPartitionContractBinding(_Strict):
    target_host: Identity
    content_sha256: Sha256


class R1RecordBoundedSnapshotSourceBinding(_Strict):
    """Byte digests of every snapshot artifact the close was issued from."""

    request_id: Identity
    freeze_request_sha256: Sha256
    freeze_ack_sha256: Sha256
    run_finalized_sha256: Sha256
    reconciliation_sha256: Sha256
    freeze_generation_observation_sha256: Sha256
    export_generation_observation_sha256: Sha256


class R1RecordPositionClose(BaseModel):
    """Role3-acceptable close of one verified RecordId-bounded snapshot."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-record-position-close"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["record_position_close"]
    close_id: Identity
    run_id: Identity
    partition: R1StreamPartition
    required_partition_contract: R1RequiredPartitionContractBinding
    position_frontier: R1RecordPositionFrontier
    covered_through_chunk_sequence: PositiveCount
    covered_chunks_sha256: Sha256
    post_commit_ack_count: PositiveCount
    event_count: PositiveCount
    source_native_identity_sha256: Sha256
    live_identity_sha256: Sha256
    canonical_identity_sha256: Sha256
    source_snapshot: R1RecordBoundedSnapshotSourceBinding
    candidate_boundary_at: UtcMilliseconds
    observation_boundary_at: UtcMilliseconds
    emitted_at: UtcMilliseconds
    guarantee: Literal[R1_RECORD_POSITION_FINALITY_GUARANTEE]
    non_guarantees: NonGuarantees

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("non_guarantees")
    @classmethod
    def validate_non_guarantees(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_non_guarantees(value)

    @model_validator(mode="after")
    def validate_bindings(self) -> R1RecordPositionClose:
        if self.partition.run_id != self.run_id:
            raise ValueError("position close partition must belong to its run_id")
        if self.required_partition_contract.target_host != self.partition.host_id:
            raise ValueError("required-partition contract must bind the closed host")
        if self.live_identity_sha256 != self.canonical_identity_sha256:
            raise ValueError("live and canonical identity digests must be equal")
        if self.post_commit_ack_count != self.covered_through_chunk_sequence:
            raise ValueError("every covered chunk must have exactly one post-commit ack")
        if self.observation_boundary_at < self.candidate_boundary_at:
            raise ValueError("observation_boundary_at must not precede candidate_boundary_at")
        if self.emitted_at < self.observation_boundary_at:
            raise ValueError("a position close must not be emitted before the observation boundary")
        return self


class R1AcceptedRecordPositionCloseReceipt(BaseModel):
    """Immutable acceptance read back from the Role3 ledger after its commit."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-record-position-close-receipt"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    run_id: Identity
    close_id: Identity
    partition: R1StreamPartition
    close_content_sha256: Sha256
    ledger_entry_id: Annotated[StrictInt, Field(ge=1)]
    accepted_at: UtcMilliseconds

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @model_validator(mode="after")
    def validate_partition(self) -> R1AcceptedRecordPositionCloseReceipt:
        if self.partition.run_id != self.run_id:
            raise ValueError("receipt partition must belong to its run_id")
        return self


def record_position_close_sha256(close: R1RecordPositionClose) -> str:
    """Canonical content digest the Role3 ledger records for a position close."""

    if not isinstance(close, R1RecordPositionClose):
        raise TypeError("close must be an R1RecordPositionClose")
    return _canonical_sha256(close.model_dump(mode="json", by_alias=True))


def record_position_close_receipt_sha256(receipt: R1AcceptedRecordPositionCloseReceipt) -> str:
    """Canonical content digest of an accepted position-close receipt."""

    if not isinstance(receipt, R1AcceptedRecordPositionCloseReceipt):
        raise TypeError("receipt must be an R1AcceptedRecordPositionCloseReceipt")
    return _canonical_sha256(receipt.model_dump(mode="json", by_alias=True))


def covered_chunk_list_sha256(chunks: Sequence[tuple[int, str, str]]) -> str:
    """Digest of ordered ``(chunk_sequence, chunk_id, chunk_content_sha256)`` entries.

    The finalizer computes it from the spool and the Role3 ledger recomputes it from
    its accepted chunk rows, so both sides bind the same covered chunk list.
    """

    entries = [
        {
            "chunk_content_sha256": content_sha256,
            "chunk_id": chunk_id,
            "chunk_sequence": sequence,
        }
        for sequence, chunk_id, content_sha256 in chunks
    ]
    data = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((data + "\n").encode("utf-8")).hexdigest()


def require_receipt_binds_close(
    receipt: R1AcceptedRecordPositionCloseReceipt,
    close: R1RecordPositionClose,
) -> None:
    """Fail closed unless the ledger receipt binds exactly this close."""

    if not isinstance(receipt, R1AcceptedRecordPositionCloseReceipt):
        raise TypeError("receipt must be an R1AcceptedRecordPositionCloseReceipt")
    if (receipt.run_id, receipt.close_id, receipt.partition) != (
        close.run_id,
        close.close_id,
        close.partition,
    ):
        raise ValueError("position-close receipt is bound to another run, close or partition")
    if receipt.close_content_sha256 != record_position_close_sha256(close):
        raise ValueError("position-close receipt does not match the close content")
    if receipt.accepted_at < close.emitted_at:
        raise ValueError("a position close cannot be accepted before it was emitted")


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "R1_RECORD_POSITION_CLOSE_CONTRACT_VERSION",
    "R1_RECORD_POSITION_CLOSE_RECEIPT_SCHEMA",
    "R1_RECORD_POSITION_CLOSE_SCHEMA",
    "R1_RECORD_POSITION_FINALITY_GUARANTEE",
    "R1_RECORD_POSITION_FINALITY_KIND",
    "R1_RECORD_POSITION_FINALITY_NON_GUARANTEES",
    "R1AcceptedRecordPositionCloseReceipt",
    "R1RecordBoundedSnapshotSourceBinding",
    "R1RecordPositionClose",
    "R1RecordPositionFrontier",
    "R1RequiredPartitionContractBinding",
    "covered_chunk_list_sha256",
    "record_position_close_receipt_sha256",
    "record_position_close_sha256",
    "require_receipt_binds_close",
]
