"""Durable, versioned Role2 checkpoint for R1 incremental Evidence state."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, is_dataclass
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

from incident_awareness.collection.r1_role2_verified_close_proof import (
    R1Role2VerifiedCloseProof,
)
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
)
from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed
from incident_awareness.pipeline.r1_artifact_io import fsync_parent_directory
from incident_awareness.pipeline.r1_causal_availability import R1CausalPolicyIdentity
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
)

R1_INCREMENTAL_CHECKPOINT_SCHEMA = "r1-incremental-evidence-checkpoint"
R1_INCREMENTAL_CHECKPOINT_CONTRACT_VERSION = "v0.1"


class R1IncrementalApprovedPolicyIdentity(R1CausalPolicyIdentity):
    """Approved-lineage identity fields needed to reject recovery drift."""

    family_id: StrictStr
    lifecycle: Literal["development", "frozen"]


class R1IncrementalSelectorIdentity(R1CausalPolicyIdentity):
    lineage_event_count: StrictInt = Field(ge=1)


class R1IncrementalEvidenceDigest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: StrictStr
    content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class R1IncrementalEvidenceCheckpoint(BaseModel):
    """Lossless accepted inputs plus terminal identity for deterministic recovery."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-incremental-evidence-checkpoint"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    generation: StrictInt = Field(ge=0)
    run_id: StrictStr
    entity_id: StrictStr
    run_start: datetime
    scenario_family_id: StrictStr
    required_partition_contract: R1RequiredPartitionContract
    selector_policy_identity: R1IncrementalSelectorIdentity
    approved_policy_identity: R1IncrementalApprovedPolicyIdentity
    candidate_policy_identity: R1CausalPolicyIdentity | None = None
    accepted_chunks: tuple[R1EventChunk, ...] = ()
    accepted_run_closed: R1RunClosed | None = None
    accepted_close_receipt: R1AcceptedRunCloseReceipt | None = None
    verified_close_proof: R1Role2VerifiedCloseProof | None = None
    proof_validated_at: datetime | None = None
    status: Literal["accumulating", "provisional", "finalized", "failed_closed"]
    close_mode: Literal["authoritative_run_end_fallback", "verified_close_proof"] | None = None
    candidate_boundary_at: datetime | None = None
    available_at: datetime | None = None
    evidence_digests: tuple[R1IncrementalEvidenceDigest, ...] = ()
    diagnostics: tuple[StrictStr, ...] = ()
    checkpoint_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("run_id", "entity_id", "scenario_family_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("incremental checkpoint identities must be non-blank and unpadded")
        return value

    @field_validator(
        "run_start",
        "proof_validated_at",
        "candidate_boundary_at",
        "available_at",
        mode="before",
    )
    @classmethod
    def reject_numeric_time(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("incremental checkpoint time must not be a numeric Unix timestamp")
        return value

    @field_validator("run_start", "proof_validated_at", "candidate_boundary_at", "available_at")
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("incremental checkpoint times must include timezone information")
        if value.utcoffset() != timedelta(0):
            raise ValueError("incremental checkpoint times must be UTC")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> R1IncrementalEvidenceCheckpoint:
        if self.required_partition_contract.target_host != self.entity_id:
            raise ValueError("checkpoint partition contract must match entity_id")
        chunks = tuple(sorted(self.accepted_chunks, key=_chunk_sort_key))
        if self.accepted_chunks != chunks:
            raise ValueError("accepted_chunks must use canonical ordering")
        chunk_keys = tuple(_chunk_identity(chunk) for chunk in self.accepted_chunks)
        if len(chunk_keys) != len(set(chunk_keys)):
            raise ValueError("accepted_chunks must contain unique scoped identities")
        if any(chunk.partition.run_id != self.run_id for chunk in self.accepted_chunks):
            raise ValueError("accepted chunk run_id must match checkpoint run_id")
        if self.accepted_run_closed is not None and self.accepted_run_closed.run_id != self.run_id:
            raise ValueError("accepted run_closed must match checkpoint run_id")
        proof_fields = (
            self.accepted_run_closed,
            self.accepted_close_receipt,
            self.verified_close_proof,
            self.proof_validated_at,
            self.candidate_policy_identity,
        )
        if self.accepted_close_receipt is not None and self.accepted_run_closed is None:
            raise ValueError("accepted close receipt requires accepted run_closed")
        if self.verified_close_proof is not None and any(item is None for item in proof_fields):
            raise ValueError("stored verified proof requires every trusted binding")
        if (
            self.status == "finalized"
            and self.close_mode == "verified_close_proof"
            and any(item is None for item in proof_fields)
        ):
            raise ValueError("verified proof checkpoint is missing a trusted binding")
        if self.status == "finalized" and self.close_mode is None:
            raise ValueError("finalized checkpoint requires close_mode")
        if self.status not in {"finalized", "failed_closed"} and self.evidence_digests:
            raise ValueError("provisional checkpoint must not contain Evidence digests")
        if self.evidence_digests != tuple(
            sorted(self.evidence_digests, key=lambda item: item.evidence_id)
        ):
            raise ValueError("Evidence digests must use canonical ordering")
        _require_content_hash(self)
        return self


def build_r1_incremental_checkpoint(payload: dict[str, object]) -> R1IncrementalEvidenceCheckpoint:
    """Add the canonical content hash and strictly validate a checkpoint payload."""

    content = dict(payload)
    content["schema"] = R1_INCREMENTAL_CHECKPOINT_SCHEMA
    content["contract_version"] = R1_INCREMENTAL_CHECKPOINT_CONTRACT_VERSION
    content.pop("checkpoint_content_sha256", None)
    normalized = _jsonable(content)
    normalized["checkpoint_content_sha256"] = _canonical_sha256(normalized)
    return R1IncrementalEvidenceCheckpoint.model_validate(normalized)


def write_r1_incremental_checkpoint(
    path: Path,
    checkpoint: R1IncrementalEvidenceCheckpoint,
) -> None:
    """Replace single-writer state while rejecting generation conflicts.

    Callers must serialize writers targeting the same path. The generation
    check followed by ``os.replace`` is not a multi-writer atomic CAS.
    """

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    if not isinstance(checkpoint, R1IncrementalEvidenceCheckpoint):
        raise TypeError("checkpoint must be an R1IncrementalEvidenceCheckpoint")
    if path.exists():
        existing = load_r1_incremental_checkpoint(path)
        if checkpoint.generation < existing.generation:
            raise ValueError("checkpoint generation must not move backwards")
        if checkpoint.generation == existing.generation:
            if checkpoint.checkpoint_content_sha256 == existing.checkpoint_content_sha256:
                return
            raise ValueError("checkpoint generation was reused with different content")

    encoded = (
        json.dumps(
            checkpoint.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_parent_directory(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_r1_incremental_checkpoint(path: Path) -> R1IncrementalEvidenceCheckpoint:
    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
        return R1IncrementalEvidenceCheckpoint.model_validate(payload)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ) as error:
        raise ValueError("R1 incremental checkpoint is invalid or corrupted") from error


def incremental_checkpoint_sha256(checkpoint: R1IncrementalEvidenceCheckpoint) -> str:
    return _canonical_sha256(checkpoint.model_dump(mode="json", by_alias=True))


def incremental_evidence_sha256(evidence: Evidence) -> str:
    """Return the checkpoint contract's canonical digest of one Evidence."""

    if not isinstance(evidence, Evidence):
        raise TypeError("evidence must be an Evidence")
    return _canonical_sha256(evidence.model_dump(mode="json", by_alias=True))


def validate_r1_incremental_finalized_evidence(
    checkpoint: R1IncrementalEvidenceCheckpoint,
    evidences: tuple[Evidence, ...],
    *,
    expected_close_mode: Literal["authoritative_run_end_fallback", "verified_close_proof"]
    | None = None,
) -> None:
    """Bind finalized Evidence IDs and full canonical content to a checkpoint."""

    if checkpoint.status != "finalized":
        raise ValueError("Evidence output requires a finalized checkpoint")
    if checkpoint.close_mode is None or (
        expected_close_mode is not None and checkpoint.close_mode != expected_close_mode
    ):
        raise ValueError("checkpoint close_mode is not valid for this Evidence output")
    actual = tuple(
        (evidence.evidence_id, incremental_evidence_sha256(evidence))
        for evidence in sorted(evidences, key=lambda item: item.evidence_id)
    )
    expected = tuple(
        (item.evidence_id, item.content_sha256) for item in checkpoint.evidence_digests
    )
    if actual != expected:
        raise ValueError("Evidence identity/content does not match checkpoint digests")


def _require_content_hash(checkpoint: R1IncrementalEvidenceCheckpoint) -> None:
    payload = checkpoint.model_dump(mode="json", by_alias=True)
    actual = payload.pop("checkpoint_content_sha256")
    if actual != _canonical_sha256(payload):
        raise ValueError("checkpoint_content_sha256 does not match canonical content")


def _chunk_identity(chunk: R1EventChunk) -> tuple[str, str, str, str, str, str, str]:
    partition = chunk.partition
    return (
        chunk.schema_id,
        chunk.contract_version,
        partition.run_id,
        partition.host_id,
        partition.source,
        partition.source_channel,
        chunk.chunk_id,
    )


def _chunk_sort_key(chunk: R1EventChunk) -> tuple[str, str, str, int, str]:
    partition = chunk.partition
    return (
        partition.host_id,
        partition.source,
        partition.source_channel,
        chunk.chunk_sequence,
        chunk.chunk_id,
    )


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_jsonable(item) for item in value]
    return value


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
    "R1_INCREMENTAL_CHECKPOINT_CONTRACT_VERSION",
    "R1_INCREMENTAL_CHECKPOINT_SCHEMA",
    "R1IncrementalApprovedPolicyIdentity",
    "R1IncrementalEvidenceCheckpoint",
    "R1IncrementalEvidenceDigest",
    "R1IncrementalSelectorIdentity",
    "build_r1_incremental_checkpoint",
    "incremental_checkpoint_sha256",
    "incremental_evidence_sha256",
    "load_r1_incremental_checkpoint",
    "validate_r1_incremental_finalized_evidence",
    "write_r1_incremental_checkpoint",
]
