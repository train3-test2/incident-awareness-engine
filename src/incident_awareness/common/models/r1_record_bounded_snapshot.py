"""R1 Sysmon RecordId-bounded snapshot artifacts and channel-generation observations.

The four ``v0.1`` artifacts implement
``docs/schema/r1-sysmon-record-bounded-finality-v0.md``.  They prove only that one
accepted, RecordId-bounded canonical snapshot was delivered by the collector.  None of
them is an event-time ``source_watermark`` or a stream close, and
``observation_boundary_at`` is never an event-time frontier.

``r1-sysmon-channel-generation-observation`` is an additive artifact for the separate
RecordId position-finality contract.  It records the raw XML of the two bound records
and the channel state, once with the freeze ack and once after the canonical export,
so a cleared, rolled-over or regenerated channel can be detected.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from incident_awareness.common.models.r1_stream import R1StreamPartition

R1_SNAPSHOT_CONTRACT_VERSION = "v0.1"
R1_SNAPSHOT_TARGET_EVENT_IDS = (1, 3)
R1_FREEZE_REQUEST_SCHEMA = "r1-sysmon-collection-freeze-request"
R1_FREEZE_ACK_SCHEMA = "r1-sysmon-collection-freeze-ack"
R1_RUN_FINALIZED_SCHEMA = "r1-sysmon-run-finalized"
R1_RECORD_BOUNDED_RECONCILIATION_SCHEMA = "r1-sysmon-record-bounded-finality"
R1_CHANNEL_GENERATION_OBSERVATION_SCHEMA = "r1-sysmon-channel-generation-observation"


class R1RecordBoundedSnapshotError(ValueError):
    """Raised when a snapshot artifact cannot be read or trusted."""


def _reject_numeric_datetime(value: object) -> object:
    if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
        raise ValueError("datetime must not be a numeric Unix timestamp")
    return value


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include a timezone")
    if value.utcoffset() != timedelta(0):
        raise ValueError("datetime must be UTC")
    if value.microsecond % 1000 != 0:
        raise ValueError("datetime must use millisecond precision")
    return value.astimezone(UTC)


def _unpadded(value: str) -> str:
    if not value.strip() or value != value.strip():
        raise ValueError("identity must be non-blank without surrounding whitespace")
    return value


UtcMilliseconds = Annotated[
    datetime,
    BeforeValidator(_reject_numeric_datetime),
    AfterValidator(_utc_milliseconds),
]
Identity = Annotated[StrictStr, Field(min_length=1), AfterValidator(_unpadded)]
Sha256 = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
RecordId = Annotated[StrictInt, Field(ge=1)]
PositiveCount = Annotated[StrictInt, Field(ge=1)]


class _SnapshotArtifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


def _require_target_event_ids(value: tuple[int, ...]) -> tuple[int, ...]:
    if value != R1_SNAPSHOT_TARGET_EVENT_IDS:
        raise ValueError("target_event_ids must be exactly [1, 3]")
    return value


TargetEventIds = Annotated[tuple[StrictInt, ...], AfterValidator(_require_target_event_ids)]


class R1CollectionFreezeRequest(_SnapshotArtifact):
    """Runner request to freeze collection after the observation boundary."""

    schema_id: Literal["r1-sysmon-collection-freeze-request"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    request_id: Identity
    partition: R1StreamPartition
    candidate_boundary_at: UtcMilliseconds
    observation_boundary_at: UtcMilliseconds
    requested_at: UtcMilliseconds

    @model_validator(mode="after")
    def validate_order(self) -> R1CollectionFreezeRequest:
        if self.observation_boundary_at < self.candidate_boundary_at:
            raise ValueError("observation_boundary_at must not precede candidate_boundary_at")
        if self.requested_at < self.observation_boundary_at:
            raise ValueError("a freeze must not be requested before the observation boundary")
        return self


class R1CollectionFreezeAck(_SnapshotArtifact):
    """Live producer acknowledgement that every bounded target Event is durably published."""

    schema_id: Literal["r1-sysmon-collection-freeze-ack"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    request_id: Identity
    partition: R1StreamPartition
    source_lower_record_id: RecordId
    source_upper_record_id: RecordId
    target_event_ids: TargetEventIds
    target_event_count: PositiveCount
    target_identity_sha256: Sha256
    covered_through_chunk_sequence: PositiveCount
    allowed_lateness_ms: Annotated[StrictInt, Field(ge=0)]
    raw_segment_inventory_sha256: Sha256
    acked_at: UtcMilliseconds

    @model_validator(mode="after")
    def validate_bound(self) -> R1CollectionFreezeAck:
        if self.source_lower_record_id > self.source_upper_record_id:
            raise ValueError("source_lower_record_id must not exceed source_upper_record_id")
        return self


class R1SysmonRunFinalized(_SnapshotArtifact):
    """Runner record that the canonical Run was exported through the same RecordId bound."""

    schema_id: Literal["r1-sysmon-run-finalized"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    request_id: Identity
    partition: R1StreamPartition
    source_lower_record_id: RecordId
    source_upper_record_id: RecordId
    target_event_ids: TargetEventIds
    canonical_event_count: PositiveCount
    canonical_identity_sha256: Sha256
    canonical_evtx_sha256: Sha256
    canonical_jsonl_sha256: Sha256
    manifest_sha256: Sha256
    finalized_at: UtcMilliseconds

    @model_validator(mode="after")
    def validate_bound(self) -> R1SysmonRunFinalized:
        if self.source_lower_record_id > self.source_upper_record_id:
            raise ValueError("source_lower_record_id must not exceed source_upper_record_id")
        return self


class R1RecordBoundedReconciliation(_SnapshotArtifact):
    """Finalizer result for one verified RecordId-bounded snapshot delivery.

    ``observation_boundary_at`` is the observation boundary of the freeze request and is
    not an event-time watermark.  ``allowed_lateness_ms`` is provenance only and grants
    no watermark authority.
    """

    schema_id: Literal["r1-sysmon-record-bounded-finality"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    request_id: Identity
    freeze_request_sha256: Sha256
    freeze_ack_sha256: Sha256
    run_finalized_sha256: Sha256
    partition: R1StreamPartition
    required_partition_contract_sha256: Sha256
    source_lower_record_id: RecordId
    source_upper_record_id: RecordId
    target_event_ids: TargetEventIds
    live_event_count: PositiveCount
    live_identity_sha256: Sha256
    canonical_event_count: PositiveCount
    canonical_identity_sha256: Sha256
    covered_through_chunk_sequence: PositiveCount
    post_commit_ack_count: PositiveCount
    observation_boundary_at: UtcMilliseconds
    allowed_lateness_ms: Annotated[StrictInt, Field(ge=0)]
    reconciled_at: UtcMilliseconds
    status: Literal["verified_snapshot_delivery"]

    @model_validator(mode="after")
    def validate_gates(self) -> R1RecordBoundedReconciliation:
        if self.source_lower_record_id > self.source_upper_record_id:
            raise ValueError("source_lower_record_id must not exceed source_upper_record_id")
        if self.live_event_count != self.canonical_event_count:
            raise ValueError("live and canonical event counts must be equal")
        if self.live_identity_sha256 != self.canonical_identity_sha256:
            raise ValueError("live and canonical identity digests must be equal")
        if self.post_commit_ack_count != self.covered_through_chunk_sequence:
            raise ValueError("every covered chunk must have exactly one post-commit ack")
        if self.reconciled_at < self.observation_boundary_at:
            raise ValueError("reconciled_at must not precede the observation boundary")
        return self


class R1SysmonChannelGenerationObservation(_SnapshotArtifact):
    """One observation of the Sysmon channel generation around the RecordId bound."""

    schema_id: Literal["r1-sysmon-channel-generation-observation"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    phase: Literal["freeze_ack", "after_canonical_export"]
    request_id: Identity
    partition: R1StreamPartition
    source_lower_record_id: RecordId
    source_upper_record_id: RecordId
    lower_anchor_raw_xml_sha256: Sha256
    upper_anchor_raw_xml_sha256: Sha256
    oldest_record_number: RecordId
    log_creation_time_utc: UtcMilliseconds
    observed_at: UtcMilliseconds

    @model_validator(mode="after")
    def validate_bound(self) -> R1SysmonChannelGenerationObservation:
        if self.source_lower_record_id > self.source_upper_record_id:
            raise ValueError("source_lower_record_id must not exceed source_upper_record_id")
        if self.oldest_record_number > self.source_lower_record_id:
            raise ValueError("the channel no longer retains the lower bound record")
        return self


def canonical_json_bytes(value: object) -> bytes:
    """Return the sorted, compact UTF-8 JSON bytes used by the R1 file spool."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 hex digest of ``data``."""

    return hashlib.sha256(data).hexdigest()


def snapshot_identity_sha256(lines: tuple[str, ...]) -> str:
    """Digest identity lines the way the Target-A tools do: newline-joined plus a final LF."""

    return sha256_hex(("\n".join(lines) + "\n").encode("utf-8"))


def load_r1_snapshot_artifact[ArtifactT: BaseModel](
    path: Path, model: type[ArtifactT]
) -> tuple[ArtifactT, str]:
    """Strictly load one immutable artifact and return it with the SHA-256 of its bytes."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        data = path.read_bytes()
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1RecordBoundedSnapshotError(f"artifact is not valid UTF-8 JSON: {path}") from error
    try:
        return model.model_validate(payload), sha256_hex(data)
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError(
            f"artifact does not match {model.__name__}: {path}"
        ) from error


def write_r1_snapshot_artifact(path: Path, artifact: BaseModel) -> str:
    """Publish an artifact immutably and return the SHA-256 of its bytes."""

    data = canonical_json_bytes(artifact.model_dump(mode="json", by_alias=True))
    publish_immutable_bytes(path, data)
    return sha256_hex(data)


def publish_immutable_bytes(path: Path, data: bytes) -> None:
    """Create ``path`` once; an identical republish is a no-op and any change fails closed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return
        raise R1RecordBoundedSnapshotError(
            f"immutable path conflicts with existing content: {path}"
        )
    stage = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with stage.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(stage, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise R1RecordBoundedSnapshotError(
                    f"immutable path conflicts with existing content: {path}"
                ) from None
        finally:
            stage.unlink(missing_ok=True)
    except BaseException:
        stage.unlink(missing_ok=True)
        raise


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


__all__ = [
    "R1_CHANNEL_GENERATION_OBSERVATION_SCHEMA",
    "R1_FREEZE_ACK_SCHEMA",
    "R1_FREEZE_REQUEST_SCHEMA",
    "R1_RECORD_BOUNDED_RECONCILIATION_SCHEMA",
    "R1_RUN_FINALIZED_SCHEMA",
    "R1_SNAPSHOT_CONTRACT_VERSION",
    "R1_SNAPSHOT_TARGET_EVENT_IDS",
    "Identity",
    "PositiveCount",
    "R1CollectionFreezeAck",
    "R1CollectionFreezeRequest",
    "R1RecordBoundedReconciliation",
    "R1RecordBoundedSnapshotError",
    "R1SysmonChannelGenerationObservation",
    "R1SysmonRunFinalized",
    "RecordId",
    "Sha256",
    "TargetEventIds",
    "UtcMilliseconds",
    "canonical_json_bytes",
    "load_r1_snapshot_artifact",
    "publish_immutable_bytes",
    "sha256_hex",
    "snapshot_identity_sha256",
    "write_r1_snapshot_artifact",
]
