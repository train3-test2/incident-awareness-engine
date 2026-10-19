"""Finalizer for one R1 Sysmon RecordId-bounded snapshot delivery (v0.1).

The finalizer re-reads every input instead of trusting a status field: the freeze
request/ack, the canonical Run artifacts and manifest, the live raw segments, every
covered Event chunk and its post-commit Role3 ack.  It records
``status=verified_snapshot_delivery`` only when all of them describe exactly the same
RecordId-bounded snapshot.

The result proves collector delivery of that snapshot and nothing more: it is not an
event-time watermark, does not prove Sysmon provider queue drain, and says nothing
about Events written after the bound.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

from pydantic import ValidationError

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1_SNAPSHOT_TARGET_EVENT_IDS,
    R1CollectionFreezeAck,
    R1CollectionFreezeRequest,
    R1RecordBoundedReconciliation,
    R1RecordBoundedSnapshotError,
    R1SysmonChannelGenerationObservation,
    R1SysmonRunFinalized,
    canonical_json_bytes,
    load_r1_snapshot_artifact,
    sha256_hex,
    snapshot_identity_sha256,
    write_r1_snapshot_artifact,
)
from incident_awareness.common.models.r1_record_position_close import covered_chunk_list_sha256
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
    R1RequiredPartitionContractError,
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1EventChunk, R1StreamPartition
from incident_awareness.pipeline.r1_stream_ingress import r1_stream_message_sha256

_EVENT_TYPE_BY_EVENT_ID = {1: "process_create", 3: "network_connection"}
_ACCEPTED_DISPOSITIONS = frozenset({"accepted", "duplicate"})


@dataclass(frozen=True, slots=True)
class R1SnapshotSources:
    """Every file the finalizer reads for one Run.

    ``run_spool_root`` is ``<spool>/<run_id>``: the directory that holds
    ``raw-segments/``, ``outbox/`` and ``acks/``.
    """

    run_spool_root: Path
    freeze_request_path: Path
    freeze_ack_path: Path
    run_finalized_path: Path
    canonical_evtx_path: Path
    canonical_jsonl_path: Path
    canonical_manifest_path: Path
    required_partition_contract_path: Path


@dataclass(frozen=True, slots=True)
class R1CoveredChunk:
    """One covered Event chunk and the SHA-256 of the spool bytes its ack binds."""

    chunk_sequence: int
    chunk_id: str
    chunk_content_sha256: str
    message_sha256: str


@dataclass(frozen=True, slots=True)
class R1VerifiedSnapshotDelivery:
    """Every verified binding of one RecordId-bounded snapshot."""

    request: R1CollectionFreezeRequest
    request_sha256: str
    ack: R1CollectionFreezeAck
    ack_sha256: str
    finalized: R1SysmonRunFinalized
    finalized_sha256: str
    contract: R1RequiredPartitionContract
    contract_sha256: str
    event_count: int
    source_native_identity_sha256: str
    covered_chunks: tuple[R1CoveredChunk, ...]
    covered_chunks_sha256: str
    post_bound_chunk_sequences: tuple[int, ...]

    @property
    def partition(self) -> R1StreamPartition:
        return self.request.partition


@dataclass(frozen=True, slots=True)
class R1VerifiedChannelGeneration:
    """Two matching observations of the channel generation around the bound."""

    channel_generation_id: str
    freeze_observation: R1SysmonChannelGenerationObservation
    freeze_observation_sha256: str
    export_observation: R1SysmonChannelGenerationObservation
    export_observation_sha256: str


@dataclass(frozen=True, slots=True)
class _Identity:
    host_id: str
    source_channel: str
    record_id: int
    event_id: int

    def line(self) -> str:
        return f"{self.host_id}\t{self.source_channel}\t{self.record_id}\t{self.event_id}"


def required_partition_contract_sha256(contract: R1RequiredPartitionContract) -> str:
    """Canonical content digest of a required-partition contract.

    This is the same digest ``r1_stream_wiring`` binds into a ``run_closed`` ack.
    """

    return sha256_hex(canonical_json_bytes(contract.model_dump(mode="json")))


def verify_r1_record_bounded_snapshot(sources: R1SnapshotSources) -> R1VerifiedSnapshotDelivery:
    """Verify every gate of the v0.1 contract and fail closed on the first mismatch."""

    request, request_sha256 = load_r1_snapshot_artifact(
        sources.freeze_request_path, R1CollectionFreezeRequest
    )
    ack, ack_sha256 = load_r1_snapshot_artifact(sources.freeze_ack_path, R1CollectionFreezeAck)
    finalized, finalized_sha256 = load_r1_snapshot_artifact(
        sources.run_finalized_path, R1SysmonRunFinalized
    )
    partition = request.partition
    contract = _load_contract(sources.required_partition_contract_path, partition)
    _verify_artifact_bindings(request, ack, finalized)
    _verify_canonical_files(sources, finalized)

    lower, upper = ack.source_lower_record_id, ack.source_upper_record_id
    canonical = _read_canonical_identities(sources.canonical_jsonl_path, partition, lower, upper)
    if len(canonical) != finalized.canonical_event_count:
        raise R1RecordBoundedSnapshotError(
            "canonical JSONL event count does not match run-finalized"
        )

    segments = _read_covered_segments(sources.run_spool_root, ack.covered_through_chunk_sequence)
    if _raw_segment_inventory_sha256(sources.run_spool_root, segments) != (
        ack.raw_segment_inventory_sha256
    ):
        raise R1RecordBoundedSnapshotError(
            "live raw segment inventory does not match the freeze ack"
        )
    live = _live_identities(segments, partition, lower, upper)
    if len(live) != ack.target_event_count:
        raise R1RecordBoundedSnapshotError("live raw event count does not match the freeze ack")
    if set(live) != set(canonical):
        raise R1RecordBoundedSnapshotError(
            "live raw and canonical snapshots do not contain the same Event identities"
        )

    covered, chunk_identities, post_bound = _verify_chunks(
        sources.run_spool_root,
        partition=partition,
        covered_through=ack.covered_through_chunk_sequence,
        segments=segments,
        upper=upper,
    )
    if chunk_identities != set(live):
        raise R1RecordBoundedSnapshotError(
            "covered chunks do not contain exactly the live raw Event identities"
        )

    ordered_lines = tuple(identity.line() for identity in sorted(canonical, key=_identity_order))
    return R1VerifiedSnapshotDelivery(
        request=request,
        request_sha256=request_sha256,
        ack=ack,
        ack_sha256=ack_sha256,
        finalized=finalized,
        finalized_sha256=finalized_sha256,
        contract=contract,
        contract_sha256=required_partition_contract_sha256(contract),
        event_count=len(canonical),
        source_native_identity_sha256=snapshot_identity_sha256(ordered_lines),
        covered_chunks=covered,
        covered_chunks_sha256=covered_chunks_sha256(covered),
        post_bound_chunk_sequences=post_bound,
    )


def covered_chunks_sha256(chunks: tuple[R1CoveredChunk, ...]) -> str:
    """Digest of the ordered ``(sequence, chunk_id, chunk_content_sha256)`` list."""

    return covered_chunk_list_sha256(
        tuple(
            (chunk.chunk_sequence, chunk.chunk_id, chunk.chunk_content_sha256) for chunk in chunks
        )
    )


def reconcile_r1_record_bounded_snapshot(
    sources: R1SnapshotSources,
    *,
    output_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    """Verify the snapshot and publish ``r1_finality_reconciliation.json`` immutably."""

    verified = verify_r1_record_bounded_snapshot(sources)
    reconciled_at = _utc_milliseconds(clock())
    reconciliation = build_r1_record_bounded_reconciliation(verified, reconciled_at=reconciled_at)
    write_r1_snapshot_artifact(output_path, reconciliation)
    return output_path


def build_r1_record_bounded_reconciliation(
    verified: R1VerifiedSnapshotDelivery,
    *,
    reconciled_at: datetime,
) -> R1RecordBoundedReconciliation:
    """Build the reconciliation artifact from already verified bindings."""

    if reconciled_at < verified.finalized.finalized_at:
        raise R1RecordBoundedSnapshotError("reconciled_at must not precede finalized_at")
    try:
        return R1RecordBoundedReconciliation.model_validate(
            {
                "schema": "r1-sysmon-record-bounded-finality",
                "contract_version": "v0.1",
                "request_id": verified.request.request_id,
                "freeze_request_sha256": verified.request_sha256,
                "freeze_ack_sha256": verified.ack_sha256,
                "run_finalized_sha256": verified.finalized_sha256,
                "partition": verified.partition.model_dump(mode="json"),
                "required_partition_contract_sha256": verified.contract_sha256,
                "source_lower_record_id": verified.ack.source_lower_record_id,
                "source_upper_record_id": verified.ack.source_upper_record_id,
                "target_event_ids": list(R1_SNAPSHOT_TARGET_EVENT_IDS),
                "live_event_count": verified.ack.target_event_count,
                "live_identity_sha256": verified.ack.target_identity_sha256,
                "canonical_event_count": verified.finalized.canonical_event_count,
                "canonical_identity_sha256": verified.finalized.canonical_identity_sha256,
                "covered_through_chunk_sequence": verified.ack.covered_through_chunk_sequence,
                "post_commit_ack_count": len(verified.covered_chunks),
                "observation_boundary_at": verified.request.observation_boundary_at,
                "allowed_lateness_ms": verified.ack.allowed_lateness_ms,
                "reconciled_at": reconciled_at,
                "status": "verified_snapshot_delivery",
            }
        )
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError("reconciliation gates did not pass") from error


def verify_r1_record_bounded_reconciliation(
    reconciliation_path: Path,
    sources: R1SnapshotSources,
) -> tuple[R1RecordBoundedReconciliation, str, R1VerifiedSnapshotDelivery]:
    """Re-verify the snapshot and require the stored reconciliation to match it exactly."""

    reconciliation, reconciliation_sha256 = load_r1_snapshot_artifact(
        reconciliation_path, R1RecordBoundedReconciliation
    )
    verified = verify_r1_record_bounded_snapshot(sources)
    expected = build_r1_record_bounded_reconciliation(
        verified,
        reconciled_at=reconciliation.reconciled_at,
    )
    if expected != reconciliation:
        raise R1RecordBoundedSnapshotError(
            "reconciliation artifact does not match its re-verified source artifacts"
        )
    return reconciliation, reconciliation_sha256, verified


def verify_r1_channel_generation(
    *,
    freeze_observation_path: Path,
    export_observation_path: Path,
    snapshot: R1VerifiedSnapshotDelivery,
) -> R1VerifiedChannelGeneration:
    """Require the channel generation captured with the bound to survive the export."""

    freeze, freeze_sha256 = load_r1_snapshot_artifact(
        freeze_observation_path, R1SysmonChannelGenerationObservation
    )
    export, export_sha256 = load_r1_snapshot_artifact(
        export_observation_path, R1SysmonChannelGenerationObservation
    )
    if freeze.phase != "freeze_ack" or export.phase != "after_canonical_export":
        raise R1RecordBoundedSnapshotError("channel generation observations have the wrong phase")
    bound = (
        snapshot.request.request_id,
        snapshot.partition,
        snapshot.ack.source_lower_record_id,
        snapshot.ack.source_upper_record_id,
    )
    for observation in (freeze, export):
        if (
            observation.request_id,
            observation.partition,
            observation.source_lower_record_id,
            observation.source_upper_record_id,
        ) != bound:
            raise R1RecordBoundedSnapshotError(
                "channel generation observation is bound to another request, host or bound"
            )
    if (
        freeze.lower_anchor_raw_xml_sha256,
        freeze.upper_anchor_raw_xml_sha256,
        freeze.log_creation_time_utc,
    ) != (
        export.lower_anchor_raw_xml_sha256,
        export.upper_anchor_raw_xml_sha256,
        export.log_creation_time_utc,
    ):
        raise R1RecordBoundedSnapshotError(
            "the Sysmon channel generation changed between the freeze ack and the export"
        )
    if export.oldest_record_number < freeze.oldest_record_number:
        raise R1RecordBoundedSnapshotError(
            "the Sysmon channel oldest record moved backwards between the observations"
        )
    if not snapshot.request.requested_at <= freeze.observed_at <= snapshot.ack.acked_at:
        raise R1RecordBoundedSnapshotError(
            "the freeze generation observation is outside the freeze request and ack"
        )
    if not snapshot.ack.acked_at <= export.observed_at <= snapshot.finalized.finalized_at:
        raise R1RecordBoundedSnapshotError(
            "the export generation observation is outside the freeze ack and finalization"
        )
    generation_id = sha256_hex(
        canonical_json_bytes(
            {
                "host_id": snapshot.partition.host_id,
                "log_creation_time_utc": freeze.model_dump(mode="json")["log_creation_time_utc"],
                "lower_anchor_raw_xml_sha256": freeze.lower_anchor_raw_xml_sha256,
                "lower_record_id": freeze.source_lower_record_id,
                "source_channel": snapshot.partition.source_channel,
                "upper_anchor_raw_xml_sha256": freeze.upper_anchor_raw_xml_sha256,
                "upper_record_id": freeze.source_upper_record_id,
            }
        )
    )
    return R1VerifiedChannelGeneration(
        channel_generation_id=generation_id,
        freeze_observation=freeze,
        freeze_observation_sha256=freeze_sha256,
        export_observation=export,
        export_observation_sha256=export_sha256,
    )


def _load_contract(path: Path, partition: R1StreamPartition) -> R1RequiredPartitionContract:
    try:
        contract = load_r1_required_partition_contract(path, expected_target_host=partition.host_id)
    except R1RequiredPartitionContractError as error:
        raise R1RecordBoundedSnapshotError(
            "required-partition contract does not bind the snapshot host"
        ) from error
    required = tuple((item.source, item.source_channel) for item in contract.required_partitions)
    if required != ((partition.source, partition.source_channel),):
        raise R1RecordBoundedSnapshotError(
            "a single-partition snapshot must cover every required partition of the contract"
        )
    return contract


def _verify_artifact_bindings(
    request: R1CollectionFreezeRequest,
    ack: R1CollectionFreezeAck,
    finalized: R1SysmonRunFinalized,
) -> None:
    if not request.request_id == ack.request_id == finalized.request_id:
        raise R1RecordBoundedSnapshotError("freeze request, ack and finalization use different IDs")
    if not request.partition == ack.partition == finalized.partition:
        raise R1RecordBoundedSnapshotError(
            "freeze request, ack and finalization bind different partitions"
        )
    if (ack.source_lower_record_id, ack.source_upper_record_id) != (
        finalized.source_lower_record_id,
        finalized.source_upper_record_id,
    ):
        raise R1RecordBoundedSnapshotError(
            "canonical export RecordId bound differs from the freeze ack"
        )
    if not request.requested_at <= ack.acked_at <= finalized.finalized_at:
        raise R1RecordBoundedSnapshotError("freeze request, ack and finalization are out of order")
    if ack.target_event_count != finalized.canonical_event_count:
        raise R1RecordBoundedSnapshotError("live and canonical event counts differ")
    if ack.target_identity_sha256 != finalized.canonical_identity_sha256:
        raise R1RecordBoundedSnapshotError("live and canonical identity digests differ")


def _verify_canonical_files(sources: R1SnapshotSources, finalized: R1SysmonRunFinalized) -> None:
    evtx_sha256 = _file_sha256(sources.canonical_evtx_path)
    jsonl_sha256 = _file_sha256(sources.canonical_jsonl_path)
    manifest_bytes = _read_bytes(sources.canonical_manifest_path)
    if evtx_sha256 != finalized.canonical_evtx_sha256:
        raise R1RecordBoundedSnapshotError("canonical EVTX digest does not match run-finalized")
    if jsonl_sha256 != finalized.canonical_jsonl_sha256:
        raise R1RecordBoundedSnapshotError("canonical JSONL digest does not match run-finalized")
    if sha256_hex(manifest_bytes) != finalized.manifest_sha256:
        raise R1RecordBoundedSnapshotError("manifest digest does not match run-finalized")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R1RecordBoundedSnapshotError("canonical manifest is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict) or manifest.get("run_id") != finalized.partition.run_id:
        raise R1RecordBoundedSnapshotError("canonical manifest is bound to another Run")
    items = manifest.get("items")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise R1RecordBoundedSnapshotError("canonical manifest has no item list")
    evtx_items = [
        item
        for item in items
        if item.get("source") == "sysmon"
        and "derived_from" not in item
        and str(item.get("path", "")).casefold().endswith(".evtx")
    ]
    if len(evtx_items) != 1:
        raise R1RecordBoundedSnapshotError("canonical manifest must list exactly one Sysmon EVTX")
    evtx_item = evtx_items[0]
    jsonl_items = [item for item in items if item.get("derived_from") == evtx_item.get("path")]
    if len(jsonl_items) != 1:
        raise R1RecordBoundedSnapshotError(
            "canonical manifest must list exactly one JSONL derived from the EVTX"
        )
    jsonl_item = jsonl_items[0]
    for item, actual, path in (
        (evtx_item, evtx_sha256, sources.canonical_evtx_path),
        (jsonl_item, jsonl_sha256, sources.canonical_jsonl_path),
    ):
        if item.get("sha256") != actual:
            raise R1RecordBoundedSnapshotError(
                "canonical manifest digest does not match the actual file"
            )
        if PureWindowsPath(str(item.get("path"))).name.casefold() != path.name.casefold():
            raise R1RecordBoundedSnapshotError(
                "canonical manifest item does not name the verified file"
            )


def _read_canonical_identities(
    path: Path,
    partition: R1StreamPartition,
    lower: int,
    upper: int,
) -> tuple[_Identity, ...]:
    identities: list[_Identity] = []
    try:
        for record in read_sysmon_jsonl(path):
            data = record.data
            if data.get("Channel") != partition.source_channel:
                raise R1RecordBoundedSnapshotError(
                    "canonical JSONL record belongs to another channel"
                )
            identities.append(_record_identity(data, partition, lower, upper, "canonical JSONL"))
    except (OSError, SysmonJsonlReadError) as error:
        raise R1RecordBoundedSnapshotError("canonical JSONL cannot be read") from error
    return _unique_identities(identities, "canonical JSONL")


def _read_covered_segments(
    run_spool_root: Path,
    covered_through: int,
) -> dict[int, tuple[dict[str, object], ...]]:
    segments: dict[int, tuple[dict[str, object], ...]] = {}
    for segment_no in range(1, covered_through + 1):
        path = _segment_path(run_spool_root, segment_no)
        capture = path.with_name(path.name + ".capture.json")
        if not path.is_file() or not capture.is_file():
            raise R1RecordBoundedSnapshotError(
                f"covered live raw segment or capture metadata is missing: {path.name}"
            )
        try:
            segments[segment_no] = tuple(record.data for record in read_sysmon_jsonl(path))
        except (OSError, SysmonJsonlReadError) as error:
            raise R1RecordBoundedSnapshotError(
                f"live raw segment cannot be read: {path}"
            ) from error
    return segments


def _raw_segment_inventory_sha256(
    run_spool_root: Path,
    segments: dict[int, tuple[dict[str, object], ...]],
) -> str:
    entries = []
    for segment_no in sorted(segments):
        path = _segment_path(run_spool_root, segment_no)
        for item in (path, path.with_name(path.name + ".capture.json")):
            data = _read_bytes(item)
            entries.append(
                {
                    "path": item.relative_to(run_spool_root).as_posix(),
                    "sha256": sha256_hex(data),
                    "size": len(data),
                }
            )
    return sha256_hex(canonical_json_bytes(sorted(entries, key=lambda entry: entry["path"])))


def r1_raw_segment_inventory_sha256(run_spool_root: Path, covered_through: int) -> str:
    """Return the inventory digest a freeze ack must bind for the covered raw segments."""

    return _raw_segment_inventory_sha256(
        run_spool_root, _read_covered_segments(run_spool_root, covered_through)
    )


def _live_identities(
    segments: dict[int, tuple[dict[str, object], ...]],
    partition: R1StreamPartition,
    lower: int,
    upper: int,
) -> tuple[_Identity, ...]:
    identities = [
        _record_identity(record, partition, lower, upper, "live raw segment")
        for segment_no in sorted(segments)
        for record in segments[segment_no]
    ]
    return _unique_identities(identities, "live raw segments")


def _verify_chunks(
    run_spool_root: Path,
    *,
    partition: R1StreamPartition,
    covered_through: int,
    segments: dict[int, tuple[dict[str, object], ...]],
    upper: int,
) -> tuple[tuple[R1CoveredChunk, ...], set[_Identity], tuple[int, ...]]:
    chunks: dict[int, tuple[Path, R1EventChunk]] = {}
    for path in sorted((run_spool_root / "outbox").glob("*-event_chunk.json")):
        try:
            chunk = R1EventChunk.model_validate_json(path.read_bytes())
        except (OSError, ValidationError) as error:
            raise R1RecordBoundedSnapshotError(f"Event chunk cannot be read: {path}") from error
        if chunk.partition != partition:
            raise R1RecordBoundedSnapshotError("an Event chunk belongs to another partition")
        if chunk.chunk_sequence in chunks:
            raise R1RecordBoundedSnapshotError("two spool files publish the same chunk sequence")
        if r1_stream_message_sha256(chunk) != chunk.chunk_content_sha256:
            raise R1RecordBoundedSnapshotError("Event chunk content digest does not match")
        chunks[chunk.chunk_sequence] = (path, chunk)

    missing = [sequence for sequence in range(1, covered_through + 1) if sequence not in chunks]
    if missing:
        raise R1RecordBoundedSnapshotError(
            f"covered chunk sequence has a gap: missing {missing[0]}"
        )

    covered: list[R1CoveredChunk] = []
    identities: set[_Identity] = set()
    for sequence in range(1, covered_through + 1):
        path, chunk = chunks[sequence]
        message_sha256 = _require_post_commit_ack(run_spool_root, path)
        for event in chunk.events:
            identity = _chunk_event_identity(event, chunk, segments, partition)
            if identity in identities:
                raise R1RecordBoundedSnapshotError("a covered Event was published twice")
            identities.add(identity)
        covered.append(
            R1CoveredChunk(
                chunk_sequence=sequence,
                chunk_id=chunk.chunk_id,
                chunk_content_sha256=chunk.chunk_content_sha256,
                message_sha256=message_sha256,
            )
        )

    post_bound: list[int] = []
    for sequence in sorted(chunks):
        if sequence <= covered_through:
            continue
        _, chunk = chunks[sequence]
        for event in chunk.events:
            if _source_record_id(event.raw_ref.source_record_id) <= upper:
                raise R1RecordBoundedSnapshotError(
                    "an Event inside the RecordId bound was published after the covered chunks"
                )
        post_bound.append(sequence)
    return tuple(covered), identities, tuple(post_bound)


def _require_post_commit_ack(run_spool_root: Path, message_path: Path) -> str:
    """Apply the ``load_accepted_spool_message`` ack rule to one covered chunk."""

    message_bytes = _read_bytes(message_path)
    ack_path = run_spool_root / "acks" / f"{message_path.name}.ack.json"
    if not ack_path.is_file():
        raise R1RecordBoundedSnapshotError(
            f"covered chunk has no post-commit Role3 ack: {message_path.name}"
        )
    try:
        ack = json.loads(ack_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R1RecordBoundedSnapshotError(f"Role3 ack cannot be read: {ack_path}") from error
    message_sha256 = sha256_hex(message_bytes)
    if not isinstance(ack, dict):
        raise R1RecordBoundedSnapshotError("Role3 ack must be a JSON object")
    if ack.get("message_path") != str(message_path.resolve()):
        raise R1RecordBoundedSnapshotError("Role3 ack is bound to another spool message path")
    if ack.get("message_sha256") != message_sha256:
        raise R1RecordBoundedSnapshotError("Role3 ack does not match the chunk bytes")
    if ack.get("disposition") not in _ACCEPTED_DISPOSITIONS:
        raise R1RecordBoundedSnapshotError("Role3 ack has no accepted delivery disposition")
    return message_sha256


def _chunk_event_identity(
    event: NormalizedEvent,
    chunk: R1EventChunk,
    segments: dict[int, tuple[dict[str, object], ...]],
    partition: R1StreamPartition,
) -> _Identity:
    raw_ref = event.raw_ref
    if raw_ref.segment_no != chunk.chunk_sequence:
        raise R1RecordBoundedSnapshotError(
            "a covered Event references a raw segment other than its chunk"
        )
    records = segments.get(raw_ref.segment_no, ())
    if not 1 <= raw_ref.record_no <= len(records):
        raise R1RecordBoundedSnapshotError("a covered Event references a missing raw record")
    record = records[raw_ref.record_no - 1]
    if record.get("Channel") != partition.source_channel:
        raise R1RecordBoundedSnapshotError("a covered Event raw record belongs to another channel")
    record_id = _source_record_id(raw_ref.source_record_id)
    if record.get("RecordId") != record_id:
        raise R1RecordBoundedSnapshotError("a covered Event does not match its raw record")
    event_id = record.get("EventId")
    if _EVENT_TYPE_BY_EVENT_ID.get(event_id) != event.event_type:
        raise R1RecordBoundedSnapshotError("a covered Event type does not match its raw record")
    return _Identity(partition.host_id, partition.source_channel, record_id, int(event_id))


def _record_identity(
    data: dict[str, object],
    partition: R1StreamPartition,
    lower: int,
    upper: int,
    label: str,
) -> _Identity:
    record_id = data.get("RecordId")
    event_id = data.get("EventId")
    if isinstance(record_id, bool) or not isinstance(record_id, int):
        raise R1RecordBoundedSnapshotError(f"{label} record has no integer RecordId")
    if isinstance(event_id, bool) or event_id not in R1_SNAPSHOT_TARGET_EVENT_IDS:
        raise R1RecordBoundedSnapshotError(f"{label} record is not Sysmon EID 1 or 3")
    if data.get("Computer") != partition.host_id:
        raise R1RecordBoundedSnapshotError(f"{label} record belongs to another host")
    if data.get("Channel") != partition.source_channel:
        raise R1RecordBoundedSnapshotError(f"{label} record belongs to another channel")
    if not lower <= record_id <= upper:
        raise R1RecordBoundedSnapshotError(f"{label} record is outside the RecordId bound")
    return _Identity(partition.host_id, partition.source_channel, record_id, event_id)


def _unique_identities(identities: list[_Identity], label: str) -> tuple[_Identity, ...]:
    record_ids = [identity.record_id for identity in identities]
    if len(record_ids) != len(set(record_ids)):
        raise R1RecordBoundedSnapshotError(f"{label} contains a duplicate RecordId")
    return tuple(identities)


def _identity_order(identity: _Identity) -> tuple[int, int]:
    return identity.record_id, identity.event_id


def _source_record_id(value: str | None) -> int:
    if value is None or not value.isdecimal():
        raise R1RecordBoundedSnapshotError("an Event chunk has no decimal source_record_id")
    return int(value)


def _segment_path(run_spool_root: Path, segment_no: int) -> Path:
    return run_spool_root / "raw-segments" / f"sysmon-{segment_no:08d}.jsonl"


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise R1RecordBoundedSnapshotError(f"required file cannot be read: {path}") from error


def _file_sha256(path: Path) -> str:
    return sha256_hex(_read_bytes(path))


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


__all__ = [
    "R1CoveredChunk",
    "R1SnapshotSources",
    "R1VerifiedChannelGeneration",
    "R1VerifiedSnapshotDelivery",
    "build_r1_record_bounded_reconciliation",
    "covered_chunks_sha256",
    "r1_raw_segment_inventory_sha256",
    "reconcile_r1_record_bounded_snapshot",
    "required_partition_contract_sha256",
    "verify_r1_channel_generation",
    "verify_r1_record_bounded_reconciliation",
    "verify_r1_record_bounded_snapshot",
]
