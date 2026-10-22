"""Producer-side freeze artifacts of an R1 Sysmon RecordId-bounded snapshot.

The live producer calls this module after it has fixed one all-channel upper RecordId,
published every bound Event as chunks and seen their post-commit Role3 acks.  The
module re-reads the spool with the finalizer's own rules before it writes anything:

- ``write-freeze-ack`` writes ``collection-freeze-ack.json`` only when the covered raw
  segments hold exactly the bound Events of the request partition and every covered
  chunk exists without a gap with an ack bound to its bytes.
- ``write-generation-observation`` writes one ``r1-sysmon-channel-generation-observation``
  for the freeze ack or for the canonical export.

Neither artifact is an event-time watermark or a stream close.  A freeze ack proves
collector delivery of one bounded snapshot; it does not prove Sysmon provider queue
drain or completeness outside the bound.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1CollectionFreezeAck,
    R1CollectionFreezeRequest,
    R1RecordBoundedSnapshotError,
    R1SysmonChannelGenerationObservation,
    load_r1_snapshot_artifact,
    write_r1_snapshot_artifact,
)
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContractError,
    load_r1_required_partition_contract,
)
from incident_awareness.pipeline.r1_record_bounded_reconciliation import (
    verify_r1_live_snapshot_delivery,
)

_TARGET_EVENT_IDS = [1, 3]


def load_r1_freeze_request(
    path: Path,
    *,
    expected_run_id: str,
    expected_host_id: str,
    required_partition_contract_path: Path,
) -> R1CollectionFreezeRequest:
    """Load a freeze request and bind it to the producer's Run, host and contract."""

    request, _ = load_r1_snapshot_artifact(path, R1CollectionFreezeRequest)
    partition = request.partition
    if (partition.run_id, partition.host_id) != (expected_run_id, expected_host_id):
        raise R1RecordBoundedSnapshotError("freeze request is bound to another Run or host")
    try:
        contract = load_r1_required_partition_contract(
            required_partition_contract_path, expected_target_host=expected_host_id
        )
    except R1RequiredPartitionContractError as error:
        raise R1RecordBoundedSnapshotError(
            "required-partition contract does not bind the host"
        ) from error
    required = tuple((item.source, item.source_channel) for item in contract.required_partitions)
    if required != ((partition.source, partition.source_channel),):
        raise R1RecordBoundedSnapshotError("freeze request partition is not the required partition")
    return request


def issue_r1_collection_freeze_ack(
    *,
    run_spool_root: Path,
    request: R1CollectionFreezeRequest,
    source_lower_record_id: int,
    source_upper_record_id: int,
    target_event_count: int,
    target_identity_sha256: str,
    covered_through_chunk_sequence: int,
    allowed_lateness_ms: int,
    output_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> R1CollectionFreezeAck:
    """Verify the live delivery of the bound and publish the freeze ack immutably."""

    delivery = verify_r1_live_snapshot_delivery(
        run_spool_root,
        partition=request.partition,
        lower=source_lower_record_id,
        upper=source_upper_record_id,
        covered_through=covered_through_chunk_sequence,
    )
    if delivery.event_count != target_event_count:
        raise R1RecordBoundedSnapshotError(
            "the bounded Target-A query and the live raw segments hold different Event counts"
        )
    acked_at = _utc_milliseconds(clock())
    try:
        ack = R1CollectionFreezeAck.model_validate(
            {
                "schema": "r1-sysmon-collection-freeze-ack",
                "contract_version": "v0.1",
                "request_id": request.request_id,
                "partition": request.partition.model_dump(mode="json"),
                "source_lower_record_id": source_lower_record_id,
                "source_upper_record_id": source_upper_record_id,
                "target_event_ids": _TARGET_EVENT_IDS,
                "target_event_count": target_event_count,
                "target_identity_sha256": target_identity_sha256,
                "covered_through_chunk_sequence": covered_through_chunk_sequence,
                "allowed_lateness_ms": allowed_lateness_ms,
                "raw_segment_inventory_sha256": delivery.raw_segment_inventory_sha256,
                "acked_at": acked_at,
            }
        )
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError("freeze ack values are invalid") from error
    if ack.acked_at < request.requested_at:
        raise R1RecordBoundedSnapshotError("a freeze ack cannot precede its request")
    write_r1_snapshot_artifact(output_path, ack)
    return ack


def issue_r1_channel_generation_observation(
    *,
    phase: str,
    request: R1CollectionFreezeRequest,
    source_lower_record_id: int,
    source_upper_record_id: int,
    lower_anchor_raw_xml_sha256: str,
    upper_anchor_raw_xml_sha256: str,
    oldest_record_number: int,
    log_creation_time_utc: datetime,
    observed_at: datetime,
    output_path: Path,
) -> R1SysmonChannelGenerationObservation:
    """Publish one channel-generation observation bound to the freeze request."""

    try:
        observation = R1SysmonChannelGenerationObservation.model_validate(
            {
                "schema": "r1-sysmon-channel-generation-observation",
                "contract_version": "v0.1",
                "phase": phase,
                "request_id": request.request_id,
                "partition": request.partition.model_dump(mode="json"),
                "source_lower_record_id": source_lower_record_id,
                "source_upper_record_id": source_upper_record_id,
                "lower_anchor_raw_xml_sha256": lower_anchor_raw_xml_sha256,
                "upper_anchor_raw_xml_sha256": upper_anchor_raw_xml_sha256,
                "oldest_record_number": oldest_record_number,
                "log_creation_time_utc": log_creation_time_utc,
                "observed_at": observed_at,
            }
        )
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError("channel generation observation is invalid") from error
    if observation.observed_at < request.requested_at:
        raise R1RecordBoundedSnapshotError("a generation observation cannot precede the request")
    write_r1_snapshot_artifact(output_path, observation)
    return observation


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("datetime arguments must carry a timezone")
    return parsed.astimezone(UTC)


def _request(args: argparse.Namespace) -> R1CollectionFreezeRequest:
    return load_r1_freeze_request(
        Path(args.request),
        expected_run_id=args.run_id,
        expected_host_id=args.target_host,
        required_partition_contract_path=Path(args.required_partition_contract),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    for name in ("--request", "--run-id", "--target-host", "--required-partition-contract"):
        common.add_argument(name, required=True)
    common.add_argument("--lower", required=True, type=int)
    common.add_argument("--upper", required=True, type=int)
    common.add_argument("--output", required=True)

    ack = commands.add_parser("write-freeze-ack", parents=[common])
    ack.add_argument("--run-spool-root", required=True)
    ack.add_argument("--target-event-count", required=True, type=int)
    ack.add_argument("--target-identity-sha256", required=True)
    ack.add_argument("--covered-through-chunk-sequence", required=True, type=int)
    ack.add_argument("--allowed-lateness-ms", required=True, type=int)

    generation = commands.add_parser("write-generation-observation", parents=[common])
    generation.add_argument(
        "--phase", required=True, choices=["freeze_ack", "after_canonical_export"]
    )
    generation.add_argument("--lower-anchor-raw-xml-sha256", required=True)
    generation.add_argument("--upper-anchor-raw-xml-sha256", required=True)
    generation.add_argument("--oldest-record-number", required=True, type=int)
    generation.add_argument("--log-creation-time-utc", required=True)
    generation.add_argument("--observed-at", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    request = _request(args)
    if args.command == "write-freeze-ack":
        issue_r1_collection_freeze_ack(
            run_spool_root=Path(args.run_spool_root),
            request=request,
            source_lower_record_id=args.lower,
            source_upper_record_id=args.upper,
            target_event_count=args.target_event_count,
            target_identity_sha256=args.target_identity_sha256,
            covered_through_chunk_sequence=args.covered_through_chunk_sequence,
            allowed_lateness_ms=args.allowed_lateness_ms,
            output_path=Path(args.output),
        )
    else:
        issue_r1_channel_generation_observation(
            phase=args.phase,
            request=request,
            source_lower_record_id=args.lower,
            source_upper_record_id=args.upper,
            lower_anchor_raw_xml_sha256=args.lower_anchor_raw_xml_sha256,
            upper_anchor_raw_xml_sha256=args.upper_anchor_raw_xml_sha256,
            oldest_record_number=args.oldest_record_number,
            log_creation_time_utc=_parse_utc(args.log_creation_time_utc),
            observed_at=_parse_utc(args.observed_at),
            output_path=Path(args.output),
        )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "issue_r1_channel_generation_observation",
    "issue_r1_collection_freeze_ack",
    "load_r1_freeze_request",
]
