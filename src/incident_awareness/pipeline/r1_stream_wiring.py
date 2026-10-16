"""Executable file-spool wiring for the R1 development incremental stream.

The spool is a transport, never the acceptance authority.  Only a committed
``R1StreamDeliveryRepository`` row is accepted Role3 state.  A single producer
writes immutable messages through atomic rename; the consumer acknowledges a
message only after the ledger transaction commits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1FinalPartitionWatermark,
    R1LateEventDeadLetter,
    R1RunClosed,
    R1SourceWatermark,
    R1StreamPartition,
)
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamIngress,
    r1_stream_message_sha256,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
    R1StreamDeliveryRepository,
)

_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _publish_immutable(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return
        raise ValueError(f"immutable spool path conflicts with existing content: {path}")
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
                raise ValueError(f"immutable spool path conflicts with existing content: {path}")
        finally:
            stage.unlink(missing_ok=True)
    except BaseException:
        stage.unlink(missing_ok=True)
        raise


def _partition(run_id: str, host_id: str) -> R1StreamPartition:
    return R1StreamPartition(
        run_id=run_id,
        host_id=host_id,
        source="sysmon",
        source_channel=_CHANNEL,
    )


def _require_partition(
    contract: R1RequiredPartitionContract,
    partition: R1StreamPartition,
) -> None:
    if partition.host_id != contract.target_host:
        raise ValueError("stream partition host_id does not match required-partition contract")
    expected = {(item.source, item.source_channel) for item in contract.required_partitions}
    if (partition.source, partition.source_channel) not in expected:
        raise ValueError("stream partition is not required by the contract")


def publish_sysmon_segment(
    *,
    raw_jsonl: Path,
    spool_root: Path,
    run_id: str,
    host_id: str,
    raw_log_id: str,
    segment_no: int,
    chunk_sequence: int,
    message_ordinal: int,
    required_partition_contract: R1RequiredPartitionContract,
    observed_at: datetime | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    """Normalize one live-captured immutable segment and publish one chunk."""

    partition = _partition(run_id, host_id)
    _require_partition(required_partition_contract, partition)
    observed_at = _utc_milliseconds(clock() if observed_at is None else observed_at)
    context = SysmonNormalizationContext(
        run_id=run_id,
        raw_log_id=raw_log_id,
        segment_no=segment_no,
    )
    events = []
    for record in read_sysmon_jsonl(raw_jsonl):
        event_id = record.data.get("EventId")
        if event_id == 1:
            event = normalize_sysmon_process_create(record, context=context)
        elif event_id == 3:
            event = normalize_sysmon_network_connection(record, context=context)
        else:
            raise ValueError("live Sysmon segment may contain only Event ID 1 or 3")
        events.append(event.model_copy(update={"ingest_time": observed_at}))
    if not events:
        raise ValueError("live Sysmon segment must contain at least one record")
    provisional = R1EventChunk(
        schema="r1-incremental-stream",
        contract_version="v0.1",
        message_type="event_chunk",
        chunk_id=f"{run_id}-sysmon-{chunk_sequence:08d}",
        partition=partition,
        chunk_sequence=chunk_sequence,
        chunk_content_sha256="0" * 64,
        event_contract_version="v0.3",
        events=tuple(events),
    )
    chunk = provisional.model_copy(
        update={"chunk_content_sha256": r1_stream_message_sha256(provisional)}
    )
    path = spool_root / "outbox" / f"{message_ordinal:012d}-event_chunk.json"
    _publish_immutable(path, _canonical_bytes(chunk.model_dump(mode="json", by_alias=True)))
    return path


def publish_source_watermark(
    *,
    spool_root: Path,
    run_id: str,
    host_id: str,
    watermark_sequence: int,
    covered_through_chunk_sequence: int,
    watermark_at: datetime,
    allowed_lateness_ms: int,
    message_ordinal: int,
    required_partition_contract: R1RequiredPartitionContract,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    partition = _partition(run_id, host_id)
    _require_partition(required_partition_contract, partition)
    emitted_at = _utc_milliseconds(clock())
    watermark = R1SourceWatermark(
        schema="r1-incremental-stream",
        contract_version="v0.1",
        message_type="source_watermark",
        watermark_id=f"{run_id}-sysmon-watermark-{watermark_sequence:08d}",
        partition=partition,
        watermark_sequence=watermark_sequence,
        watermark_at=watermark_at,
        allowed_lateness_ms=allowed_lateness_ms,
        covered_through_chunk_sequence=covered_through_chunk_sequence,
        emitted_at=emitted_at,
    )
    path = spool_root / "outbox" / f"{message_ordinal:012d}-source_watermark.json"
    _publish_immutable(path, _canonical_bytes(watermark.model_dump(mode="json", by_alias=True)))
    return path


def publish_run_closed(
    *,
    spool_root: Path,
    final_watermark_path: Path,
    candidate_boundary_at: datetime,
    message_ordinal: int,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    watermark = R1SourceWatermark.model_validate_json(final_watermark_path.read_bytes())
    if watermark.watermark_at < candidate_boundary_at:
        raise ValueError("final watermark must cover the A04 candidate boundary")
    final = R1FinalPartitionWatermark.model_validate(
        {
            "partition": watermark.partition.model_dump(mode="json"),
            "watermark_id": watermark.watermark_id,
            "watermark_sequence": watermark.watermark_sequence,
            "watermark_at": watermark.watermark_at,
            "allowed_lateness_ms": watermark.allowed_lateness_ms,
            "covered_through_chunk_sequence": watermark.covered_through_chunk_sequence,
        }
    )
    run_closed = R1RunClosed(
        schema="r1-incremental-stream",
        contract_version="v0.1",
        message_type="run_closed",
        close_id=f"{watermark.partition.run_id}-close-v0.1",
        run_id=watermark.partition.run_id,
        final_watermarks=(final,),
        emitted_at=_utc_milliseconds(clock()),
    )
    path = spool_root / "outbox" / f"{message_ordinal:012d}-run_closed.json"
    _publish_immutable(path, _canonical_bytes(run_closed.model_dump(mode="json", by_alias=True)))
    return path


class _FileDeadLetterSink:
    def __init__(self, root: Path) -> None:
        self._root = root

    def write(self, dead_letter: R1LateEventDeadLetter) -> None:
        path = self._root / "dead-letter" / f"{dead_letter.chunk_id}.json"
        _publish_immutable(
            path, _canonical_bytes(dead_letter.model_dump(mode="json", by_alias=True))
        )


def consume_spool_once(
    *,
    spool_root: Path,
    contract: R1RequiredPartitionContract,
    connection: Any,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[Path, ...]:
    """Accept unacknowledged files in publication order and ack after commit."""

    accepted = []
    for path in sorted((spool_root / "outbox").glob("*.json")):
        ack_path = spool_root / "acks" / f"{path.name}.ack.json"
        if ack_path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        message_type = payload.get("message_type")
        ledger = R1StreamDeliveryRepository(connection)
        ingress = R1StreamIngress(
            ledger,
            dead_letter_sink=_FileDeadLetterSink(spool_root),
            clock=clock,
        )
        if message_type == "event_chunk":
            message = R1EventChunk.model_validate(payload)
            _require_partition(contract, message.partition)
            result = ingress.accept_chunk(message)
        elif message_type == "source_watermark":
            message = R1SourceWatermark.model_validate(payload)
            _require_partition(contract, message.partition)
            result = ingress.accept_watermark(message)
        elif message_type == "run_closed":
            message = R1RunClosed.model_validate(payload)
            expected = {
                (contract.target_host, item.source, item.source_channel)
                for item in contract.required_partitions
            }
            actual = {
                (item.partition.host_id, item.partition.source, item.partition.source_channel)
                for item in message.final_watermarks
            }
            if actual != expected:
                raise ValueError("run_closed does not exactly cover required partitions")
            result = ingress.accept_run_closed(message)
        else:
            raise ValueError(f"unsupported spool message_type: {message_type!r}")
        connection.commit()
        ack = {
            "message_path": str(path.resolve()),
            "message_sha256": _sha256(path.read_bytes()),
            "disposition": result.disposition.value,
            "accepted_at": _utc_milliseconds(clock()).isoformat().replace("+00:00", "Z"),
        }
        _publish_immutable(ack_path, _canonical_bytes(ack))
        accepted.append(path)
    return tuple(accepted)


def export_accepted_close(
    *,
    spool_root: Path,
    accepted_run_closed_path: Path,
    connection: Any,
    contract_path: Path,
) -> Path:
    """Export the close payload only when its binding is present in Role3 ledger."""

    run_closed = R1RunClosed.model_validate_json(accepted_run_closed_path.read_bytes())
    receipt = R1StreamDeliveryRepository(connection).load_accepted_run_close_receipt(
        run_closed.run_id
    )
    if receipt is None:
        raise ValueError("Role3 ledger has no accepted close for the requested run")
    expected_hash = r1_stream_message_sha256(run_closed)
    if receipt.close_id != run_closed.close_id or receipt.content_sha256 != expected_hash:
        raise ValueError("accepted close payload does not match the Role3 ledger receipt")
    payload = {
        "schema": "r1-accepted-close-export",
        "contract_version": "v0.1",
        "accepted_run_closed": run_closed.model_dump(mode="json", by_alias=True),
        "acceptance_receipt": {
            "run_id": receipt.run_id,
            "close_id": receipt.close_id,
            "content_sha256": receipt.content_sha256,
        },
        "required_partition_contract": {
            "path": str(contract_path.resolve()),
            "sha256": _sha256(contract_path.read_bytes()),
        },
    }
    destination = spool_root / "exports" / run_closed.run_id / "accepted-run-closed.json"
    _publish_immutable(destination, _canonical_bytes(payload))
    return destination


def load_close_export(path: Path) -> tuple[R1RunClosed, R1AcceptedRunCloseReceipt]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    run_closed = R1RunClosed.model_validate(payload["accepted_run_closed"])
    receipt = R1AcceptedRunCloseReceipt(**payload["acceptance_receipt"])
    if receipt.content_sha256 != r1_stream_message_sha256(run_closed):
        raise ValueError("exported accepted close does not match its ledger receipt")
    return run_closed, receipt


def load_accepted_spool_message(
    message_path: Path,
    ack_path: Path,
) -> R1EventChunk | R1SourceWatermark | R1RunClosed:
    """Load a Role2 input only when the post-commit Role3 ack binds its bytes."""

    message_bytes = message_path.read_bytes()
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    if ack.get("message_path") != str(message_path.resolve()):
        raise ValueError("Role3 ack is bound to another spool message path")
    if ack.get("message_sha256") != _sha256(message_bytes):
        raise ValueError("Role3 ack does not match the spool message bytes")
    if ack.get("disposition") not in {"accepted", "duplicate"}:
        raise ValueError("Role3 ack has no accepted delivery disposition")
    payload = json.loads(message_bytes)
    model_by_type = {
        "event_chunk": R1EventChunk,
        "source_watermark": R1SourceWatermark,
        "run_closed": R1RunClosed,
    }
    model = model_by_type.get(payload.get("message_type"))
    if model is None:
        raise ValueError("unsupported accepted spool message_type")
    return model.model_validate(payload)


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return _utc_milliseconds(parsed)


def _contract(path: str, target_host: str) -> R1RequiredPartitionContract:
    return load_r1_required_partition_contract(path, expected_target_host=target_host)


def render_required_partition_contract(*, path: Path, target_host: str) -> Path:
    """Render the existing v0.1 contract for the runner-verified target host."""

    contract = R1RequiredPartitionContract.model_validate(
        {
            "schema": "r1-required-partitions",
            "contract_version": "v0.1",
            "target_host": target_host,
            "required_partitions": [{"source": "sysmon", "source_channel": _CHANNEL}],
        }
    )
    _publish_immutable(path, _canonical_bytes(contract.model_dump(mode="json", by_alias=True)))
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-contract")
    render.add_argument("--output", required=True)
    render.add_argument("--target-host", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--spool-root", required=True)
    common.add_argument("--required-partition-contract", required=True)
    common.add_argument("--target-host", required=True)

    segment = commands.add_parser("publish-segment", parents=[common])
    segment.add_argument("--raw-jsonl", required=True)
    segment.add_argument("--run-id", required=True)
    segment.add_argument("--raw-log-id", required=True)
    segment.add_argument("--segment-no", required=True, type=int)
    segment.add_argument("--chunk-sequence", required=True, type=int)
    segment.add_argument("--message-ordinal", required=True, type=int)
    segment.add_argument("--observed-at", required=True)

    watermark = commands.add_parser("publish-watermark", parents=[common])
    watermark.add_argument("--run-id", required=True)
    watermark.add_argument("--watermark-sequence", required=True, type=int)
    watermark.add_argument("--covered-through-chunk-sequence", required=True, type=int)
    watermark.add_argument("--watermark-at", required=True)
    watermark.add_argument("--allowed-lateness-ms", required=True, type=int)
    watermark.add_argument("--message-ordinal", required=True, type=int)

    close = commands.add_parser("publish-close")
    close.add_argument("--spool-root", required=True)
    close.add_argument("--final-watermark", required=True)
    close.add_argument("--candidate-boundary-at", required=True)
    close.add_argument("--message-ordinal", required=True, type=int)

    commands.add_parser("consume", parents=[common])

    export = commands.add_parser("export-close")
    export.add_argument("--spool-root", required=True)
    export.add_argument("--accepted-run-closed", required=True)
    export.add_argument("--required-partition-contract", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "render-contract":
        result = render_required_partition_contract(
            path=Path(args.output), target_host=args.target_host
        )
    elif args.command == "publish-segment":
        result = publish_sysmon_segment(
            raw_jsonl=Path(args.raw_jsonl),
            spool_root=Path(args.spool_root),
            run_id=args.run_id,
            host_id=args.target_host,
            raw_log_id=args.raw_log_id,
            segment_no=args.segment_no,
            chunk_sequence=args.chunk_sequence,
            message_ordinal=args.message_ordinal,
            observed_at=_parse_utc(args.observed_at),
            required_partition_contract=_contract(
                args.required_partition_contract, args.target_host
            ),
        )
    elif args.command == "publish-watermark":
        result = publish_source_watermark(
            spool_root=Path(args.spool_root),
            run_id=args.run_id,
            host_id=args.target_host,
            watermark_sequence=args.watermark_sequence,
            covered_through_chunk_sequence=args.covered_through_chunk_sequence,
            watermark_at=_parse_utc(args.watermark_at),
            allowed_lateness_ms=args.allowed_lateness_ms,
            message_ordinal=args.message_ordinal,
            required_partition_contract=_contract(
                args.required_partition_contract, args.target_host
            ),
        )
    elif args.command == "publish-close":
        result = publish_run_closed(
            spool_root=Path(args.spool_root),
            final_watermark_path=Path(args.final_watermark),
            candidate_boundary_at=_parse_utc(args.candidate_boundary_at),
            message_ordinal=args.message_ordinal,
        )
    else:
        config = DatabaseConfig.from_environment()
        with psycopg.connect(config.url, autocommit=False) as connection:
            if args.command == "consume":
                result = consume_spool_once(
                    spool_root=Path(args.spool_root),
                    contract=_contract(args.required_partition_contract, args.target_host),
                    connection=connection,
                )
            else:
                result = export_accepted_close(
                    spool_root=Path(args.spool_root),
                    accepted_run_closed_path=Path(args.accepted_run_closed),
                    connection=connection,
                    contract_path=Path(args.required_partition_contract),
                )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "consume_spool_once",
    "export_accepted_close",
    "load_accepted_spool_message",
    "load_close_export",
    "publish_run_closed",
    "publish_source_watermark",
    "publish_sysmon_segment",
    "render_required_partition_contract",
]
