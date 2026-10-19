"""R1 Sysmon RecordId position finality: issue, Role3 acceptance and receipt export.

The flow is separate from the event-time ``r1-incremental-stream/v0.1`` messages:

1. ``reconcile-snapshot`` verifies the RecordId-bounded snapshot (v0.1 contract).
2. ``issue-position-close`` re-verifies the reconciliation and the channel generation,
   then publishes one ``r1-record-position-close`` message.
3. ``consume-position-close`` records it in the Role3 ledger and writes the ack only
   after the transaction commits.
4. ``export-position-close`` reads the committed receipt back from the ledger and
   exports the close, the receipt and the contract linkage for Role4 and Role2.

Nothing here publishes a ``source_watermark`` or a ``run_closed``.  The position close
guarantees only ``R1_RECORD_POSITION_FINALITY_GUARANTEE``; every item of
``R1_RECORD_POSITION_FINALITY_NON_GUARANTEES`` stays unproven.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1RecordBoundedSnapshotError,
    canonical_json_bytes,
    publish_immutable_bytes,
    sha256_hex,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_GUARANTEE,
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
    record_position_close_sha256,
    require_receipt_binds_close,
)
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
    load_r1_required_partition_contract,
)
from incident_awareness.pipeline.r1_record_bounded_reconciliation import (
    R1SnapshotSources,
    reconcile_r1_record_bounded_snapshot,
    required_partition_contract_sha256,
    verify_r1_channel_generation,
    verify_r1_record_bounded_reconciliation,
)
from incident_awareness.storage.repositories.r1_position_close_repository import (
    R1PositionCloseRepository,
)

R1_POSITION_CLOSE_EXPORT_SCHEMA = "r1-accepted-record-position-close-export"
_POSITION_DIRECTORY = "position-finality"
_CLOSE_FILENAME = "record-position-close.json"
_EXPORT_FILENAME = "accepted-record-position-close.json"


def position_close_path(run_spool_root: Path) -> Path:
    """``<spool>/<run_id>/position-finality/outbox/record-position-close.json``."""

    return run_spool_root / _POSITION_DIRECTORY / "outbox" / _CLOSE_FILENAME


def position_close_ack_path(run_spool_root: Path) -> Path:
    """``<spool>/<run_id>/position-finality/acks/record-position-close.json.ack.json``."""

    return run_spool_root / _POSITION_DIRECTORY / "acks" / f"{_CLOSE_FILENAME}.ack.json"


def position_close_export_path(run_spool_root: Path, run_id: str) -> Path:
    """``<spool>/<run_id>/exports/<run_id>/accepted-record-position-close.json``."""

    return run_spool_root / "exports" / run_id / _EXPORT_FILENAME


def issue_r1_record_position_close(
    *,
    sources: R1SnapshotSources,
    reconciliation_path: Path,
    freeze_generation_path: Path,
    export_generation_path: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> R1RecordPositionClose:
    """Issue a position close only from a re-verified snapshot and channel generation."""

    reconciliation, reconciliation_sha256, snapshot = verify_r1_record_bounded_reconciliation(
        reconciliation_path, sources
    )
    generation = verify_r1_channel_generation(
        freeze_observation_path=freeze_generation_path,
        export_observation_path=export_generation_path,
        snapshot=snapshot,
    )
    emitted_at = _utc_milliseconds(clock())
    if emitted_at < reconciliation.reconciled_at:
        raise R1RecordBoundedSnapshotError("a position close cannot precede its reconciliation")
    partition = snapshot.partition
    try:
        return R1RecordPositionClose.model_validate(
            {
                "schema": "r1-record-position-close",
                "contract_version": "v0.1",
                "message_type": "record_position_close",
                "close_id": f"{partition.run_id}-record-position-close-v0.1",
                "run_id": partition.run_id,
                "partition": partition.model_dump(mode="json"),
                "required_partition_contract": {
                    "target_host": snapshot.contract.target_host,
                    "content_sha256": snapshot.contract_sha256,
                },
                "position_frontier": {
                    "finality_kind": "sysmon_record_id_position",
                    "lower_record_id": snapshot.ack.source_lower_record_id,
                    "upper_record_id": snapshot.ack.source_upper_record_id,
                    "target_event_ids": [1, 3],
                    "channel_generation_id": generation.channel_generation_id,
                },
                "covered_through_chunk_sequence": snapshot.ack.covered_through_chunk_sequence,
                "covered_chunks_sha256": snapshot.covered_chunks_sha256,
                "post_commit_ack_count": len(snapshot.covered_chunks),
                "event_count": snapshot.event_count,
                "source_native_identity_sha256": snapshot.source_native_identity_sha256,
                "live_identity_sha256": reconciliation.live_identity_sha256,
                "canonical_identity_sha256": reconciliation.canonical_identity_sha256,
                "source_snapshot": {
                    "request_id": snapshot.request.request_id,
                    "freeze_request_sha256": snapshot.request_sha256,
                    "freeze_ack_sha256": snapshot.ack_sha256,
                    "run_finalized_sha256": snapshot.finalized_sha256,
                    "reconciliation_sha256": reconciliation_sha256,
                    "freeze_generation_observation_sha256": generation.freeze_observation_sha256,
                    "export_generation_observation_sha256": generation.export_observation_sha256,
                },
                "candidate_boundary_at": snapshot.request.candidate_boundary_at,
                "observation_boundary_at": snapshot.request.observation_boundary_at,
                "emitted_at": emitted_at,
                "guarantee": R1_RECORD_POSITION_FINALITY_GUARANTEE,
                "non_guarantees": list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES),
            }
        )
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError("position close bindings are inconsistent") from error


def publish_r1_record_position_close(close: R1RecordPositionClose, run_spool_root: Path) -> Path:
    """Publish the close immutably; a byte-identical republish is a no-op."""

    path = position_close_path(run_spool_root)
    publish_immutable_bytes(
        path, canonical_json_bytes(close.model_dump(mode="json", by_alias=True))
    )
    return path


def load_r1_record_position_close(path: Path) -> R1RecordPositionClose:
    """Strictly load a published position close (duplicate keys and drift fail closed)."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
        return R1RecordPositionClose.model_validate(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1RecordBoundedSnapshotError(f"position close cannot be loaded: {path}") from error


class R1RecordPositionCloseIngress:
    """Role3 acceptance of a position close inside the caller's DB transaction."""

    def __init__(
        self,
        repository: R1PositionCloseRepository,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._repository = repository
        self._clock = clock

    def accept(
        self,
        close: R1RecordPositionClose,
        *,
        contract: R1RequiredPartitionContract,
    ) -> tuple[bool, R1AcceptedRecordPositionCloseReceipt]:
        if not isinstance(close, R1RecordPositionClose):
            raise TypeError("close must be an R1RecordPositionClose; event-time messages differ")
        _require_contract_binding(close, contract)
        admission = self._repository.save_position_close(
            close,
            content_sha256=record_position_close_sha256(close),
            accepted_at=_utc_milliseconds(self._clock()),
        )
        return admission.accepted, admission.receipt


def consume_r1_record_position_close(
    *,
    run_spool_root: Path,
    contract: R1RequiredPartitionContract,
    connection: Any,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path | None:
    """Accept the published close and write its ack only after the commit succeeds."""

    message_path = position_close_path(run_spool_root)
    ack_path = position_close_ack_path(run_spool_root)
    if ack_path.exists() or not message_path.exists():
        return None
    message_bytes = message_path.read_bytes()
    close = load_r1_record_position_close(message_path)
    ingress = R1RecordPositionCloseIngress(R1PositionCloseRepository(connection), clock=clock)
    try:
        accepted, receipt = ingress.accept(close, contract=contract)
        connection.commit()
    except BaseException:
        if hasattr(connection, "rollback"):
            connection.rollback()
        raise
    ack = {
        "message_path": str(message_path.resolve()),
        "message_sha256": sha256_hex(message_bytes),
        "disposition": "accepted" if accepted else "duplicate",
        "ledger_entry_id": receipt.ledger_entry_id,
        "accepted_at": _datetime_json(receipt.accepted_at),
        "required_partition_contract_sha256": required_partition_contract_sha256(contract),
    }
    publish_immutable_bytes(ack_path, canonical_json_bytes(ack))
    return message_path


def export_r1_accepted_record_position_close(
    *,
    run_spool_root: Path,
    connection: Any,
    contract_path: Path,
) -> Path:
    """Export the close only when the committed Role3 ledger receipt binds it."""

    message_path = position_close_path(run_spool_root)
    close = load_r1_record_position_close(message_path)
    contract = load_r1_required_partition_contract(
        contract_path, expected_target_host=close.partition.host_id
    )
    _require_contract_binding(close, contract)
    ack = _load_post_commit_ack(position_close_ack_path(run_spool_root), message_path)
    receipt = R1PositionCloseRepository(connection).load_accepted_position_close_receipt(
        close.run_id
    )
    if receipt is None:
        raise R1RecordBoundedSnapshotError(
            "Role3 ledger has no accepted position close for the run"
        )
    require_receipt_binds_close(receipt, close)
    if ack.get("ledger_entry_id") != receipt.ledger_entry_id:
        raise R1RecordBoundedSnapshotError("Role3 ack does not name the committed ledger entry")
    if ack.get("required_partition_contract_sha256") != required_partition_contract_sha256(
        contract
    ):
        raise R1RecordBoundedSnapshotError(
            "contract digest differs from the one used at acceptance"
        )
    payload = {
        "schema": R1_POSITION_CLOSE_EXPORT_SCHEMA,
        "contract_version": "v0.1",
        "accepted_record_position_close": close.model_dump(mode="json", by_alias=True),
        "acceptance_receipt": receipt.model_dump(mode="json", by_alias=True),
        "required_partition_contract": {
            "path": str(contract_path.resolve()),
            "sha256": sha256_hex(contract_path.read_bytes()),
            "content_sha256": required_partition_contract_sha256(contract),
            "target_host": contract.target_host,
        },
    }
    destination = position_close_export_path(run_spool_root, close.run_id)
    publish_immutable_bytes(destination, canonical_json_bytes(payload))
    return destination


def load_r1_accepted_record_position_close_export(
    path: Path,
    *,
    contract_path: Path,
) -> tuple[R1RecordPositionClose, R1AcceptedRecordPositionCloseReceipt]:
    """Role4/Role2 loader: verify the receipt and the contract linkage before use."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1RecordBoundedSnapshotError(
            f"position close export cannot be read: {path}"
        ) from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "contract_version",
        "accepted_record_position_close",
        "acceptance_receipt",
        "required_partition_contract",
    }:
        raise R1RecordBoundedSnapshotError("position close export has an unexpected structure")
    if (payload["schema"], payload["contract_version"]) != (
        R1_POSITION_CLOSE_EXPORT_SCHEMA,
        "v0.1",
    ):
        raise R1RecordBoundedSnapshotError("position close export schema is not supported")
    try:
        close = R1RecordPositionClose.model_validate(payload["accepted_record_position_close"])
        receipt = R1AcceptedRecordPositionCloseReceipt.model_validate(payload["acceptance_receipt"])
    except ValidationError as error:
        raise R1RecordBoundedSnapshotError("position close export content is invalid") from error
    require_receipt_binds_close(receipt, close)

    linkage = payload["required_partition_contract"]
    if not isinstance(linkage, dict):
        raise R1RecordBoundedSnapshotError("position close export has no contract linkage")
    contract_file = contract_path
    if not contract_file.is_file():
        raise R1RecordBoundedSnapshotError(
            f"linked required-partition contract is missing: {contract_file}"
        )
    if sha256_hex(contract_file.read_bytes()) != linkage.get("sha256"):
        raise R1RecordBoundedSnapshotError(
            "linked required-partition contract file digest mismatch"
        )
    contract = load_r1_required_partition_contract(
        contract_file, expected_target_host=close.partition.host_id
    )
    if linkage.get("content_sha256") != required_partition_contract_sha256(contract):
        raise R1RecordBoundedSnapshotError("linked required-partition contract content mismatch")
    _require_contract_binding(close, contract)
    return close, receipt


def _require_contract_binding(
    close: R1RecordPositionClose,
    contract: R1RequiredPartitionContract,
) -> None:
    if not isinstance(contract, R1RequiredPartitionContract):
        raise TypeError("contract must be an R1RequiredPartitionContract")
    if contract.target_host != close.partition.host_id:
        raise R1RecordBoundedSnapshotError("position close host does not match the contract")
    required = tuple((item.source, item.source_channel) for item in contract.required_partitions)
    if required != ((close.partition.source, close.partition.source_channel),):
        raise R1RecordBoundedSnapshotError(
            "position close partition does not cover the required partitions"
        )
    if close.required_partition_contract.content_sha256 != required_partition_contract_sha256(
        contract
    ):
        raise R1RecordBoundedSnapshotError("position close was issued for another contract")


def _load_post_commit_ack(ack_path: Path, message_path: Path) -> dict[str, object]:
    try:
        ack = json.loads(ack_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1RecordBoundedSnapshotError(
            "position close has no readable post-commit ack"
        ) from error
    if not isinstance(ack, dict):
        raise R1RecordBoundedSnapshotError("position close ack must be a JSON object")
    if ack.get("message_path") != str(message_path.resolve()):
        raise R1RecordBoundedSnapshotError("position close ack is bound to another message path")
    if ack.get("message_sha256") != sha256_hex(message_path.read_bytes()):
        raise R1RecordBoundedSnapshotError("position close ack does not match the message bytes")
    if ack.get("disposition") not in {"accepted", "duplicate"}:
        raise R1RecordBoundedSnapshotError("position close ack has no accepted disposition")
    return ack


def _unique_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


def _datetime_json(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sources(args: argparse.Namespace) -> R1SnapshotSources:
    return R1SnapshotSources(
        run_spool_root=Path(args.run_spool_root),
        freeze_request_path=Path(args.freeze_request),
        freeze_ack_path=Path(args.freeze_ack),
        run_finalized_path=Path(args.run_finalized),
        canonical_evtx_path=Path(args.canonical_evtx),
        canonical_jsonl_path=Path(args.canonical_jsonl),
        canonical_manifest_path=Path(args.canonical_manifest),
        required_partition_contract_path=Path(args.required_partition_contract),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = argparse.ArgumentParser(add_help=False)
    for name in (
        "--run-spool-root",
        "--freeze-request",
        "--freeze-ack",
        "--run-finalized",
        "--canonical-evtx",
        "--canonical-jsonl",
        "--canonical-manifest",
        "--required-partition-contract",
    ):
        snapshot.add_argument(name, required=True)

    reconcile = commands.add_parser("reconcile-snapshot", parents=[snapshot])
    reconcile.add_argument("--output", required=True)

    issue = commands.add_parser("issue-position-close", parents=[snapshot])
    issue.add_argument("--reconciliation", required=True)
    issue.add_argument("--freeze-generation", required=True)
    issue.add_argument("--export-generation", required=True)

    consume = commands.add_parser("consume-position-close")
    consume.add_argument("--run-spool-root", required=True)
    consume.add_argument("--required-partition-contract", required=True)
    consume.add_argument("--target-host", required=True)

    export = commands.add_parser("export-position-close")
    export.add_argument("--run-spool-root", required=True)
    export.add_argument("--required-partition-contract", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "reconcile-snapshot":
        result: object = reconcile_r1_record_bounded_snapshot(
            _sources(args), output_path=Path(args.output)
        )
    elif args.command == "issue-position-close":
        close = issue_r1_record_position_close(
            sources=_sources(args),
            reconciliation_path=Path(args.reconciliation),
            freeze_generation_path=Path(args.freeze_generation),
            export_generation_path=Path(args.export_generation),
        )
        result = publish_r1_record_position_close(close, Path(args.run_spool_root))
    else:
        import psycopg

        from incident_awareness.storage.config import DatabaseConfig

        config = DatabaseConfig.from_environment()
        with psycopg.connect(config.url, autocommit=False) as connection:
            if args.command == "consume-position-close":
                result = consume_r1_record_position_close(
                    run_spool_root=Path(args.run_spool_root),
                    contract=load_r1_required_partition_contract(
                        args.required_partition_contract, expected_target_host=args.target_host
                    ),
                    connection=connection,
                )
            else:
                result = export_r1_accepted_record_position_close(
                    run_spool_root=Path(args.run_spool_root),
                    connection=connection,
                    contract_path=Path(args.required_partition_contract),
                )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "R1_POSITION_CLOSE_EXPORT_SCHEMA",
    "R1RecordPositionCloseIngress",
    "consume_r1_record_position_close",
    "export_r1_accepted_record_position_close",
    "issue_r1_record_position_close",
    "load_r1_accepted_record_position_close_export",
    "load_r1_record_position_close",
    "position_close_ack_path",
    "position_close_export_path",
    "position_close_path",
    "publish_r1_record_position_close",
]
