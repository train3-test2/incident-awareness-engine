"""Synthetic RecordId-bounded snapshot for the R1 position-finality tests.

The fixture writes a complete Run spool, canonical Run artifacts and every snapshot
artifact under ``tmp_path``.  No real Run or Pair identity is used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1CollectionFreezeAck,
    R1CollectionFreezeRequest,
    R1SysmonChannelGenerationObservation,
    R1SysmonRunFinalized,
    canonical_json_bytes,
    sha256_hex,
    snapshot_identity_sha256,
)
from incident_awareness.common.models.r1_required_partition import R1RequiredPartitionContract
from incident_awareness.common.models.r1_stream import R1EventChunk, R1StreamPartition
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.r1_record_bounded_reconciliation import (
    R1SnapshotSources,
    r1_raw_segment_inventory_sha256,
    reconcile_r1_record_bounded_snapshot,
)
from incident_awareness.pipeline.r1_stream_ingress import r1_stream_message_sha256

RUN_ID = "RUN-20261019-001"
HOST_ID = "R1-TGTA"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
LOWER_RECORD_ID = 1001
UPPER_RECORD_ID = 1006
CANDIDATE_BOUNDARY_AT = datetime(2026, 10, 19, 1, 12, tzinfo=UTC)
OBSERVATION_BOUNDARY_AT = datetime(2026, 10, 19, 1, 13, tzinfo=UTC)
REQUESTED_AT = datetime(2026, 10, 19, 1, 13, 1, tzinfo=UTC)
FREEZE_OBSERVED_AT = datetime(2026, 10, 19, 1, 13, 3, tzinfo=UTC)
ACKED_AT = datetime(2026, 10, 19, 1, 13, 5, tzinfo=UTC)
EXPORT_OBSERVED_AT = datetime(2026, 10, 19, 1, 13, 20, tzinfo=UTC)
FINALIZED_AT = datetime(2026, 10, 19, 1, 13, 30, tzinfo=UTC)
RECONCILED_AT = datetime(2026, 10, 19, 1, 14, tzinfo=UTC)
CLOSE_EMITTED_AT = datetime(2026, 10, 19, 1, 14, 1, tzinfo=UTC)

# Records of the bound: three EID 1 (WMI provider host, intermediate, PowerShell) and one
# EID 3.  RecordIds 1005 and 1006 are other Sysmon events below the all-channel upper bound.
_RECORDS = (
    (1001, 1, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "{00000000-0000-0000-0000-00000000a001}", None),
    (1002, 1, "C:\\Windows\\System32\\wscript.exe", "{00000000-0000-0000-0000-00000000a002}", "{00000000-0000-0000-0000-00000000a001}"),
    (1003, 1, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "{00000000-0000-0000-0000-00000000a003}", "{00000000-0000-0000-0000-00000000a002}"),
    (1004, 3, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "{00000000-0000-0000-0000-00000000a003}", None),
)  # fmt: skip
_SEGMENTS = ((1001, 1002), (1003, 1004))


def partition() -> R1StreamPartition:
    return R1StreamPartition(
        run_id=RUN_ID, host_id=HOST_ID, source="sysmon", source_channel=CHANNEL
    )


def raw_record(record_id: int, *, host_id: str = HOST_ID) -> dict[str, object]:
    record_id, event_id, image, guid, parent = next(
        item for item in _RECORDS if item[0] == record_id
    )
    utc_time = f"2026-10-19 01:0{record_id - 1000}:00.000"
    data: dict[str, object] = {"UtcTime": utc_time, "ProcessGuid": guid, "Image": image}
    if event_id == 1:
        data.update({"ProcessId": str(record_id), "CommandLine": image, "User": "R1\\operator"})
        if parent is not None:
            data["ParentProcessGuid"] = parent
    else:
        data.update(
            {
                "Protocol": "tcp",
                "SourceIp": "192.0.2.10",
                "SourcePort": "50000",
                "DestinationIp": "192.0.2.30",
                "DestinationPort": "8443",
            }
        )
    return {
        "RecordId": record_id,
        "EventId": event_id,
        "Computer": host_id,
        "TimeCreated": f"2026-10-19T01:0{record_id - 1000}:00.100Z",
        "Provider": "Microsoft-Windows-Sysmon",
        "EventData": data,
    }


def _jsonl(records: list[dict[str, object]]) -> bytes:
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode()


@dataclass
class Snapshot:
    """Paths of one synthetic Run; tests may rewrite any file before verifying."""

    root: Path
    run_spool_root: Path
    control_root: Path
    canonical_root: Path
    contract_path: Path
    reconciliation_path: Path
    freeze_generation_path: Path
    export_generation_path: Path
    chunk_paths: list[Path] = field(default_factory=list)

    @property
    def sources(self) -> R1SnapshotSources:
        return R1SnapshotSources(
            run_spool_root=self.run_spool_root,
            freeze_request_path=self.control_root / "collection-freeze-requested.json",
            freeze_ack_path=self.control_root / "collection-freeze-ack.json",
            run_finalized_path=self.control_root / "run-finalized.json",
            canonical_evtx_path=self.canonical_root / "sysmon-0001.evtx",
            canonical_jsonl_path=self.canonical_root / "sysmon-0001.jsonl",
            canonical_manifest_path=self.canonical_root / "manifest.json",
            required_partition_contract_path=self.contract_path,
        )

    def read_json(self, path: Path) -> dict[str, object]:
        return json.loads(path.read_text(encoding="utf-8"))

    def rewrite_json(self, path: Path, payload: dict[str, object]) -> None:
        path.write_bytes(canonical_json_bytes(payload))


def build_snapshot(tmp_path: Path, *, reconcile: bool = True) -> Snapshot:
    root = tmp_path / "r1"
    run_spool_root = root / "spool" / RUN_ID
    control_root = root / "control" / RUN_ID
    canonical_root = root / "raw" / RUN_ID / "telemetry"
    contract_path = root / "spool" / "contracts" / f"{RUN_ID}-required-partitions.json"
    snapshot = Snapshot(
        root=root,
        run_spool_root=run_spool_root,
        control_root=control_root,
        canonical_root=canonical_root,
        contract_path=contract_path,
        reconciliation_path=run_spool_root
        / "position-finality"
        / "r1_finality_reconciliation.json",
        freeze_generation_path=control_root / "collection-freeze-generation.json",
        export_generation_path=control_root / "canonical-export-generation.json",
    )
    write_contract(contract_path, HOST_ID)
    _write_live_spool(snapshot)
    _write_canonical(snapshot)
    _write_snapshot_artifacts(snapshot)
    if reconcile:
        reconcile_r1_record_bounded_snapshot(
            snapshot.sources,
            output_path=snapshot.reconciliation_path,
            clock=lambda: RECONCILED_AT,
        )
    return snapshot


def write_contract(path: Path, target_host: str) -> R1RequiredPartitionContract:
    contract = R1RequiredPartitionContract.model_validate(
        {
            "schema": "r1-required-partitions",
            "contract_version": "v0.1",
            "target_host": target_host,
            "required_partitions": [{"source": "sysmon", "source_channel": CHANNEL}],
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(contract.model_dump(mode="json", by_alias=True)))
    return contract


def _write_live_spool(snapshot: Snapshot) -> None:
    raw_root = snapshot.run_spool_root / "raw-segments"
    raw_root.mkdir(parents=True)
    for segment_no, record_ids in enumerate(_SEGMENTS, start=1):
        segment = raw_root / f"sysmon-{segment_no:08d}.jsonl"
        segment.write_bytes(_jsonl([raw_record(record_id) for record_id in record_ids]))
        segment.with_name(segment.name + ".capture.json").write_bytes(
            canonical_json_bytes(
                {
                    "controller_received_at_utc": f"2026-10-19T01:0{segment_no}:30.000Z",
                    "observed_at_utc": f"2026-10-19T01:0{segment_no}:30.000Z",
                    "target_queried_at_utc": f"2026-10-19T01:0{segment_no}:29.900Z",
                }
            )
        )
        snapshot.chunk_paths.append(publish_chunk(snapshot, segment_no))


def publish_chunk(snapshot: Snapshot, segment_no: int, *, ordinal: int | None = None) -> Path:
    """Normalize one raw segment, publish its chunk and write a post-commit ack."""

    segment = snapshot.run_spool_root / "raw-segments" / f"sysmon-{segment_no:08d}.jsonl"
    context = SysmonNormalizationContext(
        run_id=RUN_ID, raw_log_id=f"R1-INCREMENTAL-{RUN_ID}-SYSMON", segment_no=segment_no
    )
    observed_at = datetime(2026, 10, 19, 1, segment_no, 30, tzinfo=UTC)
    events = []
    for record in read_sysmon_jsonl(segment):
        normalize = (
            normalize_sysmon_process_create
            if record.data["EventId"] == 1
            else normalize_sysmon_network_connection
        )
        events.append(
            normalize(record, context=context).model_copy(update={"ingest_time": observed_at})
        )
    provisional = R1EventChunk(
        schema="r1-incremental-stream",
        contract_version="v0.1",
        message_type="event_chunk",
        chunk_id=f"{RUN_ID}-sysmon-{segment_no:08d}",
        partition=partition(),
        chunk_sequence=segment_no,
        chunk_content_sha256="0" * 64,
        event_contract_version="v0.3",
        events=tuple(events),
    )
    chunk = provisional.model_copy(
        update={"chunk_content_sha256": r1_stream_message_sha256(provisional)}
    )
    path = snapshot.run_spool_root / "outbox" / f"{(ordinal or segment_no):012d}-event_chunk.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json_bytes(chunk.model_dump(mode="json", by_alias=True))
    path.write_bytes(data)
    write_ack(snapshot, path)
    return path


def write_ack(snapshot: Snapshot, message_path: Path) -> Path:
    ack_path = snapshot.run_spool_root / "acks" / f"{message_path.name}.ack.json"
    ack_path.parent.mkdir(parents=True, exist_ok=True)
    ack_path.write_bytes(
        canonical_json_bytes(
            {
                "accepted_at": "2026-10-19T01:10:00.000Z",
                "disposition": "accepted",
                "message_path": str(message_path.resolve()),
                "message_sha256": sha256_hex(message_path.read_bytes()),
            }
        )
    )
    return ack_path


def _write_canonical(snapshot: Snapshot) -> None:
    snapshot.canonical_root.mkdir(parents=True)
    records = [raw_record(record_id) | {"Channel": CHANNEL} for record_id, *_ in _RECORDS]
    jsonl = snapshot.canonical_root / "sysmon-0001.jsonl"
    evtx = snapshot.canonical_root / "sysmon-0001.evtx"
    jsonl.write_bytes(_jsonl(records))
    evtx.write_bytes(b"synthetic EVTX bytes for the RecordId-bounded export")
    write_manifest(snapshot)


def write_manifest(snapshot: Snapshot) -> None:
    evtx_path = f"C:\\R1\\raw\\{RUN_ID}\\telemetry\\sysmon-0001.evtx"
    manifest = {
        "run_id": RUN_ID,
        "generated_at": "2026-10-19T01:13:25.000Z",
        "items": [
            {
                "raw_log_id": "RAW-001",
                "path": evtx_path,
                "sha256": sha256_hex((snapshot.canonical_root / "sysmon-0001.evtx").read_bytes()),
                "layer": "raw_telemetry",
                "source": "sysmon",
            },
            {
                "raw_log_id": "RAW-002",
                "path": f"C:\\R1\\raw\\{RUN_ID}\\telemetry\\sysmon-0001.jsonl",
                "sha256": sha256_hex((snapshot.canonical_root / "sysmon-0001.jsonl").read_bytes()),
                "layer": "raw_telemetry",
                "source": "sysmon",
                "derived_from": evtx_path,
            },
        ],
    }
    (snapshot.canonical_root / "manifest.json").write_bytes(
        json.dumps(manifest, indent=2).encode() + b"\n"
    )


def target_identity_sha256() -> str:
    """Stand-in for the Target-A digest of host/channel/RecordId/EventId/raw-XML lines."""

    return snapshot_identity_sha256(
        tuple(
            f"{HOST_ID}\t{CHANNEL}\t{record_id}\t{event_id}\t{record_id:064x}"
            for record_id, event_id, *_ in _RECORDS
        )
    )


def _write_snapshot_artifacts(snapshot: Snapshot) -> None:
    common = {"request_id": f"{RUN_ID}-freeze-0001", "partition": partition().model_dump()}
    bound = {"source_lower_record_id": LOWER_RECORD_ID, "source_upper_record_id": UPPER_RECORD_ID}
    request = R1CollectionFreezeRequest.model_validate(
        {
            "schema": "r1-sysmon-collection-freeze-request",
            "contract_version": "v0.1",
            **common,
            "candidate_boundary_at": CANDIDATE_BOUNDARY_AT,
            "observation_boundary_at": OBSERVATION_BOUNDARY_AT,
            "requested_at": REQUESTED_AT,
        }
    )
    ack = R1CollectionFreezeAck.model_validate(
        {
            "schema": "r1-sysmon-collection-freeze-ack",
            "contract_version": "v0.1",
            **common,
            **bound,
            "target_event_ids": [1, 3],
            "target_event_count": len(_RECORDS),
            "target_identity_sha256": target_identity_sha256(),
            "covered_through_chunk_sequence": len(_SEGMENTS),
            "allowed_lateness_ms": 2000,
            "raw_segment_inventory_sha256": r1_raw_segment_inventory_sha256(
                snapshot.run_spool_root, len(_SEGMENTS)
            ),
            "acked_at": ACKED_AT,
        }
    )
    sources = snapshot.sources
    finalized = R1SysmonRunFinalized.model_validate(
        {
            "schema": "r1-sysmon-run-finalized",
            "contract_version": "v0.1",
            **common,
            **bound,
            "target_event_ids": [1, 3],
            "canonical_event_count": len(_RECORDS),
            "canonical_identity_sha256": target_identity_sha256(),
            "canonical_evtx_sha256": sha256_hex(sources.canonical_evtx_path.read_bytes()),
            "canonical_jsonl_sha256": sha256_hex(sources.canonical_jsonl_path.read_bytes()),
            "manifest_sha256": sha256_hex(sources.canonical_manifest_path.read_bytes()),
            "finalized_at": FINALIZED_AT,
        }
    )
    snapshot.control_root.mkdir(parents=True)
    for path, artifact in (
        (sources.freeze_request_path, request),
        (sources.freeze_ack_path, ack),
        (sources.run_finalized_path, finalized),
        (snapshot.freeze_generation_path, generation("freeze_ack", FREEZE_OBSERVED_AT)),
        (snapshot.export_generation_path, generation("after_canonical_export", EXPORT_OBSERVED_AT)),
    ):
        path.write_bytes(canonical_json_bytes(artifact.model_dump(mode="json", by_alias=True)))


def generation(
    phase: str,
    observed_at: datetime,
    **overrides: object,
) -> R1SysmonChannelGenerationObservation:
    payload: dict[str, object] = {
        "schema": "r1-sysmon-channel-generation-observation",
        "contract_version": "v0.1",
        "phase": phase,
        "request_id": f"{RUN_ID}-freeze-0001",
        "partition": partition().model_dump(),
        "source_lower_record_id": LOWER_RECORD_ID,
        "source_upper_record_id": UPPER_RECORD_ID,
        "lower_anchor_raw_xml_sha256": "1" * 64,
        "upper_anchor_raw_xml_sha256": "2" * 64,
        "oldest_record_number": 900,
        "log_creation_time_utc": datetime(2026, 10, 19, 0, 59, tzinfo=UTC),
        "observed_at": observed_at,
    }
    payload.update(overrides)
    return R1SysmonChannelGenerationObservation.model_validate(payload)


class _Cursor:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def fetchone(self) -> tuple[object, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._rows)


class FakeLedgerConnection:
    """In-memory stand-in for the Role3 tables a position close reads and writes."""

    def __init__(
        self,
        *,
        chunks: list[tuple[str, int, str]] | None = None,
        event_time_closed_runs: set[str] | None = None,
    ) -> None:
        self.chunks = list(chunks or [])
        self.event_time_closed_runs = set(event_time_closed_runs or set())
        self.position_closes: dict[str, tuple[object, ...]] = {}
        self._pending: dict[str, tuple[object, ...]] = {}
        self.commits = 0
        self.rollbacks = 0
        self.queries: list[str] = []

    @classmethod
    def with_snapshot_chunks(cls, snapshot: Snapshot) -> FakeLedgerConnection:
        rows = []
        for path in snapshot.chunk_paths:
            chunk = R1EventChunk.model_validate_json(path.read_bytes())
            rows.append((chunk.chunk_id, chunk.chunk_sequence, chunk.chunk_content_sha256))
        return cls(chunks=rows)

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.queries.append(query)
        if "pg_advisory_xact_lock" in query:
            return _Cursor([(None,)])
        if "INSERT INTO r1_stream_position_closes" in query:
            run_id = str(params[0])
            if run_id in self.position_closes or run_id in self._pending:
                return _Cursor([])
            ledger_entry_id = len(self.position_closes) + len(self._pending) + 1
            host_id, source, channel, close_id, content = params[1:6]
            accepted_at = params[10]
            self._pending[run_id] = (
                ledger_entry_id,
                close_id,
                host_id,
                source,
                channel,
                content,
                accepted_at,
            )
            return _Cursor([(ledger_entry_id,)])
        if "FROM r1_stream_position_closes" in query:
            run_id = str(params[0])
            row = self._pending.get(run_id) or self.position_closes.get(run_id)
            return _Cursor([row] if row else [])
        if "FROM r1_stream_run_closes" in query:
            return _Cursor([(1,)] if params[0] in self.event_time_closed_runs else [])
        if "FROM r1_stream_chunks" in query:
            limit = int(params[4])
            rows = sorted((row for row in self.chunks if row[1] <= limit), key=lambda row: row[1])
            return _Cursor(rows)
        raise AssertionError(f"unexpected query: {query}")

    def commit(self) -> None:
        self.position_closes.update(self._pending)
        self._pending.clear()
        self.commits += 1

    def rollback(self) -> None:
        self._pending.clear()
        self.rollbacks += 1


def refresh_finalized(snapshot: Snapshot, **overrides: object) -> None:
    """Rewrite run-finalized with current canonical digests plus ``overrides``."""

    path = snapshot.sources.run_finalized_path
    payload = snapshot.read_json(path)
    sources = snapshot.sources
    payload.update(
        {
            "canonical_evtx_sha256": sha256_hex(sources.canonical_evtx_path.read_bytes()),
            "canonical_jsonl_sha256": sha256_hex(sources.canonical_jsonl_path.read_bytes()),
            "manifest_sha256": sha256_hex(sources.canonical_manifest_path.read_bytes()),
        }
    )
    payload.update(overrides)
    snapshot.rewrite_json(path, payload)
