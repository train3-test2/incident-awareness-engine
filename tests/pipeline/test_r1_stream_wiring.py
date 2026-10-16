from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.common.models.r1_required_partition import (
    load_r1_required_partition_contract,
)
from incident_awareness.pipeline import r1_stream_wiring as wiring
from incident_awareness.pipeline.r1_stream_wiring import (
    load_accepted_spool_message,
    load_close_export,
    publish_run_closed,
    publish_source_watermark,
    publish_sysmon_segment,
    render_required_partition_contract,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
    R1AcceptedWatermark,
    R1ChunkAdmission,
)

RUN_ID = "RUN-20300101-001"
HOST = "Target-A"
T0 = datetime(2030, 1, 1, tzinfo=UTC)


def _raw_record(record_id: int = 10) -> str:
    return (
        f'{{"RecordId":{record_id},"EventId":1,"Computer":"Target-A",'
        '"TimeCreated":"2030-01-01T00:00:01.000+00:00","Provider":"Sysmon",'
        '"EventData":{"UtcTime":"2030-01-01 00:00:01.000",'
        '"Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","ProcessId":"10",'
        '"ProcessGuid":"{11111111-1111-1111-1111-111111111111}",'
        '"ParentProcessId":"4","ParentProcessGuid":'
        '"{00000000-0000-0000-0000-000000000004}",'
        '"ParentImage":"C:\\\\Windows\\\\System32\\\\WmiPrvSE.exe"}}\n'
    )


class _Connection:
    def __init__(self) -> None:
        self.commits = 0

    def commit(self) -> None:
        self.commits += 1


class _Ledger:
    def __init__(self, _connection: object) -> None:
        self.chunks: dict[int, tuple[str, str]] = {}
        self.events: dict[str, str] = {}
        self.watermarks: dict[int, R1AcceptedWatermark] = {}
        self.close: R1AcceptedRunCloseReceipt | None = None

    def inspect_chunk_admission(
        self, *, partition, chunk_id, sequence, content_sha256, event_content_sha256s
    ):
        existing = self.chunks.get(sequence)
        if existing is not None:
            if existing != (chunk_id, content_sha256):
                raise ValueError("chunk sequence conflict")
            return R1ChunkAdmission(True, (), self._latest())
        if sequence != len(self.chunks) + 1:
            raise ValueError("chunk sequences must be contiguous")
        return R1ChunkAdmission(
            False, tuple(item[0] for item in event_content_sha256s), self._latest()
        )

    def save_events(self, *, partition, event_content_sha256s):
        result = []
        for event_id, digest in event_content_sha256s:
            if event_id in self.events and self.events[event_id] != digest:
                raise ValueError("event conflict")
            if event_id not in self.events:
                self.events[event_id] = digest
                result.append(event_id)
        return tuple(result)

    def save_chunk(self, *, partition, chunk_id, sequence, content_sha256):
        if sequence in self.chunks:
            return False
        self.chunks[sequence] = (chunk_id, content_sha256)
        return True

    def save_watermark(self, watermark, *, content_sha256):
        if watermark.covered_through_chunk_sequence not in self.chunks:
            raise ValueError("watermark covers a missing chunk")
        existing = self.watermarks.get(watermark.watermark_sequence)
        accepted = R1AcceptedWatermark(
            watermark.watermark_id,
            watermark.watermark_sequence,
            watermark.watermark_at,
            watermark.allowed_lateness_ms,
            watermark.covered_through_chunk_sequence,
        )
        if existing is not None:
            if existing != accepted:
                raise ValueError("watermark conflict")
            return False
        self.watermarks[watermark.watermark_sequence] = accepted
        return True

    def assert_final_watermarks_match(self, final_watermarks):
        latest = self._latest()
        assert latest is not None
        item = final_watermarks[0]
        if item.watermark_id != latest.watermark_id:
            raise ValueError("final watermark mismatch")

    def save_run_close(self, *, run_id, close_id, content_sha256):
        candidate = R1AcceptedRunCloseReceipt(run_id, close_id, content_sha256)
        if self.close is not None:
            if self.close != candidate:
                raise ValueError("close conflict")
            return False
        self.close = candidate
        return True

    def load_accepted_run_close_receipt(self, run_id):
        return self.close if self.close is not None and self.close.run_id == run_id else None

    def _latest(self):
        return self.watermarks[max(self.watermarks)] if self.watermarks else None


def _inputs(tmp_path: Path):
    contract_path = render_required_partition_contract(
        path=tmp_path / "required-partitions.json", target_host=HOST
    )
    contract = load_r1_required_partition_contract(contract_path, expected_target_host=HOST)
    raw = tmp_path / "segment.jsonl"
    raw.write_text(_raw_record(), encoding="utf-8")
    return contract_path, contract, raw


def test_producer_ingress_receipt_export_rehearsal(tmp_path, monkeypatch):
    # Given
    contract_path, contract, raw = _inputs(tmp_path)
    spool = tmp_path / "spool"
    times = iter(datetime(2030, 1, 1, 0, 0, second, tzinfo=UTC) for second in range(2, 20))
    chunk_path = publish_sysmon_segment(
        raw_jsonl=raw,
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        raw_log_id="raw-live",
        segment_no=1,
        chunk_sequence=1,
        message_ordinal=1,
        required_partition_contract=contract,
        clock=lambda: next(times),
    )
    watermark_path = publish_source_watermark(
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        watermark_sequence=1,
        covered_through_chunk_sequence=1,
        watermark_at=datetime(2030, 1, 1, 0, 0, 4, tzinfo=UTC),
        allowed_lateness_ms=2000,
        message_ordinal=2,
        required_partition_contract=contract,
        clock=lambda: next(times),
    )
    close_path = publish_run_closed(
        spool_root=spool,
        final_watermark_path=watermark_path,
        candidate_boundary_at=datetime(2030, 1, 1, 0, 0, 3, tzinfo=UTC),
        message_ordinal=3,
        clock=lambda: next(times),
    )
    ledger = _Ledger(object())
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda connection: ledger)
    connection = _Connection()

    # When
    accepted = wiring.consume_spool_once(
        spool_root=spool, contract=contract, connection=connection, clock=lambda: next(times)
    )
    export = wiring.export_accepted_close(
        spool_root=spool,
        accepted_run_closed_path=close_path,
        connection=connection,
        contract_path=contract_path,
    )
    run_closed, receipt = load_close_export(export)

    # Then
    assert accepted == (chunk_path, watermark_path, close_path)
    assert connection.commits == 3
    assert len(tuple((spool / "acks").glob("*.json"))) == 3
    accepted_chunk = load_accepted_spool_message(
        chunk_path,
        spool / "acks" / f"{chunk_path.name}.ack.json",
    )
    assert isinstance(accepted_chunk, wiring.R1EventChunk)
    assert run_closed.run_id == receipt.run_id == RUN_ID
    assert run_closed.close_id == receipt.close_id
    chunk = wiring.R1EventChunk.model_validate_json(chunk_path.read_bytes())
    assert chunk.events[0].ingest_time == datetime(2030, 1, 1, 0, 0, 2, tzinfo=UTC)
    assert chunk.events[0].raw_ref.segment_no == 1
    assert chunk.events[0].raw_ref.record_no == 1
    assert chunk.events[0].raw_ref.source_record_id == "10"


def test_exact_replay_after_ack_loss_is_duplicate(tmp_path, monkeypatch):
    _, contract, raw = _inputs(tmp_path)
    spool = tmp_path / "spool"
    path = publish_sysmon_segment(
        raw_jsonl=raw,
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        raw_log_id="raw-live",
        segment_no=1,
        chunk_sequence=1,
        message_ordinal=1,
        required_partition_contract=contract,
        clock=lambda: T0,
    )
    ledger = _Ledger(object())
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda connection: ledger)
    connection = _Connection()
    wiring.consume_spool_once(spool_root=spool, contract=contract, connection=connection)
    (spool / "acks" / f"{path.name}.ack.json").unlink()

    wiring.consume_spool_once(spool_root=spool, contract=contract, connection=connection)

    assert connection.commits == 2
    assert len(ledger.chunks) == 1


def test_missing_sequence_and_mutated_content_fail_closed(tmp_path, monkeypatch):
    _, contract, raw = _inputs(tmp_path)
    spool = tmp_path / "spool"
    publish_sysmon_segment(
        raw_jsonl=raw,
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        raw_log_id="raw-live",
        segment_no=2,
        chunk_sequence=2,
        message_ordinal=1,
        required_partition_contract=contract,
        clock=lambda: T0,
    )
    ledger = _Ledger(object())
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda connection: ledger)
    with pytest.raises(ValueError, match="contiguous"):
        wiring.consume_spool_once(spool_root=spool, contract=contract, connection=_Connection())

    chunk_path = next((spool / "outbox").glob("*.json"))
    text = chunk_path.read_text(encoding="utf-8").replace("cmd.exe", "evil.exe")
    chunk_path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="chunk_content_sha256"):
        wiring.consume_spool_once(spool_root=spool, contract=contract, connection=_Connection())


def test_target_host_binding_is_required(tmp_path):
    contract_path = render_required_partition_contract(
        path=tmp_path / "required.json", target_host=HOST
    )
    with pytest.raises(ValueError, match="target_host"):
        load_r1_required_partition_contract(contract_path, expected_target_host="Other-Host")


def test_role2_handoff_rejects_message_changed_after_role3_ack(tmp_path, monkeypatch):
    _, contract, raw = _inputs(tmp_path)
    spool = tmp_path / "spool"
    path = publish_sysmon_segment(
        raw_jsonl=raw,
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        raw_log_id="raw-live",
        segment_no=1,
        chunk_sequence=1,
        message_ordinal=1,
        required_partition_contract=contract,
        clock=lambda: T0,
    )
    ledger = _Ledger(object())
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda connection: ledger)
    wiring.consume_spool_once(spool_root=spool, contract=contract, connection=_Connection())
    ack = spool / "acks" / f"{path.name}.ack.json"
    path.write_text(
        path.read_text(encoding="utf-8").replace("cmd.exe", "evil.exe"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match"):
        load_accepted_spool_message(path, ack)


def test_close_requires_final_watermark_to_cover_candidate_boundary(tmp_path):
    _, contract, _ = _inputs(tmp_path)
    spool = tmp_path / "spool"
    watermark = publish_source_watermark(
        spool_root=spool,
        run_id=RUN_ID,
        host_id=HOST,
        watermark_sequence=1,
        covered_through_chunk_sequence=1,
        watermark_at=T0,
        allowed_lateness_ms=2000,
        message_ordinal=1,
        required_partition_contract=contract,
        clock=lambda: T0,
    )
    with pytest.raises(ValueError, match="must cover"):
        publish_run_closed(
            spool_root=spool,
            final_watermark_path=watermark,
            candidate_boundary_at=datetime(2030, 1, 1, 0, 0, 1, tzinfo=UTC),
            message_ordinal=2,
            clock=lambda: T0,
        )
