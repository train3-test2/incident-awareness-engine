"""Role3 acceptance, receipt export and the boundary to event-time stream finality."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import r1_position_finality_fixture as fixture
from pydantic import ValidationError

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1RecordBoundedSnapshotError,
    canonical_json_bytes,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1RecordPositionClose,
    record_position_close_sha256,
)
from incident_awareness.common.models.r1_required_partition import (
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1RunClosed, R1SourceWatermark
from incident_awareness.pipeline.r1_record_position_finality import (
    R1RecordPositionCloseIngress,
    consume_r1_record_position_close,
    export_r1_accepted_record_position_close,
    issue_r1_record_position_close,
    load_r1_accepted_record_position_close_export,
    position_close_ack_path,
    position_close_export_path,
    position_close_path,
    publish_r1_record_position_close,
)
from incident_awareness.storage.repositories.r1_position_close_repository import (
    R1PositionCloseRepository,
)

ACCEPTED_AT = datetime(2026, 10, 19, 1, 14, 2, tzinfo=UTC)


def _published(tmp_path):
    snapshot = fixture.build_snapshot(tmp_path)
    close = issue_r1_record_position_close(
        sources=snapshot.sources,
        reconciliation_path=snapshot.reconciliation_path,
        freeze_generation_path=snapshot.freeze_generation_path,
        export_generation_path=snapshot.export_generation_path,
        clock=lambda: fixture.CLOSE_EMITTED_AT,
    )
    publish_r1_record_position_close(close, snapshot.run_spool_root)
    return snapshot, close


def _contract(snapshot: fixture.Snapshot):
    return load_r1_required_partition_contract(
        snapshot.contract_path, expected_target_host=fixture.HOST_ID
    )


def _consume(snapshot, connection):
    return consume_r1_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        contract=_contract(snapshot),
        connection=connection,
        clock=lambda: ACCEPTED_AT,
    )


def test_role3_commit_then_ack_then_receipt_export(tmp_path) -> None:
    snapshot, close = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)

    assert _consume(snapshot, connection) == position_close_path(snapshot.run_spool_root)
    ack = json.loads(position_close_ack_path(snapshot.run_spool_root).read_text("utf-8"))
    export_path = export_r1_accepted_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        connection=connection,
        contract_path=snapshot.contract_path,
    )
    loaded_close, receipt = load_r1_accepted_record_position_close_export(
        export_path, contract_path=snapshot.contract_path
    )

    assert connection.commits == 1
    assert ack["disposition"] == "accepted"
    assert ack["ledger_entry_id"] == receipt.ledger_entry_id == 1
    assert loaded_close == close
    assert receipt.close_content_sha256 == record_position_close_sha256(close)
    assert receipt.accepted_at == ACCEPTED_AT
    assert export_path == (
        snapshot.run_spool_root / "exports" / fixture.RUN_ID / "accepted-record-position-close.json"
    )
    serialized = export_path.read_text(encoding="utf-8")
    for forbidden in ("available_at", "watermark_at", "final_watermarks", "run_closed"):
        assert forbidden not in serialized


def test_exact_redelivery_is_idempotent_and_keeps_the_committed_receipt(tmp_path) -> None:
    snapshot, close = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    first_ack = position_close_ack_path(snapshot.run_spool_root).read_bytes()

    assert _consume(snapshot, connection) is None
    position_close_ack_path(snapshot.run_spool_root).unlink()
    later = datetime(2026, 10, 19, 1, 20, tzinfo=UTC)
    consume_r1_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        contract=_contract(snapshot),
        connection=connection,
        clock=lambda: later,
    )
    second_ack = json.loads(position_close_ack_path(snapshot.run_spool_root).read_text("utf-8"))

    assert json.loads(first_ack)["ledger_entry_id"] == second_ack["ledger_entry_id"]
    assert second_ack["disposition"] == "duplicate"
    assert second_ack["accepted_at"] == "2026-10-19T01:14:02Z"
    assert len(connection.position_closes) == 1
    publish_r1_record_position_close(close, snapshot.run_spool_root)


def test_ledger_chunk_gap_rolls_back_without_an_ack(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    connection.chunks = [row for row in connection.chunks if row[1] != 2]

    with pytest.raises(ValueError, match="gap in the covered chunk sequence"):
        _consume(snapshot, connection)
    assert connection.rollbacks == 1
    assert not connection.position_closes
    assert not position_close_ack_path(snapshot.run_spool_root).exists()


def test_ledger_chunk_content_mismatch_fails_closed(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    chunk_id, sequence, _ = connection.chunks[0]
    connection.chunks[0] = (chunk_id, sequence, "e" * 64)

    with pytest.raises(ValueError, match="do not match the position close"):
        _consume(snapshot, connection)


def _export(snapshot, connection):
    return export_r1_accepted_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        connection=connection,
        contract_path=snapshot.contract_path,
    )


def test_event_time_close_first_then_position_close_keep_separate_meanings(tmp_path) -> None:
    snapshot, close = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    connection.event_time_closed_runs.add(fixture.RUN_ID)

    _consume(snapshot, connection)
    loaded_close, receipt = load_r1_accepted_record_position_close_export(
        _export(snapshot, connection), contract_path=snapshot.contract_path
    )

    assert loaded_close == close
    assert receipt.schema_id == "r1-record-position-close-receipt"
    assert loaded_close.position_frontier.finality_kind == "sysmon_record_id_position"
    assert "event_time_completeness" in loaded_close.non_guarantees
    assert not any("r1_stream_run_closes" in query for query in connection.queries)
    assert not any("r1_stream_watermarks" in query for query in connection.queries)


def test_position_close_first_then_event_time_close_keep_separate_meanings(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    first_export = _export(snapshot, connection).read_bytes()
    _, first_receipt = load_r1_accepted_record_position_close_export(
        position_close_export_path(snapshot.run_spool_root, fixture.RUN_ID),
        contract_path=snapshot.contract_path,
    )

    # A later event-time close is a separate v0.1 ledger record; the position ledger
    # neither reads it nor lets it change the committed position receipt.
    connection.event_time_closed_runs.add(fixture.RUN_ID)
    second_export = _export(snapshot, connection).read_bytes()
    _, second_receipt = load_r1_accepted_record_position_close_export(
        position_close_export_path(snapshot.run_spool_root, fixture.RUN_ID),
        contract_path=snapshot.contract_path,
    )

    assert first_export == second_export
    assert first_receipt == second_receipt
    assert not any("r1_stream_run_closes" in query for query in connection.queries)


def test_position_ingress_rejects_an_event_time_run_closed(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    run_closed = R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": f"{fixture.RUN_ID}-close-v0.1",
            "run_id": fixture.RUN_ID,
            "final_watermarks": [
                {
                    "partition": fixture.partition().model_dump(),
                    "watermark_id": f"{fixture.RUN_ID}-sysmon-watermark-00000001",
                    "watermark_sequence": 1,
                    "watermark_at": "2026-10-19T01:13:00.000Z",
                    "allowed_lateness_ms": 2000,
                    "covered_through_chunk_sequence": 2,
                }
            ],
            "emitted_at": "2026-10-19T01:14:00.000Z",
        }
    )
    ingress = R1RecordPositionCloseIngress(
        R1PositionCloseRepository(fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)),
        clock=lambda: ACCEPTED_AT,
    )

    with pytest.raises(TypeError, match="must be an R1RecordPositionClose"):
        ingress.accept(run_closed, contract=_contract(snapshot))
    with pytest.raises(ValidationError):
        R1RecordPositionClose.model_validate(run_closed.model_dump(mode="json", by_alias=True))


def test_same_close_id_with_different_payload_fails_closed(tmp_path) -> None:
    snapshot, close = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    changed = close.model_copy(update={"emitted_at": datetime(2026, 10, 19, 1, 14, 9, tzinfo=UTC)})
    ingress = R1RecordPositionCloseIngress(
        R1PositionCloseRepository(connection), clock=lambda: ACCEPTED_AT
    )

    with pytest.raises(ValueError, match="conflicts with previously accepted content"):
        ingress.accept(changed, contract=_contract(snapshot))
    with pytest.raises(R1RecordBoundedSnapshotError, match="immutable path"):
        publish_r1_record_position_close(changed, snapshot.run_spool_root)


def test_another_close_id_for_the_same_run_fails_closed(tmp_path) -> None:
    snapshot, close = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    other = close.model_copy(update={"close_id": f"{fixture.RUN_ID}-record-position-close-other"})
    ingress = R1RecordPositionCloseIngress(
        R1PositionCloseRepository(connection), clock=lambda: ACCEPTED_AT
    )

    with pytest.raises(ValueError, match="different accepted position close"):
        ingress.accept(other, contract=_contract(snapshot))


def test_required_partition_contract_mismatch_is_rejected(tmp_path) -> None:
    _, close = _published(tmp_path)
    other_path = tmp_path / "other-contract.json"
    fixture.write_contract(other_path, "R1-TGTB")
    other = load_r1_required_partition_contract(other_path, expected_target_host="R1-TGTB")
    ingress = R1RecordPositionCloseIngress(
        R1PositionCloseRepository(fixture.FakeLedgerConnection()), clock=lambda: ACCEPTED_AT
    )

    with pytest.raises(R1RecordBoundedSnapshotError, match="host does not match the contract"):
        ingress.accept(close, contract=other)


def test_export_contract_linkage_tampering_fails_closed(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    export_path = export_r1_accepted_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        connection=connection,
        contract_path=snapshot.contract_path,
    )
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    payload["required_partition_contract"]["sha256"] = "0" * 64
    export_path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(R1RecordBoundedSnapshotError, match="contract file digest mismatch"):
        load_r1_accepted_record_position_close_export(
            export_path, contract_path=snapshot.contract_path
        )


def test_role2_loader_uses_the_explicitly_delivered_contract_path(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    export_path = _export(snapshot, connection)
    delivered_root = tmp_path / "role2-delivery"
    delivered_root.mkdir()
    delivered_export = delivered_root / export_path.name
    delivered_contract = delivered_root / snapshot.contract_path.name
    delivered_export.write_bytes(export_path.read_bytes())
    delivered_contract.write_bytes(snapshot.contract_path.read_bytes())
    snapshot.contract_path.unlink()

    loaded_close, receipt = load_r1_accepted_record_position_close_export(
        delivered_export, contract_path=delivered_contract
    )

    assert loaded_close.run_id == fixture.RUN_ID
    assert receipt.close_id == loaded_close.close_id


def test_role2_loader_reports_the_missing_delivered_contract_path(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    export_path = _export(snapshot, connection)
    missing = tmp_path / "role2-delivery" / snapshot.contract_path.name

    with pytest.raises(R1RecordBoundedSnapshotError) as error:
        load_r1_accepted_record_position_close_export(export_path, contract_path=missing)
    assert str(missing) in str(error.value)


def test_export_requires_a_committed_receipt_and_its_ack(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match="post-commit ack"):
        export_r1_accepted_record_position_close(
            run_spool_root=snapshot.run_spool_root,
            connection=connection,
            contract_path=snapshot.contract_path,
        )
    _consume(snapshot, connection)
    connection.position_closes.clear()
    with pytest.raises(R1RecordBoundedSnapshotError, match="no accepted position close"):
        export_r1_accepted_record_position_close(
            run_spool_root=snapshot.run_spool_root,
            connection=connection,
            contract_path=snapshot.contract_path,
        )


def test_export_requires_the_ack_to_name_the_committed_ledger_entry(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    ack_path = position_close_ack_path(snapshot.run_spool_root)
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    ack["ledger_entry_id"] = 2
    ack_path.write_bytes(canonical_json_bytes(ack))

    with pytest.raises(R1RecordBoundedSnapshotError, match="committed ledger entry"):
        export_r1_accepted_record_position_close(
            run_spool_root=snapshot.run_spool_root,
            connection=connection,
            contract_path=snapshot.contract_path,
        )


def test_export_receipt_that_does_not_bind_the_close_fails_closed(tmp_path) -> None:
    snapshot, _ = _published(tmp_path)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    _consume(snapshot, connection)
    row = list(connection.position_closes[fixture.RUN_ID])
    row[5] = "d" * 64
    connection.position_closes[fixture.RUN_ID] = tuple(row)

    with pytest.raises(ValueError, match="does not match the close content"):
        export_r1_accepted_record_position_close(
            run_spool_root=snapshot.run_spool_root,
            connection=connection,
            contract_path=snapshot.contract_path,
        )


def test_position_close_cannot_be_read_as_an_event_time_message(tmp_path) -> None:
    _, close = _published(tmp_path)
    payload = close.model_dump(mode="json", by_alias=True)

    with pytest.raises(ValidationError):
        R1RunClosed.model_validate(payload)
    with pytest.raises(ValidationError):
        R1SourceWatermark.model_validate(payload)
    with pytest.raises(ValidationError):
        R1RecordPositionClose.model_validate(
            payload | {"watermark_at": payload["observation_boundary_at"]}
        )
    frontier = payload["position_frontier"] | {"finality_kind": "event_time_watermark"}
    with pytest.raises(ValidationError):
        R1RecordPositionClose.model_validate(payload | {"position_frontier": frontier})
    with pytest.raises(ValidationError):
        R1RecordPositionClose.model_validate(
            payload | {"non_guarantees": payload["non_guarantees"][1:]}
        )


def test_event_time_spool_consumer_rejects_a_position_close(tmp_path) -> None:
    pytest.importorskip("psycopg")
    from incident_awareness.pipeline import r1_stream_wiring

    snapshot, close = _published(tmp_path)
    outbox = snapshot.run_spool_root / "outbox"
    misplaced = outbox / "000000000099-record_position_close.json"
    misplaced.write_bytes(canonical_json_bytes(close.model_dump(mode="json", by_alias=True)))

    with pytest.raises(ValueError, match="unsupported spool message_type"):
        r1_stream_wiring.consume_spool_once(
            spool_root=snapshot.run_spool_root,
            contract=_contract(snapshot),
            connection=fixture.FakeLedgerConnection(),
        )
    ack = fixture.write_ack(snapshot, misplaced)
    with pytest.raises(ValueError, match="unsupported accepted spool message_type"):
        r1_stream_wiring.load_accepted_spool_message(misplaced, ack)
