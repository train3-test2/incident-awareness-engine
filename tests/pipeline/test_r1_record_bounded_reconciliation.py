"""RecordId-bounded snapshot reconciliation and position-close issuance."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import r1_position_finality_fixture as fixture

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1RecordBoundedReconciliation,
    R1RecordBoundedSnapshotError,
    canonical_json_bytes,
    load_r1_snapshot_artifact,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_GUARANTEE,
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
)
from incident_awareness.common.models.r1_stream import R1EventChunk
from incident_awareness.pipeline.r1_record_bounded_reconciliation import (
    _chunk_event_identity,
    r1_raw_segment_inventory_sha256,
    reconcile_r1_record_bounded_snapshot,
    verify_r1_record_bounded_reconciliation,
    verify_r1_record_bounded_snapshot,
)
from incident_awareness.pipeline.r1_record_position_finality import (
    issue_r1_record_position_close,
)
from incident_awareness.pipeline.r1_stream_ingress import r1_stream_message_sha256


def _issue(snapshot: fixture.Snapshot):
    return issue_r1_record_position_close(
        sources=snapshot.sources,
        reconciliation_path=snapshot.reconciliation_path,
        freeze_generation_path=snapshot.freeze_generation_path,
        export_generation_path=snapshot.export_generation_path,
        clock=lambda: fixture.CLOSE_EMITTED_AT,
    )


def test_reconciles_a_verified_snapshot_without_any_watermark_claim(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)

    reconciliation, _ = load_r1_snapshot_artifact(
        snapshot.reconciliation_path, R1RecordBoundedReconciliation
    )

    assert reconciliation.status == "verified_snapshot_delivery"
    assert reconciliation.live_event_count == reconciliation.canonical_event_count == 4
    assert reconciliation.covered_through_chunk_sequence == 2
    assert reconciliation.post_commit_ack_count == 2
    assert reconciliation.observation_boundary_at == fixture.OBSERVATION_BOUNDARY_AT
    serialized = snapshot.reconciliation_path.read_text(encoding="utf-8")
    for forbidden in ("watermark_at", "run_closed", "available_at"):
        assert forbidden not in serialized


def test_issues_a_position_close_bound_to_every_snapshot_artifact(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)

    close = _issue(snapshot)

    assert close.close_id == f"{fixture.RUN_ID}-record-position-close-v0.1"
    assert close.partition == fixture.partition()
    assert close.position_frontier.finality_kind == "sysmon_record_id_position"
    assert (close.position_frontier.lower_record_id, close.position_frontier.upper_record_id) == (
        fixture.LOWER_RECORD_ID,
        fixture.UPPER_RECORD_ID,
    )
    assert close.position_frontier.target_event_ids == (1, 3)
    assert close.covered_through_chunk_sequence == close.post_commit_ack_count == 2
    assert close.event_count == 4
    assert close.required_partition_contract.target_host == fixture.HOST_ID
    assert close.candidate_boundary_at == fixture.CANDIDATE_BOUNDARY_AT
    assert close.observation_boundary_at == fixture.OBSERVATION_BOUNDARY_AT
    assert close.emitted_at == fixture.CLOSE_EMITTED_AT
    assert close.guarantee == R1_RECORD_POSITION_FINALITY_GUARANTEE
    assert close.non_guarantees == R1_RECORD_POSITION_FINALITY_NON_GUARANTEES
    source = close.source_snapshot
    assert len({source.freeze_request_sha256, source.freeze_ack_sha256}) == 2
    assert (
        source.reconciliation_sha256
        == load_r1_snapshot_artifact(snapshot.reconciliation_path, R1RecordBoundedReconciliation)[1]
    )


def test_chunk_sequence_gap_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    snapshot.chunk_paths[1].unlink()

    with pytest.raises(R1RecordBoundedSnapshotError, match="gap"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_missing_post_commit_ack_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    (snapshot.run_spool_root / "acks" / f"{snapshot.chunk_paths[0].name}.ack.json").unlink()

    with pytest.raises(R1RecordBoundedSnapshotError, match="post-commit Role3 ack"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_ack_that_no_longer_matches_the_chunk_bytes_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    path = snapshot.chunk_paths[0]
    path.write_bytes(path.read_bytes().replace(b'"chunk_sequence":1', b'"chunk_sequence":1 '))

    with pytest.raises(R1RecordBoundedSnapshotError, match="ack does not match"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_changed_recordid_bound_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    fixture.refresh_finalized(snapshot, source_upper_record_id=fixture.UPPER_RECORD_ID + 1)

    with pytest.raises(R1RecordBoundedSnapshotError, match="RecordId bound differs"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_canonical_record_outside_the_bound_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    path = snapshot.sources.canonical_jsonl_path
    path.write_bytes(path.read_bytes().replace(b'"RecordId": 1004', b'"RecordId": 1007'))
    fixture.write_manifest(snapshot)
    fixture.refresh_finalized(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match="outside the RecordId bound"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (b'"Computer": "R1-TGTA"', b'"Computer": "R1-TGTB"', "another host"),
        (
            b'"Channel": "Microsoft-Windows-Sysmon/Operational"',
            b'"Channel": "Microsoft-Windows-PowerShell/Operational"',
            "another channel",
        ),
    ],
)
def test_canonical_host_or_channel_change_fails_closed(tmp_path, old, new, message) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    path = snapshot.sources.canonical_jsonl_path
    path.write_bytes(path.read_bytes().replace(old, new, 1))
    fixture.write_manifest(snapshot)
    fixture.refresh_finalized(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match=message):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def _rewrite_live_channel_and_refresh_delivery(snapshot: fixture.Snapshot) -> None:
    segment = snapshot.run_spool_root / "raw-segments" / "sysmon-00000001.jsonl"
    records = [json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()]
    records[0]["Channel"] = "Microsoft-Windows-PowerShell/Operational"
    segment.write_bytes(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode()
    )
    fixture.publish_chunk(snapshot, 1)
    freeze_ack = snapshot.read_json(snapshot.sources.freeze_ack_path)
    freeze_ack["raw_segment_inventory_sha256"] = r1_raw_segment_inventory_sha256(
        snapshot.run_spool_root, 2
    )
    snapshot.rewrite_json(snapshot.sources.freeze_ack_path, freeze_ack)


def test_live_raw_channel_change_fails_after_inventory_chunk_and_ack_refresh(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    _rewrite_live_channel_and_refresh_delivery(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match="live raw segment.*another channel"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_covered_chunk_rejects_a_raw_record_from_another_channel(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    chunk = R1EventChunk.model_validate_json(snapshot.chunk_paths[0].read_bytes())
    records = [
        json.loads(line)
        for line in (snapshot.run_spool_root / "raw-segments" / "sysmon-00000001.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    records[0]["Channel"] = "Microsoft-Windows-PowerShell/Operational"

    with pytest.raises(R1RecordBoundedSnapshotError, match="raw record belongs to another channel"):
        _chunk_event_identity(chunk.events[0], chunk, {1: tuple(records)}, fixture.partition())


def test_contract_bound_to_another_host_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    fixture.write_contract(snapshot.contract_path, "R1-TGTB")

    with pytest.raises(R1RecordBoundedSnapshotError, match="does not bind the snapshot host"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_live_and_canonical_identity_digest_mismatch_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    fixture.refresh_finalized(snapshot, canonical_identity_sha256="f" * 64)

    with pytest.raises(R1RecordBoundedSnapshotError, match="identity digests differ"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_canonical_snapshot_missing_a_live_event_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    path = snapshot.sources.canonical_jsonl_path
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]) + lines[-1].replace(b"1004", b"1005", 1))
    fixture.write_manifest(snapshot)
    fixture.refresh_finalized(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_manifest_digest_that_differs_from_the_file_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    manifest = snapshot.read_json(snapshot.sources.canonical_manifest_path)
    manifest["items"][0]["sha256"] = "0" * 64
    snapshot.sources.canonical_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    fixture.refresh_finalized(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match="manifest digest"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_raw_segment_changed_after_the_freeze_ack_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    capture = snapshot.run_spool_root / "raw-segments" / "sysmon-00000001.jsonl.capture.json"
    capture.write_bytes(capture.read_bytes() + b" ")

    with pytest.raises(R1RecordBoundedSnapshotError, match="inventory"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_event_inside_the_bound_published_after_the_covered_chunks_fails_closed(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    # Republish the Events of segment 2 as chunk sequence 3: in-bound Events after the ack.
    original = R1EventChunk.model_validate_json(snapshot.chunk_paths[1].read_bytes())
    provisional = original.model_copy(
        update={"chunk_sequence": 3, "chunk_id": f"{fixture.RUN_ID}-sysmon-00000003"}
    )
    late = provisional.model_copy(
        update={"chunk_content_sha256": r1_stream_message_sha256(provisional)}
    )
    path = snapshot.run_spool_root / "outbox" / "000000000003-event_chunk.json"
    path.write_bytes(canonical_json_bytes(late.model_dump(mode="json", by_alias=True)))
    fixture.write_ack(snapshot, path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="published after the covered chunks"):
        verify_r1_record_bounded_snapshot(snapshot.sources)


def test_post_bound_chunks_are_reported_without_joining_the_snapshot(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    original = R1EventChunk.model_validate_json(snapshot.chunk_paths[1].read_bytes())
    event = original.events[0]
    after_bound = event.model_copy(
        update={
            "event_id": f"{event.event_id}-after-bound",
            "source_event_id": "1009",
            "raw_ref": event.raw_ref.model_copy(
                update={"source_record_id": "1009", "segment_no": 3}
            ),
        }
    )
    provisional = original.model_copy(
        update={
            "chunk_sequence": 3,
            "chunk_id": f"{fixture.RUN_ID}-sysmon-00000003",
            "events": (after_bound,),
        }
    )
    late = provisional.model_copy(
        update={"chunk_content_sha256": r1_stream_message_sha256(provisional)}
    )
    path = snapshot.run_spool_root / "outbox" / "000000000003-event_chunk.json"
    path.write_bytes(canonical_json_bytes(late.model_dump(mode="json", by_alias=True)))

    verified = verify_r1_record_bounded_snapshot(snapshot.sources)

    assert verified.post_bound_chunk_sequences == (3,)
    assert [chunk.chunk_sequence for chunk in verified.covered_chunks] == [1, 2]
    assert verified.event_count == 4


def test_tampered_reconciliation_artifact_is_rejected_by_the_issuer(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)
    payload = snapshot.read_json(snapshot.reconciliation_path)
    payload["live_event_count"] = payload["canonical_event_count"] = 5
    snapshot.rewrite_json(snapshot.reconciliation_path, payload)

    with pytest.raises(R1RecordBoundedSnapshotError, match="re-verified source artifacts"):
        _issue(snapshot)


def test_reconciliation_with_another_status_cannot_be_loaded(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)
    payload = snapshot.read_json(snapshot.reconciliation_path)
    payload["status"] = "verified_event_time_frontier"
    snapshot.rewrite_json(snapshot.reconciliation_path, payload)

    with pytest.raises(R1RecordBoundedSnapshotError, match="does not match"):
        verify_r1_record_bounded_reconciliation(snapshot.reconciliation_path, snapshot.sources)


def test_source_artifact_changed_after_reconciliation_is_rejected(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)
    fixture.refresh_finalized(snapshot, finalized_at="2026-10-19T01:13:31.000Z")

    with pytest.raises(R1RecordBoundedSnapshotError, match="re-verified source artifacts"):
        _issue(snapshot)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"upper_anchor_raw_xml_sha256": "3" * 64}, "generation changed"),
        ({"lower_anchor_raw_xml_sha256": "4" * 64}, "generation changed"),
        (
            {"log_creation_time_utc": datetime(2026, 10, 19, 1, 13, 10, tzinfo=UTC)},
            "generation changed",
        ),
        ({"oldest_record_number": 899}, "moved backwards"),
        ({"source_upper_record_id": fixture.UPPER_RECORD_ID + 1}, "another request, host"),
        ({"partition": {**fixture.partition().model_dump(), "host_id": "R1-TGTB"}}, "another"),
    ],
)
def test_channel_generation_or_anchor_change_blocks_the_close(tmp_path, overrides, message):
    snapshot = fixture.build_snapshot(tmp_path)
    observation = fixture.generation(
        "after_canonical_export", fixture.EXPORT_OBSERVED_AT, **overrides
    )
    snapshot.export_generation_path.write_bytes(
        canonical_json_bytes(observation.model_dump(mode="json", by_alias=True))
    )

    with pytest.raises(R1RecordBoundedSnapshotError, match=message):
        _issue(snapshot)


def test_generation_observed_outside_its_window_blocks_the_close(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)
    late = fixture.generation("freeze_ack", datetime(2026, 10, 19, 1, 13, 6, tzinfo=UTC))
    snapshot.freeze_generation_path.write_bytes(
        canonical_json_bytes(late.model_dump(mode="json", by_alias=True))
    )

    with pytest.raises(R1RecordBoundedSnapshotError, match="outside the freeze request and ack"):
        _issue(snapshot)


def test_close_cannot_precede_its_reconciliation(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="precede its reconciliation"):
        issue_r1_record_position_close(
            sources=snapshot.sources,
            reconciliation_path=snapshot.reconciliation_path,
            freeze_generation_path=snapshot.freeze_generation_path,
            export_generation_path=snapshot.export_generation_path,
            clock=lambda: datetime(2026, 10, 19, 1, 13, 59, tzinfo=UTC),
        )


def test_reconciliation_output_is_immutable(tmp_path) -> None:
    snapshot = fixture.build_snapshot(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="immutable path"):
        reconcile_r1_record_bounded_snapshot(
            snapshot.sources,
            output_path=snapshot.reconciliation_path,
            clock=lambda: datetime(2026, 10, 19, 1, 15, tzinfo=UTC),
        )
