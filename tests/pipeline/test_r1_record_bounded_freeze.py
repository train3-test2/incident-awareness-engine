"""Producer-side freeze ack and channel-generation observation for the VM path."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import r1_position_finality_fixture as fixture

from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1CollectionFreezeAck,
    R1RecordBoundedSnapshotError,
    R1SysmonChannelGenerationObservation,
    load_r1_snapshot_artifact,
)
from incident_awareness.pipeline.r1_record_bounded_freeze import (
    issue_r1_channel_generation_observation,
    issue_r1_collection_freeze_ack,
    load_r1_freeze_request,
    main,
)
from incident_awareness.pipeline.r1_record_bounded_reconciliation import (
    r1_raw_segment_inventory_sha256,
    reconcile_r1_record_bounded_snapshot,
)
from incident_awareness.pipeline.r1_record_position_finality import (
    issue_r1_record_position_close,
)

TARGET_EVENT_COUNT = 4
COVERED_THROUGH = 2


def _prepared(tmp_path) -> fixture.Snapshot:
    """A synthetic Run whose producer-side freeze artifacts are written by this module."""

    snapshot = fixture.build_snapshot(tmp_path, reconcile=False)
    for path in (
        snapshot.sources.freeze_ack_path,
        snapshot.freeze_generation_path,
    ):
        path.unlink()
    return snapshot


def _request(
    snapshot: fixture.Snapshot, *, host_id: str = fixture.HOST_ID, run_id: str = fixture.RUN_ID
):
    return load_r1_freeze_request(
        snapshot.sources.freeze_request_path,
        expected_run_id=run_id,
        expected_host_id=host_id,
        required_partition_contract_path=snapshot.contract_path,
    )


def _ack(snapshot: fixture.Snapshot, **overrides: object) -> R1CollectionFreezeAck:
    arguments: dict[str, object] = {
        "run_spool_root": snapshot.run_spool_root,
        "request": _request(snapshot),
        "source_lower_record_id": fixture.LOWER_RECORD_ID,
        "source_upper_record_id": fixture.UPPER_RECORD_ID,
        "target_event_count": TARGET_EVENT_COUNT,
        "target_identity_sha256": fixture.target_identity_sha256(),
        "covered_through_chunk_sequence": COVERED_THROUGH,
        "allowed_lateness_ms": 2000,
        "output_path": snapshot.sources.freeze_ack_path,
        "clock": lambda: fixture.ACKED_AT,
    }
    arguments.update(overrides)
    return issue_r1_collection_freeze_ack(**arguments)


def _freeze_generation(snapshot: fixture.Snapshot, **overrides: object):
    arguments: dict[str, object] = {
        "phase": "freeze_ack",
        "request": _request(snapshot),
        "source_lower_record_id": fixture.LOWER_RECORD_ID,
        "source_upper_record_id": fixture.UPPER_RECORD_ID,
        "lower_anchor_raw_xml_sha256": "1" * 64,
        "upper_anchor_raw_xml_sha256": "2" * 64,
        "oldest_record_number": 900,
        "log_creation_time_utc": datetime(2026, 10, 19, 0, 59, tzinfo=UTC),
        "observed_at": fixture.FREEZE_OBSERVED_AT,
        "output_path": snapshot.freeze_generation_path,
    }
    arguments.update(overrides)
    return issue_r1_channel_generation_observation(**arguments)


def test_freeze_request_ack_export_finalized_path_reaches_a_position_close(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    _freeze_generation(snapshot)
    ack = _ack(snapshot)
    reconcile_r1_record_bounded_snapshot(
        snapshot.sources,
        output_path=snapshot.reconciliation_path,
        clock=lambda: fixture.RECONCILED_AT,
    )
    close = issue_r1_record_position_close(
        sources=snapshot.sources,
        reconciliation_path=snapshot.reconciliation_path,
        freeze_generation_path=snapshot.freeze_generation_path,
        export_generation_path=snapshot.export_generation_path,
        clock=lambda: fixture.CLOSE_EMITTED_AT,
    )

    assert ack.target_event_count == close.event_count == TARGET_EVENT_COUNT
    assert close.covered_through_chunk_sequence == COVERED_THROUGH
    assert (
        load_r1_snapshot_artifact(snapshot.sources.freeze_ack_path, R1CollectionFreezeAck)[0] == ack
    )


def test_both_ends_of_the_bound_are_inclusive(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    ack = _ack(snapshot, source_upper_record_id=1004)

    assert (ack.source_lower_record_id, ack.source_upper_record_id) == (1001, 1004)


def test_a_live_event_below_the_lower_bound_fails_closed(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="outside the RecordId bound"):
        _ack(snapshot, source_lower_record_id=1002)
    assert not snapshot.sources.freeze_ack_path.exists()


def test_a_bound_event_missing_from_the_live_segments_fails_closed(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="different Event counts"):
        _ack(snapshot, target_event_count=TARGET_EVENT_COUNT + 1)
    assert not snapshot.sources.freeze_ack_path.exists()


def test_a_post_bound_event_inside_a_covered_segment_fails_closed(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="outside the RecordId bound"):
        _ack(snapshot, source_upper_record_id=1003)


def test_chunk_sequence_gap_fails_closed(tmp_path) -> None:
    snapshot = _prepared(tmp_path)
    snapshot.chunk_paths[1].unlink()

    with pytest.raises(R1RecordBoundedSnapshotError, match="gap"):
        _ack(snapshot)


def test_missing_post_commit_ack_fails_closed(tmp_path) -> None:
    snapshot = _prepared(tmp_path)
    (snapshot.run_spool_root / "acks" / f"{snapshot.chunk_paths[1].name}.ack.json").unlink()

    with pytest.raises(R1RecordBoundedSnapshotError, match="post-commit Role3 ack"):
        _ack(snapshot)


@pytest.mark.parametrize(
    ("host_id", "run_id"),
    [("R1-TGTB", fixture.RUN_ID), (fixture.HOST_ID, "RUN-20261019-002")],
)
def test_request_for_another_host_or_run_is_rejected(tmp_path, host_id, run_id) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError):
        _request(snapshot, host_id=host_id, run_id=run_id)


def test_contract_for_another_host_is_rejected(tmp_path) -> None:
    snapshot = _prepared(tmp_path)
    fixture.write_contract(snapshot.contract_path, "R1-TGTB")

    with pytest.raises(R1RecordBoundedSnapshotError, match="does not bind the host"):
        _request(snapshot)


def test_generation_observation_before_the_request_is_rejected(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="cannot precede the request"):
        _freeze_generation(snapshot, observed_at=datetime(2026, 10, 19, 1, 13, tzinfo=UTC))


def test_generation_that_lost_the_lower_bound_is_rejected(tmp_path) -> None:
    snapshot = _prepared(tmp_path)

    with pytest.raises(R1RecordBoundedSnapshotError, match="invalid"):
        _freeze_generation(snapshot, oldest_record_number=fixture.LOWER_RECORD_ID + 1)


def test_ack_is_immutable_once_written(tmp_path) -> None:
    snapshot = _prepared(tmp_path)
    _ack(snapshot)

    with pytest.raises(R1RecordBoundedSnapshotError, match="immutable path"):
        _ack(snapshot, clock=lambda: datetime(2026, 10, 19, 1, 13, 6, tzinfo=UTC))


def test_cli_writes_the_same_artifacts(tmp_path) -> None:
    snapshot = _prepared(tmp_path)
    common = [
        "--request", str(snapshot.sources.freeze_request_path),
        "--run-id", fixture.RUN_ID,
        "--target-host", fixture.HOST_ID,
        "--required-partition-contract", str(snapshot.contract_path),
        "--lower", str(fixture.LOWER_RECORD_ID),
        "--upper", str(fixture.UPPER_RECORD_ID),
    ]  # fmt: skip

    assert main([
        "write-generation-observation", *common,
        "--output", str(snapshot.freeze_generation_path),
        "--phase", "freeze_ack",
        "--lower-anchor-raw-xml-sha256", "1" * 64,
        "--upper-anchor-raw-xml-sha256", "2" * 64,
        "--oldest-record-number", "900",
        "--log-creation-time-utc", "2026-10-19T00:59:00.000Z",
        "--observed-at", "2026-10-19T01:13:03.000Z",
    ]) == 0  # fmt: skip
    assert main([
        "write-freeze-ack", *common,
        "--output", str(snapshot.sources.freeze_ack_path),
        "--run-spool-root", str(snapshot.run_spool_root),
        "--target-event-count", str(TARGET_EVENT_COUNT),
        "--target-identity-sha256", fixture.target_identity_sha256(),
        "--covered-through-chunk-sequence", str(COVERED_THROUGH),
        "--allowed-lateness-ms", "2000",
    ]) == 0  # fmt: skip
    ack, _ = load_r1_snapshot_artifact(snapshot.sources.freeze_ack_path, R1CollectionFreezeAck)
    observation, _ = load_r1_snapshot_artifact(
        snapshot.freeze_generation_path, R1SysmonChannelGenerationObservation
    )

    assert ack.raw_segment_inventory_sha256 == r1_raw_segment_inventory_sha256(
        snapshot.run_spool_root, COVERED_THROUGH
    )
    assert ack.acked_at >= fixture.REQUESTED_AT
    assert observation == fixture.generation("freeze_ack", fixture.FREEZE_OBSERVED_AT)
