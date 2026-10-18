"""SQL-level contract of the Role3 position-close ledger."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_GUARANTEE,
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
    R1RecordPositionClose,
    covered_chunk_list_sha256,
    record_position_close_sha256,
)
from incident_awareness.storage.repositories.r1_position_close_repository import (
    R1PositionCloseRepository,
)

RUN_ID = "RUN-20261019-002"
ACCEPTED_AT = datetime(2026, 10, 19, 1, 14, 2, tzinfo=UTC)
CHUNKS = ((1, f"{RUN_ID}-sysmon-00000001", "a" * 64), (2, f"{RUN_ID}-sysmon-00000002", "b" * 64))
PARTITION = {
    "run_id": RUN_ID,
    "host_id": "R1-TGTA",
    "source": "sysmon",
    "source_channel": "Microsoft-Windows-Sysmon/Operational",
}


def _close(**overrides: object) -> R1RecordPositionClose:
    payload: dict[str, object] = {
        "schema": "r1-record-position-close",
        "contract_version": "v0.1",
        "message_type": "record_position_close",
        "close_id": f"{RUN_ID}-record-position-close-v0.1",
        "run_id": RUN_ID,
        "partition": PARTITION,
        "required_partition_contract": {"target_host": "R1-TGTA", "content_sha256": "c" * 64},
        "position_frontier": {
            "finality_kind": "sysmon_record_id_position",
            "lower_record_id": 1001,
            "upper_record_id": 1006,
            "target_event_ids": [1, 3],
            "channel_generation_id": "d" * 64,
        },
        "covered_through_chunk_sequence": 2,
        "covered_chunks_sha256": covered_chunk_list_sha256(CHUNKS),
        "post_commit_ack_count": 2,
        "event_count": 4,
        "source_native_identity_sha256": "e" * 64,
        "live_identity_sha256": "f" * 64,
        "canonical_identity_sha256": "f" * 64,
        "source_snapshot": {
            "request_id": f"{RUN_ID}-freeze-0001",
            "freeze_request_sha256": "1" * 64,
            "freeze_ack_sha256": "2" * 64,
            "run_finalized_sha256": "3" * 64,
            "reconciliation_sha256": "4" * 64,
            "freeze_generation_observation_sha256": "5" * 64,
            "export_generation_observation_sha256": "6" * 64,
        },
        "candidate_boundary_at": "2026-10-19T01:12:00.000Z",
        "observation_boundary_at": "2026-10-19T01:13:00.000Z",
        "emitted_at": "2026-10-19T01:14:01.000Z",
        "guarantee": R1_RECORD_POSITION_FINALITY_GUARANTEE,
        "non_guarantees": list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES),
    }
    payload.update(overrides)
    return R1RecordPositionClose.model_validate(payload)


def _stored_row(close: R1RecordPositionClose, content: str | None = None) -> tuple[object, ...]:
    return (
        7,
        close.close_id,
        "R1-TGTA",
        "sysmon",
        "Microsoft-Windows-Sysmon/Operational",
        content or record_position_close_sha256(close),
        ACCEPTED_AT,
    )


class _Cursor:
    def __init__(self, result: object) -> None:
        self._result = result

    def fetchone(self) -> tuple[object, ...] | None:
        if isinstance(self._result, list):
            return self._result[0] if self._result else None
        return self._result  # type: ignore[return-value]

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._result) if isinstance(self._result, list) else []


class _Connection:
    """Answer each statement from a queue of scripted results."""

    def __init__(self, *results: object) -> None:
        self._results = list(results)
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))
        return _Cursor(self._results.pop(0))


def _chunk_rows() -> list[tuple[object, ...]]:
    return [(chunk_id, sequence, digest) for sequence, chunk_id, digest in CHUNKS]


def test_records_a_first_close_under_the_run_lock_after_ledger_checks() -> None:
    close = _close()
    connection = _Connection((None,), None, _chunk_rows(), (41,))

    admission = R1PositionCloseRepository(connection).save_position_close(
        close, content_sha256=record_position_close_sha256(close), accepted_at=ACCEPTED_AT
    )

    queries = [query for query, _ in connection.statements]
    assert "pg_advisory_xact_lock" in queries[0]
    assert "FROM r1_stream_position_closes" in queries[1]
    assert "FROM r1_stream_chunks" in queries[2] and "FOR KEY SHARE" in queries[2]
    assert "INSERT INTO r1_stream_position_closes" in queries[3]
    assert "ON CONFLICT DO NOTHING" in queries[3]
    assert len(queries) == 4
    assert connection.statements[0][1] == (RUN_ID,)
    assert admission.accepted
    assert admission.receipt.ledger_entry_id == 41
    assert admission.receipt.accepted_at == ACCEPTED_AT
    assert not any("r1_stream_watermarks" in query for query in queries)
    assert not any("r1_stream_run_closes" in query for query in queries)


def test_exact_replay_returns_the_committed_receipt_without_writing() -> None:
    close = _close()
    connection = _Connection((None,), _stored_row(close))

    admission = R1PositionCloseRepository(connection).save_position_close(
        close,
        content_sha256=record_position_close_sha256(close),
        accepted_at=datetime(2026, 10, 19, 2, 0, tzinfo=UTC),
    )

    assert not admission.accepted
    assert admission.receipt.ledger_entry_id == 7
    assert admission.receipt.accepted_at == ACCEPTED_AT
    assert len(connection.statements) == 2


def test_same_close_id_with_other_content_fails_closed() -> None:
    close = _close()
    connection = _Connection((None,), _stored_row(close, content="9" * 64))

    with pytest.raises(ValueError, match="conflicts with previously accepted content"):
        R1PositionCloseRepository(connection).save_position_close(
            close, content_sha256=record_position_close_sha256(close), accepted_at=ACCEPTED_AT
        )


def test_concurrent_insert_conflict_resolves_to_the_stored_receipt() -> None:
    close = _close()
    connection = _Connection((None,), None, _chunk_rows(), None, _stored_row(close))

    admission = R1PositionCloseRepository(connection).save_position_close(
        close, content_sha256=record_position_close_sha256(close), accepted_at=ACCEPTED_AT
    )

    assert not admission.accepted
    assert admission.receipt.ledger_entry_id == 7


def test_content_digest_must_be_the_canonical_close_digest() -> None:
    with pytest.raises(ValueError, match="does not match the canonical position close"):
        R1PositionCloseRepository(_Connection()).save_position_close(
            _close(), content_sha256="0" * 64, accepted_at=ACCEPTED_AT
        )


@pytest.mark.parametrize(
    "rows",
    [
        [(f"{RUN_ID}-sysmon-00000002", 2, "b" * 64)],
        [(f"{RUN_ID}-sysmon-00000001", 1, "a" * 64)],
        [(f"{RUN_ID}-sysmon-00000001", 1, "a" * 64), (f"{RUN_ID}-sysmon-00000003", 3, "b" * 64)],
    ],
)
def test_ledger_gap_in_covered_chunks_fails_closed(rows) -> None:
    connection = _Connection((None,), None, rows)

    with pytest.raises(ValueError, match="gap in the covered chunk sequence"):
        R1PositionCloseRepository(connection).save_position_close(
            _close(),
            content_sha256=record_position_close_sha256(_close()),
            accepted_at=ACCEPTED_AT,
        )


def test_malformed_ledger_rows_fail_closed() -> None:
    connection = _Connection((7, "close", "R1-TGTA", "sysmon", "channel", "a" * 64, "not-a-time"))

    with pytest.raises(TypeError, match="accepted_at must be a datetime"):
        R1PositionCloseRepository(connection).load_accepted_position_close_receipt(RUN_ID)
    with pytest.raises(TypeError, match="positive integer"):
        R1PositionCloseRepository(
            _Connection((0, "close", "R1-TGTA", "sysmon", "channel", "a" * 64, ACCEPTED_AT))
        ).load_accepted_position_close_receipt(RUN_ID)


def test_absent_close_has_no_receipt() -> None:
    assert (
        R1PositionCloseRepository(_Connection(None)).load_accepted_position_close_receipt(RUN_ID)
        is None
    )
