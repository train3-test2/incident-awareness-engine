"""Persist and recover R1 Sysmon RecordId position closes in the Role3 ledger.

The ledger accepts a position close only when every covered chunk sequence is already a
committed ``r1_stream_chunks`` row and the ordered covered chunk list matches the close.

Position finality and event-time finality may both exist for one Run.  This ledger never
reads or writes the event-time watermark or ``run_closed`` tables, so an event-time close
neither blocks nor stands in for a position close, and the reverse holds as well.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from incident_awareness.common.models.r1_record_position_close import (
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
    covered_chunk_list_sha256,
    record_position_close_sha256,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...

    def fetchall(self) -> list[tuple[object, ...]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


# The same key as the event-time stream ledger, so chunk acceptance and a position close
# of one Run are serialized by one advisory lock.
_LOCK_RUN = """
SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))
"""
_SELECT_POSITION_CLOSE_BY_RUN = """
SELECT ledger_entry_id, close_id, host_id, source, source_channel, content_sha256, accepted_at
FROM r1_stream_position_closes
WHERE run_id = %s
"""
_SELECT_COVERED_CHUNKS = """
SELECT chunk_id, chunk_sequence, content_sha256
FROM r1_stream_chunks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s
  AND chunk_sequence <= %s
ORDER BY chunk_sequence
FOR KEY SHARE
"""
_INSERT_POSITION_CLOSE = """
INSERT INTO r1_stream_position_closes (
    run_id, host_id, source, source_channel, close_id, content_sha256,
    lower_record_id, upper_record_id, covered_through_chunk_sequence, covered_chunks_sha256,
    accepted_at
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT DO NOTHING
RETURNING ledger_entry_id
"""


@dataclass(frozen=True, slots=True)
class R1PositionCloseAdmission:
    """``accepted`` is ``False`` for an exact replay of an already committed close."""

    accepted: bool
    receipt: R1AcceptedRecordPositionCloseReceipt


class R1PositionCloseRepository:
    """Append-only position-close ledger used inside the caller's DB transaction."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save_position_close(
        self,
        close: R1RecordPositionClose,
        *,
        content_sha256: str,
        accepted_at: datetime,
    ) -> R1PositionCloseAdmission:
        """Record a first close, return the stored receipt for an exact replay, or fail."""

        if not isinstance(close, R1RecordPositionClose):
            raise TypeError("close must be an R1RecordPositionClose")
        if content_sha256 != record_position_close_sha256(close):
            raise ValueError("content_sha256 does not match the canonical position close")
        partition = close.partition
        self._connection.execute(_LOCK_RUN, (close.run_id,)).fetchone()

        existing = self.load_accepted_position_close_receipt(close.run_id)
        if existing is not None:
            return R1PositionCloseAdmission(False, _resolve_replay(existing, close))
        self._require_committed_covered_chunks(close)

        inserted = self._connection.execute(
            _INSERT_POSITION_CLOSE,
            (
                *_partition_params(partition),
                close.close_id,
                content_sha256,
                close.position_frontier.lower_record_id,
                close.position_frontier.upper_record_id,
                close.covered_through_chunk_sequence,
                close.covered_chunks_sha256,
                accepted_at,
            ),
        ).fetchone()
        if inserted is None:
            concurrent = self.load_accepted_position_close_receipt(close.run_id)
            if concurrent is None:
                raise ValueError("position close conflicts with an unavailable ledger record")
            return R1PositionCloseAdmission(False, _resolve_replay(concurrent, close))
        ledger_entry_id = _positive_integer(inserted[0] if len(inserted) == 1 else None)
        receipt = _receipt(
            run_id=close.run_id,
            close_id=close.close_id,
            partition=partition,
            close_content_sha256=content_sha256,
            ledger_entry_id=ledger_entry_id,
            accepted_at=accepted_at,
        )
        return R1PositionCloseAdmission(True, receipt)

    def load_accepted_position_close_receipt(
        self,
        run_id: str,
    ) -> R1AcceptedRecordPositionCloseReceipt | None:
        """Read the committed acceptance of a Run's position close, if any."""

        if not isinstance(run_id, str) or not run_id.strip() or run_id != run_id.strip():
            raise ValueError("run_id must be a non-blank, unpadded string")
        row = self._connection.execute(_SELECT_POSITION_CLOSE_BY_RUN, (run_id,)).fetchone()
        if row is None:
            return None
        if len(row) != 7:
            raise TypeError("position close ledger row has an invalid column count")
        ledger_entry_id, close_id, host_id, source, source_channel, content_sha256, accepted = row
        if not all(isinstance(value, str) for value in (close_id, host_id, source, source_channel)):
            raise TypeError("position close ledger identity columns must be strings")
        if not isinstance(content_sha256, str):
            raise TypeError("position close ledger content_sha256 must be a string")
        if not isinstance(accepted, datetime):
            raise TypeError("position close ledger accepted_at must be a datetime")
        return _receipt(
            run_id=run_id,
            close_id=str(close_id),
            partition=R1StreamPartition(
                run_id=run_id,
                host_id=str(host_id),
                source=str(source),
                source_channel=str(source_channel),
            ),
            close_content_sha256=content_sha256,
            ledger_entry_id=_positive_integer(ledger_entry_id),
            accepted_at=accepted,
        )

    def _require_committed_covered_chunks(self, close: R1RecordPositionClose) -> None:
        rows = self._connection.execute(
            _SELECT_COVERED_CHUNKS,
            (*_partition_params(close.partition), close.covered_through_chunk_sequence),
        ).fetchall()
        entries: list[tuple[int, str, str]] = []
        for row in rows:
            if len(row) != 3:
                raise TypeError("chunk ledger row has an invalid column count")
            chunk_id, sequence, chunk_sha256 = row
            if not isinstance(chunk_id, str) or not isinstance(chunk_sha256, str):
                raise TypeError("chunk ledger identity and digest must be strings")
            entries.append((_positive_integer(sequence), chunk_id, chunk_sha256))
        sequences = [sequence for sequence, _, _ in entries]
        if sequences != list(range(1, close.covered_through_chunk_sequence + 1)):
            raise ValueError("Role3 ledger has a gap in the covered chunk sequence")
        if covered_chunk_list_sha256(entries) != close.covered_chunks_sha256:
            raise ValueError("Role3 ledger chunks do not match the position close")


def _resolve_replay(
    existing: R1AcceptedRecordPositionCloseReceipt,
    close: R1RecordPositionClose,
) -> R1AcceptedRecordPositionCloseReceipt:
    if existing.close_id != close.close_id:
        raise ValueError("run already has a different accepted position close")
    if existing.partition != close.partition:
        raise ValueError("position close identity conflicts with another partition")
    if existing.close_content_sha256 != record_position_close_sha256(close):
        raise ValueError("position close identity conflicts with previously accepted content")
    return existing


def _receipt(
    *,
    run_id: str,
    close_id: str,
    partition: R1StreamPartition,
    close_content_sha256: str,
    ledger_entry_id: int,
    accepted_at: datetime,
) -> R1AcceptedRecordPositionCloseReceipt:
    if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
        raise TypeError("position close accepted_at must be timezone-aware")
    return R1AcceptedRecordPositionCloseReceipt.model_validate(
        {
            "schema": "r1-record-position-close-receipt",
            "contract_version": "v0.1",
            "run_id": run_id,
            "close_id": close_id,
            "partition": partition.model_dump(mode="json"),
            "close_content_sha256": close_content_sha256,
            "ledger_entry_id": ledger_entry_id,
            "accepted_at": accepted_at.astimezone(UTC),
        }
    )


def _positive_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TypeError("ledger integer column must be a positive integer")
    return value


def _partition_params(partition: R1StreamPartition) -> tuple[str, str, str, str]:
    return (partition.run_id, partition.host_id, partition.source, partition.source_channel)


__all__ = [
    "R1PositionCloseAdmission",
    "R1PositionCloseRepository",
]
