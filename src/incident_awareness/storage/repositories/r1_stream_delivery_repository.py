"""Persist and recover idempotent R1 incremental-stream deliveries."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from incident_awareness.common.models.r1_stream import (
    R1FinalPartitionWatermark,
    R1SourceWatermark,
    R1StreamPartition,
)


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_INSERT_CHUNK = """
INSERT INTO r1_stream_chunks (
    run_id, host_id, source, source_channel, chunk_id, chunk_sequence, content_sha256
)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT DO NOTHING
RETURNING chunk_id
"""
_SELECT_CHUNK_BY_ID = """
SELECT chunk_id, chunk_sequence, content_sha256
FROM r1_stream_chunks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND chunk_id = %s
"""
_SELECT_CHUNK_BY_SEQUENCE = """
SELECT chunk_id, chunk_sequence, content_sha256
FROM r1_stream_chunks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND chunk_sequence = %s
"""
_INSERT_EVENT = """
INSERT INTO r1_stream_events (
    run_id, host_id, source, source_channel, event_id, content_sha256
)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT DO NOTHING
RETURNING event_id
"""
_SELECT_EVENT_BY_ID = """
SELECT event_id, content_sha256
FROM r1_stream_events
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND event_id = %s
"""
_INSERT_WATERMARK = """
INSERT INTO r1_stream_watermarks (
    run_id, host_id, source, source_channel, watermark_id, watermark_sequence, content_sha256,
    watermark_at, allowed_lateness_ms, covered_through_chunk_sequence
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT DO NOTHING
RETURNING watermark_id
"""
_SELECT_WATERMARK_BY_ID = """
SELECT watermark_id, watermark_sequence, content_sha256
FROM r1_stream_watermarks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND watermark_id = %s
"""
_SELECT_WATERMARK_BINDING = """
SELECT watermark_id, watermark_sequence, watermark_at, allowed_lateness_ms,
       covered_through_chunk_sequence
FROM r1_stream_watermarks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND watermark_id = %s
"""
_SELECT_WATERMARK_BY_SEQUENCE = """
SELECT watermark_id, watermark_sequence, content_sha256
FROM r1_stream_watermarks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s AND watermark_sequence = %s
"""
_LOCK_WATERMARK_PARTITION = """
SELECT pg_advisory_xact_lock(
    hashtextextended(concat_ws(E'\\x1f', %s, %s, %s, %s), 0)
)
"""
_LOCK_RUN = """
SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))
"""
_SELECT_CLOSE_EXISTS = """
SELECT 1
FROM r1_stream_run_closes
WHERE run_id = %s
FOR KEY SHARE
"""
_SELECT_LATEST_WATERMARK_FOR_UPDATE = """
SELECT watermark_id, watermark_sequence, watermark_at, allowed_lateness_ms,
       covered_through_chunk_sequence
FROM r1_stream_watermarks
WHERE run_id = %s AND host_id = %s AND source = %s AND source_channel = %s
ORDER BY watermark_sequence DESC
LIMIT 1
FOR UPDATE
"""
_SELECT_WATERMARK_PARTITION_COUNT_FOR_RUN = """
SELECT COUNT(*)
FROM (
    SELECT 1
    FROM r1_stream_watermarks
    WHERE run_id = %s
    GROUP BY host_id, source, source_channel
) AS accepted_partitions
"""
_INSERT_CLOSE = """
INSERT INTO r1_stream_run_closes (run_id, close_id, content_sha256)
VALUES (%s, %s, %s)
ON CONFLICT DO NOTHING
RETURNING close_id
"""
_SELECT_CLOSE_BY_ID = """
SELECT close_id, content_sha256
FROM r1_stream_run_closes
WHERE run_id = %s AND close_id = %s
"""
_SELECT_CLOSE_BY_RUN = """
SELECT close_id, content_sha256
FROM r1_stream_run_closes
WHERE run_id = %s
"""


@dataclass(frozen=True, slots=True)
class R1StreamDelivery:
    """Identity and immutable content hash of one persisted delivery."""

    identity: str
    sequence: int | None
    content_sha256: str


@dataclass(frozen=True, slots=True)
class R1AcceptedWatermark:
    """The persisted source watermark values a final watermark must reproduce."""

    watermark_id: str
    watermark_sequence: int
    watermark_at: datetime
    allowed_lateness_ms: int
    covered_through_chunk_sequence: int


class R1StreamDeliveryRepository:
    """Append-only ledger used by a transactional stream worker.

    Each call returns ``True`` only for a first accepted message.  An exact replay
    returns ``False``; a reused identity or sequence with different content raises
    ``ValueError`` without changing the prior record.
    """

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save_chunk(
        self, *, partition: R1StreamPartition, chunk_id: str, sequence: int, content_sha256: str
    ) -> bool:
        inserted = self._connection.execute(
            _INSERT_CHUNK,
            (*_partition_params(partition), chunk_id, sequence, content_sha256),
        ).fetchone()
        if inserted is not None:
            return True
        return self._resolve_partition_conflict(
            select_by_id_query=_SELECT_CHUNK_BY_ID,
            select_by_sequence_query=_SELECT_CHUNK_BY_SEQUENCE,
            partition=partition,
            identity=chunk_id,
            sequence=sequence,
            content_sha256=content_sha256,
            label="chunk",
        )

    def save_events(
        self,
        *,
        partition: R1StreamPartition,
        event_content_sha256s: tuple[tuple[str, str], ...],
    ) -> None:
        """Persist immutable Event identities before their containing chunk.

        The caller commits this with the chunk ledger entry, so an Event conflict
        rolls back the new chunk rather than allowing conflicting Event content.
        """
        partition_params = _partition_params(partition)
        for event_id, content_sha256 in event_content_sha256s:
            inserted = self._connection.execute(
                _INSERT_EVENT,
                (*partition_params, event_id, content_sha256),
            ).fetchone()
            if inserted is not None:
                continue
            existing = self._row_to_delivery(
                self._connection.execute(
                    _SELECT_EVENT_BY_ID,
                    (*partition_params, event_id),
                ).fetchone(),
                label="event",
                has_sequence=False,
            )
            if existing is None:
                raise ValueError("event delivery conflicts with an unavailable ledger record")
            if existing.content_sha256 != content_sha256:
                raise ValueError("event identity conflicts with previously accepted content")

    def save_watermark(self, watermark: R1SourceWatermark, *, content_sha256: str) -> bool:
        partition_params = _partition_params(watermark.partition)
        self._lock_run(watermark.partition.run_id)
        if (
            self._connection.execute(_SELECT_CLOSE_EXISTS, (watermark.partition.run_id,)).fetchone()
            is not None
        ):
            raise ValueError("cannot accept a watermark after run_closed is accepted")
        # The advisory lock also serializes the first watermark, when no table row
        # exists yet. The caller owns the surrounding database transaction.
        self._connection.execute(_LOCK_WATERMARK_PARTITION, partition_params).fetchone()
        latest = self._accepted_watermark_from_row(
            self._connection.execute(
                _SELECT_LATEST_WATERMARK_FOR_UPDATE, partition_params
            ).fetchone()
        )
        existing_by_id = self._row_to_delivery(
            self._connection.execute(
                _SELECT_WATERMARK_BY_ID,
                (*partition_params, watermark.watermark_id),
            ).fetchone(),
            label="watermark",
            has_sequence=True,
        )
        if existing_by_id is not None:
            if (
                existing_by_id.sequence == watermark.watermark_sequence
                and existing_by_id.content_sha256 == content_sha256
            ):
                return False
            raise ValueError("watermark identity conflicts with previously accepted content")
        existing_by_sequence = self._row_to_delivery(
            self._connection.execute(
                _SELECT_WATERMARK_BY_SEQUENCE,
                (*partition_params, watermark.watermark_sequence),
            ).fetchone(),
            label="watermark",
            has_sequence=True,
        )
        if existing_by_sequence is not None:
            raise ValueError("watermark sequence conflicts with previously accepted identity")
        if latest is not None:
            if watermark.watermark_sequence <= latest.watermark_sequence:
                raise ValueError(
                    "watermark sequence must advance beyond the latest durable watermark"
                )
            if watermark.watermark_at < latest.watermark_at:
                raise ValueError(
                    "watermark_at must not move backwards from the latest durable watermark"
                )
            if watermark.allowed_lateness_ms != latest.allowed_lateness_ms:
                raise ValueError("allowed_lateness_ms must remain constant within a partition")
        inserted = self._connection.execute(
            _INSERT_WATERMARK,
            (
                *partition_params,
                watermark.watermark_id,
                watermark.watermark_sequence,
                content_sha256,
                watermark.watermark_at,
                watermark.allowed_lateness_ms,
                watermark.covered_through_chunk_sequence,
            ),
        ).fetchone()
        if inserted is not None:
            return True
        return self._resolve_partition_conflict(
            select_by_id_query=_SELECT_WATERMARK_BY_ID,
            select_by_sequence_query=_SELECT_WATERMARK_BY_SEQUENCE,
            partition=watermark.partition,
            identity=watermark.watermark_id,
            sequence=watermark.watermark_sequence,
            content_sha256=content_sha256,
            label="watermark",
        )

    def assert_final_watermarks_match(
        self, final_watermarks: tuple[R1FinalPartitionWatermark, ...]
    ) -> None:
        """Fail closed unless final references cover every latest partition watermark."""
        if not final_watermarks:
            raise ValueError("run close must contain at least one final watermark")
        run_ids = {watermark.partition.run_id for watermark in final_watermarks}
        if len(run_ids) != 1:
            raise ValueError("run close final watermarks must belong to one run")
        run_id = next(iter(run_ids))
        self._lock_run(run_id)
        for final_watermark in final_watermarks:
            partition_params = _partition_params(final_watermark.partition)
            existing = self._accepted_watermark_from_row(
                self._connection.execute(
                    _SELECT_LATEST_WATERMARK_FOR_UPDATE,
                    partition_params,
                ).fetchone()
            )
            if existing is None:
                raise ValueError(
                    "run close references a source watermark not accepted for its partition"
                )
            if existing != R1AcceptedWatermark(
                watermark_id=final_watermark.watermark_id,
                watermark_sequence=final_watermark.watermark_sequence,
                watermark_at=final_watermark.watermark_at,
                allowed_lateness_ms=final_watermark.allowed_lateness_ms,
                covered_through_chunk_sequence=final_watermark.covered_through_chunk_sequence,
            ):
                raise ValueError(
                    "run close final watermark does not match its latest accepted partition watermark"
                )
        partition_count = self._partition_count_from_row(
            self._connection.execute(
                _SELECT_WATERMARK_PARTITION_COUNT_FOR_RUN,
                (run_id,),
            ).fetchone()
        )
        if partition_count != len(final_watermarks):
            raise ValueError("run close final watermarks do not cover every accepted partition")

    def save_run_close(self, *, run_id: str, close_id: str, content_sha256: str) -> bool:
        self._lock_run(run_id)
        inserted = self._connection.execute(
            _INSERT_CLOSE, (run_id, close_id, content_sha256)
        ).fetchone()
        if inserted is not None:
            return True
        existing = self._row_to_delivery(
            self._connection.execute(_SELECT_CLOSE_BY_ID, (run_id, close_id)).fetchone(),
            label="run close",
            has_sequence=False,
        )
        if existing is not None:
            if existing.content_sha256 == content_sha256:
                return False
            raise ValueError("run close identity conflicts with previously accepted content")
        raise ValueError("run already has a different accepted close_id")

    def _lock_run(self, run_id: str) -> None:
        """Serialize watermark and close transitions for one Run until commit."""
        self._connection.execute(_LOCK_RUN, (run_id,)).fetchone()

    def _resolve_partition_conflict(
        self,
        *,
        select_by_id_query: str,
        select_by_sequence_query: str,
        partition: R1StreamPartition,
        identity: str,
        sequence: int,
        content_sha256: str,
        label: str,
    ) -> bool:
        partition_params = _partition_params(partition)
        existing = self._row_to_delivery(
            self._connection.execute(select_by_id_query, (*partition_params, identity)).fetchone(),
            label=label,
            has_sequence=True,
        )
        if existing is not None:
            if existing.sequence == sequence and existing.content_sha256 == content_sha256:
                return False
            raise ValueError(f"{label} identity conflicts with previously accepted content")
        raise ValueError(f"{label} sequence conflicts with previously accepted identity")

    @staticmethod
    def _accepted_watermark_from_row(row: tuple[object, ...] | None) -> R1AcceptedWatermark | None:
        if row is None:
            return None
        if len(row) != 5:
            raise TypeError("watermark binding row has an invalid column count")
        (
            watermark_id,
            sequence,
            watermark_at,
            allowed_lateness_ms,
            covered_through_chunk_sequence,
        ) = row
        if not isinstance(watermark_id, str) or not watermark_id.strip():
            raise TypeError("watermark binding identity must be a non-blank string")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise TypeError("watermark binding sequence must be a positive integer")
        if not isinstance(watermark_at, datetime):
            raise TypeError("watermark binding watermark_at must be a datetime")
        if isinstance(allowed_lateness_ms, bool) or not isinstance(allowed_lateness_ms, int):
            raise TypeError("watermark binding allowed_lateness_ms must be an integer")
        if (
            isinstance(covered_through_chunk_sequence, bool)
            or not isinstance(covered_through_chunk_sequence, int)
            or covered_through_chunk_sequence < 1
        ):
            raise TypeError("watermark binding covered_through_chunk_sequence must be positive")
        return R1AcceptedWatermark(
            watermark_id=watermark_id,
            watermark_sequence=sequence,
            watermark_at=watermark_at,
            allowed_lateness_ms=allowed_lateness_ms,
            covered_through_chunk_sequence=covered_through_chunk_sequence,
        )

    @staticmethod
    def _partition_count_from_row(row: tuple[object, ...] | None) -> int:
        if row is None or len(row) != 1:
            raise TypeError("watermark partition count row has an invalid column count")
        count = row[0]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise TypeError("watermark partition count must be a non-negative integer")
        return count

    @staticmethod
    def _row_to_delivery(
        row: tuple[object, ...] | None, *, label: str, has_sequence: bool
    ) -> R1StreamDelivery | None:
        if row is None:
            return None
        expected_columns = 3 if has_sequence else 2
        if len(row) != expected_columns:
            raise TypeError(f"{label} ledger row has an invalid column count")
        identity = row[0]
        content_sha256 = row[-1]
        if not isinstance(identity, str) or not identity.strip():
            raise TypeError(f"{label} ledger identity must be a non-blank string")
        if not isinstance(content_sha256, str) or len(content_sha256) != 64:
            raise TypeError(f"{label} ledger content_sha256 must be a SHA-256 string")
        sequence = row[1] if has_sequence else None
        if has_sequence and (
            isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
        ):
            raise TypeError(f"{label} ledger sequence must be a positive integer")
        return R1StreamDelivery(identity=identity, sequence=sequence, content_sha256=content_sha256)


def _partition_params(partition: R1StreamPartition) -> tuple[str, str, str, str]:
    return (partition.run_id, partition.host_id, partition.source, partition.source_channel)


__all__ = ["R1AcceptedWatermark", "R1StreamDelivery", "R1StreamDeliveryRepository"]
