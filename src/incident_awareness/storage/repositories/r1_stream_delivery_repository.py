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

    def save_watermark(self, watermark: R1SourceWatermark, *, content_sha256: str) -> bool:
        partition_params = _partition_params(watermark.partition)
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
        """Fail closed unless every final watermark exactly matches its partition record."""
        for final_watermark in final_watermarks:
            partition_params = _partition_params(final_watermark.partition)
            existing = self._accepted_watermark_from_row(
                self._connection.execute(
                    _SELECT_WATERMARK_BINDING,
                    (*partition_params, final_watermark.watermark_id),
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
                    "run close final watermark does not match its accepted partition watermark"
                )

    def save_run_close(self, *, run_id: str, close_id: str, content_sha256: str) -> bool:
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
