"""R1 incremental stream에서 watermark 뒤 Event를 fail-closed로 거부한다."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1LateEventDeadLetter,
    R1SourceWatermark,
    R1StreamPartition,
)


class R1StreamDeadLetterSink(Protocol):
    """Stream transport가 제공하는 durable dead-letter writer 경계."""

    def write(self, dead_letter: R1LateEventDeadLetter) -> None: ...


class LateStreamEventError(ValueError):
    """새 Event가 이미 선언된 source watermark보다 늦게 도착했다."""


@dataclass(frozen=True, slots=True)
class _AcceptedWatermark:
    watermark_id: str
    watermark_sequence: int
    watermark_at: datetime
    allowed_lateness_ms: int
    covered_through_chunk_sequence: int
    emitted_at: datetime


class R1LateEventGuard:
    """수락한 watermark 이하의 새 Event chunk 전체를 거부한다.

    이 클래스는 transport 내구성이나 재전달 dedup ledger를 소유하지 않는다. caller는
    durable sink를 제공해야 하고, 이후 recovery 계층이 동일 chunk 재전달을 분리한다.
    다만 같은 process 안에서 앞선 watermark identity가 재전달된 경우에는 frontier를
    되돌리지 않고 exact replay로만 허용한다.
    """

    def __init__(
        self,
        dead_letter_sink: R1StreamDeadLetterSink,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._dead_letter_sink = dead_letter_sink
        self._clock = clock
        self._watermarks: dict[tuple[str, str, str, str], _AcceptedWatermark] = {}
        self._watermarks_by_identity: dict[
            tuple[tuple[str, str, str, str], str], _AcceptedWatermark
        ] = {}

    def accept_watermark(self, watermark: R1SourceWatermark) -> None:
        """Advance one partition frontier without permitting regression or mutation."""
        partition_key = _partition_key(watermark.partition)
        accepted = _AcceptedWatermark(
            watermark_id=watermark.watermark_id,
            watermark_sequence=watermark.watermark_sequence,
            watermark_at=watermark.watermark_at,
            allowed_lateness_ms=watermark.allowed_lateness_ms,
            covered_through_chunk_sequence=watermark.covered_through_chunk_sequence,
            emitted_at=watermark.emitted_at,
        )
        identity_key = (partition_key, watermark.watermark_id)
        accepted_by_identity = self._watermarks_by_identity.get(identity_key)
        if accepted_by_identity is not None:
            if accepted == accepted_by_identity:
                return
            raise ValueError("watermark identity conflicts with previously accepted content")
        existing = self._watermarks.get(partition_key)
        if existing is None:
            self._watermarks[partition_key] = accepted
            self._watermarks_by_identity[identity_key] = accepted
            return
        if accepted.watermark_sequence <= existing.watermark_sequence:
            raise ValueError(
                "watermark sequence must increase unless the watermark is an exact duplicate"
            )
        if accepted.watermark_at < existing.watermark_at:
            raise ValueError("watermark_at must not move backwards")
        if accepted.allowed_lateness_ms != existing.allowed_lateness_ms:
            raise ValueError("allowed_lateness_ms must remain constant within a partition")
        self._watermarks[partition_key] = accepted
        self._watermarks_by_identity[identity_key] = accepted

    def accept_chunk(self, chunk: R1EventChunk) -> None:
        """Accept a chunk only when none of its Events are at or before the frontier."""
        watermark = self._watermarks.get(_partition_key(chunk.partition))
        if watermark is None:
            return

        violating_event_ids = tuple(
            event.event_id for event in chunk.events if event.timestamp <= watermark.watermark_at
        )
        if not violating_event_ids:
            return

        dead_letter = R1LateEventDeadLetter(
            schema="r1-incremental-stream-dead-letter",
            contract_version="v0.1",
            message_type="late_event",
            chunk_id=chunk.chunk_id,
            partition=chunk.partition,
            watermark_id=watermark.watermark_id,
            watermark_at=watermark.watermark_at,
            violating_event_ids=violating_event_ids,
            rejected_at=_utc_milliseconds(self._clock()),
        )
        self._dead_letter_sink.write(dead_letter)
        raise LateStreamEventError(
            f"chunk {chunk.chunk_id!r} contains Event(s) at or before watermark "
            f"{watermark.watermark_id!r}"
        )


def _partition_key(partition: R1StreamPartition) -> tuple[str, str, str, str]:
    return (
        partition.run_id,
        partition.host_id,
        partition.source,
        partition.source_channel,
    )


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)
