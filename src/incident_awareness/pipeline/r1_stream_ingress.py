"""Transactional idempotency boundary for future R1 incremental-stream workers."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1LateEventDeadLetter,
    R1RunClosed,
    R1SourceWatermark,
)
from incident_awareness.pipeline.r1_stream_boundary import (
    LateStreamEventError,
    R1StreamDeadLetterSink,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedWatermark,
    R1StreamDeliveryRepository,
)


class R1StreamDeliveryDisposition(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class R1StreamDeliveryResult:
    """The worker can commit either result and forward only newly accepted Events."""

    disposition: R1StreamDeliveryDisposition
    new_event_ids: tuple[str, ...] = ()


class R1StreamIngress:
    """Record a stream message exactly once within the caller's DB transaction.

    A worker must commit its database transaction before acknowledging SQS (or a
    future transport).  If it dies before commit, no ledger state is durable and
    the retry is accepted; if it dies after commit, the retry becomes a duplicate.
    This boundary intentionally does not alter the existing whole-JSONL #228 path.
    """

    def __init__(
        self,
        ledger: R1StreamDeliveryRepository,
        *,
        dead_letter_sink: R1StreamDeadLetterSink,
        clock: Callable[[], datetime],
    ) -> None:
        self._ledger = ledger
        self._dead_letter_sink = dead_letter_sink
        self._clock = clock

    def accept_chunk(self, chunk: R1EventChunk) -> R1StreamDeliveryResult:
        content_sha256 = _canonical_sha256(chunk)
        if content_sha256 != chunk.chunk_content_sha256:
            raise ValueError("chunk_content_sha256 does not match the canonical chunk payload")
        event_content_sha256s = tuple(
            (event.event_id, _canonical_event_sha256(event)) for event in chunk.events
        )
        admission = self._ledger.inspect_chunk_admission(
            partition=chunk.partition,
            chunk_id=chunk.chunk_id,
            sequence=chunk.chunk_sequence,
            content_sha256=content_sha256,
            event_content_sha256s=event_content_sha256s,
        )
        if admission.is_exact_chunk_replay:
            return _result(False)
        self._reject_late_events(
            chunk,
            admission.new_event_ids,
            admission.latest_watermark,
        )
        new_event_ids = self._ledger.save_events(
            partition=chunk.partition,
            event_content_sha256s=event_content_sha256s,
        )
        accepted = self._ledger.save_chunk(
            partition=chunk.partition,
            chunk_id=chunk.chunk_id,
            sequence=chunk.chunk_sequence,
            content_sha256=content_sha256,
        )
        return _result(accepted, new_event_ids=new_event_ids)

    def _reject_late_events(
        self,
        chunk: R1EventChunk,
        new_event_ids: tuple[str, ...],
        latest_watermark: R1AcceptedWatermark | None,
    ) -> None:
        if latest_watermark is None:
            return
        violating_event_ids = tuple(
            event.event_id
            for event in chunk.events
            if event.event_id in new_event_ids and event.timestamp <= latest_watermark.watermark_at
        )
        if not violating_event_ids:
            return
        self._dead_letter_sink.write(
            R1LateEventDeadLetter(
                schema="r1-incremental-stream-dead-letter",
                contract_version="v0.1",
                message_type="late_event",
                chunk_id=chunk.chunk_id,
                partition=chunk.partition,
                watermark_id=latest_watermark.watermark_id,
                watermark_at=latest_watermark.watermark_at,
                violating_event_ids=violating_event_ids,
                rejected_at=_utc_milliseconds(self._clock()),
            )
        )
        raise LateStreamEventError(
            f"chunk {chunk.chunk_id!r} contains Event(s) at or before watermark "
            f"{latest_watermark.watermark_id!r}"
        )

    def accept_watermark(self, watermark: R1SourceWatermark) -> R1StreamDeliveryResult:
        accepted = self._ledger.save_watermark(
            watermark, content_sha256=_canonical_sha256(watermark)
        )
        return _result(accepted)

    def accept_run_closed(self, run_closed: R1RunClosed) -> R1StreamDeliveryResult:
        self._ledger.assert_final_watermarks_match(run_closed.final_watermarks)
        accepted = self._ledger.save_run_close(
            run_id=run_closed.run_id,
            close_id=run_closed.close_id,
            content_sha256=_canonical_sha256(run_closed),
        )
        return _result(accepted)


def _result(accepted: bool, *, new_event_ids: tuple[str, ...] = ()) -> R1StreamDeliveryResult:
    return R1StreamDeliveryResult(
        R1StreamDeliveryDisposition.ACCEPTED if accepted else R1StreamDeliveryDisposition.DUPLICATE,
        new_event_ids,
    )


def _canonical_sha256(message: R1EventChunk | R1SourceWatermark | R1RunClosed) -> str:
    payload = message.model_dump(mode="json", by_alias=True)
    if isinstance(message, R1EventChunk):
        del payload["chunk_content_sha256"]
    return _canonical_payload_sha256(payload)


def r1_stream_message_sha256(
    message: R1EventChunk | R1SourceWatermark | R1RunClosed,
) -> str:
    """Return the canonical content digest used by the durable Role3 ledger."""

    return _canonical_sha256(message)


def _canonical_event_sha256(event: NormalizedEvent) -> str:
    return _canonical_payload_sha256(event.model_dump(mode="json", by_alias=True))


def _canonical_payload_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


__all__ = [
    "R1StreamDeliveryDisposition",
    "R1StreamDeliveryResult",
    "R1StreamIngress",
    "r1_stream_message_sha256",
]
