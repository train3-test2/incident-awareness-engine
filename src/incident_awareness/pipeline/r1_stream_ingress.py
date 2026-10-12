"""Transactional idempotency boundary for future R1 incremental-stream workers."""

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1RunClosed,
    R1SourceWatermark,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1StreamDeliveryRepository,
)


class R1StreamDeliveryDisposition(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class R1StreamDeliveryResult:
    """The worker can commit either result and acknowledge the transport message."""

    disposition: R1StreamDeliveryDisposition


class R1StreamIngress:
    """Record a stream message exactly once within the caller's DB transaction.

    A worker must commit its database transaction before acknowledging SQS (or a
    future transport).  If it dies before commit, no ledger state is durable and
    the retry is accepted; if it dies after commit, the retry becomes a duplicate.
    This boundary intentionally does not alter the existing whole-JSONL #228 path.
    """

    def __init__(self, ledger: R1StreamDeliveryRepository) -> None:
        self._ledger = ledger

    def accept_chunk(self, chunk: R1EventChunk) -> R1StreamDeliveryResult:
        accepted = self._ledger.save_chunk(
            partition=chunk.partition,
            chunk_id=chunk.chunk_id,
            sequence=chunk.chunk_sequence,
            content_sha256=chunk.chunk_content_sha256,
        )
        return _result(accepted)

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


def _result(accepted: bool) -> R1StreamDeliveryResult:
    return R1StreamDeliveryResult(
        R1StreamDeliveryDisposition.ACCEPTED if accepted else R1StreamDeliveryDisposition.DUPLICATE
    )


def _canonical_sha256(message: R1SourceWatermark | R1RunClosed) -> str:
    payload = message.model_dump(mode="json", by_alias=True)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["R1StreamDeliveryDisposition", "R1StreamDeliveryResult", "R1StreamIngress"]
