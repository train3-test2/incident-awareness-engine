from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed, R1SourceWatermark
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamDeliveryDisposition,
    R1StreamIngress,
)


class _Ledger:
    def __init__(self) -> None:
        self.accepted: set[tuple[str, str]] = set()

    def save_chunk(self, *, chunk_id: str, **_: object) -> bool:
        return self._save("chunk", chunk_id)

    def save_watermark(self, *, watermark_id: str, **_: object) -> bool:
        return self._save("watermark", watermark_id)

    def save_run_close(self, *, close_id: str, **_: object) -> bool:
        return self._save("close", close_id)

    def _save(self, kind: str, identity: str) -> bool:
        key = (kind, identity)
        if key in self.accepted:
            return False
        self.accepted.add(key)
        return True


def test_chunk_replay_is_a_duplicate_not_a_second_delivery() -> None:
    ingress = R1StreamIngress(_Ledger())  # type: ignore[arg-type]
    chunk = _chunk()

    assert ingress.accept_chunk(chunk).disposition is R1StreamDeliveryDisposition.ACCEPTED
    assert ingress.accept_chunk(chunk).disposition is R1StreamDeliveryDisposition.DUPLICATE


def test_watermark_and_close_replays_are_idempotent() -> None:
    ingress = R1StreamIngress(_Ledger())  # type: ignore[arg-type]

    assert (
        ingress.accept_watermark(_watermark()).disposition is R1StreamDeliveryDisposition.ACCEPTED
    )
    assert (
        ingress.accept_watermark(_watermark()).disposition is R1StreamDeliveryDisposition.DUPLICATE
    )
    assert ingress.accept_run_closed(_close()).disposition is R1StreamDeliveryDisposition.ACCEPTED
    assert ingress.accept_run_closed(_close()).disposition is R1StreamDeliveryDisposition.DUPLICATE


def _partition() -> dict[str, str]:
    return {
        "run_id": "RUN-20261012-001",
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
    }


def _chunk() -> R1EventChunk:
    return R1EventChunk.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "event_chunk",
            "chunk_id": "CHK-001",
            "partition": _partition(),
            "chunk_sequence": 1,
            "chunk_content_sha256": "a" * 64,
            "event_contract_version": "v0.3",
            "events": [
                {
                    "event_id": "evt-001",
                    "run_id": "RUN-20261012-001",
                    "timestamp": "2026-10-12T01:02:03.456Z",
                    "timestamp_source": "event_time",
                    "event_time": "2026-10-12T01:02:03.456Z",
                    "record_time": None,
                    "ingest_time": None,
                    "host_id": "WIN-01",
                    "source": "sysmon",
                    "source_layer": "raw_telemetry",
                    "source_event_id": "1",
                    "event_type": "process_create",
                    "raw_ref": {"raw_log_id": "RAW-001", "segment_no": 1, "record_no": 1},
                }
            ],
        }
    )


def _watermark() -> R1SourceWatermark:
    return R1SourceWatermark.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "source_watermark",
            "watermark_id": "WM-001",
            "partition": _partition(),
            "watermark_sequence": 1,
            "watermark_at": "2026-10-12T01:02:03.456Z",
            "allowed_lateness_ms": 0,
            "covered_through_chunk_sequence": 1,
            "emitted_at": "2026-10-12T01:02:04.000Z",
        }
    )


def _close() -> R1RunClosed:
    return R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": "CLOSE-001",
            "run_id": "RUN-20261012-001",
            "final_watermarks": [
                {
                    "partition": _partition(),
                    "watermark_id": "WM-001",
                    "watermark_sequence": 1,
                    "watermark_at": "2026-10-12T01:02:03.456Z",
                    "allowed_lateness_ms": 0,
                    "covered_through_chunk_sequence": 1,
                }
            ],
            "emitted_at": "2026-10-12T01:02:04.000Z",
        }
    )
