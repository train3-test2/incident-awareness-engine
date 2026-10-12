from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1LateEventDeadLetter,
    R1SourceWatermark,
)
from incident_awareness.pipeline.r1_stream_boundary import LateStreamEventError, R1LateEventGuard


def _event(event_id: str, timestamp: str) -> dict[str, object]:
    return {
        "event_id": event_id,
        "run_id": "RUN-20261012-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "record_time": None,
        "ingest_time": None,
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": event_id.removeprefix("evt-"),
        "event_type": "process_create",
        "raw_ref": {"raw_log_id": "RAW-001", "segment_no": 1, "record_no": 1},
    }


def _partition(*, host_id: str = "WIN-01") -> dict[str, str]:
    return {
        "run_id": "RUN-20261012-001",
        "host_id": host_id,
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
    }


def _chunk(*, events: list[dict[str, object]], chunk_id: str = "CHK-001") -> R1EventChunk:
    return R1EventChunk.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "event_chunk",
            "chunk_id": chunk_id,
            "partition": _partition(),
            "chunk_sequence": 1,
            "chunk_content_sha256": "a" * 64,
            "event_contract_version": "v0.3",
            "events": events,
        }
    )


def _watermark(*, host_id: str = "WIN-01", **updates: object) -> R1SourceWatermark:
    payload: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "source_watermark",
        "watermark_id": "WM-001",
        "partition": _partition(host_id=host_id),
        "watermark_sequence": 1,
        "watermark_at": "2026-10-12T01:02:03.456Z",
        "allowed_lateness_ms": 30_000,
        "covered_through_chunk_sequence": 1,
        "emitted_at": "2026-10-12T01:02:04.000Z",
    }
    payload.update(updates)
    return R1SourceWatermark.model_validate(payload)


class _DeadLetterSink:
    def __init__(self) -> None:
        self.messages: list[R1LateEventDeadLetter] = []

    def write(self, dead_letter: R1LateEventDeadLetter) -> None:
        self.messages.append(dead_letter)


def _guard(sink: _DeadLetterSink) -> R1LateEventGuard:
    return R1LateEventGuard(
        sink,
        clock=lambda: datetime(2026, 10, 12, 1, 2, 5, 123456, tzinfo=UTC),
    )


def test_rejects_the_entire_chunk_and_writes_a_dead_letter_for_events_at_watermark() -> None:
    sink = _DeadLetterSink()
    guard = _guard(sink)
    guard.accept_watermark(_watermark())

    with pytest.raises(LateStreamEventError, match="CHK-001"):
        guard.accept_chunk(
            _chunk(
                events=[
                    _event("evt-at-watermark", "2026-10-12T01:02:03.456Z"),
                    _event("evt-after-watermark", "2026-10-12T01:02:03.457Z"),
                ]
            )
        )

    assert len(sink.messages) == 1
    dead_letter = sink.messages[0]
    assert dead_letter.violating_event_ids == ("evt-at-watermark",)
    assert dead_letter.rejected_at == datetime(2026, 10, 12, 1, 2, 5, 123000, tzinfo=UTC)


def test_accepts_an_event_strictly_after_the_watermark() -> None:
    sink = _DeadLetterSink()
    guard = _guard(sink)
    guard.accept_watermark(_watermark())

    guard.accept_chunk(_chunk(events=[_event("evt-after", "2026-10-12T01:02:03.457Z")]))

    assert sink.messages == []


def test_does_not_apply_a_watermark_to_another_partition() -> None:
    sink = _DeadLetterSink()
    guard = _guard(sink)
    guard.accept_watermark(_watermark(host_id="WIN-02"))

    guard.accept_chunk(_chunk(events=[_event("evt-before", "2026-10-12T01:02:03.000Z")]))

    assert sink.messages == []


def test_accepts_an_exact_watermark_duplicate_without_changing_the_frontier() -> None:
    sink = _DeadLetterSink()
    guard = _guard(sink)
    watermark = _watermark()
    guard.accept_watermark(watermark)
    guard.accept_watermark(watermark)

    with pytest.raises(LateStreamEventError, match="WM-001"):
        guard.accept_chunk(_chunk(events=[_event("evt-before", "2026-10-12T01:02:03.000Z")]))


@pytest.mark.parametrize(
    ("updated_watermark", "error"),
    (
        (
            {
                "watermark_id": "WM-000",
                "watermark_sequence": 1,
                "watermark_at": "2026-10-12T01:02:02.000Z",
            },
            "watermark sequence",
        ),
        (
            {
                "watermark_id": "WM-002",
                "watermark_sequence": 3,
                "watermark_at": "2026-10-12T01:02:02.000Z",
            },
            "watermark_at",
        ),
        (
            {"watermark_id": "WM-002", "watermark_sequence": 3, "allowed_lateness_ms": 0},
            "allowed_lateness_ms",
        ),
        ({"watermark_id": "WM-002", "watermark_sequence": 2}, "watermark sequence"),
        ({"emitted_at": "2026-10-12T01:02:05.000Z"}, "watermark sequence"),
    ),
)
def test_rejects_conflicting_watermark_without_regressing_the_current_frontier(
    updated_watermark: dict[str, object], error: str
) -> None:
    sink = _DeadLetterSink()
    guard = _guard(sink)
    guard.accept_watermark(_watermark(watermark_sequence=2))

    with pytest.raises(ValueError, match=error):
        guard.accept_watermark(_watermark(**updated_watermark))

    with pytest.raises(LateStreamEventError, match="WM-001"):
        guard.accept_chunk(_chunk(events=[_event("evt-before", "2026-10-12T01:02:03.000Z")]))


def test_propagates_dead_letter_write_failure_without_accepting_the_late_chunk() -> None:
    class _FailingDeadLetterSink:
        def write(self, dead_letter: R1LateEventDeadLetter) -> None:
            raise OSError("DLQ unavailable")

    guard = R1LateEventGuard(
        _FailingDeadLetterSink(),
        clock=lambda: datetime(2026, 10, 12, 1, 2, 5, tzinfo=UTC),
    )
    guard.accept_watermark(_watermark())

    with pytest.raises(OSError, match="DLQ unavailable"):
        guard.accept_chunk(_chunk(events=[_event("evt-before", "2026-10-12T01:02:03.000Z")]))
