from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.r1_stream import R1EventChunk, R1SourceWatermark


def _event(
    *, event_id: str = "evt-001", host_id: str = "WIN-01", source: str = "sysmon"
) -> dict[str, object]:
    timestamp = datetime(2026, 10, 12, 1, 2, 3, 456000, tzinfo=UTC)
    return {
        "event_id": event_id,
        "run_id": "RUN-20261012-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "record_time": None,
        "ingest_time": None,
        "host_id": host_id,
        "source": source,
        "source_layer": "raw_telemetry",
        "source_event_id": event_id.removeprefix("evt-"),
        "event_type": "process_create",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "segment_no": 1,
            "record_no": 1,
        },
    }


def _chunk(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "event_chunk",
        "chunk_id": "CHK-000001",
        "partition": {
            "run_id": "RUN-20261012-001",
            "host_id": "WIN-01",
            "source": "sysmon",
            "source_channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "chunk_sequence": 1,
        "chunk_content_sha256": "a" * 64,
        "event_contract_version": "v0.3",
        "events": [_event()],
    }
    value.update(updates)
    return value


def _watermark(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "source_watermark",
        "watermark_id": "WM-000001",
        "partition": _chunk()["partition"],
        "watermark_sequence": 1,
        "watermark_at": "2026-10-12T01:02:03.456Z",
        "covered_through_chunk_sequence": 1,
        "emitted_at": "2026-10-12T01:02:04.000Z",
    }
    value.update(updates)
    return value


def test_accepts_one_partition_scoped_normalized_event_chunk() -> None:
    chunk = R1EventChunk.model_validate(_chunk())

    assert chunk.chunk_id == "CHK-000001"
    assert chunk.events[0].event_id == "evt-001"
    assert chunk.model_dump(by_alias=True)["schema"] == "r1-incremental-stream"


def test_rejects_duplicate_event_identity_inside_a_chunk() -> None:
    payload = _chunk(events=[_event(), _event()])

    with pytest.raises(ValidationError, match="duplicate event_id"):
        R1EventChunk.model_validate(payload)


@pytest.mark.parametrize(
    ("event_update", "error"),
    [
        ({"run_id": "RUN-20261012-002"}, "Event run_id"),
        ({"host_id": "WIN-02"}, "Event host_id"),
        ({"source": "security"}, "Event source"),
    ],
)
def test_rejects_event_outside_the_chunk_partition(
    event_update: dict[str, str], error: str
) -> None:
    event = _event()
    event.update(event_update)

    with pytest.raises(ValidationError, match=error):
        R1EventChunk.model_validate(_chunk(events=[event]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "other-stream"),
        ("contract_version", "v0.2"),
        ("message_type", "watermark"),
        ("event_contract_version", "v0.2"),
        ("chunk_sequence", 0),
        ("chunk_content_sha256", "A" * 64),
        ("chunk_id", " CHK-000001"),
    ],
)
def test_rejects_unknown_contract_or_invalid_chunk_identity(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        R1EventChunk.model_validate(_chunk(**{field: value}))


def test_accepts_a_partition_scoped_source_watermark() -> None:
    watermark = R1SourceWatermark.model_validate(_watermark())

    assert watermark.watermark_at == datetime(2026, 10, 12, 1, 2, 3, 456000, tzinfo=UTC)
    assert watermark.covered_through_chunk_sequence == 1
    assert watermark.model_dump(by_alias=True)["message_type"] == "source_watermark"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("watermark_at", 0),
        ("watermark_at", "2026-10-12T10:02:03.456+09:00"),
        ("watermark_at", "2026-10-12T01:02:03.456789Z"),
        ("watermark_sequence", 0),
        ("watermark_id", " WM-000001"),
    ],
)
def test_rejects_invalid_source_watermark(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        R1SourceWatermark.model_validate(_watermark(**{field: value}))
