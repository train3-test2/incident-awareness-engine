from collections import Counter
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)


def test_normalizes_every_committed_sysmon_sample_record() -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    context = SysmonNormalizationContext(
        run_id="RUN-20260912-001",
        raw_log_id="RAW-SYSMON-SAMPLE-001",
        segment_no=1,
    )

    events = []
    for record in read_sysmon_jsonl(sample_path):
        event_id = record.data["EventId"]
        if event_id == 1:
            events.append(normalize_sysmon_process_create(record, context=context))
        elif event_id == 3:
            events.append(normalize_sysmon_network_connection(record, context=context))
        else:
            raise AssertionError(f"Unexpected EventId in committed Sysmon sample: {event_id}")

    assert len(events) == 7
    assert Counter(event.event_type for event in events) == {
        "process_create": 4,
        "network_connection": 3,
    }
    assert [event.source_event_id for event in events] == [
        "3389",
        "3390",
        "3391",
        "3392",
        "3393",
        "3394",
        "3395",
    ]

    for record, event in zip(read_sysmon_jsonl(sample_path), events, strict=True):
        assert event.raw_ref.record_no == record.record_no
        assert event.raw_ref.source_record_id == str(record.data["RecordId"])
        assert event.timestamp == event.event_time
        assert event.timestamp_source == "event_time"
