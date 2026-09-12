from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
)


@pytest.fixture
def normalization_context() -> SysmonNormalizationContext:
    return SysmonNormalizationContext(
        run_id="RUN-20260912-001",
        raw_log_id="RAW-SYSMON-SAMPLE-001",
        segment_no=1,
    )


def test_normalize_sysmon_network_connection_maps_event_id_3(
    normalization_context: SysmonNormalizationContext,
) -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    raw_record = next(
        record for record in read_sysmon_jsonl(sample_path) if record.data["RecordId"] == 3395
    )

    event = normalize_sysmon_network_connection(raw_record, context=normalization_context)

    assert event.event_id.startswith("evt-")
    assert event.run_id == "RUN-20260912-001"
    assert event.event_type == "network_connection"
    assert event.timestamp == datetime(2026, 9, 8, 16, 35, 35, 367000, tzinfo=UTC)
    assert event.timestamp_source == "event_time"
    assert event.event_time == event.timestamp
    assert event.record_time == datetime(2026, 9, 8, 16, 35, 36, 980000, tzinfo=UTC)
    assert event.host_id == "WIN-01"
    assert event.source == "sysmon"
    assert event.source_layer == "raw_telemetry"
    assert event.source_event_id == "3395"
    assert event.user == "WIN-01\\labuser"
    assert event.process is not None
    assert event.process.model_dump() == {
        "pid": 5544,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": None,
        "parent_pid": None,
        "parent_name": None,
    }
    assert event.network is not None
    assert event.network.model_dump() == {
        "protocol": "tcp",
        "src_ip": "192.168.9.129",
        "src_port": 62790,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
    }
    assert event.raw_ref.model_dump() == {
        "raw_log_id": "RAW-SYSMON-SAMPLE-001",
        "source_record_id": "3395",
        "segment_no": 1,
        "record_no": 7,
        "parser_id": "sysmon-normalizer",
        "parser_version": "v0.2",
    }


def test_normalize_sysmon_network_connection_rejects_non_event_id_3(
    normalization_context: SysmonNormalizationContext,
) -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    process_record = next(read_sysmon_jsonl(sample_path))

    with pytest.raises(ValueError, match="requires Sysmon Event ID 3"):
        normalize_sysmon_network_connection(process_record, context=normalization_context)
