from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_process_create,
)


@pytest.fixture
def normalization_context() -> SysmonNormalizationContext:
    return SysmonNormalizationContext(
        run_id="RUN-20260912-001",
        raw_log_id="RAW-SYSMON-SAMPLE-001",
        segment_no=1,
    )


def test_normalize_sysmon_process_create_maps_event_id_1(
    normalization_context: SysmonNormalizationContext,
) -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    raw_record = next(read_sysmon_jsonl(sample_path))

    event = normalize_sysmon_process_create(raw_record, context=normalization_context)

    assert event.event_id.startswith("evt-")
    assert event.run_id == "RUN-20260912-001"
    assert event.event_type == "process_create"
    assert event.timestamp == datetime(2026, 9, 8, 16, 35, 30, 816000, tzinfo=UTC)
    assert event.timestamp_source == "event_time"
    assert event.event_time == event.timestamp
    assert event.record_time == datetime(2026, 9, 8, 16, 35, 30, 818000, tzinfo=UTC)
    assert event.host_id == "WIN-01"
    assert event.source == "sysmon"
    assert event.source_layer == "raw_telemetry"
    assert event.source_event_id == "3389"
    assert event.user == "WIN-01\\labuser"
    assert event.process is not None
    assert event.process.model_dump() == {
        "pid": 6896,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": (
            '"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
            "-NoProfile -NonInteractive -Command Get-Date | Out-Null "
        ),
        "parent_pid": 5544,
        "parent_name": "powershell.exe",
    }
    assert event.network is None
    assert event.raw_ref.model_dump() == {
        "raw_log_id": "RAW-SYSMON-SAMPLE-001",
        "source_record_id": "3389",
        "segment_no": 1,
        "record_no": 1,
        "parser_id": "sysmon-normalizer",
        "parser_version": "v0.2",
    }


def test_normalize_sysmon_process_create_is_deterministic(
    normalization_context: SysmonNormalizationContext,
) -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    raw_record = next(read_sysmon_jsonl(sample_path))

    first = normalize_sysmon_process_create(raw_record, context=normalization_context)
    second = normalize_sysmon_process_create(raw_record, context=normalization_context)

    assert first.event_id == second.event_id


def test_normalize_sysmon_process_create_rejects_non_event_id_1(
    normalization_context: SysmonNormalizationContext,
) -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
    network_record = next(
        record for record in read_sysmon_jsonl(sample_path) if record.data["EventId"] == 3
    )

    with pytest.raises(ValueError, match="requires Sysmon Event ID 1"):
        normalize_sysmon_process_create(network_record, context=normalization_context)
