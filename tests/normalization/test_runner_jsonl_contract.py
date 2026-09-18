"""The S0 runner's JSONL must be readable by the Sysmon normalizer as it is.

`tests/normalization/test_sysmon_sample_normalization.py` and
`test_sysmon_evidence_integration.py` already cover the normalizer, but both read
`samples/raw/sysmon-0001.jsonl`, a committed sample produced by
`tools/collect_sysmon_sample.ps1`. Nothing checked that the file
`scenarios/S0/run-common.ps1` writes at collection time has the same shape.

This module closes that gap. The fixture below is written the way
`Export-SysmonRunWindow` writes it - the same seven top level keys, in the same
order, with `EventData` flattened from the Sysmon XML - and is then pushed
through the real reader and the real normalizers. It is a contract test for the
runner's output format, not another test of the normalizer's logic.

No rehearsal artifact is committed: the records are built here and written to
`tmp_path`, so the test needs no VM and performs no connection.
"""

import json
from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)

RUN_ID = "RUN-20260914-002"
CONTEXT = SysmonNormalizationContext(
    run_id=RUN_ID,
    raw_log_id="RAW-001",
    segment_no=1,
)

# Written exactly as Export-SysmonRunWindow builds each line: RecordId, EventId,
# TimeCreated, Channel, Computer, Provider, EventData.
PROCESS_CREATE_RECORD = {
    "RecordId": 7809,
    "EventId": 1,
    "TimeCreated": "2026-09-14T15:21:46.216Z",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "WIN-01",
    "Provider": "Microsoft-Windows-Sysmon",
    "EventData": {
        "RuleName": "-",
        "UtcTime": "2026-09-14 15:21:46.210",
        "ProcessGuid": "{c1ae1b3a-0300-6aa8-6402-000000000900}",
        "ProcessId": "444",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "User": "WIN-01\\poc",
        "CommandLine": (
            '"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile '
            "-NonInteractive -ExecutionPolicy Bypass -File C:\\S0\\work\\s0_anchor.ps1"
        ),
        "ParentProcessId": "5744",
        "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    },
}

NETWORK_CONNECTION_RECORD = {
    "RecordId": 7808,
    "EventId": 3,
    "TimeCreated": "2026-09-14T15:21:44.100Z",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "WIN-01",
    "Provider": "Microsoft-Windows-Sysmon",
    "EventData": {
        "RuleName": "-",
        "UtcTime": "2026-09-14 15:21:44.095",
        "ProcessGuid": "{c1ae1b3a-fe08-6aa7-eb03-000000000000}",
        "ProcessId": "4",
        "Image": "System",
        "User": "NT AUTHORITY\\SYSTEM",
        "Protocol": "udp",
        "Initiated": "true",
        "SourceIp": "192.168.9.129",
        "SourcePort": "137",
        "DestinationIp": "192.168.9.2",
        "DestinationPort": "137",
    },
}


@pytest.fixture
def runner_jsonl(tmp_path: Path) -> Path:
    """A two record file in the runner's own output format."""
    path = tmp_path / "sysmon-0001.jsonl"
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False) + "\n"
            for record in (NETWORK_CONNECTION_RECORD, PROCESS_CREATE_RECORD)
        ),
        encoding="utf-8",
        newline="",
    )
    return path


def test_runner_jsonl_is_readable_by_the_sysmon_reader(runner_jsonl: Path) -> None:
    records = list(read_sysmon_jsonl(runner_jsonl))

    assert [record.record_no for record in records] == [1, 2]
    assert [record.data["EventId"] for record in records] == [3, 1]
    assert [record.data["RecordId"] for record in records] == [7808, 7809]


def test_runner_process_create_record_normalizes_to_event_v0(runner_jsonl: Path) -> None:
    record = next(r for r in read_sysmon_jsonl(runner_jsonl) if r.data["EventId"] == 1)

    event = normalize_sysmon_process_create(record, context=CONTEXT)

    assert event.run_id == RUN_ID
    assert event.source == "sysmon"
    assert event.source_layer == "raw_telemetry"
    assert event.event_type == "process_create"
    assert event.host_id == "WIN-01"
    # The Sysmon UtcTime inside EventData wins over the channel's TimeCreated.
    assert event.timestamp.isoformat() == "2026-09-14T15:21:46.210000+00:00"
    assert event.timestamp_source == "event_time"
    assert event.record_time is not None
    assert event.record_time.isoformat() == "2026-09-14T15:21:46.216000+00:00"
    # reference_source_event_id in run_metadata.json is this same Sysmon RecordId.
    assert event.source_event_id == "7809"
    assert event.process is not None
    assert event.process.pid == 444
    assert event.process.name == "powershell.exe"
    assert event.raw_ref.raw_log_id == "RAW-001"
    assert event.raw_ref.source_record_id == "7809"
    assert event.raw_ref.segment_no == 1
    assert event.raw_ref.record_no == 2


def test_runner_network_connection_record_normalizes_to_event_v0(runner_jsonl: Path) -> None:
    record = next(r for r in read_sysmon_jsonl(runner_jsonl) if r.data["EventId"] == 3)

    event = normalize_sysmon_network_connection(record, context=CONTEXT)

    assert event.run_id == RUN_ID
    assert event.source == "sysmon"
    assert event.source_layer == "raw_telemetry"
    assert event.event_type == "network_connection"
    assert event.host_id == "WIN-01"
    assert event.timestamp.isoformat() == "2026-09-14T15:21:44.095000+00:00"
    assert event.source_event_id == "7808"
    assert event.network is not None
    assert event.network.protocol == "udp"
    assert event.network.dst_ip == "192.168.9.2"
    assert event.network.dst_port == 137
    assert event.raw_ref.source_record_id == "7808"
    assert event.raw_ref.record_no == 1


def test_normalized_runner_events_round_trip_through_the_contract(runner_jsonl: Path) -> None:
    """The serialized form is still a valid event_v0 document."""
    records = {record.data["EventId"]: record for record in read_sysmon_jsonl(runner_jsonl)}
    events = [
        normalize_sysmon_process_create(records[1], context=CONTEXT),
        normalize_sysmon_network_connection(records[3], context=CONTEXT),
    ]

    for event in events:
        restored = NormalizedEvent.model_validate(event.model_dump(mode="json"))
        assert restored == event
        assert restored.run_id == RUN_ID
