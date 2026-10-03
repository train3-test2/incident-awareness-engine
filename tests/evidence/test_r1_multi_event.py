import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_multi_event import (
    EXTRACTOR_VERSION,
    extract_remote_process_network_follow_on,
)

_BASE_TIME = datetime(2026, 10, 3, 1, 0, tzinfo=UTC)
_PROCESS_GUID = "{11111111-1111-1111-1111-111111111111}"


def _normalized_event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    run_id: str = "RUN-20261003-001",
    host_id: str = "TARGET-A",
    source: str = "sysmon",
    source_layer: str = "raw_telemetry",
    process_guid: str | None = _PROCESS_GUID,
) -> NormalizedEvent:
    is_network_event = event_type == "network_connection"
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": run_id,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": timestamp,
            "ingest_time": timestamp,
            "host_id": host_id,
            "source": source,
            "source_layer": source_layer,
            "source_event_id": "3" if is_network_event else "1",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-001",
                "source_record_id": "3" if is_network_event else "1",
                "segment_no": 1,
                "record_no": 2 if is_network_event else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": "powershell.exe",
                "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": "powershell.exe",
                "parent_pid": None,
                "parent_process_guid": None,
                "parent_name": None,
            },
            "network": (
                {
                    "protocol": "tcp",
                    "src_ip": "10.0.0.10",
                    "src_port": 52132,
                    "dst_ip": "10.0.0.20",
                    "dst_port": 5985,
                }
                if is_network_event
                else None
            ),
        }
    )


def _matching_events(
    *,
    process_timestamp: datetime = _BASE_TIME,
    network_timestamp: datetime = _BASE_TIME + timedelta(seconds=3),
) -> tuple[NormalizedEvent, NormalizedEvent]:
    return (
        _normalized_event(
            event_id="evt-r1-process-001",
            event_type="process_create",
            timestamp=process_timestamp,
        ),
        _normalized_event(
            event_id="evt-r1-network-001",
            event_type="network_connection",
            timestamp=network_timestamp,
        ),
    )


def test_extracts_remote_process_network_follow_on() -> None:
    # Given
    process_event, network_event = _matching_events()

    # When
    evidences = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert isinstance(evidence, Evidence)
    assert evidence.run_id == process_event.run_id
    assert evidence.entity_id == process_event.host_id
    assert evidence.evidence_type == "remote_process_network_follow_on"
    assert evidence.event_ids == [process_event.event_id, network_event.event_id]
    assert evidence.timestamp == network_event.timestamp
    assert evidence.derived_from_source_layer == "raw_telemetry"
    assert evidence.feature_channel_group == "fusion_feature"
    assert evidence.extractor_version == "r1-v0.1"
    assert evidence.attack_technique_ids == []
    assert evidence.features == {}
    assert "source_event_id" not in evidence.model_dump()
    assert "raw_ref" not in evidence.model_dump()


def test_allows_same_timestamp() -> None:
    # Given
    process_event, network_event = _matching_events(
        process_timestamp=_BASE_TIME,
        network_timestamp=_BASE_TIME,
    )

    # When
    evidences = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert len(evidences) == 1
    assert evidences[0].timestamp == _BASE_TIME


def test_rejects_network_event_before_process_event() -> None:
    # Given
    process_event, network_event = _matching_events(
        process_timestamp=_BASE_TIME,
        network_timestamp=_BASE_TIME - timedelta(milliseconds=1),
    )

    # When
    evidences = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert evidences == []


@pytest.mark.parametrize(
    ("process_overrides", "network_overrides"),
    [
        ({"run_id": "RUN-20261003-002"}, {}),
        ({"host_id": "TARGET-B"}, {}),
        ({"process_guid": "{22222222-2222-2222-2222-222222222222}"}, {}),
        ({"source": "security"}, {}),
        ({}, {"source": "velociraptor"}),
        ({"source_layer": "detector_output"}, {}),
        ({}, {"source_layer": "detector_output"}),
        ({"event_type": "file_create"}, {}),
        ({}, {"event_type": "registry_change"}),
    ],
    ids=[
        "different_run",
        "different_host",
        "different_process_guid",
        "process_source_mismatch",
        "network_source_mismatch",
        "process_source_layer_mismatch",
        "network_source_layer_mismatch",
        "process_event_type_mismatch",
        "network_event_type_mismatch",
    ],
)
def test_rejects_contract_mismatch(
    process_overrides: dict[str, object],
    network_overrides: dict[str, object],
) -> None:
    # Given
    process_payload = {
        "event_id": "evt-r1-process-001",
        "event_type": "process_create",
        "timestamp": _BASE_TIME,
        **process_overrides,
    }
    network_payload = {
        "event_id": "evt-r1-network-001",
        "event_type": "network_connection",
        "timestamp": _BASE_TIME + timedelta(seconds=3),
        **network_overrides,
    }
    process_event = _normalized_event(**process_payload)
    network_event = _normalized_event(**network_payload)

    # When
    evidences = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert evidences == []


@pytest.mark.parametrize(
    ("process_guid", "network_process_guid"),
    [
        (None, _PROCESS_GUID),
        (_PROCESS_GUID, None),
        (None, None),
    ],
    ids=["process_guid_missing", "network_guid_missing", "both_guids_missing"],
)
def test_rejects_missing_process_guid(
    process_guid: str | None,
    network_process_guid: str | None,
) -> None:
    # Given
    process_event = _normalized_event(
        event_id="evt-r1-process-001",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid=process_guid,
    )
    network_event = _normalized_event(
        event_id="evt-r1-network-001",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=network_process_guid,
    )

    # When
    evidences = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert evidences == []


def test_evidence_id_is_deterministic_and_uses_canonical_event_ids() -> None:
    # Given
    process_event = _normalized_event(
        event_id="evt-z-process",
        event_type="process_create",
        timestamp=_BASE_TIME,
    )
    network_event = _normalized_event(
        event_id="evt-a-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
    )
    canonical_event_ids = sorted([process_event.event_id, network_event.event_id])
    identity = json.dumps(
        [
            process_event.run_id,
            canonical_event_ids,
            "remote_process_network_follow_on",
            EXTRACTOR_VERSION,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    expected_evidence_id = f"E-{uuid5(NAMESPACE_URL, identity)}"

    # When
    first = extract_remote_process_network_follow_on(process_event, network_event)
    second = extract_remote_process_network_follow_on(process_event, network_event)

    # Then
    assert first == second
    assert first[0].evidence_id == expected_evidence_id
    assert first[0].evidence_id.startswith("E-")
