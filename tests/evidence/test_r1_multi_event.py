import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

import pytest

import incident_awareness.evidence.r1_multi_event as r1_multi_event_module
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_multi_event import (
    EXTRACTOR_VERSION,
    ApprovedLineagePolicy,
    extract_remote_process_network_follow_on,
    extract_remote_session_process_lineage_deviation,
)

_BASE_TIME = datetime(2026, 10, 3, 1, 0, tzinfo=UTC)
_PROCESS_GUID = "{11111111-1111-1111-1111-111111111111}"
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
_SVCHOST_GUID = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
_SERVICES_GUID = "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"


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
    process_name: str = "powershell.exe",
    parent_process_guid: str | None = None,
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
                "name": process_name,
                "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": "powershell.exe",
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
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


def _approved_policy(
    approved_lineage: tuple[str, ...] = (
        "session-anchor.exe",
        "approved-hop.exe",
        "terminal-tool.exe",
    ),
    *,
    version: str = "v1",
    config_hash: str = "sha256:approved-policy-v1",
) -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="r1-target-a-lineage",
        version=version,
        config_hash=config_hash,
        approved_lineage=approved_lineage,
    )


def _lineage_events(
    *,
    anchor_timestamp: datetime = _BASE_TIME,
    middle_timestamp: datetime = _BASE_TIME + timedelta(seconds=1),
    terminal_timestamp: datetime = _BASE_TIME + timedelta(seconds=2),
    anchor_parent_guid: str | None = None,
    anchor_overrides: dict[str, object] | None = None,
    middle_overrides: dict[str, object] | None = None,
    terminal_overrides: dict[str, object] | None = None,
) -> tuple[NormalizedEvent, NormalizedEvent, NormalizedEvent]:
    anchor_payload = {
        "event_id": "evt-r1-anchor",
        "event_type": "process_create",
        "timestamp": anchor_timestamp,
        "process_guid": _ANCHOR_GUID,
        "process_name": "session-anchor.exe",
        "parent_process_guid": anchor_parent_guid,
        **(anchor_overrides or {}),
    }
    middle_payload = {
        "event_id": "evt-r1-middle",
        "event_type": "process_create",
        "timestamp": middle_timestamp,
        "process_guid": _MIDDLE_GUID,
        "process_name": "runtime-hop.exe",
        "parent_process_guid": _ANCHOR_GUID,
        **(middle_overrides or {}),
    }
    terminal_payload = {
        "event_id": "evt-r1-terminal",
        "event_type": "process_create",
        "timestamp": terminal_timestamp,
        "process_guid": _TERMINAL_GUID,
        "process_name": "terminal-tool.exe",
        "parent_process_guid": _MIDDLE_GUID,
        **(terminal_overrides or {}),
    }
    return (
        _normalized_event(**anchor_payload),
        _normalized_event(**middle_payload),
        _normalized_event(**terminal_payload),
    )


def test_matching_approved_lineage_does_not_create_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        middle_overrides={"process_name": "approved-hop.exe"},
    )
    policy = _approved_policy()

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        policy,
    )

    # Then
    assert evidences == []


def test_lineage_excludes_os_ancestors_above_anchor() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_parent_guid=_SVCHOST_GUID,
        middle_overrides={"process_name": "approved-hop.exe"},
    )
    svchost = _normalized_event(
        event_id="evt-r1-svchost",
        event_type="process_create",
        timestamp=_BASE_TIME - timedelta(seconds=1),
        process_guid=_SVCHOST_GUID,
        process_name="svchost.exe",
        parent_process_guid=_SERVICES_GUID,
    )
    services = _normalized_event(
        event_id="evt-r1-services",
        event_type="process_create",
        timestamp=_BASE_TIME - timedelta(seconds=2),
        process_guid=_SERVICES_GUID,
        process_name="services.exe",
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [services, svchost, anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


def test_anchor_scope_is_complete_without_observing_anchor_parent() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(anchor_parent_guid=_SVCHOST_GUID)

    # When
    (evidence,) = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidence.event_ids == [anchor.event_id, middle.event_id, terminal.event_id]


def test_anchor_can_be_the_terminal_event() -> None:
    # Given
    terminal = _normalized_event(
        event_id="evt-r1-anchor-terminal",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid=_TERMINAL_GUID,
        process_name="single-terminal.exe",
        parent_process_guid=_SVCHOST_GUID,
    )
    policy = _approved_policy(approved_lineage=("different-terminal.exe",))

    # When
    (evidence,) = extract_remote_session_process_lineage_deviation(
        [terminal],
        terminal,
        terminal,
        policy,
    )

    # Then
    assert evidence.event_ids == [terminal.event_id]
    assert evidence.timestamp == terminal.timestamp


def test_process_name_comparison_is_case_insensitive() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_overrides={"process_name": "Session-Anchor.EXE"},
        middle_overrides={"process_name": "Approved-Hop.EXE"},
        terminal_overrides={"process_name": "Terminal-Tool.EXE"},
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


def test_arbitrary_process_name_deviation_creates_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    policy = _approved_policy()

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [terminal, anchor, middle],
        anchor,
        terminal,
        policy,
    )

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert isinstance(evidence, Evidence)
    assert evidence.evidence_type == "remote_session_process_lineage_deviation"
    assert evidence.run_id == terminal.run_id
    assert evidence.entity_id == terminal.host_id
    assert evidence.event_ids == [anchor.event_id, middle.event_id, terminal.event_id]
    assert evidence.timestamp == terminal.timestamp
    assert evidence.derived_from_source_layer == "raw_telemetry"
    assert evidence.feature_channel_group == "fusion_feature"
    assert evidence.extractor_version == "r1-v0.1"
    assert evidence.attack_technique_ids == []
    assert evidence.features == {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "config_hash": policy.config_hash,
    }
    assert "source_event_id" not in evidence.model_dump()
    assert "raw_ref" not in evidence.model_dump()


def test_lineage_allows_equal_parent_and_child_timestamps() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_timestamp=_BASE_TIME,
        middle_timestamp=_BASE_TIME,
        terminal_timestamp=_BASE_TIME,
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert len(evidences) == 1
    assert evidences[0].timestamp == _BASE_TIME


def test_lineage_rejects_parent_created_after_child() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_timestamp=_BASE_TIME + timedelta(seconds=2),
        middle_timestamp=_BASE_TIME + timedelta(seconds=1),
        terminal_timestamp=_BASE_TIME + timedelta(seconds=3),
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


def test_missing_anchor_process_guid_does_not_create_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_overrides={"process_guid": None},
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


def test_missing_parent_event_is_truncated_without_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        middle_overrides={
            "parent_process_guid": "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
        }
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []
    correlation = r1_multi_event_module._reconstruct_process_lineage(
        (middle, terminal),
        anchor,
        terminal,
    )
    assert correlation.status == "truncated"
    assert correlation.failure_reason == "missing_parent"
    assert correlation.duplicate_process_guid is None


def test_duplicate_terminal_process_guid_fails_closed() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    duplicate_terminal = _normalized_event(
        event_id="evt-r1-terminal-duplicate",
        event_type="process_create",
        timestamp=terminal.timestamp,
        process_guid=_TERMINAL_GUID,
        process_name="terminal-tool.exe",
        parent_process_guid=_MIDDLE_GUID,
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal, duplicate_terminal],
        anchor,
        terminal,
        _approved_policy(),
    )
    correlation = r1_multi_event_module._reconstruct_process_lineage(
        (anchor, middle, terminal, duplicate_terminal),
        anchor,
        terminal,
    )

    # Then
    assert evidences == []
    assert correlation.status == "truncated"
    assert correlation.failure_reason == "duplicate_process_guid"
    assert correlation.duplicate_process_guid == _TERMINAL_GUID


def test_duplicate_intermediate_process_guid_fails_closed() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    duplicate_middle = _normalized_event(
        event_id="evt-r1-middle-duplicate",
        event_type="process_create",
        timestamp=middle.timestamp,
        process_guid=_MIDDLE_GUID,
        process_name="other-runtime-hop.exe",
        parent_process_guid=_ANCHOR_GUID,
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, duplicate_middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )
    correlation = r1_multi_event_module._reconstruct_process_lineage(
        (anchor, middle, duplicate_middle, terminal),
        anchor,
        terminal,
    )

    # Then
    assert evidences == []
    assert correlation.status == "truncated"
    assert correlation.failure_reason == "duplicate_process_guid"
    assert correlation.duplicate_process_guid == _MIDDLE_GUID


def test_cycle_does_not_create_deviation_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_timestamp=_BASE_TIME,
        middle_timestamp=_BASE_TIME,
        terminal_timestamp=_BASE_TIME,
        middle_overrides={"parent_process_guid": _TERMINAL_GUID},
    )

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


@pytest.mark.parametrize(
    "anchor_overrides",
    [
        {"run_id": "RUN-20261003-002"},
        {"host_id": "TARGET-B"},
        {"source": "security"},
        {"source_layer": "detector_output"},
        {"event_type": "file_create"},
    ],
    ids=[
        "different_run",
        "different_host",
        "source_mismatch",
        "source_layer_mismatch",
        "event_type_mismatch",
    ],
)
def test_invalid_anchor_event_does_not_create_evidence(
    anchor_overrides: dict[str, object],
) -> None:
    # Given
    anchor, middle, terminal = _lineage_events(anchor_overrides=anchor_overrides)

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


@pytest.mark.parametrize(
    "terminal_overrides",
    [
        {"source": "security"},
        {"source_layer": "detector_output"},
        {"event_type": "file_create"},
        {"process_guid": None},
    ],
    ids=[
        "terminal_source_mismatch",
        "terminal_source_layer_mismatch",
        "terminal_event_type_mismatch",
        "terminal_guid_missing",
    ],
)
def test_invalid_terminal_event_does_not_create_evidence(
    terminal_overrides: dict[str, object],
) -> None:
    # Given
    anchor, middle, terminal = _lineage_events(terminal_overrides=terminal_overrides)

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidences == []


def test_lineage_uses_latest_source_event_timestamp() -> None:
    # Given
    anchor, middle, terminal = _lineage_events(
        anchor_timestamp=_BASE_TIME,
        middle_timestamp=_BASE_TIME + timedelta(seconds=3),
        terminal_timestamp=_BASE_TIME + timedelta(seconds=7),
    )

    # When
    (evidence,) = extract_remote_session_process_lineage_deviation(
        [middle, terminal, anchor],
        anchor,
        terminal,
        _approved_policy(),
    )

    # Then
    assert evidence.timestamp == terminal.timestamp


def test_lineage_evidence_id_is_deterministic_for_same_policy() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    first_policy = _approved_policy()
    equivalent_policy = _approved_policy()

    # When
    first = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        first_policy,
    )
    second = extract_remote_session_process_lineage_deviation(
        [terminal, middle, anchor],
        anchor,
        terminal,
        equivalent_policy,
    )

    # Then
    assert first == second
    assert first[0].evidence_id.startswith("E-")


def test_lineage_evidence_id_includes_policy_identity() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    first_policy = _approved_policy(version="v1", config_hash="sha256:policy-v1")
    second_policy = _approved_policy(version="v2", config_hash="sha256:policy-v2")

    # When
    first = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        first_policy,
    )
    second = extract_remote_session_process_lineage_deviation(
        [anchor, middle, terminal],
        anchor,
        terminal,
        second_policy,
    )

    # Then
    assert first[0].evidence_id != second[0].evidence_id
