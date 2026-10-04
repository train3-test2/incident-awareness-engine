from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence import extract_evidence
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline,
)

_BASE_TIME = datetime(2026, 10, 5, 1, 0, tzinfo=UTC)
_RUN_ID = "RUN-20261005-001"
_HOST_ID = "TARGET-A"
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str | None,
    run_id: str = _RUN_ID,
    host_id: str = _HOST_ID,
    process_name: str = "powershell.exe",
    parent_process_guid: str | None = None,
    command_line: str = "powershell.exe",
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
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-PIPELINE",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 2 if is_network_event else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": command_line,
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


def _network_events(
    *,
    process_timestamp: datetime = _BASE_TIME,
    network_timestamp: datetime = _BASE_TIME + timedelta(seconds=3),
    process_guid: str | None = _TERMINAL_GUID,
    network_guid: str | None = _TERMINAL_GUID,
    network_run_id: str = _RUN_ID,
    network_host_id: str = _HOST_ID,
) -> tuple[NormalizedEvent, NormalizedEvent]:
    return (
        _event(
            event_id="evt-process",
            event_type="process_create",
            timestamp=process_timestamp,
            process_guid=process_guid,
        ),
        _event(
            event_id="evt-network",
            event_type="network_connection",
            timestamp=network_timestamp,
            process_guid=network_guid,
            run_id=network_run_id,
            host_id=network_host_id,
        ),
    )


def _lineage_events() -> tuple[NormalizedEvent, NormalizedEvent, NormalizedEvent]:
    return (
        _event(
            event_id="evt-anchor",
            event_type="process_create",
            timestamp=_BASE_TIME,
            process_guid=_ANCHOR_GUID,
            process_name="anchor.exe",
        ),
        _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="runtime-hop.exe",
            parent_process_guid=_ANCHOR_GUID,
        ),
        _event(
            event_id="evt-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
    )


def _policy(
    approved_lineage: tuple[str, ...] = (
        "anchor.exe",
        "approved-hop.exe",
        "terminal.exe",
    ),
) -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="r1-target-a-lineage",
        version="v1",
        config_hash="sha256:approved-policy-v1",
        approved_lineage=approved_lineage,
    )


def _lineage_input(policy: ApprovedLineagePolicy | None = None) -> R1LineageInput:
    return R1LineageInput(
        anchor_event_id="evt-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=policy or _policy(),
    )


def _terminal_lineage_input(
    terminal_event_id: str = "evt-process",
    process_name: str = "powershell.exe",
) -> R1LineageInput:
    return R1LineageInput(
        anchor_event_id=terminal_event_id,
        terminal_event_id=terminal_event_id,
        approved_policy=_policy(approved_lineage=(process_name,)),
    )


def test_extracts_network_follow_on_from_shuffled_batch() -> None:
    # Given
    process_event, network_event = _network_events()

    # When
    evidences = run_r1_evidence_pipeline(
        [network_event, process_event],
        lineage_inputs=[_terminal_lineage_input()],
    )

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "remote_process_network_follow_on"
    assert evidence.event_ids == [process_event.event_id, network_event.event_id]
    assert evidence.timestamp == network_event.timestamp


def test_uses_only_selected_terminal_for_same_key_network_candidates() -> None:
    # Given
    process_one = _event(
        event_id="evt-process-1",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid=_TERMINAL_GUID,
    )
    process_two = _event(
        event_id="evt-process-2",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_TERMINAL_GUID,
    )
    network_one = _event(
        event_id="evt-network-1",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=2),
        process_guid=_TERMINAL_GUID,
    )
    network_two = _event(
        event_id="evt-network-2",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
    )

    # When
    evidences = run_r1_evidence_pipeline(
        [network_two, process_two, network_one, process_one],
        lineage_inputs=[_terminal_lineage_input("evt-process-2")],
    )

    # Then
    assert {tuple(evidence.event_ids) for evidence in evidences} == {
        ("evt-process-2", "evt-network-1"),
        ("evt-process-2", "evt-network-2"),
    }


def test_ignores_unrelated_process_and_network_pair() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    unrelated_process = _event(
        event_id="evt-unrelated-process",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
    )
    unrelated_network = _event(
        event_id="evt-unrelated-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
    )
    matching_policy = _policy(approved_lineage=("anchor.exe", "runtime-hop.exe", "terminal.exe"))

    # When
    evidences = run_r1_evidence_pipeline(
        [anchor, middle, terminal, unrelated_process, unrelated_network],
        lineage_inputs=[_lineage_input(matching_policy)],
    )

    # Then
    assert evidences == ()


def test_extracts_lineage_deviation_from_explicit_input() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()

    # When
    evidences = run_r1_evidence_pipeline(
        [terminal, anchor, middle],
        lineage_inputs=[_lineage_input()],
    )

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "remote_session_process_lineage_deviation"
    assert evidence.event_ids == [anchor.event_id, middle.event_id, terminal.event_id]
    assert evidence.timestamp == terminal.timestamp


def test_matching_approved_lineage_does_not_create_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    matching_policy = _policy(approved_lineage=("anchor.exe", "runtime-hop.exe", "terminal.exe"))

    # When
    evidences = run_r1_evidence_pipeline(
        [anchor, middle, terminal],
        lineage_inputs=[_lineage_input(matching_policy)],
    )

    # Then
    assert evidences == ()


def test_empty_lineage_inputs_do_not_auto_select_terminal_for_network() -> None:
    # Given
    process_event, network_event = _network_events()

    # When
    evidences = run_r1_evidence_pipeline(
        [process_event, network_event],
        lineage_inputs=(),
    )

    # Then
    assert evidences == ()


@pytest.mark.parametrize(
    "network_overrides",
    [
        {"network_run_id": "RUN-20261005-002"},
        {"network_host_id": "TARGET-B"},
        {"network_guid": "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"},
    ],
    ids=["different_run", "different_host", "different_guid"],
)
def test_network_pairing_stays_within_run_host_and_guid(
    network_overrides: dict[str, str],
) -> None:
    # Given
    process_event, network_event = _network_events(**network_overrides)

    # When
    evidences = run_r1_evidence_pipeline(
        [process_event, network_event],
        lineage_inputs=[_terminal_lineage_input()],
    )

    # Then
    assert evidences == ()


def test_network_event_before_process_event_does_not_create_evidence() -> None:
    # Given
    process_event, network_event = _network_events(
        process_timestamp=_BASE_TIME + timedelta(seconds=1),
        network_timestamp=_BASE_TIME,
    )

    # When
    evidences = run_r1_evidence_pipeline(
        [process_event, network_event],
        lineage_inputs=[_terminal_lineage_input()],
    )

    # Then
    assert evidences == ()


@pytest.mark.parametrize(
    ("process_guid", "network_guid"),
    [(None, _TERMINAL_GUID), (_TERMINAL_GUID, None)],
    ids=["process_guid_missing", "network_guid_missing"],
)
def test_missing_guid_is_not_a_network_pairing_candidate(
    process_guid: str | None,
    network_guid: str | None,
) -> None:
    # Given
    process_event, network_event = _network_events(
        process_guid=process_guid,
        network_guid=network_guid,
    )

    # When
    evidences = run_r1_evidence_pipeline(
        [process_event, network_event],
        lineage_inputs=[_terminal_lineage_input()],
    )

    # Then
    assert evidences == ()


@pytest.mark.parametrize(
    ("anchor_event_id", "terminal_event_id", "missing_field"),
    [
        ("evt-missing-anchor", "evt-terminal", "anchor_event_id"),
        ("evt-anchor", "evt-missing-terminal", "terminal_event_id"),
    ],
    ids=["missing_anchor", "missing_terminal"],
)
def test_missing_lineage_event_id_fails_fast(
    anchor_event_id: str,
    terminal_event_id: str,
    missing_field: str,
) -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    lineage_input = R1LineageInput(
        anchor_event_id=anchor_event_id,
        terminal_event_id=terminal_event_id,
        approved_policy=_policy(),
    )

    # When / Then
    with pytest.raises(ValueError, match=missing_field):
        run_r1_evidence_pipeline(
            [anchor, middle, terminal],
            lineage_inputs=[lineage_input],
        )


def test_duplicate_event_id_fails_fast() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    duplicate_anchor = _event(
        event_id=anchor.event_id,
        event_type="process_create",
        timestamp=anchor.timestamp + timedelta(milliseconds=1),
        process_guid="{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}",
        process_name="other-anchor.exe",
    )

    # When / Then
    with pytest.raises(ValueError, match="unique event_id"):
        run_r1_evidence_pipeline(
            [anchor, duplicate_anchor, middle, terminal],
            lineage_inputs=[_lineage_input()],
        )


def test_repeated_lineage_input_returns_one_lineage_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    lineage_input = _lineage_input()

    # When
    evidences = run_r1_evidence_pipeline(
        [anchor, middle, terminal],
        lineage_inputs=[lineage_input, lineage_input],
    )

    # Then
    assert len(evidences) == 1
    assert evidences[0].evidence_type == "remote_session_process_lineage_deviation"


def test_shared_terminal_across_lineage_inputs_returns_one_network_evidence() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    network_event = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
    )
    anchor_to_terminal = _lineage_input(
        _policy(approved_lineage=("anchor.exe", "runtime-hop.exe", "terminal.exe"))
    )
    middle_to_terminal = R1LineageInput(
        anchor_event_id=middle.event_id,
        terminal_event_id=terminal.event_id,
        approved_policy=_policy(approved_lineage=("runtime-hop.exe", "terminal.exe")),
    )

    # When
    evidences = run_r1_evidence_pipeline(
        [anchor, middle, terminal, network_event],
        lineage_inputs=[anchor_to_terminal, middle_to_terminal],
    )

    # Then
    network_evidences = [
        evidence
        for evidence in evidences
        if evidence.evidence_type == "remote_process_network_follow_on"
    ]
    assert len(network_evidences) == 1
    assert network_evidences[0].event_ids == [terminal.event_id, network_event.event_id]


def test_evidence_ids_do_not_depend_on_input_event_order() -> None:
    # Given
    anchor, middle, terminal = _lineage_events()
    network_event = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
    )
    events = [anchor, middle, terminal, network_event]

    # When
    first = run_r1_evidence_pipeline(events, lineage_inputs=[_lineage_input()])
    second = run_r1_evidence_pipeline(
        reversed(events),
        lineage_inputs=[_lineage_input()],
    )

    # Then
    assert {evidence.evidence_id for evidence in first} == {
        evidence.evidence_id for evidence in second
    }


def test_does_not_merge_s0_evidence_or_require_fusion() -> None:
    # Given
    s0_event = _event(
        event_id="evt-s0-encoded-command",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid=_TERMINAL_GUID,
        command_line="powershell.exe -enc SQBFAFgA",
    )
    assert extract_evidence(s0_event)

    # When
    evidences = run_r1_evidence_pipeline([s0_event])

    # Then
    assert evidences == ()
