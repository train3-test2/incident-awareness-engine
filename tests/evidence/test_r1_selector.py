from dataclasses import fields
from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_selector import (
    R1SelectorPolicy,
    select_r1_lineage,
)

_BASE_TIME = datetime(2026, 10, 7, 1, 0, tzinfo=UTC)
_RUN_ID = "RUN-20261007-001"
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
    parent_process_guid: str | None = None,
    process_name: str = "arbitrary.exe",
    pid: int = 4200,
    run_id: str = _RUN_ID,
    host_id: str = _HOST_ID,
    source: str = "sysmon",
    source_layer: str = "raw_telemetry",
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
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-SELECTOR",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 2 if is_network_event else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": pid,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
                "parent_name": None,
            },
            "network": (
                {
                    "protocol": "tcp",
                    "src_ip": "192.0.2.10",
                    "src_port": 50000,
                    "dst_ip": "192.0.2.20",
                    "dst_port": 443,
                }
                if is_network_event
                else None
            ),
        }
    )


def _events(
    *,
    process_names: tuple[str, str, str] = (
        "anchor-role.exe",
        "middle-role.exe",
        "terminal-role.exe",
    ),
    pids: tuple[int, int, int] = (100, 200, 300),
) -> tuple[NormalizedEvent, ...]:
    anchor = _event(
        event_id="evt-anchor",
        event_type="process_create",
        timestamp=_BASE_TIME,
        process_guid=_ANCHOR_GUID,
        process_name=process_names[0],
        pid=pids[0],
    )
    middle = _event(
        event_id="evt-middle",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_MIDDLE_GUID,
        parent_process_guid=_ANCHOR_GUID,
        process_name=process_names[1],
        pid=pids[1],
    )
    terminal = _event(
        event_id="evt-terminal",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=2),
        process_guid=_TERMINAL_GUID,
        parent_process_guid=_MIDDLE_GUID,
        process_name=process_names[2],
        pid=pids[2],
    )
    network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
        process_name=process_names[2],
        pid=pids[2],
    )
    return anchor, middle, terminal, network


def _policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=3,
    )


def test_selector_policy_exposes_only_structural_scope_and_provenance() -> None:
    # Given
    policy_field_names = {field.name for field in fields(R1SelectorPolicy)}

    # When
    forbidden_label_inputs = {
        "ground_truth",
        "run_type",
        "attack_label",
        "process_name",
        "record_id",
        "event_id",
        "destination_ip",
        "destination_port",
        "pid",
    }

    # Then
    assert policy_field_names == {
        "policy_id",
        "version",
        "config_hash",
        "lineage_event_count",
    }
    assert policy_field_names.isdisjoint(forbidden_label_inputs)


@pytest.mark.parametrize(
    "lineage_event_count",
    [True, 0, -1],
)
def test_selector_policy_rejects_invalid_lineage_event_count(
    lineage_event_count: object,
) -> None:
    # Given
    policy_data = {
        "policy_id": "r1-structural-lineage-selector",
        "version": "v0.1",
        "config_hash": "hash",
        "lineage_event_count": lineage_event_count,
    }

    # When
    with pytest.raises((TypeError, ValueError)):
        R1SelectorPolicy(**policy_data)  # type: ignore[arg-type]

    # Then
    # Invalid structural scope never becomes a selector policy.


def test_selects_unique_guid_lineage_deterministically() -> None:
    # Given
    events = _events()

    # When
    first = select_r1_lineage(events, policy=_policy())
    second = select_r1_lineage(reversed(events), policy=_policy())

    # Then
    assert first == second
    assert first.diagnostics == ()
    assert first.selection is not None
    assert first.selection.run_id == _RUN_ID
    assert first.selection.entity_id == _HOST_ID
    assert first.selection.anchor_event_id == "evt-anchor"
    assert first.selection.terminal_event_id == "evt-terminal"
    assert first.selection.selector_policy_id == _policy().policy_id
    assert first.selection.selector_policy_version == _policy().version
    assert first.selection.selector_policy_config_hash == _policy().config_hash


def test_process_names_do_not_change_selection() -> None:
    # Given
    first_events = _events(
        process_names=("alpha.exe", "cscript.exe", "omega.exe"),
    )
    second_events = _events(
        process_names=("other.exe", "cmd.exe", "different.exe"),
    )

    # When
    first = select_r1_lineage(first_events, policy=_policy())
    second = select_r1_lineage(second_events, policy=_policy())

    # Then
    assert first == second


def test_pid_values_do_not_change_selection() -> None:
    # Given
    first_events = _events(pids=(100, 200, 300))
    second_events = _events(pids=(901, 902, 903))

    # When
    first = select_r1_lineage(first_events, policy=_policy())
    second = select_r1_lineage(second_events, policy=_policy())

    # Then
    assert first == second


def test_duplicate_process_guid_fails_closed() -> None:
    # Given
    events = _events()
    duplicate = _event(
        event_id="evt-terminal-duplicate",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=2),
        process_guid=_TERMINAL_GUID,
        parent_process_guid=_MIDDLE_GUID,
    )

    # When
    result = select_r1_lineage((*events, duplicate), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("duplicate_process_guid",)


def test_missing_process_guid_fails_closed() -> None:
    # Given
    anchor, middle, _, network = _events()
    terminal_without_guid = _event(
        event_id="evt-terminal",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=2),
        process_guid=None,
        parent_process_guid=_MIDDLE_GUID,
    )

    # When
    result = select_r1_lineage(
        (anchor, middle, terminal_without_guid, network),
        policy=_policy(),
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("missing_process_guid",)


def test_missing_parent_event_is_truncated() -> None:
    # Given
    anchor, _, terminal, network = _events()

    # When
    result = select_r1_lineage((anchor, terminal, network), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("truncated_lineage",)


def test_missing_parent_guid_is_truncated() -> None:
    # Given
    anchor, _, terminal, network = _events()
    middle_without_parent = _event(
        event_id="evt-middle",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_MIDDLE_GUID,
        parent_process_guid=None,
    )

    # When
    result = select_r1_lineage(
        (anchor, middle_without_parent, terminal, network),
        policy=_policy(),
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("truncated_lineage",)


def test_lineage_cycle_fails_closed() -> None:
    # Given
    _, _, terminal, network = _events()
    middle = _event(
        event_id="evt-middle",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_MIDDLE_GUID,
        parent_process_guid=_TERMINAL_GUID,
    )

    # When
    result = select_r1_lineage((middle, terminal, network), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("lineage_cycle",)


@pytest.mark.parametrize(
    ("scope_field", "expected_diagnostic"),
    [
        ("run_id", "mixed_run_scope"),
        ("host_id", "mixed_host_scope"),
    ],
)
def test_cross_scope_events_fail_closed(
    scope_field: str,
    expected_diagnostic: str,
) -> None:
    # Given
    anchor, middle, terminal, _ = _events()
    overrides = {scope_field: "RUN-20261007-002" if scope_field == "run_id" else "TARGET-B"}
    network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
        **overrides,
    )

    # When
    result = select_r1_lineage((anchor, middle, terminal, network), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == (expected_diagnostic,)


def test_network_before_terminal_is_temporal_inversion() -> None:
    # Given
    anchor, middle, terminal, _ = _events()
    early_network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_TERMINAL_GUID,
    )

    # When
    result = select_r1_lineage(
        (anchor, middle, terminal, early_network),
        policy=_policy(),
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("temporal_inversion",)


def test_parent_after_child_is_temporal_inversion() -> None:
    # Given
    anchor = _event(
        event_id="evt-anchor",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=2),
        process_guid=_ANCHOR_GUID,
    )
    middle = _event(
        event_id="evt-middle",
        event_type="process_create",
        timestamp=_BASE_TIME + timedelta(seconds=1),
        process_guid=_MIDDLE_GUID,
        parent_process_guid=_ANCHOR_GUID,
    )
    _, _, terminal, network = _events()

    # When
    result = select_r1_lineage((anchor, middle, terminal, network), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("temporal_inversion",)


def test_multiple_structural_terminal_candidates_are_ambiguous() -> None:
    # Given
    first_events = _events()
    second_anchor_guid = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
    second_middle_guid = "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"
    second_terminal_guid = "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
    second_events = (
        _event(
            event_id="evt-anchor-2",
            event_type="process_create",
            timestamp=_BASE_TIME,
            process_guid=second_anchor_guid,
        ),
        _event(
            event_id="evt-middle-2",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=second_middle_guid,
            parent_process_guid=second_anchor_guid,
        ),
        _event(
            event_id="evt-terminal-2",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=second_terminal_guid,
            parent_process_guid=second_middle_guid,
        ),
        _event(
            event_id="evt-network-2",
            event_type="network_connection",
            timestamp=_BASE_TIME + timedelta(seconds=3),
            process_guid=second_terminal_guid,
        ),
    )

    # When
    result = select_r1_lineage((*first_events, *second_events), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("ambiguous_terminal_candidate",)


def test_multiple_network_events_for_one_terminal_do_not_require_arbitrary_selection() -> None:
    # Given
    events = _events()
    second_network = _event(
        event_id="evt-network-2",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=4),
        process_guid=_TERMINAL_GUID,
    )

    # When
    result = select_r1_lineage((*events, second_network), policy=_policy())

    # Then
    assert result.selection is not None
    assert result.selection.terminal_event_id == "evt-terminal"
    assert result.diagnostics == ()


def test_no_structural_terminal_candidate_fails_closed() -> None:
    # Given
    anchor, middle, terminal, _ = _events()

    # When
    result = select_r1_lineage((anchor, middle, terminal), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("no_terminal_candidate",)


@pytest.mark.parametrize(
    "terminal_overrides",
    [
        {"source": "security"},
        {"source_layer": "detector_output"},
        {"event_type": "file_create"},
    ],
    ids=["wrong_source", "wrong_source_layer", "wrong_event_type"],
)
def test_terminal_outside_r1_event_contract_is_not_selected(
    terminal_overrides: dict[str, str],
) -> None:
    # Given
    anchor, middle, _, network = _events()
    terminal_data = {
        "event_id": "evt-terminal",
        "event_type": "process_create",
        "timestamp": _BASE_TIME + timedelta(seconds=2),
        "process_guid": _TERMINAL_GUID,
        "parent_process_guid": _MIDDLE_GUID,
        **terminal_overrides,
    }
    terminal = _event(**terminal_data)  # type: ignore[arg-type]

    # When
    result = select_r1_lineage((anchor, middle, terminal, network), policy=_policy())

    # Then
    assert result.selection is None
    assert result.diagnostics == ("no_terminal_candidate",)
