import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
)
from incident_awareness.evidence.r1_multi_event import (
    REMOTE_PROCESS_NETWORK_FOLLOW_ON,
    REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION,
)
from incident_awareness.evidence.r1_selector import R1SelectorPolicy, select_r1_lineage
from incident_awareness.pipeline.r1_artifacts import load_r1_evidence_artifacts
from incident_awareness.pipeline.r1_automated import (
    run_and_write_r1_evidence_artifacts_from_policy,
    run_r1_evidence_pipeline_from_policy,
)

_RUN_ID = "RUN-20261010-001"
_HOST_ID = "TARGET-A"
_RUN_START = datetime(2026, 10, 10, 1, 0, tzinfo=UTC)
_CONTEXT_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
_WMI_POLICY_ID = "r1-wmi-management-approved-lineage"
_WMI_POLICY_VERSION = "v0.1"


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    parent_process_guid: str | None = None,
    process_name: str = "arbitrary.exe",
) -> NormalizedEvent:
    is_network_event = event_type == "network_connection"
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": _RUN_ID,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": timestamp,
            "ingest_time": timestamp,
            "host_id": _HOST_ID,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-WMI-CONTEXT",
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


def _wmi_events(*, middle_process_name: str) -> tuple[NormalizedEvent, ...]:
    context = _event(
        event_id="evt-context",
        event_type="process_create",
        timestamp=_RUN_START - timedelta(seconds=1),
        process_guid=_CONTEXT_GUID,
        process_name="WmiPrvSE.exe",
    )
    middle = _event(
        event_id="evt-middle",
        event_type="process_create",
        timestamp=_RUN_START + timedelta(seconds=1),
        process_guid=_MIDDLE_GUID,
        parent_process_guid=_CONTEXT_GUID,
        process_name=middle_process_name,
    )
    terminal = _event(
        event_id="evt-terminal",
        event_type="process_create",
        timestamp=_RUN_START + timedelta(seconds=2),
        process_guid=_TERMINAL_GUID,
        parent_process_guid=_MIDDLE_GUID,
        process_name="powershell.exe",
    )
    network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_RUN_START + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
        process_name="powershell.exe",
    )
    return context, middle, terminal, network


def _selector_policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=3,
    )


def _run_pipeline(events: tuple[NormalizedEvent, ...]):
    return run_r1_evidence_pipeline_from_policy(
        events,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        run_start=_RUN_START,
    )


def test_wmi_normal_uses_pre_run_ancestor_only_as_context(tmp_path: Path) -> None:
    # Given
    events = _wmi_events(middle_process_name="wscript.exe")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        run_start=_RUN_START,
    )
    loaded = load_r1_evidence_artifacts(tmp_path)
    summary_payload = json.loads(result.artifact_run.summary_path.read_text(encoding="utf-8"))

    # Then
    selection = result.pipeline_result.selector_result.selection
    assert selection is not None
    assert selection.context_event_ids == ("evt-context",)
    assert result.pipeline_result.lineage_input is not None
    assert result.pipeline_result.lineage_input.context_event_ids == ("evt-context",)
    assert len(result.artifact_run.evidences) == 1
    assert [evidence.evidence_type for evidence in result.artifact_run.evidences] == [
        REMOTE_PROCESS_NETWORK_FOLLOW_ON
    ]
    assert result.artifact_run.evidences[0].event_ids == ["evt-terminal", "evt-network"]
    assert result.artifact_run.evidences[0].timestamp == events[-1].timestamp
    assert summary_payload["lineage_inputs"][0]["context_event_ids"] == ["evt-context"]
    assert loaded.summary == result.artifact_run.summary
    assert loaded.summary.lineage_inputs is not None
    events_by_id = {event.event_id: event for event in events}
    resolved_context = tuple(
        events_by_id[event_id] for event_id in loaded.summary.lineage_inputs[0].context_event_ids
    )
    assert resolved_context[0].raw_ref.source_record_id == "record-evt-context"


def test_wmi_attack_excludes_pre_run_context_from_lineage_evidence(tmp_path: Path) -> None:
    # Given
    events = _wmi_events(middle_process_name="cmd.exe")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        run_start=_RUN_START,
    )
    loaded = load_r1_evidence_artifacts(tmp_path)

    # Then
    evidence_by_type = {evidence.evidence_type: evidence for evidence in loaded.evidences}
    lineage_evidence = evidence_by_type[REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION]
    assert len(loaded.evidences) == 2
    assert result.pipeline_result.selector_result.selection is not None
    assert result.pipeline_result.selector_result.selection.context_event_ids == ("evt-context",)
    assert lineage_evidence.event_ids == ["evt-middle", "evt-terminal"]
    assert "evt-context" not in lineage_evidence.event_ids
    assert lineage_evidence.timestamp == events[2].timestamp
    assert "context_event_ids" not in lineage_evidence.features
    assert evidence_by_type[REMOTE_PROCESS_NETWORK_FOLLOW_ON].event_ids == [
        "evt-terminal",
        "evt-network",
    ]


def test_missing_pre_run_ancestor_keeps_truncated_fail_closed_semantics() -> None:
    # Given
    _, middle, terminal, network = _wmi_events(middle_process_name="cmd.exe")

    # When
    result = _run_pipeline((middle, terminal, network))

    # Then
    assert result.selector_result.selection is None
    assert result.selector_result.diagnostics == ("truncated_lineage",)
    assert result.evidences == ()


def test_pre_run_terminal_like_candidate_is_not_eligible() -> None:
    # Given
    context, middle, terminal, network = _wmi_events(middle_process_name="cmd.exe")
    pre_run_terminal = _event(
        event_id="evt-pre-run-terminal",
        event_type="process_create",
        timestamp=_RUN_START - timedelta(seconds=3),
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
    )
    pre_run_network = _event(
        event_id="evt-pre-run-network",
        event_type="network_connection",
        timestamp=_RUN_START - timedelta(seconds=2),
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
    )

    # When
    result = select_r1_lineage(
        (pre_run_terminal, pre_run_network, context, middle, terminal, network),
        policy=_selector_policy(),
        run_start=_RUN_START,
    )

    # Then
    assert result.selection is not None
    assert result.selection.terminal_event_id == "evt-terminal"
    assert result.selection.context_event_ids == ("evt-context",)


def test_only_pre_run_terminal_like_candidate_fails_closed() -> None:
    # Given
    pre_run_terminal = _event(
        event_id="evt-pre-run-terminal",
        event_type="process_create",
        timestamp=_RUN_START - timedelta(seconds=2),
        process_guid=_TERMINAL_GUID,
    )
    pre_run_network = _event(
        event_id="evt-pre-run-network",
        event_type="network_connection",
        timestamp=_RUN_START - timedelta(seconds=1),
        process_guid=_TERMINAL_GUID,
    )

    # When
    result = select_r1_lineage(
        (pre_run_terminal, pre_run_network),
        policy=_selector_policy(),
        run_start=_RUN_START,
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("no_terminal_candidate",)


def test_multiple_run_terminal_candidates_keep_ambiguity_fail_closed() -> None:
    # Given
    events = _wmi_events(middle_process_name="cmd.exe")
    second_terminal = _event(
        event_id="evt-terminal-2",
        event_type="process_create",
        timestamp=_RUN_START + timedelta(seconds=2),
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
        parent_process_guid=_MIDDLE_GUID,
    )
    second_network = _event(
        event_id="evt-network-2",
        event_type="network_connection",
        timestamp=_RUN_START + timedelta(seconds=3),
        process_guid="{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
    )

    # When
    result = select_r1_lineage(
        (*events, second_terminal, second_network),
        policy=_selector_policy(),
        run_start=_RUN_START,
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("ambiguous_terminal_candidate",)


def test_duplicate_context_process_guid_keeps_duplicate_fail_closed_semantics() -> None:
    # Given
    events = _wmi_events(middle_process_name="cmd.exe")
    duplicate_context = _event(
        event_id="evt-context-duplicate",
        event_type="process_create",
        timestamp=_RUN_START - timedelta(seconds=1),
        process_guid=_CONTEXT_GUID,
        process_name="unrelated-name.exe",
    )

    # When
    result = select_r1_lineage(
        (*events, duplicate_context),
        policy=_selector_policy(),
        run_start=_RUN_START,
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("duplicate_process_guid",)


def test_temporal_inversion_precedes_terminal_selection_with_run_boundary() -> None:
    # Given
    context, middle, terminal, _ = _wmi_events(middle_process_name="cmd.exe")
    early_network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_RUN_START + timedelta(seconds=1),
        process_guid=_TERMINAL_GUID,
    )

    # When
    result = select_r1_lineage(
        (context, middle, terminal, early_network),
        policy=_selector_policy(),
        run_start=_RUN_START,
    )

    # Then
    assert result.selection is None
    assert result.diagnostics == ("temporal_inversion",)


def test_run_start_requires_utc_datetime() -> None:
    # Given
    events = _wmi_events(middle_process_name="cmd.exe")

    # When
    with pytest.raises(ValueError, match="timezone"):
        select_r1_lineage(
            events,
            policy=_selector_policy(),
            run_start=_RUN_START.replace(tzinfo=None),
        )

    # Then
    # A naive boundary never participates in terminal eligibility.
