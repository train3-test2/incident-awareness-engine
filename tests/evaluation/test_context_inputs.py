from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
)
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_automated import (
    run_and_write_r1_evidence_artifacts_from_policy,
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


from incident_awareness.evaluation.context_inputs import validate_context_inputs


@pytest.mark.parametrize("middle", ["cmd.exe", "wscript.exe"])
@pytest.mark.parametrize("fault", [None, "missing", "duplicate", "host", "boundary", "post_run"])
def test_context_input_boundary(tmp_path: Path, middle, fault):
    events = list(_wmi_events(middle_process_name=middle))
    artifact = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        run_start=_RUN_START,
    ).artifact_run
    end = _RUN_START + timedelta(seconds=3)
    if fault == "missing":
        events = events[1:]
    elif fault == "duplicate":
        events.append(events[0])
    elif fault == "host":
        events[0] = events[0].model_copy(update={"host_id": "OTHER"})
    elif fault == "boundary":
        events[0] = events[0].model_copy(update={"timestamp": _RUN_START})
    elif fault == "post_run":
        events[-1] = events[-1].model_copy(update={"timestamp": end + timedelta(milliseconds=1)})

    def check():
        return validate_context_inputs(
            artifact, events, run_id=_RUN_ID, entity_id=_HOST_ID, run_start=_RUN_START, run_end=end
        )

    if fault:
        with pytest.raises(ValueError):
            check()
    else:
        assert check() == ("evt-context",)
