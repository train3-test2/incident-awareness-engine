from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evaluation.context_inputs import validate_context_inputs
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


@pytest.mark.parametrize("middle", ["cmd.exe", "wscript.exe"])
@pytest.mark.parametrize("fault", [None, "missing", "duplicate", "host", "boundary", "post_run"])
def test_context_input_boundary(tmp_path: Path, middle, fault):
    # Given
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

    # When
    if fault:
        with pytest.raises(ValueError) as error:
            check()
        result = None
    else:
        result = check()

    # Then
    if fault:
        assert str(error.value)
    else:
        assert result == ("evt-context",)


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("direct_context", "direct Evidence includes context"),
        ("missing_direct", "missing direct Event"),
        ("evidence_host", "Evidence Run/host mismatch"),
        ("evidence_time", "Evidence outside Run"),
        ("summary_run", "completed artifact must match Run"),
        ("naive", "boundaries must be UTC"),
        ("offset", "boundaries must be UTC"),
        ("zero_duration", "positive duration"),
    ],
)
def test_rejects_invalid_evidence_and_metadata(tmp_path: Path, fault, message):
    # Given
    events = list(_wmi_events(middle_process_name="cmd.exe"))
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
    start = _RUN_START
    end = start + timedelta(seconds=3)
    first, *rest = artifact.evidences
    # Mutate a loaded object to exercise the evaluation boundary independently
    # of the upstream loader's own validation.
    if fault == "direct_context":
        first = first.model_copy(update={"event_ids": ["evt-context", *first.event_ids]})
    elif fault == "missing_direct":
        first = first.model_copy(update={"event_ids": ["absent"]})
    elif fault == "evidence_host":
        first = first.model_copy(update={"entity_id": "OTHER"})
    elif fault == "evidence_time":
        first = first.model_copy(update={"timestamp": end + timedelta(milliseconds=1)})
    elif fault == "summary_run":
        artifact = replace(artifact, summary=replace(artifact.summary, run_id="RUN-20261010-002"))
    elif fault == "naive":
        start = start.replace(tzinfo=None)
    elif fault == "offset":
        start = start.astimezone(timezone(timedelta(hours=9)))
    elif fault == "zero_duration":
        end = start
    artifact = replace(artifact, evidences=(first, *rest))
    # When
    with pytest.raises(ValueError) as error:
        validate_context_inputs(
            artifact, events, run_id=_RUN_ID, entity_id=_HOST_ID, run_start=start, run_end=end
        )

    # Then
    assert message in str(error.value)


@pytest.mark.parametrize(
    "fault",
    [
        "start_precision",
        "end_precision",
        "truncated",
        "no_selector",
        "no_lineage",
        "empty_lineage",
        "add",
        "remove",
        "no_context",
    ],
)
def test_context_validation_review_regressions(tmp_path, fault):
    # Given
    events = list(_wmi_events(middle_process_name="cmd.exe"))
    start = _RUN_START
    end = start + timedelta(seconds=3)
    extra = events[0].model_copy(
        update={
            "event_id": "unreferenced",
            "process": events[0].process.model_copy(
                update={"process_guid": "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"}
            ),
        }
    )
    if fault == "truncated":
        events = events[1:]
    elif fault == "remove":
        events.append(extra)
    elif fault == "no_context":
        start -= timedelta(seconds=2)
    artifact = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        run_start=start,
    ).artifact_run
    expected = ""
    if fault == "start_precision":
        start += timedelta(microseconds=1)
        expected = "millisecond precision"
    elif fault == "end_precision":
        end += timedelta(microseconds=999)
        expected = "millisecond precision"
    elif fault == "truncated":
        expected = "selected lineage"
    elif fault == "no_selector":
        artifact = replace(artifact, summary=replace(artifact.summary, selector=None))
        expected = "selected lineage"
    elif fault in ("no_lineage", "empty_lineage"):
        artifact = replace(
            artifact,
            summary=replace(artifact.summary, lineage_inputs=None if fault == "no_lineage" else ()),
        )
        expected = "lineage provenance"
    elif fault == "add":
        events.append(extra)
        expected = "Event count"
    elif fault == "remove":
        events.pop()
        expected = "Event count"

    # When
    if expected:
        with pytest.raises(ValueError) as error:
            validate_context_inputs(
                artifact, events, run_id=_RUN_ID, entity_id=_HOST_ID, run_start=start, run_end=end
            )
        result = None
    else:
        result = validate_context_inputs(
            artifact, events, run_id=_RUN_ID, entity_id=_HOST_ID, run_start=start, run_end=end
        )

    # Then
    if expected:
        assert expected in str(error.value)
    else:
        assert result == ()
        assert artifact.summary.selector.status == "selected"
    if fault == "truncated":
        assert "truncated_lineage" in artifact.summary.selector.diagnostics
