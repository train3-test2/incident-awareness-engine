"""R1 Pilot run validation over synthetic artifact trees.

Every artifact here is written by hand in the test: the Ground Truth files, the
Manifest, the Sysmon JSONL and the scenario JSON. Nothing is copied from a
collected run, so no run id, host name, account or destination of a real capture
appears, and no test starts a process or touches a network, a VM or AWS.

The two runs are built with the same depth and the same final tool on purpose.
The validator has to tell them apart only by comparing the recorded lineage with
the design of the run type Ground Truth names, never by a process name alone.
"""

import ast
import hashlib
import inspect
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from incident_awareness.collection.r1_pilot_validation import (
    R1PilotValidationReport,
    R1ReportError,
    R1ScenarioError,
    format_report,
    load_r1_pilot_expectation,
    validate_r1_pilot_run,
    write_report,
)

RUN_ID = "RUN-20300102-001"
OTHER_RUN_ID = "RUN-20300102-002"
TARGET_HOST = "TARGET-A"
OTHER_HOST = "TARGET-B"
LAB_CIDR = "10.20.30.0/24"
DESTINATION_IP = "10.20.30.20"
DESTINATION_PORT = 8443
CONFIG_SHA256 = "5f" * 32
START_TIME = "2030-01-02T00:00:00.000Z"
END_TIME = "2030-01-02T00:11:00.000Z"

FAMILY_ID = "remote_management"
VARIATION_ID = "V02"
REPETITION = 1

SERVICE_GUID = "{00000000-0000-0000-0000-0000000000a0}"
SESSION_GUID = "{00000000-0000-0000-0000-0000000000a1}"
INTERMEDIATE_GUID = "{00000000-0000-0000-0000-0000000000a2}"
FINAL_GUID = "{00000000-0000-0000-0000-0000000000a3}"
SECOND_INTERMEDIATE_GUID = "{00000000-0000-0000-0000-0000000000b2}"
SECOND_FINAL_GUID = "{00000000-0000-0000-0000-0000000000b3}"
UNRELATED_GUID = "{00000000-0000-0000-0000-0000000000c1}"

SYSTEM32 = "C:\\Windows\\System32\\"
SESSION_HOST_IMAGE = SYSTEM32 + "wsmprovhost.exe"
WRAPPER_IMAGE = SYSTEM32 + "cmd.exe"
OTHER_INTERMEDIATE_IMAGE = SYSTEM32 + "cscript.exe"
FINAL_IMAGE = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
INTERMEDIATE_IMAGES = {"normal": WRAPPER_IMAGE, "attack": OTHER_INTERMEDIATE_IMAGE}

STEPS = (
    ("session_begin", "remote_session", 0),
    ("prepare", "file_operation", 120),
    ("launch", "process_create", 300),
    ("connect", "network_connection", 480),
    ("session_end", "remote_session", 600),
)
WMI_ACTIONS = (
    ("A01", "invoke", "wmi_process_create", 300),
    ("A02", "observe", "process_observation", 301),
    ("A03", "launch", "process_create", 302),
    ("A04", "connect", "network_connection", 480),
)
RECORDED_TIMES = (
    "2030-01-02T00:00:02.000Z",
    "2030-01-02T00:02:00.100Z",
    "2030-01-02T00:05:00.200Z",
    "2030-01-02T00:08:00.300Z",
    "2030-01-02T00:10:00.400Z",
)
ACTION_PREFIX = {"normal": "N", "attack": "A"}

# The reference of an attack run: the EID 1 of its session host, created right
# after the first action was started (RECORDED_TIMES[0]) and long enough before
# END_TIME for the evaluation horizon.
SESSION_UTC_TIME = "2030-01-02 00:00:02.050"
REFERENCE_TIME = "2030-01-02T00:00:02.050Z"
SESSION_RECORD_ID = "1"
POLICY_VERSION = "r1-ref-v0.1"
HORIZON_SEC = 600

# Passed as `protocol` to leave the Protocol field out of an EID 3.
OMITTED = object()

SCHEMA_VERSIONS = {
    "run_metadata": "v0.2",
    "event": "v0.3",
    "evidence": "v0.2",
    "fast_hit": "v0.2",
    "detection_result": "v0.2",
    "fusion_result": "v0.3",
    "decision_result": "v0.2",
    "execution_record": "v0.1",
    "evaluation_input": "v0.1",
}

Row = tuple[str, str, str, str]


def action_id(run_type: str, index: int) -> str:
    return f"{ACTION_PREFIX[run_type]}{index + 1:02d}"


def scenario(
    *,
    destination: bool = True,
    target_host: str | None = TARGET_HOST,
    final_image: str = "powershell.exe",
    normal_image: str = "cmd.exe",
    attack_image: str = "cscript.exe",
    session_host_image: str = "wsmprovhost.exe",
    family_id: str = FAMILY_ID,
    variation_id: str = VARIATION_ID,
    repetition: int = REPETITION,
    attack_reference: object = "A01",
    normal_reference: object = None,
    horizon: object = HORIZON_SEC,
    dataset_tier: object = "pilot",
    policy_version: object = POLICY_VERSION,
) -> dict:
    """The part of a rendered R1 scenario the validator reads.

    `planned_lineage` is what each run is planned to leave. The attack run names
    its reference action; the normal run names none. `dataset_tier` is the tier
    the scenario states for its Pair; `OMITTED` leaves the field out.
    """
    references = {"normal": normal_reference, "attack": attack_reference}
    rendered = {
        "scenario_version": "v1",
        "scenario_id": "R1",
        "family_id": family_id,
        "variation_id": variation_id,
        "repetition": repetition,
        "dataset_tier": dataset_tier,
        "run_metadata": {"target_host": target_host, "reference_policy_version": policy_version},
        "run_length": {"observation_sec": None, "evaluation_horizon_sec": horizon},
        "internal_connection": {
            "required": True,
            "target": DESTINATION_IP if destination else None,
            "port": DESTINATION_PORT if destination else None,
            "protocol": "TCP",
            "lab_cidr": LAB_CIDR if destination else None,
            "max_attempts": 1,
        },
        "planned_lineage": {
            "session_host": {"image": session_host_image},
            "final_tool": {"image": final_image},
            "intermediate": {
                "normal": {"image": normal_image},
                "attack": {"image": attack_image},
            },
        },
        "runs": {
            run_type: {
                "run_type": run_type,
                "reference_action_id": references[run_type],
                "actions": [
                    {
                        "action_id": action_id(run_type, index),
                        "step": step,
                        "action_type": action_type,
                        "offset_sec": offset_sec,
                        "description": "synthetic action",
                    }
                    for index, (step, action_type, offset_sec) in enumerate(STEPS)
                ],
            }
            for run_type in ("normal", "attack")
        },
    }
    if dataset_tier is OMITTED:
        del rendered["dataset_tier"]
    return rendered


def wmi_scenario() -> dict:
    """확정된 A01~A04 WMI timeline을 가진 synthetic scenario를 만든다."""
    rendered = scenario(
        family_id="wmi_management",
        attack_image="cmd.exe",
        session_host_image="WmiPrvSE.exe",
        policy_version="wmi-ref-v0.1",
    )
    rendered["runs"]["attack"]["actions"] = [
        {
            "action_id": action_id,
            "step": step,
            "action_type": action_type,
            "offset_sec": offset_sec,
            "description": "synthetic WMI action",
        }
        for action_id, step, action_type, offset_sec in WMI_ACTIONS
    ]
    return rendered


def wmi_recorded_rows() -> list[Row]:
    """확정된 WMI action 네 개의 synthetic execution record를 만든다."""
    return [
        (
            RUN_ID,
            action_id,
            f"2030-01-02T00:{offset_sec // 60:02d}:{offset_sec % 60:02d}.000Z",
            action_type,
        )
        for action_id, _, action_type, offset_sec in WMI_ACTIONS
    ]


def process_event(
    *,
    record_id: int,
    guid: str,
    parent_guid: str | None,
    image: str,
    host: str = TARGET_HOST,
    utc_time: str | None = None,
) -> dict:
    """One synthetic Sysmon EID 1 in the shape the runner writes.

    The session host is created when the session is opened, the other processes
    at the launch; `utc_time` replaces that.
    """
    if utc_time is None:
        utc_time = SESSION_UTC_TIME if guid == SESSION_GUID else "2030-01-02 00:05:00.250"
    event_data: dict[str, object] = {
        "UtcTime": utc_time,
        "ProcessGuid": guid,
        "Image": image,
    }
    if parent_guid is not None:
        event_data["ParentProcessGuid"] = parent_guid

    return {
        "RecordId": record_id,
        "EventId": 1,
        "TimeCreated": "2030-01-02T00:05:00.250Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "Provider": "Microsoft-Windows-Sysmon",
        "EventData": event_data,
    }


def connection_event(
    *,
    record_id: int,
    guid: str,
    host: str = TARGET_HOST,
    destination_ip: str = DESTINATION_IP,
    destination_port: str = str(DESTINATION_PORT),
    protocol: object = "tcp",
) -> dict:
    """One synthetic Sysmon EID 3 in the shape the runner writes.

    `protocol` replaces the Protocol value and `OMITTED` leaves the field out.
    """
    event_data: dict[str, object] = {
        "UtcTime": "2030-01-02 00:08:00.350",
        "ProcessGuid": guid,
        "Image": FINAL_IMAGE,
        "Protocol": protocol,
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port,
    }
    if protocol is OMITTED:
        del event_data["Protocol"]

    return {
        "RecordId": record_id,
        "EventId": 3,
        "TimeCreated": "2030-01-02T00:08:00.350Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "Provider": "Microsoft-Windows-Sysmon",
        "EventData": event_data,
    }


def run_events(run_type: str, *, connect: bool = True, host: str = TARGET_HOST) -> list[dict]:
    """Session host -> the intermediate of this run type -> the final tool, then one connection.

    The parent of the session host was started before the run and is never in
    the capture, as on a real target.
    """
    events = [
        process_event(
            record_id=1,
            guid=SESSION_GUID,
            parent_guid=SERVICE_GUID,
            image=SESSION_HOST_IMAGE,
            host=host,
            utc_time=SESSION_UTC_TIME,
        ),
        process_event(
            record_id=2,
            guid=INTERMEDIATE_GUID,
            parent_guid=SESSION_GUID,
            image=INTERMEDIATE_IMAGES[run_type],
            host=host,
        ),
        process_event(
            record_id=3,
            guid=FINAL_GUID,
            parent_guid=INTERMEDIATE_GUID,
            image=FINAL_IMAGE,
            host=host,
        ),
    ]
    if connect:
        events.append(connection_event(record_id=4, guid=FINAL_GUID, host=host))
    return events


def recorded_rows(run_type: str, *, connect: bool = True) -> list[Row]:
    """(run_id, action_id, timestamp, action_type) for every recorded action."""
    return [
        (RUN_ID, action_id(run_type, index), RECORDED_TIMES[index], action_type)
        for index, (step, action_type, _) in enumerate(STEPS)
        if connect or step != "connect"
    ]


def jsonl_text(events: list[dict]) -> str:
    return "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events)


def write_manifest(root: Path, run_id: str = RUN_ID) -> None:
    """Describe the two telemetry files as they are on disk right now."""
    telemetry_dir = root / "raw" / RUN_ID / "telemetry"
    vm_dir = "C:\\R1\\data\\raw\\" + run_id + "\\telemetry"
    manifest = {
        "run_id": run_id,
        "generated_at": "2030-01-02T00:11:05.000Z",
        "config_version": None,
        "sysmon": {
            "config_version": "sysmonconfig-sample-v0.1",
            "config_sha256": CONFIG_SHA256,
            "config_hash": "SHA256=" + CONFIG_SHA256.upper(),
            "hashing_algorithms": "SHA256",
        },
        "items": [
            {
                "raw_log_id": "RAW-001",
                "path": vm_dir + "\\sysmon-0001.evtx",
                "sha256": hashlib.sha256(
                    (telemetry_dir / "sysmon-0001.evtx").read_bytes()
                ).hexdigest(),
                "layer": "raw_telemetry",
                "source": "sysmon",
            },
            {
                "raw_log_id": "RAW-002",
                "path": vm_dir + "\\sysmon-0001.jsonl",
                "sha256": hashlib.sha256(
                    (telemetry_dir / "sysmon-0001.jsonl").read_bytes()
                ).hexdigest(),
                "layer": "raw_telemetry",
                "source": "sysmon",
                "derived_from": vm_dir + "\\sysmon-0001.evtx",
            },
        ],
    }
    (root / "raw" / RUN_ID / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def build_run(
    base: Path,
    *,
    run_type: str = "normal",
    events: list[dict] | None = None,
    jsonl: str | None = None,
    scenario_body: dict | None = None,
    rows: list[Row] | None = None,
    metadata: dict | None = None,
    rehearsal: bool = False,
    connect: bool = True,
) -> tuple[Path, Path]:
    """Write one complete artifact set and the scenario rendered for it.

    Returns the artifact root and the scenario path. `connect=False` is the
    lineage-only rehearsal: no destination in the scenario, no connection action
    and no EID 3.
    """
    base.mkdir(parents=True, exist_ok=True)
    root = base / "_rehearsal" if rehearsal else base / "data"
    telemetry_dir = root / "raw" / RUN_ID / "telemetry"
    ground_truth_dir = root / "ground_truth" / RUN_ID
    telemetry_dir.mkdir(parents=True)
    ground_truth_dir.mkdir(parents=True)
    if rehearsal:
        (root / "REHEARSAL.txt").write_text("Rehearsal output.", encoding="utf-8")

    (telemetry_dir / "sysmon-0001.evtx").write_bytes(bytes(range(256)) * 4)
    if jsonl is None:
        jsonl = jsonl_text(run_events(run_type, connect=connect) if events is None else events)
    (telemetry_dir / "sysmon-0001.jsonl").write_text(jsonl, encoding="utf-8", newline="\n")

    if rows is None:
        rows = recorded_rows(run_type, connect=connect)
    header = "run_id,action_id,timestamp,action_type,description\n"
    body = "".join(
        f'"{run_id}","{recorded_id}","{timestamp}","{action_type}","synthetic action"\n'
        for run_id, recorded_id, timestamp, action_type in rows
    )
    (ground_truth_dir / "execution_record.csv").write_text(header + body, encoding="utf-8")

    run_metadata = {
        "run_id": RUN_ID,
        "scenario_id": "R1",
        "run_type": run_type,
        "target_host": TARGET_HOST,
        "start_time": START_TIME,
        "end_time": END_TIME,
        "family_id": FAMILY_ID,
        "variation_id": VARIATION_ID,
        "repetition": REPETITION,
        # An attack run records its reference: the EID 1 of its session host.
        "reference_time": REFERENCE_TIME if run_type == "attack" else None,
        "reference_action_id": "A01" if run_type == "attack" else None,
        "reference_source_event_id": SESSION_RECORD_ID if run_type == "attack" else None,
        "vm_snapshot": "synthetic-snapshot",
        "sysmon_config_version": "sysmonconfig-sample-v0.1",
        "detector_set_version": None,
        "scenario_version": "v1",
        "schema_versions": SCHEMA_VERSIONS,
        "reference_policy_version": POLICY_VERSION,
    }
    run_metadata.update(metadata or {})
    (ground_truth_dir / "run_metadata.json").write_text(
        json.dumps(run_metadata, indent=2), encoding="utf-8"
    )

    write_manifest(root)

    scenario_path = base / "scenario.json"
    scenario_path.write_text(
        json.dumps(scenario(destination=connect) if scenario_body is None else scenario_body),
        encoding="utf-8",
    )
    write_trace(root, scenario_path.read_bytes(), rehearsal=rehearsal)
    return root, scenario_path


def trace_dir(root: Path) -> Path:
    return root / "operator_trace" / RUN_ID


def stated_tier(scenario_bytes: bytes) -> object:
    """The tier the runner copies to the trace: the one the scenario states.

    A scenario that cannot be read or states none gets `pilot`, so that the tests
    about such a scenario do not depend on what the trace says.
    """
    try:
        return json.loads(scenario_bytes).get("dataset_tier", "pilot")
    except (ValueError, AttributeError):
        return "pilot"


def write_trace(
    root: Path, scenario_bytes: bytes, *, rehearsal: bool = False, **stated: object
) -> None:
    """Write the operator trace the runner leaves for a run that executed these bytes.

    The scenario copy and the record are written the way the runner writes them:
    the tier of the record is the one the scenario states. `stated` replaces
    values of the record, for the tests that break it.
    """
    directory = trace_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "scenario.json").write_bytes(scenario_bytes)
    record = {
        "trace_version": "v1",
        "run_id": RUN_ID,
        "dataset_tier": stated_tier(scenario_bytes),
        "mode": "rehearsal" if rehearsal else "collection",
        "scenario_sha256": hashlib.sha256(scenario_bytes).hexdigest(),
    }
    record.update(stated)
    (directory / "r1_run_trace.json").write_text(json.dumps(record, indent=4), encoding="utf-8")


def validate(run: tuple[Path, Path], *, rehearsal: bool = False) -> R1PilotValidationReport:
    # The validator is given no tier: it reads the one the scenario states.
    root, scenario_path = run
    return validate_r1_pilot_run(
        artifact_root=root,
        run_id=RUN_ID,
        scenario_path=scenario_path,
        rehearsal=rehearsal,
    )


def test_wmi_reference_uses_a01_attributed_intermediate_eid1(tmp_path: Path) -> None:
    # Given
    reference_time = "2030-01-02T00:05:00.250Z"
    events = run_events("normal")
    events[0]["EventData"]["Image"] = SYSTEM32 + "WmiPrvSE.exe"
    run = build_run(
        tmp_path,
        run_type="attack",
        scenario_body=wmi_scenario(),
        events=events,
        rows=wmi_recorded_rows(),
        metadata={
            "family_id": "wmi_management",
            "reference_time": reference_time,
            "reference_source_event_id": "2",
            "reference_policy_version": "wmi-ref-v0.1",
            "end_time": "2030-01-02T00:16:00.000Z",
        },
    )

    # When
    report = validate(run)

    # Then
    assert report.ok, errors_of(report)
    assert any("A01-attributed intermediate" in check for check in report.checks)


def test_wmi_reference_before_a01_is_rejected(tmp_path: Path) -> None:
    # Given
    events = run_events("normal")
    events[0]["EventData"]["Image"] = SYSTEM32 + "WmiPrvSE.exe"
    events[1]["EventData"]["UtcTime"] = "2030-01-02 00:04:59.999"
    run = build_run(
        tmp_path,
        run_type="attack",
        scenario_body=wmi_scenario(),
        events=events,
        rows=wmi_recorded_rows(),
        metadata={
            "family_id": "wmi_management",
            "reference_time": "2030-01-02T00:04:59.999Z",
            "reference_source_event_id": "2",
            "reference_policy_version": "wmi-ref-v0.1",
            "end_time": "2030-01-02T00:16:00.000Z",
        },
    )

    # When
    report = validate(run)

    # Then
    assert not report.ok
    assert "earlier than the recorded start of A01" in errors_of(report)


def test_wmi_scenario_accepts_a01_reference_without_session_begin(tmp_path: Path) -> None:
    # Given
    scenario_path = tmp_path / "wmi-scenario.json"
    scenario_path.write_text(json.dumps(wmi_scenario()), encoding="utf-8")

    # When
    expectation = load_r1_pilot_expectation(scenario_path, "attack")

    # Then
    assert expectation.reference_action_id == "A01"
    assert [action.action_id for action in expectation.actions] == ["A01", "A02", "A03", "A04"]
    assert all(action.step != "session_begin" for action in expectation.actions)


def test_wmi_scenario_rejects_reference_action_other_than_a01(tmp_path: Path) -> None:
    # Given
    body = wmi_scenario()
    body["runs"]["attack"]["reference_action_id"] = "A02"
    scenario_path = tmp_path / "wmi-wrong-reference.json"
    scenario_path.write_text(json.dumps(body), encoding="utf-8")

    # When
    with pytest.raises(R1ScenarioError, match="must be the WMI action 'A01'"):
        load_r1_pilot_expectation(scenario_path, "attack")

    # Then
    assert body["runs"]["attack"]["reference_action_id"] == "A02"


def test_wmi_scenario_rejects_noncanonical_a01_action_type(tmp_path: Path) -> None:
    # Given
    body = wmi_scenario()
    body["runs"]["attack"]["actions"][0]["action_type"] = "process_create"
    scenario_path = tmp_path / "wmi-wrong-action-type.json"
    scenario_path.write_text(json.dumps(body), encoding="utf-8")

    # When
    with pytest.raises(R1ScenarioError, match="A01 must exist exactly once"):
        load_r1_pilot_expectation(scenario_path, "attack")

    # Then
    assert body["runs"]["attack"]["actions"][0]["action_type"] == "process_create"


def rewrite_json(path: Path, mutate: Callable[[dict], None]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def errors_of(report: R1PilotValidationReport) -> str:
    return "\n".join(report.errors)


# ---------------------------------------------------------------------------
# The two designed runs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("run_type", "intermediate_image"),
    [("normal", WRAPPER_IMAGE), ("attack", OTHER_INTERMEDIATE_IMAGE)],
)
def test_run_with_its_designed_three_step_lineage_passes(
    tmp_path: Path, run_type: str, intermediate_image: str
) -> None:
    # Given: a complete run whose telemetry holds the lineage of its run type
    run = build_run(tmp_path, run_type=run_type)

    # When
    report = validate(run)

    # Then: the lineage is reported by host and ProcessGuid, closest first
    assert report.ok, report.errors
    assert report.run_type == run_type
    assert report.lineage is not None
    assert report.lineage.host == TARGET_HOST
    assert report.lineage.process_guids == (FINAL_GUID, INTERMEDIATE_GUID, SESSION_GUID)
    assert report.lineage.images == (FINAL_IMAGE, intermediate_image, SESSION_HOST_IMAGE)
    assert [connection.record_id for connection in report.lineage.connections] == ["4"]
    assert report.lineage.connections[0].key.process_guid == FINAL_GUID

    # And: what the lineage validator verified is passed on in its own words
    expected_chain = f"{INTERMEDIATE_GUID} -> {SESSION_GUID}"
    assert f"the recorded parents match the expected chain: {expected_chain}" in report.checks
    assert "1 EID 3 record(s) carry the anchor host and ProcessGuid" in report.checks
    assert (
        f"a linked connection reaches the expected destination {DESTINATION_IP}:{DESTINATION_PORT}"
        in report.checks
    )


def test_both_runs_end_in_the_same_final_tool_at_the_same_depth(tmp_path: Path) -> None:
    # Given: one run of each type
    normal = validate(build_run(tmp_path / "normal", run_type="normal"))
    attack = validate(build_run(tmp_path / "attack", run_type="attack"))

    # Then: only the intermediate differs between the two recorded lineages
    assert normal.ok and attack.ok
    assert normal.lineage is not None and attack.lineage is not None
    assert len(normal.lineage.nodes) == len(attack.lineage.nodes) == 3
    assert normal.lineage.images[0] == attack.lineage.images[0]
    assert normal.lineage.images[2] == attack.lineage.images[2]
    assert normal.lineage.images[1] != attack.lineage.images[1]


@pytest.mark.parametrize(
    ("run_type", "telemetry_of"),
    [("normal", "attack"), ("attack", "normal")],
)
def test_run_holding_the_lineage_of_the_other_run_type_fails(
    tmp_path: Path, run_type: str, telemetry_of: str
) -> None:
    # Given: Ground Truth names one run type, the telemetry holds the other lineage
    run = build_run(tmp_path, run_type=run_type, events=run_events(telemetry_of))

    # When
    report = validate(run)

    # Then: the mismatch with the design is the failure, and no lineage is recorded
    assert not report.ok
    assert "no final tool instance has the lineage this run was designed with" in errors_of(report)
    assert report.lineage is None


def test_tool_names_come_from_the_scenario_not_from_the_validator(tmp_path: Path) -> None:
    # Given: a scenario and a capture that use other tool names for every step
    body = scenario(
        final_image="admin_tool.exe",
        normal_image="approved_wrapper.exe",
        attack_image="other_middle.exe",
        session_host_image="session_host.exe",
    )
    events = [
        process_event(
            record_id=1,
            guid=SESSION_GUID,
            parent_guid=SERVICE_GUID,
            image="C:\\synthetic\\session_host.exe",
        ),
        process_event(
            record_id=2,
            guid=INTERMEDIATE_GUID,
            parent_guid=SESSION_GUID,
            image="C:\\synthetic\\other_middle.exe",
        ),
        process_event(
            record_id=3,
            guid=FINAL_GUID,
            parent_guid=INTERMEDIATE_GUID,
            image="C:\\synthetic\\Admin_Tool.EXE",
        ),
        connection_event(record_id=4, guid=FINAL_GUID),
    ]

    # When
    report = validate(build_run(tmp_path, run_type="attack", events=events, scenario_body=body))

    # Then: the run passes against its own scenario, whatever the names are
    assert report.ok, report.errors


def test_validation_does_not_depend_on_the_order_of_the_jsonl_lines(tmp_path: Path) -> None:
    # Given: the same records in file order and in reverse order
    in_order = validate(build_run(tmp_path / "in_order", run_type="attack"))
    events = list(reversed(run_events("attack")))
    reversed_order = validate(build_run(tmp_path / "reversed", run_type="attack", events=events))

    # Then: the report, including the lineage record, is the same text
    assert in_order.ok and reversed_order.ok
    assert format_report(in_order) == format_report(reversed_order)


def test_same_run_validated_twice_gives_the_same_report(tmp_path: Path) -> None:
    run = build_run(tmp_path)

    assert format_report(validate(run)) == format_report(validate(run))


# ---------------------------------------------------------------------------
# One run_id across the four artifacts
# ---------------------------------------------------------------------------


def test_run_id_is_one_value_across_the_four_artifacts(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path))

    assert report.ok, report.errors
    assert f"every execution_record row carries run_id {RUN_ID}" in report.checks
    assert "2 manifest item hash(es) match the local artifacts" in report.checks


def test_run_metadata_of_another_run_id_fails(tmp_path: Path) -> None:
    run = build_run(tmp_path, metadata={"run_id": OTHER_RUN_ID})

    report = validate(run)

    assert not report.ok
    assert f"run_metadata.json run_id is '{OTHER_RUN_ID}'" in errors_of(report)


def test_execution_record_row_of_another_run_id_fails(tmp_path: Path) -> None:
    rows = recorded_rows("normal")
    rows[2] = (OTHER_RUN_ID, *rows[2][1:])

    report = validate(build_run(tmp_path, rows=rows))

    assert not report.ok
    assert "execution_record.csv carries run_id(s) other than" in errors_of(report)


def test_manifest_of_another_run_id_fails(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    write_manifest(run[0], run_id=OTHER_RUN_ID)

    report = validate(run)

    assert not report.ok
    assert f"manifest.json run_id is '{OTHER_RUN_ID}'" in errors_of(report)
    assert "path rejected" in errors_of(report)


def test_manifest_hash_that_does_not_match_the_jsonl_fails(tmp_path: Path) -> None:
    # Given: the JSONL changes after the Manifest was written
    run = build_run(tmp_path)
    jsonl_path = run[0] / "raw" / RUN_ID / "telemetry" / "sysmon-0001.jsonl"
    jsonl_path.write_text(
        jsonl_text([*run_events("normal"), connection_event(record_id=9, guid=FINAL_GUID)]),
        encoding="utf-8",
        newline="\n",
    )

    report = validate(run)

    assert not report.ok
    assert "sha256 mismatch for sysmon-0001.jsonl" in errors_of(report)


def test_missing_artifact_stops_the_validation(tmp_path: Path) -> None:
    run = build_run(tmp_path)
    (run[0] / "ground_truth" / RUN_ID / "run_metadata.json").unlink()

    report = validate(run)

    assert not report.ok
    assert all("required artifact is missing" in error for error in report.errors)
    assert report.lineage is None


@pytest.mark.parametrize("run_id", ["../" + RUN_ID, "RUN-2030-1", "RUN-20301340-001", ""])
def test_rejected_run_id_touches_nothing(tmp_path: Path, run_id: str) -> None:
    root, scenario_path = build_run(tmp_path)

    report = validate_r1_pilot_run(artifact_root=root, run_id=run_id, scenario_path=scenario_path)

    assert not report.ok
    assert len(report.errors) == 1
    assert report.checks == []


# ---------------------------------------------------------------------------
# Lineage failures are passed on from the lineage validator
# ---------------------------------------------------------------------------


def test_duplicate_process_guid_fails_closed(tmp_path: Path) -> None:
    # Given: a second EID 1 for the final tool's host and ProcessGuid
    events = [
        *run_events("normal"),
        process_event(record_id=5, guid=FINAL_GUID, parent_guid=UNRELATED_GUID, image=FINAL_IMAGE),
    ]

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "duplicate EID 1 for the same host and ProcessGuid" in errors_of(report)
    assert report.lineage is None


def test_parent_loop_fails_closed(tmp_path: Path) -> None:
    # Given: the session host names the final tool as its parent
    events = run_events("normal")
    events[0] = process_event(
        record_id=1, guid=SESSION_GUID, parent_guid=FINAL_GUID, image=SESSION_HOST_IMAGE
    )

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "the parent chain returns to a process already on the walk" in errors_of(report)
    assert report.lineage is None


@pytest.mark.parametrize(
    ("dropped_index", "missing_guid"),
    [(0, SESSION_GUID), (1, INTERMEDIATE_GUID)],
)
def test_missing_required_parent_fails_closed(
    tmp_path: Path, dropped_index: int, missing_guid: str
) -> None:
    # Given: the EID 1 of the session host, or of the intermediate, is not in the capture
    events = run_events("attack")
    del events[dropped_index]

    report = validate(build_run(tmp_path, run_type="attack", events=events))

    assert not report.ok
    assert "a required parent link is missing from this capture" in errors_of(report)
    assert f"ProcessGuid={missing_guid}" in errors_of(report)
    assert report.lineage is None


def test_connection_made_by_another_process_fails(tmp_path: Path) -> None:
    # Given: the only EID 3 to the destination carries the intermediate's ProcessGuid
    events = run_events("normal", connect=False)
    events.append(connection_event(record_id=4, guid=INTERMEDIATE_GUID))

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "no EID 3 record carries the anchor host and ProcessGuid" in errors_of(report)
    assert report.lineage is None


def test_connection_recorded_on_another_host_fails(tmp_path: Path) -> None:
    # Given: the EID 3 carries the final tool's ProcessGuid but another Computer
    events = run_events("normal", connect=False)
    events.append(connection_event(record_id=4, guid=FINAL_GUID, host=OTHER_HOST))

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "no EID 3 record carries the anchor host and ProcessGuid" in errors_of(report)


@pytest.mark.parametrize(
    ("destination_ip", "destination_port"),
    [("10.20.30.99", str(DESTINATION_PORT)), (DESTINATION_IP, "8444")],
)
def test_connection_to_another_destination_fails(
    tmp_path: Path, destination_ip: str, destination_port: str
) -> None:
    events = run_events("attack", connect=False)
    events.append(
        connection_event(
            record_id=4,
            guid=FINAL_GUID,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )
    )

    report = validate(build_run(tmp_path, run_type="attack", events=events))

    assert not report.ok
    assert "reaches the expected destination" in errors_of(report)
    assert report.lineage is None


def run_with_connections(run_type: str, *protocols: object) -> list[dict]:
    """The lineage of a run, then one EID 3 of the final tool per given Protocol.

    Every connection carries the final tool's ProcessGuid, the approved address
    and the approved port; only the Protocol differs. RecordIds start at 4.
    """
    events = run_events(run_type, connect=False)
    events.extend(
        connection_event(record_id=4 + index, guid=FINAL_GUID, protocol=protocol)
        for index, protocol in enumerate(protocols)
    )
    return events


@pytest.mark.parametrize("protocol", ["tcp", "TCP", "Tcp"])
def test_connection_recorded_as_tcp_passes_whatever_its_case(tmp_path: Path, protocol: str) -> None:
    report = validate(build_run(tmp_path, events=run_with_connections("normal", protocol)))

    assert report.ok, report.errors
    assert report.lineage is not None
    assert [connection.protocol for connection in report.lineage.connections] == [protocol]
    assert (
        f"a linked connection to the expected destination {DESTINATION_IP}:{DESTINATION_PORT} "
        "was recorded with the expected Protocol tcp"
    ) in report.checks


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_connection_recorded_as_udp_fails(tmp_path: Path, run_type: str) -> None:
    # Given: the final tool's EID 3 reaches the approved address and port, as udp
    run = build_run(tmp_path, run_type=run_type, events=run_with_connections(run_type, "udp"))

    report = validate(run)

    # Then: the host, the ProcessGuid, the address and the port do not make it
    # the connection of the run
    assert not report.ok
    assert report.errors == [
        (
            "no connection with the anchor host and ProcessGuid to the expected destination "
            f"{DESTINATION_IP}:{DESTINATION_PORT} was recorded with the expected Protocol tcp: "
            "the 1 EID 3 record(s) found carry Protocol udp"
        )
    ]
    assert report.lineage is None
    assert "PASS" not in format_report(report)


@pytest.mark.parametrize(
    "protocol", [OMITTED, None, "", "   ", 6], ids=["omitted", "null", "empty", "blank", "number"]
)
def test_connection_without_a_protocol_fails(tmp_path: Path, protocol: object) -> None:
    report = validate(build_run(tmp_path, events=run_with_connections("normal", protocol)))

    assert not report.ok
    assert len(report.errors) == 1
    assert "was recorded with the expected Protocol tcp" in report.errors[0]
    assert report.errors[0].endswith("the 1 EID 3 record(s) found carry Protocol (missing)")
    assert report.lineage is None


@pytest.mark.parametrize(
    "protocols",
    [("udp", "tcp", OMITTED), ("tcp", "udp", OMITTED), (OMITTED, "udp", "tcp")],
    ids=["tcp-second", "tcp-first", "tcp-last"],
)
def test_only_the_tcp_record_is_kept_as_the_connection_of_the_run(
    tmp_path: Path, protocols: tuple[object, ...]
) -> None:
    # Given: three records of the final tool to the approved address and port,
    # of which one is tcp
    run = build_run(tmp_path, run_type="attack", events=run_with_connections("attack", *protocols))

    report = validate(run)

    # Then: the run passes on the tcp record, and the lineage record holds it alone
    assert report.ok, report.errors
    assert "3 EID 3 record(s) carry the anchor host and ProcessGuid" in report.checks
    assert report.lineage is not None
    kept = report.lineage.connections
    assert [connection.record_id for connection in kept] == [str(4 + protocols.index("tcp"))]
    assert [connection.protocol for connection in kept] == ["tcp"]

    text = format_report(report)
    assert text.count("  connection: ") == 1
    assert f"connection: {DESTINATION_IP}:{DESTINATION_PORT} tcp" in text
    assert "udp" not in text
    assert "(no Protocol)" not in text


def test_udp_record_does_not_stand_in_for_a_tcp_record_of_another_process(tmp_path: Path) -> None:
    # Given: the intermediate made the tcp connection and the final tool only a udp one
    events = run_with_connections("normal", "udp")
    events.append(connection_event(record_id=5, guid=INTERMEDIATE_GUID, protocol="tcp"))

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "the 1 EID 3 record(s) found carry Protocol udp" in errors_of(report)
    assert report.lineage is None


def test_two_instances_with_the_designed_lineage_are_ambiguous(tmp_path: Path) -> None:
    # Given: a second intermediate and final tool under the same session host
    events = [
        *run_events("normal"),
        process_event(
            record_id=5,
            guid=SECOND_INTERMEDIATE_GUID,
            parent_guid=SESSION_GUID,
            image=WRAPPER_IMAGE,
        ),
        process_event(
            record_id=6,
            guid=SECOND_FINAL_GUID,
            parent_guid=SECOND_INTERMEDIATE_GUID,
            image=FINAL_IMAGE,
        ),
    ]

    report = validate(build_run(tmp_path, events=events))

    assert not report.ok
    assert "a run starts exactly one" in errors_of(report)
    assert report.lineage is None


def test_final_tool_instance_with_another_lineage_is_not_the_runs_own(tmp_path: Path) -> None:
    # Given: one more instance of the same Image, started by something else, that
    # also connects to the destination
    events = [
        *run_events("normal"),
        process_event(
            record_id=5, guid=UNRELATED_GUID, parent_guid=SERVICE_GUID, image=FINAL_IMAGE
        ),
        connection_event(record_id=6, guid=UNRELATED_GUID),
    ]

    report = validate(build_run(tmp_path, events=events))

    # Then: the Image alone decides nothing; the run's own instance is the one
    # with the designed lineage
    assert report.ok, report.errors
    assert report.lineage is not None
    assert report.lineage.process_guids[0] == FINAL_GUID
    assert [connection.record_id for connection in report.lineage.connections] == ["4"]


def test_final_tool_recorded_on_another_host_is_not_found(tmp_path: Path) -> None:
    run = build_run(tmp_path, events=run_events("normal", host=OTHER_HOST))

    report = validate(run)

    assert not report.ok
    assert "holds no EID 1 of the final tool" in errors_of(report)
    assert OTHER_HOST in errors_of(report)


@pytest.mark.parametrize(
    "jsonl",
    [
        "",
        "not json\n",
        jsonl_text(run_events("normal")) + "\n",
        jsonl_text([{"RecordId": 1, "EventId": 1, "Computer": TARGET_HOST, "EventData": {}}]),
    ],
)
def test_unreadable_capture_is_reported_by_the_lineage_reader(tmp_path: Path, jsonl: str) -> None:
    report = validate(build_run(tmp_path, jsonl=jsonl))

    assert not report.ok
    assert "sysmon-0001.jsonl" in errors_of(report)
    assert report.lineage is None


# ---------------------------------------------------------------------------
# Ground Truth
# ---------------------------------------------------------------------------


def test_normal_run_with_a_reference_is_refused(tmp_path: Path) -> None:
    run = build_run(tmp_path, metadata={"reference_action_id": "N01"})

    report = validate(run)

    assert not report.ok
    assert "records ['reference_action_id']" in errors_of(report)


def test_normal_run_records_no_reference(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path))

    assert report.ok, report.errors
    assert "run_metadata.json records no reference, as a normal run does" in report.checks


def test_attack_run_reference_is_the_record_of_its_session_host(tmp_path: Path) -> None:
    # Given: an attack run whose reference names the EID 1 of the session host of its lineage
    report = validate(build_run(tmp_path, run_type="attack"))

    # Then: the three fields are traced to that one record of the original JSONL
    assert report.ok, report.errors
    assert "run_metadata.json records the reference action the scenario names: A01" in report.checks
    assert (
        "the reference of the run is the EID 1 of its session host: RecordId 1, ProcessGuid "
        f"{SESSION_GUID}, EventData.UtcTime {SESSION_UTC_TIME}"
    ) in report.checks
    assert (
        "the collection reached the evaluation horizon: end_time is 657.950 s after "
        "reference_time, the horizon is 600 s"
    ) in report.checks


@pytest.mark.parametrize(
    "absent",
    [
        ("reference_time",),
        ("reference_action_id",),
        ("reference_source_event_id",),
        ("reference_time", "reference_action_id", "reference_source_event_id"),
    ],
)
def test_attack_run_without_its_reference_is_refused(
    tmp_path: Path, absent: tuple[str, ...]
) -> None:
    run = build_run(tmp_path, run_type="attack", metadata=dict.fromkeys(absent))

    report = validate(run)

    assert report.errors == [
        (
            f"run_metadata.json of an attack run does not record {list(absent)}; its reference is "
            "the action A01 (docs/scenarios/r1.md section 4-2)"
        )
    ]


def test_attack_run_naming_another_reference_action_is_refused(tmp_path: Path) -> None:
    run = build_run(tmp_path, run_type="attack", metadata={"reference_action_id": "A03"})

    report = validate(run)

    assert report.errors == [
        "run_metadata.json reference_action_id is 'A03', the scenario names 'A01'"
    ]


@pytest.mark.parametrize("record_id", ["2", "3", "4", "999", "01", ""])
def test_reference_that_names_another_record_is_refused(tmp_path: Path, record_id: str) -> None:
    # Given: a reference whose time is right and whose RecordId is not the session host's.
    # 2 and 3 are the intermediate and the final tool of the same run, 4 is its connection.
    run = build_run(tmp_path, run_type="attack", metadata={"reference_source_event_id": record_id})

    report = validate(run)

    assert report.errors == [
        (
            f"run_metadata.json reference_source_event_id is {record_id!r}, but the EID 1 of the "
            f"session host of this run ({SESSION_GUID}) is RecordId '1'"
        )
    ]


def test_reference_time_taken_from_time_created_is_refused(tmp_path: Path) -> None:
    # Given: Sysmon wrote the record 4 ms after the event, and the run recorded that time
    events = run_events("attack")
    events[0]["TimeCreated"] = "2030-01-02T00:00:02.054Z"
    run = build_run(
        tmp_path,
        run_type="attack",
        events=events,
        metadata={"reference_time": "2030-01-02T00:00:02.054Z"},
    )

    report = validate(run)

    # Then: the reference is the event time, and nothing else is accepted for it
    assert report.errors == [
        (
            "run_metadata.json reference_time is 2030-01-02T00:00:02.054Z, but the EventData.UtcTime "
            f"of the EID 1 of the session host of this run ({SESSION_GUID}) is {SESSION_UTC_TIME}"
        )
    ]


@pytest.mark.parametrize("utc_time", ["", "not-a-time", "2030-01-02T00:00:02.050Z", None])
def test_session_host_record_without_a_readable_event_time_leaves_no_reference(
    tmp_path: Path, utc_time: object
) -> None:
    # Given: the EID 1 of the session host has no usable UtcTime; its TimeCreated is intact
    events = run_events("attack")
    events[0]["EventData"]["UtcTime"] = utc_time
    events[0]["TimeCreated"] = REFERENCE_TIME
    run = build_run(tmp_path, run_type="attack", events=events)

    report = validate(run)

    assert not report.ok
    assert "TimeCreated is not used in its place" in errors_of(report)
    assert "the reference of the run is the EID 1 of its session host" not in "\n".join(
        report.checks
    )


def test_reference_earlier_than_its_action_is_refused(tmp_path: Path) -> None:
    # Given: a session host record that precedes the recorded start of A01, as the session
    # of the pre-run check does
    events = run_events("attack")
    events[0]["EventData"]["UtcTime"] = "2030-01-02 00:00:01.000"
    run = build_run(
        tmp_path,
        run_type="attack",
        events=events,
        metadata={"reference_time": "2030-01-02T00:00:01.000Z"},
    )

    report = validate(run)

    assert report.errors == [
        (
            "reference_time 2030-01-02T00:00:01.000Z is earlier than the recorded start of A01 "
            f"({RECORDED_TIMES[0]})"
        )
    ]


def test_reference_later_than_the_next_action_is_refused(tmp_path: Path) -> None:
    # Given: a session host record that follows the action that ran in the session
    events = run_events("attack")
    events[0]["EventData"]["UtcTime"] = "2030-01-02 00:02:30.000"
    run = build_run(
        tmp_path,
        run_type="attack",
        events=events,
        metadata={"reference_time": "2030-01-02T00:02:30.000Z"},
    )

    report = validate(run)

    assert report.errors == [
        (
            "reference_time 2030-01-02T00:02:30.000Z is later than the next recorded action A02 "
            f"({RECORDED_TIMES[1]})"
        ),
        (
            "end_time 2030-01-02T00:11:00.000Z is earlier than reference_time + 600 s: the "
            "collection observed 510.000 s after the reference"
        ),
    ]


@pytest.mark.parametrize(
    ("end_time", "ok"),
    [
        ("2030-01-02T00:10:02.050Z", True),
        ("2030-01-02T00:10:02.049Z", False),
    ],
)
def test_attack_run_has_to_reach_the_horizon_after_its_reference(
    tmp_path: Path, end_time: str, ok: bool
) -> None:
    # Given: a collection that ended exactly 600 s after the reference, and one that ended 1 ms short
    run = build_run(tmp_path, run_type="attack", metadata={"end_time": end_time})

    report = validate(run)

    assert report.ok is ok, report.errors
    if not ok:
        assert report.errors == [
            (
                f"end_time {end_time} is earlier than reference_time + 600 s: the collection "
                "observed 599.999 s after the reference"
            )
        ]


def test_normal_run_is_not_held_to_a_horizon_from_a_reference(tmp_path: Path) -> None:
    # A normal run has no reference_time, so no evaluation window is read into it.
    run = build_run(tmp_path, metadata={"end_time": "2030-01-02T00:10:00.500Z"})

    report = validate(run)

    assert report.ok, report.errors
    assert "evaluation horizon" not in "\n".join(report.checks)


@pytest.mark.parametrize("version", [None, "", "   ", 7], ids=["null", "empty", "blank", "number"])
@pytest.mark.parametrize("run_type", ["attack", "normal"])
def test_scenario_naming_an_attack_reference_without_a_policy_version_is_refused(
    tmp_path: Path, run_type: str, version: object
) -> None:
    # Given: a scenario that names the attack reference action and states no usable policy
    # version, and a run_metadata that records none either - two missing values that an
    # equality check alone would accept
    run = build_run(
        tmp_path,
        run_type=run_type,
        scenario_body=scenario(policy_version=version),
        metadata={"reference_policy_version": None},
    )

    report = validate(run)

    # Then: both runs of the Pair are refused on the scenario, before anything is compared
    assert not report.ok
    assert (
        "run_metadata.reference_policy_version must be a non-blank string when "
        f"runs.attack.reference_action_id is set, found {version!r}"
    ) in errors_of(report)
    assert report.lineage is None
    assert "PASS" not in format_report(report)


def test_any_stated_policy_version_is_accepted_when_the_run_records_the_same(
    tmp_path: Path,
) -> None:
    # No version is fixed in the validator: the scenario states it and the run records it.
    run = build_run(
        tmp_path,
        run_type="attack",
        scenario_body=scenario(policy_version="synthetic-ref-v9"),
        metadata={"reference_policy_version": "synthetic-ref-v9"},
    )

    report = validate(run)

    assert report.ok, report.errors


def test_reference_policy_version_has_to_be_the_one_of_the_scenario(tmp_path: Path) -> None:
    run = build_run(tmp_path, run_type="attack", metadata={"reference_policy_version": "other"})

    report = validate(run)

    assert report.errors == [
        "run_metadata.json reference_policy_version is 'other', the scenario states 'r1-ref-v0.1'"
    ]


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"attack_reference": None}, "runs.attack.reference_action_id must be the session_begin"),
        ({"attack_reference": "A03"}, "runs.attack.reference_action_id must be the session_begin"),
        ({"horizon": None}, "run_length.evaluation_horizon_sec must be an integer of 1 or more"),
        ({"horizon": 0}, "run_length.evaluation_horizon_sec must be an integer of 1 or more"),
        ({"horizon": "600"}, "run_length.evaluation_horizon_sec must be an integer of 1 or more"),
        ({"horizon": True}, "run_length.evaluation_horizon_sec must be an integer of 1 or more"),
    ],
)
def test_scenario_without_a_usable_reference_plan_validates_no_attack_run(
    tmp_path: Path, changes: dict, problem: str
) -> None:
    run = build_run(tmp_path, run_type="attack", scenario_body=scenario(**changes))

    report = validate(run)

    assert not report.ok
    assert "scenario definition is not usable" in errors_of(report)
    assert problem in errors_of(report)
    assert report.lineage is None


def test_scenario_that_gives_the_normal_run_a_reference_is_not_usable(tmp_path: Path) -> None:
    run = build_run(tmp_path, scenario_body=scenario(normal_reference="N01"))

    report = validate(run)

    assert not report.ok
    assert "runs.normal.reference_action_id must be null" in errors_of(report)


def test_rehearsal_attack_run_records_its_reference_and_is_not_held_to_the_horizon(
    tmp_path: Path,
) -> None:
    # Given: a rehearsal, which does not wait for the observation window
    run = build_run(
        tmp_path,
        run_type="attack",
        rehearsal=True,
        metadata={"end_time": "2030-01-02T00:10:01.000Z"},
    )

    report = validate(run, rehearsal=True)

    assert report.ok, report.errors
    assert "the reference of the run is the EID 1 of its session host" in "\n".join(report.checks)
    assert "evaluation horizon" not in "\n".join(report.checks)


def test_target_host_other_than_the_rendered_one_fails(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, metadata={"target_host": OTHER_HOST}))

    assert not report.ok
    assert "run_metadata.json target_host is 'TARGET-B'" in errors_of(report)


def test_run_metadata_of_another_scenario_is_refused(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, metadata={"scenario_id": "S0"}))

    assert not report.ok
    assert "run_metadata.json scenario_id is 'S0', expected 'R1'" in errors_of(report)
    assert report.lineage is None


@pytest.mark.parametrize("override", [{"vm_snapshot": None}, {"vm_snapshot": " "}])
def test_run_without_a_snapshot_name_fails(tmp_path: Path, override: dict) -> None:
    report = validate(build_run(tmp_path, metadata=override))

    assert not report.ok
    assert "vm_snapshot is empty" in errors_of(report)


def test_run_without_an_end_time_fails(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, metadata={"end_time": None}))

    assert not report.ok
    assert "end_time is null" in errors_of(report)


def test_actions_in_another_order_fail(tmp_path: Path) -> None:
    rows = recorded_rows("normal")
    rows[1], rows[2] = rows[2], rows[1]

    report = validate(build_run(tmp_path, rows=rows))

    assert not report.ok
    assert "the scenario designs ['N01', 'N02', 'N03', 'N04', 'N05']" in errors_of(report)


def test_actions_of_the_other_run_type_fail(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, run_type="attack", rows=recorded_rows("normal")))

    assert not report.ok
    assert "the scenario designs ['A01', 'A02', 'A03', 'A04', 'A05']" in errors_of(report)


def test_collection_run_missing_the_connection_action_fails(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, rows=recorded_rows("normal", connect=False)))

    assert not report.ok
    assert "execution_record.csv records the actions ['N01', 'N02', 'N03', 'N05']" in errors_of(
        report
    )


def test_action_type_other_than_the_designed_one_fails(tmp_path: Path) -> None:
    rows = recorded_rows("normal")
    rows[2] = (*rows[2][:3], "execution")

    report = validate(build_run(tmp_path, rows=rows))

    assert not report.ok
    assert "N03 is 'execution', scenario says 'process_create'" in errors_of(report)


def test_timestamps_going_backwards_fail(tmp_path: Path) -> None:
    rows = recorded_rows("normal")
    rows[3] = (*rows[3][:2], RECORDED_TIMES[1], rows[3][3])

    report = validate(build_run(tmp_path, rows=rows))

    assert not report.ok
    assert "timestamps go backwards" in errors_of(report)


@pytest.mark.parametrize(
    ("index", "timestamp", "outside"),
    [(0, "2030-01-01T23:59:59.000Z", "N01"), (4, "2030-01-02T00:11:00.001Z", "N05")],
)
def test_action_outside_the_run_window_fails(
    tmp_path: Path, index: int, timestamp: str, outside: str
) -> None:
    rows = recorded_rows("normal")
    rows[index] = (*rows[index][:2], timestamp, rows[index][3])

    report = validate(build_run(tmp_path, rows=rows))

    assert not report.ok
    assert f"outside the run window: ['{outside}']" in errors_of(report)


def test_designed_and_recorded_times_are_reported_without_a_verdict(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path))

    assert report.ok, report.errors
    assert report.action_times == [
        "N01 session_begin: designed t+0 s, recorded 2.000 s after start_time",
        "N02 prepare: designed t+120 s, recorded 120.100 s after start_time",
        "N03 launch: designed t+300 s, recorded 300.200 s after start_time",
        "N04 connect: designed t+480 s, recorded 480.300 s after start_time",
        "N05 session_end: designed t+600 s, recorded 600.400 s after start_time",
    ]


# ---------------------------------------------------------------------------
# The scenario the run is validated against
# ---------------------------------------------------------------------------


def test_scenario_without_a_target_host_is_not_usable(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, scenario_body=scenario(target_host=None)))

    assert not report.ok
    assert "run_metadata.target_host must be a non-empty string" in errors_of(report)
    assert report.lineage is None


@pytest.mark.parametrize(
    ("target", "lab_cidr"),
    [
        ("8.8.8.8", LAB_CIDR),
        ("203.0.113.9", LAB_CIDR),
        ("10.20.31.20", LAB_CIDR),
        ("10.20.30.255", LAB_CIDR),
        ("target-b", LAB_CIDR),
        (DESTINATION_IP, "8.8.8.0/24"),
        (DESTINATION_IP, "0.0.0.0/0"),
    ],
)
def test_scenario_naming_a_destination_outside_the_lab_cannot_pass(
    tmp_path: Path, target: str, lab_cidr: str
) -> None:
    # Given: a scenario edited to a destination the renderer would have refused,
    # and a capture that holds a connection to exactly that destination
    body = scenario()
    body["internal_connection"]["target"] = target
    body["internal_connection"]["lab_cidr"] = lab_cidr
    events = run_events("normal", connect=False)
    events.append(connection_event(record_id=4, guid=FINAL_GUID, destination_ip=target))

    report = validate(build_run(tmp_path, events=events, scenario_body=body))

    assert not report.ok
    assert "not an approved internal destination" in errors_of(report)
    assert report.lineage is None


def test_scenario_with_a_partial_destination_is_not_usable(tmp_path: Path) -> None:
    body = scenario()
    body["internal_connection"]["port"] = None

    report = validate(build_run(tmp_path, scenario_body=body))

    assert not report.ok
    assert "must be set together or all be null" in errors_of(report)


def test_collection_run_cannot_pass_without_a_destination(tmp_path: Path) -> None:
    run = build_run(tmp_path, scenario_body=scenario(destination=False))

    report = validate(run)

    assert not report.ok
    assert "a collection run cannot be validated without it" in errors_of(report)
    assert report.lineage is None


def test_expectation_is_read_per_run_type(tmp_path: Path) -> None:
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario()), encoding="utf-8")

    normal = load_r1_pilot_expectation(scenario_path, "normal")
    attack = load_r1_pilot_expectation(scenario_path, "attack")

    assert normal.images == ("powershell.exe", "cmd.exe", "wsmprovhost.exe")
    assert attack.images == ("powershell.exe", "cscript.exe", "wsmprovhost.exe")
    assert [action.action_id for action in attack.actions] == ["A01", "A02", "A03", "A04", "A05"]
    assert (normal.destination_ip, normal.destination_port) == (DESTINATION_IP, "8443")
    assert (attack.destination_ip, attack.destination_port) == (DESTINATION_IP, "8443")


def _drop_final_tool(body: dict) -> None:
    del body["planned_lineage"]["final_tool"]


def _blank_intermediate(body: dict) -> None:
    body["planned_lineage"]["intermediate"]["normal"]["image"] = " "


def _other_scenario(body: dict) -> None:
    body["scenario_id"] = "S0"


def _second_connect_step(body: dict) -> None:
    body["runs"]["normal"]["actions"][1]["step"] = "connect"


def _repeated_action_id(body: dict) -> None:
    body["runs"]["normal"]["actions"][1]["action_id"] = "N01"


def _boolean_offset(body: dict) -> None:
    body["runs"]["normal"]["actions"][0]["offset_sec"] = True


def _boolean_port(body: dict) -> None:
    body["internal_connection"]["port"] = True


@pytest.mark.parametrize(
    "mutate",
    [
        _drop_final_tool,
        _blank_intermediate,
        _other_scenario,
        _second_connect_step,
        _repeated_action_id,
        _boolean_offset,
        _boolean_port,
    ],
)
def test_malformed_scenario_is_refused(tmp_path: Path, mutate: Callable[[dict], None]) -> None:
    body = scenario()
    mutate(body)
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(R1ScenarioError):
        load_r1_pilot_expectation(scenario_path, "normal")


def test_unreadable_scenario_and_unknown_run_type_are_refused(tmp_path: Path) -> None:
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text("{", encoding="utf-8")

    with pytest.raises(R1ScenarioError):
        load_r1_pilot_expectation(scenario_path, "normal")
    with pytest.raises(R1ScenarioError):
        load_r1_pilot_expectation(tmp_path / "absent.json", "normal")
    with pytest.raises(R1ScenarioError):
        load_r1_pilot_expectation(scenario_path, "benign")


# ---------------------------------------------------------------------------
# Rehearsal
# ---------------------------------------------------------------------------


def test_rehearsal_artifacts_are_refused_as_a_collection(tmp_path: Path) -> None:
    run = build_run(tmp_path, rehearsal=True)

    report = validate(run)

    assert not report.ok
    assert "rehearsal artifacts cannot be validated as an R1 collection" in errors_of(report)


def test_rehearsal_flag_needs_the_marker_and_the_isolated_root(tmp_path: Path) -> None:
    run = build_run(tmp_path)

    report = validate(run, rehearsal=True)

    assert not report.ok
    assert "REHEARSAL.txt is missing" in errors_of(report)
    assert "is not under a _rehearsal directory" in errors_of(report)


def test_lineage_only_rehearsal_passes_without_the_connection(tmp_path: Path) -> None:
    # Given: a rehearsal rendered without a destination - four actions, no EID 3
    run = build_run(tmp_path, run_type="attack", rehearsal=True, connect=False)

    report = validate(run, rehearsal=True)

    # Then: the lineage is recorded and the report says it is not a collection
    assert report.ok, report.errors
    assert report.lineage is not None
    assert report.lineage.process_guids == (FINAL_GUID, INTERMEDIATE_GUID, SESSION_GUID)
    assert report.lineage.connections == ()
    assert "the EID 1 -> EID 3 link was not checked (rehearsal)" in "\n".join(report.checks)
    assert "REHEARSAL - not a valid R1 collection" in format_report(report)


def test_lineage_only_rehearsal_still_fails_on_another_lineage(tmp_path: Path) -> None:
    run = build_run(
        tmp_path,
        run_type="attack",
        rehearsal=True,
        connect=False,
        events=run_events("normal", connect=False),
    )

    report = validate(run, rehearsal=True)

    assert not report.ok
    assert "no final tool instance has the lineage this run was designed with" in errors_of(report)


def test_rehearsal_with_a_destination_checks_the_connection(tmp_path: Path) -> None:
    passing = validate(build_run(tmp_path / "passing", rehearsal=True), rehearsal=True)
    failing = validate(
        build_run(tmp_path / "failing", rehearsal=True, events=run_events("normal", connect=False)),
        rehearsal=True,
    )

    assert passing.ok, passing.errors
    assert not failing.ok
    assert "no EID 3 record carries the anchor host and ProcessGuid" in errors_of(failing)


def test_rehearsal_with_a_destination_refuses_a_connection_that_is_not_tcp(tmp_path: Path) -> None:
    # A rehearsal rendered with a destination checks the same connection a collection does.
    run = build_run(tmp_path, rehearsal=True, events=run_with_connections("normal", "udp"))

    report = validate(run, rehearsal=True)

    assert not report.ok
    assert "was recorded with the expected Protocol tcp" in errors_of(report)
    assert report.lineage is None


# ---------------------------------------------------------------------------
# The operator trace: the scenario a run executed, and its dataset tier
# ---------------------------------------------------------------------------

TRACE_LABEL = f"operator_trace/{RUN_ID}/r1_run_trace.json"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_run_bound_to_its_scenario_passes_and_reports_the_binding(tmp_path: Path) -> None:
    # Given: a run whose trace records the scenario it was rendered with
    run = build_run(tmp_path, run_type="attack")
    digest = sha256_of(run[1])

    # When
    report = validate(run)

    # Then: the binding and the tier are recorded facts of the report
    assert report.ok, report.errors
    assert report.trace is not None
    assert (report.trace.dataset_tier, report.trace.mode) == ("pilot", "collection")
    assert report.trace.scenario_sha256 == digest
    assert (
        "the operator trace, the scenario the run kept and the scenario given to the validator "
        f"are the same bytes: sha256={digest}"
    ) in report.checks
    assert (
        "the operator trace names this run and carries the tier its scenario states: "
        "dataset_tier=pilot mode=collection"
    ) in report.checks

    text = format_report(report)
    assert "tier        : pilot" in text
    assert f"scenario    : sha256={digest}" in text
    assert "a formal selector has to leave such a run out" in text
    assert "operator trace" in text.splitlines()[-1]


def test_run_without_an_operator_trace_is_not_validated(tmp_path: Path) -> None:
    # Given: a complete run whose trace record is gone
    run = build_run(tmp_path)
    (trace_dir(run[0]) / "r1_run_trace.json").unlink()

    report = validate(run)

    # Then: nothing is judged against a scenario that is not tied to the run
    assert not report.ok
    assert f"operator trace is missing: {TRACE_LABEL}" in errors_of(report)
    assert report.trace is None
    assert report.identity is None
    assert report.lineage is None
    assert "PASS" not in format_report(report)


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        (b"", "operator trace is not readable JSON"),
        (b"{", "operator trace is not readable JSON"),
        (b"not json", "operator trace is not readable JSON"),
        (b"\xff\xfe{}", "operator trace is not readable JSON"),
        (b"[]", "operator trace is not a JSON object"),
        (b'"pilot"', "operator trace is not a JSON object"),
        (b"null", "operator trace is not a JSON object"),
    ],
    ids=["empty", "truncated", "text", "not-utf8", "array", "string", "null"],
)
def test_operator_trace_that_is_not_a_json_object_is_refused(
    tmp_path: Path, content: bytes, problem: str
) -> None:
    run = build_run(tmp_path)
    (trace_dir(run[0]) / "r1_run_trace.json").write_bytes(content)

    report = validate(run)

    assert not report.ok
    assert f"{problem} ({TRACE_LABEL})" in errors_of(report)
    assert report.trace is None
    assert report.lineage is None


@pytest.mark.parametrize(
    ("stated", "problem"),
    [
        ({"run_id": OTHER_RUN_ID}, f"run_id is '{OTHER_RUN_ID}', expected '{RUN_ID}'"),
        ({"run_id": None}, f"run_id is None, expected '{RUN_ID}'"),
        (
            {"dataset_tier": "formal"},
            "dataset_tier is 'formal', the rendered scenario states 'pilot'",
        ),
        (
            {"dataset_tier": "Pilot"},
            "dataset_tier is 'Pilot', the rendered scenario states 'pilot'",
        ),
        ({"dataset_tier": ""}, "dataset_tier is '', the rendered scenario states 'pilot'"),
        ({"dataset_tier": None}, "dataset_tier is None, the rendered scenario states 'pilot'"),
        (
            {"dataset_tier": ["pilot"]},
            "dataset_tier is ['pilot'], the rendered scenario states 'pilot'",
        ),
        ({"trace_version": "v2"}, "trace_version is 'v2', expected 'v1'"),
        ({"trace_version": 1}, "trace_version is 1, expected 'v1'"),
        ({"mode": "rehearsal"}, "mode is 'rehearsal', expected 'collection'"),
        ({"mode": "dry_run"}, "mode is 'dry_run', expected 'collection'"),
    ],
)
def test_operator_trace_of_another_run_tier_version_or_mode_is_refused(
    tmp_path: Path, stated: dict, problem: str
) -> None:
    # Given: a trace whose digest is right and one other value is not
    root, scenario_path = build_run(tmp_path)
    write_trace(root, scenario_path.read_bytes(), **stated)

    report = validate((root, scenario_path))

    assert not report.ok
    assert report.errors == [f"operator trace {problem} ({TRACE_LABEL})"]
    assert report.trace is None
    assert report.lineage is None


@pytest.mark.parametrize(
    "name", ["trace_version", "run_id", "dataset_tier", "mode", "scenario_sha256"]
)
def test_operator_trace_that_leaves_a_value_out_is_refused(tmp_path: Path, name: str) -> None:
    root, scenario_path = build_run(tmp_path)
    rewrite_json(trace_dir(root) / "r1_run_trace.json", lambda record: record.pop(name))

    report = validate((root, scenario_path))

    assert not report.ok
    assert f"operator trace {name} is" in errors_of(report)
    assert report.trace is None


@pytest.mark.parametrize(
    "recorded",
    ["", "0" * 63, "0" * 65, "g" * 64, "AB" * 32, " " + "ab" * 32, None, 7],
    ids=["empty", "short", "long", "not-hex", "upper-case", "padded", "null", "number"],
)
def test_operator_trace_without_a_well_formed_digest_is_refused(
    tmp_path: Path, recorded: object
) -> None:
    root, scenario_path = build_run(tmp_path)
    write_trace(root, scenario_path.read_bytes(), scenario_sha256=recorded)

    report = validate((root, scenario_path))

    assert not report.ok
    assert "scenario_sha256 is not a SHA-256 in lower case hex" in errors_of(report)
    assert report.trace is None


def test_digest_written_in_upper_case_is_not_accepted_as_the_same(tmp_path: Path) -> None:
    # The runner writes lower case hex. Another spelling is another record.
    root, scenario_path = build_run(tmp_path)
    write_trace(root, scenario_path.read_bytes(), scenario_sha256=sha256_of(scenario_path).upper())

    report = validate((root, scenario_path))

    assert not report.ok
    assert "scenario_sha256 is not a SHA-256 in lower case hex" in errors_of(report)


def test_well_formed_digest_of_other_bytes_is_refused(tmp_path: Path) -> None:
    # Given: a trace that records a digest neither scenario has
    root, scenario_path = build_run(tmp_path)
    write_trace(root, scenario_path.read_bytes(), scenario_sha256="ab" * 32)

    report = validate((root, scenario_path))

    # Then: the kept copy and the given scenario are each reported
    assert not report.ok
    assert "does not have the SHA-256 its trace records" in errors_of(report)
    assert "is not the one this run executed" in errors_of(report)
    assert report.trace is None


def test_scenario_edited_after_the_run_cannot_make_the_run_pass(tmp_path: Path) -> None:
    # Given: a normal run whose telemetry shows the lineage of the other run type
    root, scenario_path = build_run(tmp_path, events=run_events("attack"))
    honest = validate((root, scenario_path))
    assert not honest.ok
    assert "no final tool instance has the lineage this run was designed with" in errors_of(honest)

    # When: the scenario handed to the validator is edited so that the plan fits
    # what the telemetry shows
    edited = scenario(normal_image="cscript.exe", attack_image="cmd.exe")
    scenario_path.write_text(json.dumps(edited), encoding="utf-8")
    report = validate((root, scenario_path))

    # Then: the run is not judged against the edited plan at all
    assert not report.ok
    assert report.errors == [
        (
            "the scenario given to the validator is not the one this run executed: its "
            f"SHA-256 is {sha256_of(scenario_path)}, the operator trace records "
            f"{sha256_of(trace_dir(root) / 'scenario.json')}"
        )
    ]
    assert report.lineage is None
    assert report.identity is None


def test_editing_the_kept_scenario_as_well_is_still_refused(tmp_path: Path) -> None:
    # Given: the same edit made to the given scenario and to the copy the run kept
    root, scenario_path = build_run(tmp_path, events=run_events("attack"))
    recorded = sha256_of(scenario_path)
    edited = json.dumps(scenario(normal_image="cscript.exe", attack_image="cmd.exe"))
    scenario_path.write_text(edited, encoding="utf-8")
    (trace_dir(root) / "scenario.json").write_text(edited, encoding="utf-8")

    report = validate((root, scenario_path))

    # Then: the digest the trace recorded at run time gives both away
    assert not report.ok
    assert len(report.errors) == 2
    assert "does not have the SHA-256 its trace records" in report.errors[0]
    assert f"recorded {recorded}" in report.errors[0]
    assert "is not the one this run executed" in report.errors[1]
    assert report.lineage is None


def test_same_values_in_other_bytes_are_not_the_scenario_of_the_run(tmp_path: Path) -> None:
    # The binding is by bytes: a scenario written out again with the same values
    # is a different file.
    root, scenario_path = build_run(tmp_path)
    values = json.loads(scenario_path.read_text(encoding="utf-8"))
    scenario_path.write_text(json.dumps(values, indent=2), encoding="utf-8")

    report = validate((root, scenario_path))

    assert not report.ok
    assert "is not the one this run executed" in errors_of(report)


def test_copy_of_the_scenario_at_another_path_is_accepted(tmp_path: Path) -> None:
    # The binding is by content, not by where the file lies.
    root, scenario_path = build_run(tmp_path)
    elsewhere = tmp_path / "elsewhere" / "rendered.json"
    elsewhere.parent.mkdir()
    elsewhere.write_bytes(scenario_path.read_bytes())

    report = validate_r1_pilot_run(artifact_root=root, run_id=RUN_ID, scenario_path=elsewhere)

    assert report.ok, report.errors

    # And: the copy the run kept is such a copy
    kept = validate_r1_pilot_run(
        artifact_root=root,
        run_id=RUN_ID,
        scenario_path=trace_dir(root) / "scenario.json",
    )
    assert kept.ok, kept.errors


def test_scenario_is_read_once_so_the_plan_comes_from_the_compared_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a scenario file that is replaced as soon as it has been read
    root, scenario_path = build_run(tmp_path)
    digest = sha256_of(scenario_path)
    read_bytes = Path.read_bytes
    replaced: list[Path] = []

    def read_then_replace(self: Path) -> bytes:
        data = read_bytes(self)
        if self == scenario_path and not replaced:
            replaced.append(self)
            self.write_text("{}", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", read_then_replace)

    # When
    report = validate((root, scenario_path))

    # Then: the run is judged against what was read and compared with the trace;
    # a second read, by any means, would have met the replaced file
    assert replaced == [scenario_path]
    assert scenario_path.read_text(encoding="utf-8") == "{}"
    assert report.ok, report.errors
    assert report.trace is not None
    assert report.trace.scenario_sha256 == digest
    assert report.lineage is not None


@pytest.mark.parametrize("change", ["missing", "changed"])
def test_kept_scenario_that_is_gone_or_changed_is_refused(tmp_path: Path, change: str) -> None:
    root, scenario_path = build_run(tmp_path)
    kept = trace_dir(root) / "scenario.json"
    if change == "missing":
        kept.unlink()
    else:
        kept.write_bytes(kept.read_bytes() + b"\n")

    report = validate((root, scenario_path))

    assert not report.ok
    assert len(report.errors) == 1
    assert f"operator_trace/{RUN_ID}/scenario.json" in report.errors[0]
    assert report.trace is None


def test_every_problem_of_a_trace_is_reported(tmp_path: Path) -> None:
    root, scenario_path = build_run(tmp_path)
    write_trace(root, scenario_path.read_bytes(), run_id=OTHER_RUN_ID, dataset_tier="formal")

    report = validate((root, scenario_path))

    assert report.errors == [
        f"operator trace run_id is '{OTHER_RUN_ID}', expected '{RUN_ID}' ({TRACE_LABEL})",
        (
            "operator trace dataset_tier is 'formal', the rendered scenario states 'pilot' "
            f"({TRACE_LABEL})"
        ),
    ]


@pytest.mark.parametrize("tier", ["development", "holdout"])
def test_run_of_a_formal_tier_passes_when_its_scenario_states_that_tier(
    tmp_path: Path, tier: str
) -> None:
    # Given: a Pair rendered as a formal tier and a run whose trace carries that tier
    run = build_run(tmp_path, run_type="attack", scenario_body=scenario(dataset_tier=tier))

    # When: the validator is given the scenario and nothing about the tier
    report = validate(run)

    # Then: the run passes and the report carries the tier of the scenario and the trace
    assert report.ok, report.errors
    assert report.trace is not None
    assert (report.trace.dataset_tier, report.trace.mode) == (tier, "collection")
    assert report.scenario_dataset_tier == tier
    assert (
        "the operator trace names this run and carries the tier its scenario states: "
        f"dataset_tier={tier} mode=collection"
    ) in report.checks

    text = format_report(report)
    assert f"tier        : {tier}" in text
    assert f"the operator trace both say dataset_tier={tier}" in text
    assert "not a formal run" not in text
    assert "dataset_tier=pilot" not in text


@pytest.mark.parametrize(
    ("in_scenario", "in_trace"),
    [
        ("development", "pilot"),
        ("holdout", "pilot"),
        ("pilot", "development"),
        ("holdout", "development"),
        ("development", "holdout"),
        ("pilot", "holdout"),
    ],
)
def test_run_whose_trace_states_another_tier_than_its_scenario_is_refused(
    tmp_path: Path, in_scenario: str, in_trace: str
) -> None:
    # Given: a run that is valid in every other respect, whose trace disagrees with the
    # scenario of its Pair
    root, scenario_path = build_run(tmp_path, scenario_body=scenario(dataset_tier=in_scenario))
    write_trace(root, scenario_path.read_bytes(), dataset_tier=in_trace)

    report = validate((root, scenario_path))

    # Then: neither value is taken to make the run fit, and nothing after the trace is judged
    assert report.errors == [
        (
            f"operator trace dataset_tier is {in_trace!r}, the rendered scenario states "
            f"{in_scenario!r} ({TRACE_LABEL})"
        )
    ]
    assert report.trace is None
    assert report.lineage is None
    assert report.scenario_dataset_tier == in_scenario
    assert f"the scenario states {in_scenario!r}" in format_report(report)


@pytest.mark.parametrize(
    "tier",
    ["", "formal", "Pilot", "DEVELOPMENT", "pilot ", " pilot", "dev", None, 1, ["pilot"], OMITTED],
    ids=[
        "empty",
        "unknown",
        "capital",
        "upper",
        "trailing-space",
        "leading-space",
        "abbreviated",
        "null",
        "number",
        "list",
        "omitted",
    ],
)
def test_scenario_without_a_usable_tier_validates_nothing(tmp_path: Path, tier: object) -> None:
    # Given: a run whose trace says pilot, and a scenario that states no tier this project has
    run = build_run(tmp_path, scenario_body=scenario(dataset_tier=tier))

    report = validate(run)

    # Then: the scenario is refused before the trace is read; the tier of the trace does not
    # stand in for the one the scenario leaves out
    assert len(report.errors) == 1
    assert "scenario definition is not usable" in report.errors[0]
    assert "dataset_tier must be one of ['pilot', 'development', 'holdout']" in report.errors[0]
    assert "--dataset-tier" in report.errors[0]
    assert report.scenario_dataset_tier is None
    assert report.trace is None
    assert report.lineage is None
    assert "PASS" not in format_report(report)


def test_validator_takes_no_expected_tier_from_its_caller(tmp_path: Path) -> None:
    # The tier of the earlier interface is gone: a caller cannot choose what a run is held to.
    root, scenario_path = build_run(tmp_path)

    assert "dataset_tier" not in inspect.signature(validate_r1_pilot_run).parameters
    with pytest.raises(TypeError, match="dataset_tier"):
        validate_r1_pilot_run(  # type: ignore[call-arg]
            artifact_root=root, run_id=RUN_ID, scenario_path=scenario_path, dataset_tier="pilot"
        )


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_both_runs_of_a_pair_are_held_to_the_tier_of_their_one_scenario(
    tmp_path: Path, run_type: str
) -> None:
    # Given: the two runs of a Pair, validated against the same rendered scenario
    run = build_run(tmp_path, run_type=run_type, scenario_body=scenario(dataset_tier="holdout"))

    report = validate(run)

    assert report.ok, report.errors
    assert report.trace is not None
    assert report.trace.dataset_tier == report.scenario_dataset_tier == "holdout"


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize("stating", ["normal", "attack"])
def test_run_block_stating_another_tier_than_its_pair_validates_nothing(
    tmp_path: Path, run_type: str, stating: str
) -> None:
    # Given: a Pair rendered as development whose trace says development as well, and one run
    # block that was given a tier of its own
    body = scenario(dataset_tier="development")
    body["runs"][stating]["dataset_tier"] = "holdout"
    root, scenario_path = build_run(tmp_path, run_type=run_type, scenario_body=body)
    trace = json.loads((trace_dir(root) / "r1_run_trace.json").read_text(encoding="utf-8"))
    assert trace["dataset_tier"] == "development"

    report = validate((root, scenario_path))

    # Then: the scenario is refused whichever run of the Pair is validated. The trace agrees
    # with the top-level tier, and that agreement does not make the run pass
    assert report.errors == [
        (
            f"scenario definition is not usable ({scenario_path}): runs.{stating} states "
            "['dataset_tier']; a Pair states them once at the top level"
        )
    ]
    assert report.scenario_dataset_tier is None
    assert report.trace is None
    assert report.lineage is None
    assert report.identity is None
    assert "PASS" not in format_report(report)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize("stating", ["normal", "attack"])
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("family_id", FAMILY_ID),
        ("family_id", "family_x7"),
        ("variation_id", VARIATION_ID),
        ("variation_id", "V09"),
        ("repetition", REPETITION),
        ("repetition", 4),
        ("dataset_tier", "pilot"),
        ("dataset_tier", "development"),
        ("dataset_tier", None),
    ],
    ids=[
        "family-same",
        "family-other",
        "variation-same",
        "variation-other",
        "repetition-same",
        "repetition-other",
        "tier-same",
        "tier-other",
        "tier-null",
    ],
)
def test_run_block_stating_a_value_of_its_pair_validates_nothing(
    tmp_path: Path, run_type: str, stating: str, name: str, value: object
) -> None:
    # Given: a run that is valid in every other respect, and a scenario in which one run block
    # carries a field the Pair states once at the top level
    body = scenario()
    body["runs"][stating][name] = value

    report = validate(build_run(tmp_path, run_type=run_type, scenario_body=body))

    # Then: the field is refused for being there. A value equal to the top-level one and a null
    # are refused like a different one, and nothing of the run is judged
    assert len(report.errors) == 1
    assert "scenario definition is not usable" in report.errors[0]
    assert (
        f"runs.{stating} states [{name!r}]; a Pair states them once at the top level"
    ) in report.errors[0]
    assert report.trace is None
    assert report.lineage is None
    assert report.identity is None


def test_every_pair_field_of_a_run_block_is_named(tmp_path: Path) -> None:
    body = scenario()
    body["runs"]["attack"].update({"repetition": 2, "dataset_tier": "holdout", "family_id": "x"})

    report = validate(build_run(tmp_path, run_type="normal", scenario_body=body))

    assert (
        "runs.attack states ['dataset_tier', 'family_id', 'repetition']; a Pair states them "
        "once at the top level"
    ) in errors_of(report)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize("stating", ["normal", "attack"])
@pytest.mark.parametrize("name", ["family_id", "variation_id", "repetition", "dataset_tier"])
def test_plan_of_a_scenario_whose_run_block_states_a_pair_field_is_not_read(
    tmp_path: Path, run_type: str, stating: str, name: str
) -> None:
    body = scenario()
    body["runs"][stating][name] = body[name]
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(R1ScenarioError, match=rf"runs\.{stating} states \['{name}'\]"):
        load_r1_pilot_expectation(scenario_path, run_type)


@pytest.mark.parametrize("tier", ["development", "holdout"])
def test_rehearsal_of_a_scenario_of_a_formal_tier_is_refused(tmp_path: Path, tier: str) -> None:
    # Given: rehearsal artifacts whose scenario and trace both claim a formal tier
    run = build_run(
        tmp_path,
        rehearsal=True,
        connect=False,
        scenario_body=scenario(destination=False, dataset_tier=tier),
    )

    report = validate(run, rehearsal=True)

    assert report.errors == [
        (
            "a rehearsal is not formal data: its scenario has to state dataset_tier 'pilot', "
            f"this one states {tier!r}"
        )
    ]
    assert report.trace is None
    assert report.lineage is None


@pytest.mark.parametrize("tier", ["development", "holdout"])
def test_rehearsal_whose_trace_claims_a_formal_tier_is_refused(tmp_path: Path, tier: str) -> None:
    # Given: a rehearsal of a pilot scenario whose trace was written with a formal tier
    root, scenario_path = build_run(tmp_path, rehearsal=True, connect=False)
    write_trace(root, scenario_path.read_bytes(), rehearsal=True, dataset_tier=tier)

    report = validate((root, scenario_path), rehearsal=True)

    assert report.errors == [
        (
            f"operator trace dataset_tier is {tier!r}, the rendered scenario states 'pilot' "
            f"({TRACE_LABEL})"
        )
    ]
    assert report.trace is None


def test_rehearsal_is_a_pilot_rehearsal_in_its_trace(tmp_path: Path) -> None:
    # Given: a lineage-only rehearsal, as the runner writes it under _rehearsal
    run = build_run(tmp_path, rehearsal=True, connect=False)

    report = validate(run, rehearsal=True)

    assert report.ok, report.errors
    assert report.trace is not None
    assert (report.trace.dataset_tier, report.trace.mode) == ("pilot", "rehearsal")
    assert "tier        : pilot" in format_report(report)


@pytest.mark.parametrize("rehearsal", [True, False])
def test_trace_of_the_other_mode_is_refused(tmp_path: Path, rehearsal: bool) -> None:
    # A collection trace does not validate a rehearsal, nor the other way round.
    root, scenario_path = build_run(tmp_path, rehearsal=rehearsal)
    write_trace(root, scenario_path.read_bytes(), rehearsal=not rehearsal)

    report = validate((root, scenario_path), rehearsal=rehearsal)

    wrong, right = ("collection", "rehearsal") if rehearsal else ("rehearsal", "collection")
    assert not report.ok
    assert f"operator trace mode is '{wrong}', expected '{right}'" in errors_of(report)


def test_trace_is_no_contract_artifact(tmp_path: Path) -> None:
    # Given: a passing run
    root, scenario_path = build_run(tmp_path)
    assert validate((root, scenario_path)).ok

    # Then: the trace lies next to the contract directories, and the Manifest
    # still lists the two telemetry files and nothing of the trace
    assert sorted(path.name for path in root.iterdir()) == ["ground_truth", "operator_trace", "raw"]
    manifest_text = (root / "raw" / RUN_ID / "manifest.json").read_text(encoding="utf-8")
    assert len(json.loads(manifest_text)["items"]) == 2
    assert "operator_trace" not in manifest_text
    assert "scenario.json" not in manifest_text


# ---------------------------------------------------------------------------
# The report and the lineage record
# ---------------------------------------------------------------------------


def test_report_of_a_passing_run_holds_the_lineage_record(tmp_path: Path) -> None:
    text = format_report(validate(build_run(tmp_path, run_type="attack")))

    assert f"run_id      : {RUN_ID}" in text
    assert "run_type    : attack" in text
    assert "lineage record (extracted from sysmon-0001.jsonl)" in text
    for value in (FINAL_GUID, INTERMEDIATE_GUID, SESSION_GUID, SERVICE_GUID, FINAL_IMAGE):
        assert value in text
    assert f"connection: {DESTINATION_IP}:{DESTINATION_PORT} tcp" in text
    assert "A03 launch: designed t+300 s" in text
    assert text.splitlines()[-1].startswith("PASS (one run:")
    assert "not the Pilot verdict" in text.splitlines()[-1]
    assert "S-1" in text and "S-7" in text


def test_report_of_a_failing_run_is_not_rendered_as_a_pass(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, events=run_events("attack")))

    text = format_report(report)

    assert not report.ok
    assert text.splitlines()[-1] == f"FAIL: {len(report.errors)} problem(s)"
    assert "PASS" not in text
    assert "lineage record" not in text


def test_lineage_record_is_written_once_outside_the_contract_directories(tmp_path: Path) -> None:
    # Given: a validated run and an evidence directory next to it
    run = build_run(tmp_path)
    report = validate(run)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    destination = evidence_dir / "r1_lineage_record.txt"

    # When
    written = write_report(report, destination, artifact_root=run[0])

    # Then: UTF-8, LF, the printed report and nothing else
    assert written == destination.resolve()
    assert destination.read_bytes() == (format_report(report) + "\n").encode("utf-8")
    assert b"\r" not in destination.read_bytes()

    # And: a second validation cannot replace it
    with pytest.raises(R1ReportError, match="already exists"):
        write_report(report, destination, artifact_root=run[0])
    assert destination.read_bytes() == (format_report(report) + "\n").encode("utf-8")


@pytest.mark.parametrize(
    "relative",
    [
        Path("raw") / "record.txt",
        Path("raw") / RUN_ID / "telemetry" / "record.txt",
        Path("ground_truth") / RUN_ID / "record.txt",
        Path("ground_truth") / RUN_ID / ".." / RUN_ID / "record.txt",
    ],
)
def test_lineage_record_is_refused_inside_the_contract_directories(
    tmp_path: Path, relative: Path
) -> None:
    run = build_run(tmp_path)
    report = validate(run)
    before = sorted(path for path in run[0].rglob("*") if path.is_file())

    with pytest.raises(R1ReportError, match="not a contract artifact"):
        write_report(report, run[0] / relative, artifact_root=run[0])

    assert sorted(path for path in run[0].rglob("*") if path.is_file()) == before


def test_lineage_record_needs_an_existing_directory(tmp_path: Path) -> None:
    run = build_run(tmp_path)

    with pytest.raises(R1ReportError, match="does not exist"):
        write_report(validate(run), tmp_path / "absent" / "record.txt", artifact_root=run[0])

    assert not (tmp_path / "absent").exists()


# ---------------------------------------------------------------------------
# The Pair a run belongs to: family, variation, repetition
# ---------------------------------------------------------------------------


def test_run_metadata_recording_the_pair_of_the_scenario_passes(tmp_path: Path) -> None:
    # Given: a scenario rendered for another family, variation and repetition
    body = scenario(family_id="family_x7", variation_id="V09", repetition=4)
    recorded = {"family_id": "family_x7", "variation_id": "V09", "repetition": 4}

    # When
    report = validate(build_run(tmp_path, scenario_body=body, metadata=recorded))

    # Then: nothing in the validator is tied to the values of the first Pilot
    assert report.ok, report.errors
    assert report.identity is not None
    assert (report.identity.family_id, report.identity.variation_id) == ("family_x7", "V09")
    assert report.identity.repetition == 4
    assert (
        "run_metadata.json records the Pair the scenario states: family_id=family_x7 "
        "variation_id=V09 repetition=4"
    ) in report.checks


@pytest.mark.parametrize(
    ("recorded", "problem"),
    [
        ({"family_id": "family_b"}, "family_id is 'family_b', the scenario states"),
        ({"variation_id": "V03"}, "variation_id is 'V03', the scenario states 'V02'"),
        ({"repetition": 2}, "repetition is 2, the scenario states 1"),
        ({"family_id": None}, "family_id is None, the scenario states"),
        ({"variation_id": None}, "variation_id is None, the scenario states 'V02'"),
        ({"repetition": None}, "repetition is None, the scenario states 1"),
    ],
)
def test_run_metadata_recording_another_pair_is_refused(
    tmp_path: Path, recorded: dict, problem: str
) -> None:
    # Given: RunMetadata that does not record what the scenario of the Pair states
    run = build_run(tmp_path, metadata=recorded)

    report = validate(run)

    # Then: the run is refused, even though its lineage and its files are intact
    assert not report.ok
    assert "run_metadata.json does not record the Pair of the scenario" in errors_of(report)
    assert problem in errors_of(report)


def test_both_runs_of_a_pair_are_validated_against_one_identity(tmp_path: Path) -> None:
    # Given: one scenario rendered for the Pair and read by both runs
    body = scenario(family_id="family_x7", variation_id="V09", repetition=4)
    recorded = {"family_id": "family_x7", "variation_id": "V09", "repetition": 4}
    normal = validate(
        build_run(tmp_path / "normal", run_type="normal", scenario_body=body, metadata=recorded)
    )
    attack = validate(
        build_run(tmp_path / "attack", run_type="attack", scenario_body=body, metadata=recorded)
    )

    # Then: both pass and neither run has an identity of its own
    assert normal.ok and attack.ok
    assert normal.identity == attack.identity


def test_run_of_a_pair_recording_another_repetition_is_refused(tmp_path: Path) -> None:
    # Given: the attack run of a Pair records repetition 2, its scenario states 1
    normal = validate(build_run(tmp_path / "normal", run_type="normal"))
    attack = validate(build_run(tmp_path / "attack", run_type="attack", metadata={"repetition": 2}))

    assert normal.ok
    assert not attack.ok
    assert "repetition is 2, the scenario states 1" in errors_of(attack)


def _no_repetition(body: dict) -> None:
    body["repetition"] = None


def _zero_repetition(body: dict) -> None:
    body["repetition"] = 0


def _text_repetition(body: dict) -> None:
    body["repetition"] = "1"


def _boolean_repetition(body: dict) -> None:
    body["repetition"] = True


def _empty_family(body: dict) -> None:
    body["family_id"] = ""


def _missing_variation(body: dict) -> None:
    del body["variation_id"]


def _labelled_family(body: dict) -> None:
    body["family_id"] = "attack_family"


def _labelled_variation(body: dict) -> None:
    body["variation_id"] = "V02-normal"


@pytest.mark.parametrize(
    "mutate",
    [
        _no_repetition,
        _zero_repetition,
        _text_repetition,
        _boolean_repetition,
        _empty_family,
        _missing_variation,
        _labelled_family,
        _labelled_variation,
    ],
)
def test_scenario_without_a_usable_identity_cannot_validate_a_run(
    tmp_path: Path, mutate: Callable[[dict], None]
) -> None:
    # Given: a scenario whose Pair identity is not usable
    body = scenario()
    mutate(body)

    report = validate(build_run(tmp_path, scenario_body=body))

    # Then: the scenario is refused before any lineage is looked at
    assert not report.ok
    assert "scenario definition is not usable" in errors_of(report)
    assert report.lineage is None
    assert report.identity is None


# ---------------------------------------------------------------------------
# Planned lineage: the only lineage the collection check reads
# ---------------------------------------------------------------------------


def test_attack_run_leaving_the_lineage_of_the_normal_run_does_not_meet_its_plan(
    tmp_path: Path,
) -> None:
    # Given: an attack run whose telemetry holds the chain the normal run is planned to leave
    run = build_run(tmp_path, run_type="attack", events=run_events("normal"))

    report = validate(run)

    # Then: it fails, because the collection check asks for the planned lineage of the run
    assert not report.ok
    assert "no final tool instance has the lineage this run was designed with" in errors_of(report)


def test_expectation_reads_one_plan_per_run_type_and_one_identity_for_the_pair(
    tmp_path: Path,
) -> None:
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario()), encoding="utf-8")

    normal = load_r1_pilot_expectation(scenario_path, "normal")
    attack = load_r1_pilot_expectation(scenario_path, "attack")

    # The plan differs by run type; the identity of the Pair does not.
    assert normal.images != attack.images
    assert normal.identity == attack.identity
    assert attack.images == ("powershell.exe", "cscript.exe", "wsmprovhost.exe")


def test_report_records_the_pair_and_says_that_approval_is_not_judged(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, run_type="attack"))

    text = format_report(report)

    assert report.ok, report.errors
    assert "pair        : family_id=remote_management variation_id=V02 repetition=1" in text
    assert "not judged here: whether the lineage is approved" in text
    assert "no approved lineage policy is read here" in text


def test_collection_modules_call_no_evidence_or_fusion_code() -> None:
    # Given: every module this change adds to or uses for collection and rendering
    root = Path(__file__).resolve().parents[2]
    modules = [
        root / "src" / "incident_awareness" / "collection" / "r1_pilot_validation.py",
        root / "src" / "incident_awareness" / "collection" / "r1_pair_identity.py",
        root / "src" / "incident_awareness" / "collection" / "r1_destination.py",
        root / "src" / "incident_awareness" / "collection" / "r1_lineage.py",
        root / "src" / "incident_awareness" / "collection" / "s0_validation.py",
        root / "tools" / "r1_scenario_to_json.py",
        root / "tools" / "validate_r1_run.py",
    ]
    allowed = ("collection", "common")

    # When: their imports are read from the source, without running anything
    imported: set[str] = set()
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)

    # Then: collection reads telemetry and Ground Truth and nothing downstream of
    # them - no Evidence extraction, no detection, no Fusion, no pipeline
    reached = sorted(
        name
        for name in imported
        if name.startswith("incident_awareness.") and name.split(".")[1] not in allowed
    )
    assert reached == []
    assert "incident_awareness.collection.r1_lineage" in imported
