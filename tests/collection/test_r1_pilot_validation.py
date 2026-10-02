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
RECORDED_TIMES = (
    "2030-01-02T00:00:02.000Z",
    "2030-01-02T00:02:00.100Z",
    "2030-01-02T00:05:00.200Z",
    "2030-01-02T00:08:00.300Z",
    "2030-01-02T00:10:00.400Z",
)
ACTION_PREFIX = {"normal": "N", "attack": "A"}

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
) -> dict:
    """The part of a rendered R1 scenario the validator reads.

    `planned_lineage` is what each run is planned to leave.
    """
    return {
        "scenario_version": "v1",
        "scenario_id": "R1",
        "family_id": family_id,
        "variation_id": variation_id,
        "repetition": repetition,
        "run_metadata": {"target_host": target_host},
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
                "reference_action_id": None,
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


def process_event(
    *,
    record_id: int,
    guid: str,
    parent_guid: str | None,
    image: str,
    host: str = TARGET_HOST,
) -> dict:
    """One synthetic Sysmon EID 1 in the shape the runner writes."""
    event_data: dict[str, object] = {
        "UtcTime": "2030-01-02 00:05:00.250",
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
) -> dict:
    """One synthetic Sysmon EID 3 in the shape the runner writes."""
    return {
        "RecordId": record_id,
        "EventId": 3,
        "TimeCreated": "2030-01-02T00:08:00.350Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "Provider": "Microsoft-Windows-Sysmon",
        "EventData": {
            "UtcTime": "2030-01-02 00:08:00.350",
            "ProcessGuid": guid,
            "Image": FINAL_IMAGE,
            "Protocol": "tcp",
            "DestinationIp": destination_ip,
            "DestinationPort": destination_port,
        },
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
        "reference_time": None,
        "reference_action_id": None,
        "reference_source_event_id": None,
        "vm_snapshot": "synthetic-snapshot",
        "sysmon_config_version": "sysmonconfig-sample-v0.1",
        "detector_set_version": None,
        "scenario_version": "v1",
        "schema_versions": SCHEMA_VERSIONS,
        "reference_policy_version": None,
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
    return root, scenario_path


def validate(run: tuple[Path, Path], *, rehearsal: bool = False) -> R1PilotValidationReport:
    root, scenario_path = run
    return validate_r1_pilot_run(
        artifact_root=root, run_id=RUN_ID, scenario_path=scenario_path, rehearsal=rehearsal
    )


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


def test_attack_run_with_a_reference_is_refused(tmp_path: Path) -> None:
    # Given: an attack run that records a reference the Pilot has not decided
    run = build_run(
        tmp_path,
        run_type="attack",
        metadata={
            "reference_time": RECORDED_TIMES[0],
            "reference_action_id": "A01",
            "reference_source_event_id": "1",
        },
    )

    report = validate(run)

    # Then: it is not reported as passing, because nothing here traces it
    assert not report.ok
    assert "this validator cannot trace one" in errors_of(report)


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
