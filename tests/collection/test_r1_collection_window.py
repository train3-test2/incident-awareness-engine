"""The windows of a raw export, its context records and the collection provenance of a run.

Every artifact is synthetic and written by hand, with the builders of
`test_r1_pilot_validation`: no run id, host, address or record of a collected
run appears, and nothing starts a process or touches a network or a VM.

The run built here is one whose intermediate is started through WMI. Its raw
export starts at the boot of the target, so it holds the process-create record
of the provider host and whatever else happened before the run. An attack run
takes its reference from the process its launch action created. The variation,
the reference policy version and the action ids named for it are made up.
"""

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_r1_pilot_validation import (
    CONFIG_SHA256,
    DESTINATION_IP,
    DESTINATION_PORT,
    END_TIME,
    FINAL_GUID,
    FINAL_IMAGE,
    HORIZON_SEC,
    INTERMEDIATE_GUID,
    RUN_ID,
    SERVICE_GUID,
    SESSION_GUID,
    SESSION_HOST_IMAGE,
    START_TIME,
    SYSTEM32,
    TARGET_HOST,
    UNRELATED_GUID,
    action_id,
    build_run,
    connection_event,
    errors_of,
    jsonl_text,
    process_event,
    run_events,
    scenario,
    trace_dir,
    validate,
    write_manifest,
)
from test_r1_policy_provenance import (
    StubReferencePolicy,
    install_stub_policy_loaders,
    stub_policy_names,
)

from incident_awareness.collection.r1_collection_profile import read_collection_profile
from incident_awareness.collection.r1_collection_window import (
    CANONICAL_CONTRACT_VERSION,
    CANONICAL_PROVENANCE_FILENAME,
    CONTEXT_REASON,
    CONTEXT_RULE_VERSION,
    CONTRACT_VERSION,
    PROVENANCE_FIELDS,
    PROVENANCE_FILENAME,
    SCHEMA_NAME,
    SELECTOR_RAW_INPUT_SCOPE,
    SYSMON_CHANNEL,
    R1CollectionWindowError,
    R1ProvenanceInputs,
    check_collection_provenance,
    check_evidence_excludes_context,
    context_record_ids_in,
    context_records,
    expected_actions,
    expected_context_events,
    expected_lineage_provenance,
    observation_records,
    parse_event_utc_time,
    parse_stamp,
    record_zone,
    wmi_created_candidates,
)
from incident_awareness.collection.r1_lineage import (
    R1LineageReport,
    build_process_tree,
    read_r1_lineage_records,
    resolve_lineage,
)
from incident_awareness.collection.r1_policy_provenance import resolve_policy_provenance

WMI_FAMILY = "wmi_management"
SYNTHETIC_VARIATION = "synthetic_variation"
SYNTHETIC_POLICY = "synthetic-reference-policy"
ROOT_GUID = "{00000000-0000-0000-0000-0000000000d1}"
ROOT_IMAGE = SYSTEM32 + "wbem\\WmiPrvSE.exe"
INTERMEDIATE_IMAGES = {"normal": SYSTEM32 + "wscript.exe", "attack": SYSTEM32 + "cmd.exe"}

BOOT_STAMP = "2030-01-01T23:50:00.000Z"
START = datetime(2030, 1, 2, 0, 0, 0, tzinfo=UTC)
READINESS = {
    "method": "out_of_band",
    "checked_at": "2030-01-01T23:59:20.000Z",
    "result": "ready",
    "active_tcp_probe_used": False,
    "record_sha256": "ab" * 32,
}

# The four actions of a run through WMI: step, action type, designed offset, and
# when the synthetic run recorded them. The session is set up before the first.
WMI_STEPS = (
    ("invoke", "wmi_process_create", 0),
    ("launch", "process_create", 300),
    ("connect", "network_connection", 480),
    ("run_end", "run_end", 720),
)
WMI_RECORDED_TIMES = (
    "2030-01-02T00:00:03.000Z",
    "2030-01-02T00:05:00.200Z",
    "2030-01-02T00:08:00.300Z",
    "2030-01-02T00:12:00.400Z",
)
# The launch action is the first of the four. It starts the intermediate through
# WMI, and the record of that process is the reference of an attack run.
LAUNCH_INDEX = 0
TOOL_START_INDEX = 1
ATTACK_REFERENCE = action_id("attack", LAUNCH_INDEX)
# What the call returned, the record that carries it and when that record says
# the process was created: after the call was made, before the action was over.
CREATED_PID = 4321
CREATED_RECORD_ID = "30"
CREATED_UTC_TIME = "2030-01-02 00:00:03.250"
CREATED_STAMP = "2030-01-02T00:00:03.250Z"
CREATED_MOMENT = parse_event_utc_time(CREATED_UTC_TIME)
ACTION_STAMP = WMI_RECORDED_TIMES[LAUNCH_INDEX]
# The window the stand-in reference policy gives after the call: from the call
# to two seconds after it, both ends included.
WINDOW_END_STAMP = "2030-01-02T00:00:05.000Z"
PLANNED_INTERMEDIATE = {"normal": "wscript.exe", "attack": "cmd.exe"}
EVALUATION_END_STAMP = "2030-01-02T00:10:03.250Z"
# A run is observed for 780 s; the export is taken a few seconds later. Both
# run types are equally long.
WMI_END_TIME = "2030-01-02T00:13:05.000Z"
END_TIMES = {"normal": WMI_END_TIME, "attack": WMI_END_TIME}
OBSERVATION_END = datetime(2030, 1, 2, 0, 13, 5, tzinfo=UTC)
PROCESS_IDS = {5: 600, 10: 700, 11: 800, 20: 900, 30: CREATED_PID, 31: 4400}


@pytest.fixture(autouse=True)
def _stand_in_registries(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two policy registries are stand-ins in every test of this module."""
    install_stub_policy_loaders(monkeypatch)


def wmi_scenario() -> dict:
    """A rendered scenario whose intermediate is started through WMI."""
    body = scenario(
        normal_image="wscript.exe",
        attack_image="cmd.exe",
        family_id=WMI_FAMILY,
        variation_id=SYNTHETIC_VARIATION,
        attack_reference=ATTACK_REFERENCE,
        policy_version=SYNTHETIC_POLICY,
    )
    body["planned_lineage"]["entry"] = {"kind": "wmi_process", "root_image": "WmiPrvSE.exe"}
    body["collection"] = {
        "raw_window": "target_boot_to_run_end",
        "readiness_method": "out_of_band",
    }
    body["reference_rule"] = {"action_step": "invoke", "source": "wmi_created_process_create"}
    body["run_length"]["observation_sec"] = 780
    body["runs"] = {
        run_type: {
            "run_type": run_type,
            "reference_action_id": ATTACK_REFERENCE if run_type == "attack" else None,
            "actions": [
                {
                    "action_id": action_id(run_type, index),
                    "step": step,
                    "action_type": action_type,
                    "offset_sec": offset_sec,
                    "description": "synthetic action",
                }
                for index, (step, action_type, offset_sec) in enumerate(WMI_STEPS)
            ],
        }
        for run_type in ("normal", "attack")
    }
    # The policies the scenario names, and what their loaders said when it was
    # rendered. Both are stand-ins here.
    body["policies"] = stub_policy_names()
    body["policy_provenance"] = resolve_policy_provenance(body)
    return body


def wmi_rows(run_type: str) -> list[tuple[str, str, str, str]]:
    """(run_id, action_id, timestamp, action_type) for the four recorded actions."""
    return [
        (RUN_ID, action_id(run_type, index), WMI_RECORDED_TIMES[index], action_type)
        for index, (_, action_type, _) in enumerate(WMI_STEPS)
    ]


def wmi_metadata(run_type: str) -> dict:
    """What RunMetadata records for a run through WMI. A normal run records no reference."""
    recorded = {
        "family_id": WMI_FAMILY,
        "variation_id": SYNTHETIC_VARIATION,
        "reference_policy_version": SYNTHETIC_POLICY,
        "end_time": END_TIMES[run_type],
    }
    if run_type == "attack":
        recorded |= {
            "reference_time": CREATED_STAMP,
            "reference_action_id": ATTACK_REFERENCE,
            "reference_source_event_id": CREATED_RECORD_ID,
        }
    return recorded


def wmi_events(run_type: str = "normal") -> list[dict]:
    """A raw export from the boot of the target to the end of the run.

    Three records are older than the run: the service host and the provider
    host, created at boot, and a background process created inside the margin
    the export has always had before the start of a run. Every process-create
    record carries its process id, as Sysmon writes it.
    """
    events = [
        process_event(
            record_id=5,
            guid=SERVICE_GUID,
            parent_guid=None,
            image=SYSTEM32 + "svchost.exe",
            utc_time="2030-01-01 23:50:05.000",
        ),
        process_event(
            record_id=10,
            guid=ROOT_GUID,
            parent_guid=SERVICE_GUID,
            image=ROOT_IMAGE,
            utc_time="2030-01-01 23:50:22.000",
        ),
        process_event(
            record_id=11,
            guid=UNRELATED_GUID,
            parent_guid=SERVICE_GUID,
            image=SYSTEM32 + "background.exe",
            utc_time="2030-01-01 23:59:55.000",
        ),
        process_event(
            record_id=20, guid=SESSION_GUID, parent_guid=SERVICE_GUID, image=SESSION_HOST_IMAGE
        ),
        process_event(
            record_id=30,
            guid=INTERMEDIATE_GUID,
            parent_guid=ROOT_GUID,
            image=INTERMEDIATE_IMAGES[run_type],
            utc_time=CREATED_UTC_TIME,
        ),
        process_event(
            record_id=31, guid=FINAL_GUID, parent_guid=INTERMEDIATE_GUID, image=FINAL_IMAGE
        ),
        connection_event(record_id=40, guid=FINAL_GUID),
    ]
    for event in events:
        if event["EventId"] == 1:
            event["EventData"]["ProcessId"] = str(PROCESS_IDS[event["RecordId"]])
    return events


def _read(events: list[dict], tmp_path: Path) -> tuple[list, list]:
    path = tmp_path / "records.jsonl"
    path.write_text(jsonl_text(events), encoding="utf-8", newline="\n")
    loaded = read_r1_lineage_records(path, R1LineageReport())
    assert loaded is not None
    return loaded


def _lineage(processes: list, connections: list) -> tuple[tuple, tuple]:
    """The three records from the final tool up, and its connections to the destination."""
    tree = build_process_tree(processes, R1LineageReport())
    final = next(p for p in processes if p.key.process_guid == FINAL_GUID)
    chain = resolve_lineage(tree, final.key)
    reaching = tuple(
        c
        for c in connections
        if c.key == final.key
        and c.destination_ip == DESTINATION_IP
        and c.destination_port == str(DESTINATION_PORT)
    )
    return chain.nodes[:3], reaching


def _process_ids(events: list[dict]) -> dict[str, str]:
    return {
        str(event["RecordId"]): str(event["EventData"]["ProcessId"])
        for event in events
        if event["EventId"] == 1 and "ProcessId" in event["EventData"]
    }


def wmi_provenance(
    run_type: str,
    processes: list,
    connections: list,
    *,
    scenario_sha256: str,
    manifest_sha256: str,
    jsonl_sha256: str,
) -> dict:
    """The provenance the runner writes for a run of `run_type` that left these records."""
    nodes, reaching = _lineage(processes, connections)
    records = [*processes, *connections]
    context = len(context_records(records, START))
    attack = run_type == "attack"
    lineage = expected_lineage_provenance(nodes, reaching, START, parse_stamp(END_TIMES[run_type]))
    return {
        "schema": SCHEMA_NAME,
        "contract_version": CONTRACT_VERSION,
        "run_id": RUN_ID,
        "target_host": TARGET_HOST,
        "scenario": {
            "scenario_id": "R1",
            "family_id": WMI_FAMILY,
            "variation_id": SYNTHETIC_VARIATION,
            "scenario_version": "v1",
        },
        "entry_kind": "wmi_process",
        "raw_window": "target_boot_to_run_end",
        "raw_collection_start": BOOT_STAMP,
        "raw_collection_end": END_TIMES[run_type],
        "collection_window_extension_reason": "lineage_root_created_before_run",
        "export_margin_ms": 10000,
        "target_boot_utc": BOOT_STAMP,
        "boot_session_id": None,
        "observation_start": START_TIME,
        "observation_end": END_TIMES[run_type],
        "time_field": "EventData.UtcTime",
        "time_fallback": "none",
        "context_rule": "EventData.UtcTime < observation_start",
        "context_rule_version": CONTEXT_RULE_VERSION,
        "run_start_inclusive": True,
        "context_use": "lineage_restoration_only",
        "selector_raw_input_scope": SELECTOR_RAW_INPUT_SCOPE,
        "evaluation_window_start": CREATED_STAMP if attack else None,
        "evaluation_horizon_sec": HORIZON_SEC,
        "evaluation_window_end": EVALUATION_END_STAMP if attack else None,
        "record_counts": {
            "total": len(records),
            "context": context,
            "observation": len(records) - context,
            "after_observation": 0,
        },
        "lineage": lineage,
        "context_events": expected_context_events(lineage),
        "evidence_link_key": "RecordId",
        "readiness": dict(READINESS),
        "raw_source": {
            "host": TARGET_HOST,
            "channel": SYSMON_CHANNEL,
            "jsonl_file": "sysmon-0001.jsonl",
            "jsonl_sha256": jsonl_sha256,
            "raw_log_id": "RAW-002",
        },
        "actions": [
            {
                "action_id": action_id(run_type, index),
                "step": step,
                "action_type": action_type,
                "planned_offset_sec": offset_sec,
                "actual_utc": WMI_RECORDED_TIMES[index],
            }
            for index, (step, action_type, offset_sec) in enumerate(WMI_STEPS)
        ],
        # Both runs state the process their first action created; only the
        # attack run takes its reference from it.
        "created_process": {
            "action_id": action_id(run_type, LAUNCH_INDEX),
            "action_utc": ACTION_STAMP,
            "window_start_utc": ACTION_STAMP,
            "window_end_utc": WINDOW_END_STAMP,
            "return_value": 0,
            "process_id": CREATED_PID,
            "expected_image": PLANNED_INTERMEDIATE[run_type],
            "candidate_record_ids": [CREATED_RECORD_ID],
            "selected_record_id": CREATED_RECORD_ID,
            "parent_record_id": "10",
        },
        "canonical_provenance_linkage": {
            "filename": CANONICAL_PROVENANCE_FILENAME,
            "contract_version": CANONICAL_CONTRACT_VERSION,
            "reference_policy_id": "synthetic-reference",
            "reference_policy_version": "synthetic-reference-policy",
            "reference_policy_config_hash": "b2" * 32,
            "canonical_sha256": None,
        },
        "scenario_sha256": scenario_sha256,
        "manifest_sha256": manifest_sha256,
        "sysmon_config_sha256": CONFIG_SHA256,
    }


def build_wmi_run(
    tmp_path: Path,
    *,
    events: list[dict] | None = None,
    change: Callable[[dict], None] | None = None,
    write_provenance: bool = True,
    run_type: str = "normal",
    metadata: dict | None = None,
    scenario_body: dict | None = None,
) -> tuple[Path, Path]:
    """One artifact tree of a run through WMI, with the provenance of an intact run.

    `events` replaces what the raw export holds; the lineage and the counts of
    the provenance are still the ones of the intact run, as a record written
    before the export was changed would have them. Its hashes are the ones of
    the files on disk, so that one test breaks one thing. `change` edits the
    provenance and `metadata` replaces values of RunMetadata.
    """
    root, scenario_path = build_run(
        tmp_path,
        run_type=run_type,
        events=wmi_events(run_type) if events is None else events,
        scenario_body=wmi_scenario() if scenario_body is None else scenario_body,
        rows=wmi_rows(run_type),
        metadata=wmi_metadata(run_type) | (metadata or {}),
    )
    if write_provenance:
        raw = root / "raw" / RUN_ID
        provenance = wmi_provenance(
            run_type,
            *_read(wmi_events(run_type), tmp_path),
            scenario_sha256=hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
            manifest_sha256=hashlib.sha256((raw / "manifest.json").read_bytes()).hexdigest(),
            jsonl_sha256=hashlib.sha256(
                (raw / "telemetry" / "sysmon-0001.jsonl").read_bytes()
            ).hexdigest(),
        )
        if change is not None:
            change(provenance)
        (trace_dir(root) / PROVENANCE_FILENAME).write_text(
            json.dumps(provenance, indent=2), encoding="utf-8"
        )
    return root, scenario_path


def _set(path: tuple[str, ...], value: object) -> Callable[[dict], None]:
    def change(provenance: dict) -> None:
        target = provenance
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return change


def _drop(path: tuple[str, ...]) -> Callable[[dict], None]:
    def change(provenance: dict) -> None:
        target = provenance
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return change


# ---------------------------------------------------------------------------
# Context and observation
# ---------------------------------------------------------------------------


def test_the_observation_starts_at_the_start_of_the_run_and_includes_it() -> None:
    assert record_zone("2030-01-01 23:59:59.999", START, OBSERVATION_END) == "context"
    assert record_zone("2030-01-02 00:00:00.000", START, OBSERVATION_END) == "observation"
    assert record_zone("2030-01-02 00:00:00.001", START, OBSERVATION_END) == "observation"
    assert record_zone("2030-01-02 00:13:05.000", START, OBSERVATION_END) == "observation"
    assert record_zone("2030-01-02 00:13:05.001", START, OBSERVATION_END) == "after_observation"


def test_the_margin_before_the_run_is_context_like_everything_before_it(tmp_path: Path) -> None:
    processes, connections = _read(wmi_events(), tmp_path)
    records = [*processes, *connections]

    before = [record.record_id for record in context_records(records, START)]
    during = [record.record_id for record in observation_records(records, START, OBSERVATION_END)]

    # 5 and 10 were created at boot, 11 five seconds before the run
    assert before == ["5", "10", "11"]
    assert during == ["20", "30", "31", "40"]
    assert sorted(before + during, key=int) == [record.record_id for record in records]


@pytest.mark.parametrize(
    "value",
    [None, "", "2030-01-02T00:05:00.250Z", "2030-01-02 00:05:00", "not a time", 20300102],
    ids=["missing", "empty", "the_form_of_TimeCreated", "no_fraction", "text", "a_number"],
)
def test_a_record_without_a_readable_utc_time_is_not_placed(value: object) -> None:
    # TimeCreated is never read in its place, so there is nothing to fall back to.
    with pytest.raises(R1CollectionWindowError):
        parse_event_utc_time(value)
    with pytest.raises(R1CollectionWindowError):
        record_zone(value, START)


def test_the_root_restored_from_context_is_told_apart_from_the_records_of_the_run(
    tmp_path: Path,
) -> None:
    processes, connections = _read(wmi_events(), tmp_path)
    records = [*processes, *connections]

    # of the three records of the lineage only the root is context
    assert context_record_ids_in(["10", "30", "31"], records, START) == ["10"]
    # what an evaluation reads holds no context record at all
    evaluation_input = [
        record.record_id for record in observation_records(records, START, OBSERVATION_END)
    ]
    assert context_record_ids_in(evaluation_input, records, START) == []


def _evidence_problems(tmp_path: Path, event_ids: list[str], timestamps: list[str]) -> list[str]:
    processes, connections = _read(wmi_events("attack"), tmp_path)
    return check_evidence_excludes_context(
        event_ids=event_ids,
        timestamps=[parse_event_utc_time(stamp) for stamp in timestamps],
        records=[*processes, *connections],
        observation_start=START,
        observation_end=OBSERVATION_END,
    )


def test_the_raw_stage_context_check_is_distinct_from_the_canonical_evidence_stage_check(
    tmp_path: Path,
) -> None:
    # The raw stage, here: an Evidence is held to the records by RecordId, before
    # normalization. "10" is the context provider host.
    raw_problems = _evidence_problems(tmp_path, ["10", "30"], [CREATED_UTC_TIME])
    assert raw_problems and "context record" in raw_problems[0]

    # The canonical Evidence stage (PR #265), by NormalizedEvent and called before
    # the Baseline features are generated. This raw-stage check does not replace
    # it. It is imported here only to fix the boundary; it needs the evaluation
    # package, which this interpreter may not be able to import.
    try:
        from incident_awareness.evaluation.context_inputs import validate_context_inputs
    except (ImportError, SyntaxError):
        pytest.skip("the evaluation package cannot be imported here")
    assert callable(validate_context_inputs)


@pytest.mark.parametrize(
    ("event_ids", "timestamps", "message"),
    [
        (
            ["10", "30", "31", "40"],
            [CREATED_UTC_TIME],
            "the Evidence lists context record(s) ['10']",
        ),
        (["11", "40"], [CREATED_UTC_TIME], "the Evidence lists context record(s) ['11']"),
        (
            ["5", "10", "30"],
            [CREATED_UTC_TIME],
            "the Evidence lists context record(s) ['5', '10']",
        ),
        (
            ["30", "31", "40"],
            ["2030-01-01 23:50:22.000", CREATED_UTC_TIME],
            "(2030-01-02T00:00:00.000Z): ['2030-01-01T23:50:22.000Z']",
        ),
        (
            ["30"],
            ["2030-01-01 23:59:59.999"],
            "the Evidence states time(s) before the start of the run",
        ),
        (["30", "99"], [CREATED_UTC_TIME], "RecordId '99', which is no record of the raw export"),
    ],
    ids=[
        "the_restored_root_among_the_events",
        "a_record_of_the_margin_before_the_run",
        "two_context_records",
        "the_time_of_the_restored_root",
        "a_time_one_millisecond_before_the_run",
        "an_id_that_is_no_record",
    ],
)
def test_an_evidence_that_holds_a_context_record_or_its_time_is_reported(
    tmp_path: Path, event_ids: list[str], timestamps: list[str], message: str
) -> None:
    problems = _evidence_problems(tmp_path, event_ids, timestamps)

    assert len(problems) == 1 and message in problems[0], problems


def test_an_evidence_of_the_records_of_the_run_holds_no_context(tmp_path: Path) -> None:
    # the created process, the final tool and its connection; the first time is the start itself
    assert (
        _evidence_problems(
            tmp_path, ["30", "31", "40"], ["2030-01-02 00:00:00.000", CREATED_UTC_TIME]
        )
        == []
    )


def test_an_evidence_time_generator_is_checked_at_both_observation_boundaries(
    tmp_path: Path,
) -> None:
    processes, connections = _read(wmi_events("attack"), tmp_path)
    moments = (
        parse_event_utc_time(stamp) for stamp in (CREATED_UTC_TIME, "2030-01-02 00:13:05.001")
    )

    problems = check_evidence_excludes_context(
        event_ids=["30"],
        timestamps=moments,
        records=[*processes, *connections],
        observation_start=START,
        observation_end=OBSERVATION_END,
    )

    assert len(problems) == 1
    assert "the Evidence states time(s) after the end of the run" in problems[0]


def test_the_lineage_of_a_provenance_names_its_context_root_outside_the_evidence_events(
    tmp_path: Path,
) -> None:
    # The provenance of a run names the context root; an Evidence built from the
    # records of the run that the lineage lists does not hold it.
    processes, connections = _read(wmi_events("attack"), tmp_path)
    lineage = expected_lineage_provenance(*_lineage(processes, connections), START, OBSERVATION_END)
    in_the_run = [r["record_id"] for r in lineage["records"] if r["zone"] == "observation"]
    times = [
        parse_event_utc_time(r["utc_time"])
        for r in lineage["records"]
        if r["zone"] == "observation"
    ]

    assert lineage["context_record_ids"] == ["10"]
    assert in_the_run == ["31", "30"]
    assert (
        check_evidence_excludes_context(
            event_ids=[*in_the_run, lineage["connection"]["record_id"]],
            timestamps=times,
            records=[*processes, *connections],
            observation_start=START,
            observation_end=OBSERVATION_END,
        )
        == []
    )


def test_the_lineage_provenance_names_the_context_root_and_what_refers_to_it(
    tmp_path: Path,
) -> None:
    nodes, reaching = _lineage(*_read(wmi_events(), tmp_path))

    lineage = expected_lineage_provenance(nodes, reaching, START, OBSERVATION_END)

    assert [(r["role"], r["record_id"], r["zone"]) for r in lineage["records"]] == [
        ("final_tool", "31", "observation"),
        ("intermediate", "30", "observation"),
        ("root", "10", "context"),
    ]
    assert lineage["linked_by"] == ["ProcessGuid", "ParentProcessGuid"]
    assert lineage["context_record_ids"] == ["10"]
    # the record of the run through which the context record reaches the run
    assert lineage["references_to_context"] == [
        {
            "record_id": "30",
            "role": "intermediate",
            "parent_process_guid": ROOT_GUID,
            "context_record_id": "10",
        }
    ]
    assert lineage["connection"]["record_id"] == "40"
    assert lineage["connection"]["zone"] == "observation"


def test_every_record_of_the_lineage_is_named_by_its_record_id_and_its_line(
    tmp_path: Path,
) -> None:
    # The RecordId is the one of the channel; the line is where the record is in
    # the file the provenance names by hash. Both come from the raw export.
    nodes, reaching = _lineage(*_read(wmi_events(), tmp_path))

    lineage = expected_lineage_provenance(nodes, reaching, START, OBSERVATION_END)

    assert [(r["record_id"], r["record_no"]) for r in lineage["records"]] == [
        ("31", 6),
        ("30", 5),
        ("10", 2),
    ]
    assert (lineage["connection"]["record_id"], lineage["connection"]["record_no"]) == ("40", 7)


# ---------------------------------------------------------------------------
# A run through WMI, validated as a whole
# ---------------------------------------------------------------------------


def test_a_normal_run_through_wmi_passes_with_its_root_restored_from_context(
    tmp_path: Path,
) -> None:
    report = validate(build_wmi_run(tmp_path))

    assert report.ok, errors_of(report)
    assert report.lineage is not None
    assert report.lineage.roles == ("final tool", "intermediate", "lineage root")
    assert [node.record_id for node in report.lineage.nodes] == ["31", "30", "10"]
    assert report.lineage.images[-1] == ROOT_IMAGE
    checks = "\n".join(report.checks)
    assert "3 of 7 record(s) are context" in checks
    assert "4 belong to the inclusive run interval" in checks
    assert "0 are after it" in checks
    assert "nothing connected from the target before the run" in checks
    assert "run_metadata.json records no reference" in checks


def test_an_attack_run_through_wmi_takes_its_reference_from_the_process_it_created(
    tmp_path: Path,
) -> None:
    report = validate(build_wmi_run(tmp_path, run_type="attack"))

    assert report.ok, errors_of(report)
    assert [node.record_id for node in report.lineage.nodes] == ["31", CREATED_RECORD_ID, "10"]
    checks = "\n".join(report.checks)
    assert (
        "the reference of the run is the EID 1 of the process its reference action created: "
        f"RecordId {CREATED_RECORD_ID}"
    ) in checks
    assert f"EventData.UtcTime {CREATED_UTC_TIME}" in checks
    # the horizon is counted from the reference, which the first action gives
    assert "the collection reached the evaluation horizon" in checks
    # the root is context and is not what the reference is taken from
    assert "3 of 7 record(s) are context" in checks


def test_the_lineage_of_the_other_run_type_is_not_the_planned_one(tmp_path: Path) -> None:
    # No Image is a condition by itself: the same record is the plan of one run
    # type and a mismatch for the other.
    report = validate(build_wmi_run(tmp_path, events=wmi_events("attack")))

    assert "no final tool instance has the lineage this run was designed with" in errors_of(report)


def test_a_normal_run_through_wmi_records_no_reference(tmp_path: Path) -> None:
    recorded = {
        "reference_time": CREATED_STAMP,
        "reference_action_id": action_id("normal", LAUNCH_INDEX),
        "reference_source_event_id": CREATED_RECORD_ID,
    }

    report = validate(build_wmi_run(tmp_path, metadata=recorded))

    assert not report.ok
    assert "reference" in errors_of(report)


def test_an_attack_run_that_ends_before_its_horizon_is_refused(tmp_path: Path) -> None:
    # A collection that ends a second before the reference plus the horizon.
    report = validate(
        build_wmi_run(
            tmp_path, run_type="attack", metadata={"end_time": "2030-01-02T00:10:02.000Z"}
        )
    )

    assert "is earlier than reference_time + 600 s" in errors_of(report)


def test_a_run_through_wmi_without_its_provenance_is_refused(tmp_path: Path) -> None:
    report = validate(build_wmi_run(tmp_path, write_provenance=False))

    assert "collection provenance is missing" in errors_of(report)


@pytest.mark.parametrize("name", PROVENANCE_FIELDS)
def test_a_provenance_without_one_of_its_fields_is_refused(tmp_path: Path, name: str) -> None:
    report = validate(build_wmi_run(tmp_path, change=_drop((name,))))

    assert f"is missing ['{name}']" in errors_of(report)


def test_a_provenance_with_a_field_it_does_not_have_is_refused(tmp_path: Path) -> None:
    report = validate(build_wmi_run(tmp_path, change=_set(("parent_image_fallback",), True)))

    assert "states unknown ['parent_image_fallback']" in errors_of(report)


def test_the_provenance_states_the_schema_and_contract_of_the_sidecar(tmp_path: Path) -> None:
    assert SCHEMA_NAME == "r1-wmi-collection-context"
    assert CONTRACT_VERSION == "v0.1"

    report = validate(build_wmi_run(tmp_path, change=_set(("schema",), "other")))

    assert "schema is 'other', expected 'r1-wmi-collection-context'" in errors_of(report)


# ---------------------------------------------------------------------------
# The three windows are recorded apart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "message"),
    [
        # the start of the export is not the start of the observation
        (_set(("observation_start",), "2030-01-01T23:59:50.000Z"), "observation_start is"),
        (_set(("observation_start",), BOOT_STAMP), "observation_start is"),
        (_set(("raw_collection_start",), "2030-01-02T00:00:05.000Z"), "after the start of the run"),
        (_set(("raw_collection_end",), "2030-01-02T00:10:00.000Z"), "raw_collection_end is"),
        (_set(("collection_window_extension_reason",), None), "extension_reason is None"),
        (_set(("raw_window",), "run_window"), "raw_window is 'run_window'"),
        (_set(("time_field",), "TimeCreated"), "time_field is 'TimeCreated'"),
        (_set(("context_use",), "evaluation_input"), "context_use is 'evaluation_input'"),
        (_set(("evaluation_horizon_sec",), 1265), "evaluation_horizon_sec is 1265"),
        # a normal run has no evaluation window, whatever its raw window is
        (
            _set(("evaluation_window_start",), START_TIME),
            "evaluation_window_start and evaluation_window_end must be null",
        ),
        (
            _set(("evaluation_window_end",), END_TIME),
            "evaluation_window_start and evaluation_window_end must be null",
        ),
    ],
    ids=[
        "observation_from_the_margin",
        "observation_from_the_boot",
        "raw_window_after_the_start",
        "another_end",
        "no_extension_reason",
        "another_raw_window",
        "another_time_field",
        "context_used_for_evaluation",
        "the_raw_length_as_the_horizon",
        "a_reference_for_a_normal_run",
        "an_evaluation_end_for_a_normal_run",
    ],
)
def test_a_provenance_that_mixes_the_windows_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    report = validate(build_wmi_run(tmp_path, change=change))

    assert message in errors_of(report)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        # a context record counted with the run, and the reverse
        (
            _set(
                ("record_counts",),
                {"total": 7, "context": 2, "observation": 5, "after_observation": 0},
            ),
            "record_counts is",
        ),
        (
            _set(
                ("record_counts",),
                {"total": 7, "context": 0, "observation": 7, "after_observation": 0},
            ),
            "record_counts is",
        ),
        (_set(("lineage", "context_record_ids"), []), "lineage.context_record_ids is []"),
        (_set(("lineage", "references_to_context"), []), "lineage.references_to_context is []"),
    ],
    ids=["one_context_record_counted", "no_context_at_all", "no_context_root", "no_reference"],
)
def test_a_provenance_that_lets_context_into_the_run_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    report = validate(build_wmi_run(tmp_path, change=change))

    assert message in errors_of(report)


def test_a_record_just_after_the_run_is_preserved_but_not_observed(tmp_path: Path) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, "normal")
    after_time = "2030-01-02 00:13:05.001"
    late = replace(
        connections[0],
        record_id="41",
        record_no=8,
        event_utc_time=after_time,
        destination_ip="192.168.34.99",
    )
    extended_connections = [*connections, late]
    records = [*processes, *extended_connections]
    provenance["raw_collection_end"] = "2030-01-02T00:13:05.001Z"
    provenance["record_counts"] = {
        "total": 8,
        "context": 3,
        "observation": 4,
        "after_observation": 1,
    }

    assert check_collection_provenance(provenance, inputs, processes, extended_connections) == []
    assert [
        record.record_id
        for record in observation_records(records, inputs.start_time, inputs.end_time)
    ] == ["20", "30", "31", "40"]
    evidence_problems = check_evidence_excludes_context(
        event_ids=["31", "41"],
        timestamps=[parse_event_utc_time(CREATED_UTC_TIME), parse_event_utc_time(after_time)],
        records=records,
        observation_start=inputs.start_time,
        observation_end=inputs.end_time,
    )
    assert any("after the end of the run" in problem for problem in evidence_problems)

    provenance["record_counts"]["after_observation"] = 0
    assert any(
        "record_counts is" in problem
        for problem in check_collection_provenance(
            provenance, inputs, processes, extended_connections
        )
    )


def test_a_provenance_that_places_the_root_in_the_run_is_refused(tmp_path: Path) -> None:
    def root_in_the_run(provenance: dict) -> None:
        provenance["lineage"]["records"][2]["zone"] = "observation"

    report = validate(build_wmi_run(tmp_path, change=root_in_the_run))

    assert "lineage.records is" in errors_of(report)


# ---------------------------------------------------------------------------
# Readiness and hashes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_set(("readiness", "active_tcp_probe_used"), True), "active_tcp_probe_used must be false"),
        (
            _set(("readiness", "active_tcp_probe_used"), "false"),
            "active_tcp_probe_used must be false",
        ),
        (_set(("readiness", "active_tcp_probe_used"), None), "active_tcp_probe_used must be false"),
        (_drop(("readiness", "active_tcp_probe_used")), "readiness must hold exactly"),
        (_set(("readiness",), None), "readiness must hold exactly"),
        (_set(("readiness", "method"), "active_tcp_from_target"), "readiness.method is"),
        (_set(("readiness", "result"), "not_ready"), "readiness.result is 'not_ready'"),
        (
            _set(("readiness", "checked_at"), "2030-01-02T00:00:30.000Z"),
            "after the start of the run",
        ),
        (_set(("readiness", "checked_at"), None), "readiness.checked_at is not a UTC stamp"),
        (_set(("readiness", "record_sha256"), "none"), "readiness.record_sha256 is not a SHA-256"),
    ],
    ids=[
        "a_probe_was_used",
        "false_as_text",
        "probe_null",
        "probe_not_stated",
        "no_readiness",
        "another_method",
        "not_ready",
        "checked_after_the_start",
        "no_time_of_the_check",
        "no_hash_of_the_record",
    ],
)
def test_a_run_whose_readiness_record_is_not_passive_and_ready_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    report = validate(build_wmi_run(tmp_path, change=change))

    assert message in errors_of(report)


@pytest.mark.parametrize("name", ["scenario_sha256", "manifest_sha256", "sysmon_config_sha256"])
def test_a_provenance_of_another_scenario_manifest_or_sysmon_config_is_refused(
    tmp_path: Path, name: str
) -> None:
    report = validate(build_wmi_run(tmp_path, change=_set((name,), "0" * 64)))

    assert f"{name} is {'0' * 64}" in errors_of(report)


# ---------------------------------------------------------------------------
# Where the records come from
# ---------------------------------------------------------------------------


def test_the_provenance_names_the_host_the_channel_and_the_file_its_record_ids_belong_to(
    tmp_path: Path,
) -> None:
    root, _ = run = build_wmi_run(tmp_path)
    provenance = json.loads((trace_dir(root) / PROVENANCE_FILENAME).read_text(encoding="utf-8"))
    jsonl = root / "raw" / RUN_ID / "telemetry" / "sysmon-0001.jsonl"

    assert validate(run).ok
    # a RecordId is one of a channel of a host, and is read here from one file
    assert provenance["raw_source"] == {
        "host": TARGET_HOST,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "jsonl_file": "sysmon-0001.jsonl",
        "jsonl_sha256": hashlib.sha256(jsonl.read_bytes()).hexdigest(),
        "raw_log_id": "RAW-002",
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_set(("raw_source", "host"), "TARGET-B"), "raw_source.host is 'TARGET-B'"),
        (_set(("raw_source", "channel"), "Security"), "raw_source.channel is 'Security'"),
        (_set(("raw_source", "jsonl_file"), "sysmon-0002.jsonl"), "raw_source.jsonl_file is"),
        (_set(("raw_source", "jsonl_sha256"), "0" * 64), "raw_source.jsonl_sha256 is"),
        # RAW-001 is the EVTX the JSONL was derived from, not the file the lines are in
        (_set(("raw_source", "raw_log_id"), "RAW-001"), "raw_source.raw_log_id is 'RAW-001'"),
        (_set(("raw_source", "raw_log_id"), None), "raw_source.raw_log_id is None"),
        (_drop(("raw_source", "channel")), "raw_source must hold exactly"),
        (_set(("raw_source", "evtx_sha256"), "0" * 64), "raw_source must hold exactly"),
        (_set(("raw_source",), None), "raw_source must hold exactly"),
    ],
    ids=[
        "another_host",
        "another_channel",
        "another_file",
        "another_hash",
        "the_id_of_the_evtx",
        "no_raw_log_id",
        "no_channel",
        "an_unknown_key",
        "not_stated",
    ],
)
def test_a_provenance_whose_raw_source_is_not_the_export_of_the_run_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    report = validate(build_wmi_run(tmp_path, change=change))

    assert message in errors_of(report)


# ---------------------------------------------------------------------------
# The registered policies a run names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_both_runs_link_to_the_canonical_artifact_and_name_their_scenario(
    tmp_path: Path, run_type: str
) -> None:
    root, _ = run = build_wmi_run(tmp_path, run_type=run_type)
    provenance = json.loads((trace_dir(root) / PROVENANCE_FILENAME).read_text(encoding="utf-8"))

    assert validate(run).ok
    # The sidecar does not copy the policy blocks; it links to the canonical
    # artifact by the reference-policy identity the collection used.
    assert "policy_provenance" not in provenance
    linkage = provenance["canonical_provenance_linkage"]
    assert linkage["filename"] == CANONICAL_PROVENANCE_FILENAME
    assert linkage["contract_version"] == CANONICAL_CONTRACT_VERSION
    assert linkage["reference_policy_id"] == "synthetic-reference"
    assert linkage["reference_policy_version"] == SYNTHETIC_POLICY
    assert linkage["reference_policy_config_hash"] == StubReferencePolicy().config_hash
    # No canonical SHA-256 at collection time: a reader compares it from a path.
    assert linkage["canonical_sha256"] is None
    assert provenance["scenario"] == {
        "scenario_id": "R1",
        "family_id": WMI_FAMILY,
        "variation_id": SYNTHETIC_VARIATION,
        "scenario_version": "v1",
    }
    assert provenance["target_host"] == TARGET_HOST


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            _set(("scenario", "scenario_id"), "S0"),
            "scenario.scenario_id is 'S0', the run states 'R1'",
        ),
        (
            _set(("scenario", "family_id"), "remote_management"),
            "scenario.family_id is 'remote_management'",
        ),
        (_set(("scenario", "variation_id"), "V09"), "scenario.variation_id is 'V09'"),
        (_drop(("scenario", "scenario_version")), "scenario must hold exactly"),
        (_set(("target_host",), "TARGET-B"), "target_host is 'TARGET-B', expected"),
    ],
    ids=[
        "another_scenario_id",
        "another_family",
        "another_variation",
        "no_version",
        "another_host",
    ],
)
def test_a_scenario_block_that_is_not_the_one_of_the_run_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    assert message in errors_of(validate(build_wmi_run(tmp_path, change=change)))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            _set(("canonical_provenance_linkage", "filename"), "other.json"),
            "canonical_provenance_linkage.filename is 'other.json', expected 'r1_collection_provenance.json'",
        ),
        (
            _set(("canonical_provenance_linkage", "contract_version"), "v9"),
            "canonical_provenance_linkage.contract_version is 'v9'",
        ),
        (
            _set(("canonical_provenance_linkage", "reference_policy_id"), "another"),
            "canonical_provenance_linkage.reference_policy_id is 'another'",
        ),
        (
            _set(("canonical_provenance_linkage", "reference_policy_config_hash"), "0" * 64),
            "canonical_provenance_linkage.reference_policy_config_hash is",
        ),
        (
            _set(("canonical_provenance_linkage", "canonical_sha256"), "nope"),
            "canonical_provenance_linkage.canonical_sha256 must be null or a SHA-256",
        ),
        (
            _drop(("canonical_provenance_linkage", "filename")),
            "canonical_provenance_linkage must hold exactly",
        ),
        (
            _set(("canonical_provenance_linkage",), None),
            "canonical_provenance_linkage must hold exactly",
        ),
    ],
    ids=[
        "another_filename",
        "another_contract",
        "another_policy_id",
        "another_policy_hash",
        "bad_canonical_hash",
        "no_filename",
        "not_stated",
    ],
)
def test_a_canonical_linkage_that_is_not_the_one_of_the_run_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    assert message in errors_of(validate(build_wmi_run(tmp_path, change=change)))


def test_a_registered_policy_that_changed_after_the_run_is_noticed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = build_wmi_run(tmp_path, run_type="attack")
    assert validate(run).ok
    # the same identity is registered with another content afterwards
    install_stub_policy_loaders(
        monkeypatch, reference=replace(StubReferencePolicy(), config_hash="d4" * 32)
    )

    errors = errors_of(validate(run))

    assert "the policy_provenance of the rendered scenario.reference.config_hash is" in errors


def test_a_run_through_wmi_whose_scenario_names_no_policy_is_refused(tmp_path: Path) -> None:
    body = wmi_scenario()
    del body["policies"], body["policy_provenance"]

    report = validate(build_wmi_run(tmp_path, scenario_body=body))

    assert "names its registered policies" in errors_of(report)
    assert "this one names none" in errors_of(report)


def test_a_rendered_scenario_whose_policy_values_were_edited_is_refused(tmp_path: Path) -> None:
    # A wider window typed into the rendered scenario would let another record
    # be the created process. The registered window is the one that counts.
    body = wmi_scenario()
    body["policy_provenance"]["reference"]["candidate_window_sec"] = 600

    report = validate(build_wmi_run(tmp_path, scenario_body=body, run_type="attack"))

    assert (
        "the policy_provenance of the rendered scenario.reference.candidate_window_sec is 600"
    ) in errors_of(report)


# ---------------------------------------------------------------------------
# The process the first action created, and the reference an attack run takes from it
# ---------------------------------------------------------------------------


def _errors(tmp_path: Path, run_type: str = "attack", **changes: object) -> str:
    return errors_of(validate(build_wmi_run(tmp_path, run_type=run_type, **changes)))


def _attack(tmp_path: Path, **changes: object) -> str:
    return _errors(tmp_path, "attack", **changes)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_both_runs_state_the_one_process_their_first_action_created(
    tmp_path: Path, run_type: str
) -> None:
    root, _ = run = build_wmi_run(tmp_path, run_type=run_type)
    created = json.loads((trace_dir(root) / PROVENANCE_FILENAME).read_text(encoding="utf-8"))[
        "created_process"
    ]

    assert validate(run).ok
    assert created["action_id"] == action_id(run_type, LAUNCH_INDEX)
    assert created["expected_image"] == PLANNED_INTERMEDIATE[run_type]
    assert created["candidate_record_ids"] == [CREATED_RECORD_ID] == [created["selected_record_id"]]
    # the window is the one of the reference policy: from the call to two seconds after it
    assert (created["window_start_utc"], created["window_end_utc"]) == (
        ACTION_STAMP,
        WINDOW_END_STAMP,
    )
    assert created["parent_record_id"] == "10"


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize(
    "value", [1, 2, 8, 21, -1, None, "0", False, 0.5], ids=lambda value: f"{value!r}"
)
def test_a_call_that_did_not_return_zero_did_not_create_a_process(
    tmp_path: Path, run_type: str, value: object
) -> None:
    change = _set(("created_process", "return_value"), value)

    assert "the action succeeded only when the call returned 0" in _errors(
        tmp_path, run_type, change=change
    )


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize(
    "value", [0, -4321, None, "4321", True, 4321.5], ids=lambda value: f"{value!r}"
)
def test_a_call_that_returned_no_process_id_did_not_create_a_process(
    tmp_path: Path, run_type: str, value: object
) -> None:
    change = _set(("created_process", "process_id"), value)

    assert "the action succeeded only when the call returned a process id" in _errors(
        tmp_path, run_type, change=change
    )


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_the_record_that_was_found_has_to_carry_the_process_id_the_call_returned(
    tmp_path: Path, run_type: str
) -> None:
    # The record is found by its program, its time and its parent. The process
    # id does not find it; it is compared afterwards, and a difference fails.
    events = wmi_events(run_type)
    events[4]["EventData"]["ProcessId"] = "9999"

    errors = _errors(tmp_path, run_type, events=events)

    assert "carries process id '9999', the call returned 4321" in errors


def test_a_record_without_a_process_id_is_not_the_created_process(tmp_path: Path) -> None:
    events = wmi_events("attack")
    del events[4]["EventData"]["ProcessId"]

    assert "carries process id None, the call returned 4321" in _attack(tmp_path, events=events)


def _same_program(record_id: int, utc_time: str, parent_guid: str = ROOT_GUID) -> dict:
    """One more process-create record of the planned program of the attack run."""
    event = process_event(
        record_id=record_id,
        guid="{00000000-0000-0000-0000-0000000000e1}",
        parent_guid=parent_guid,
        image=INTERMEDIATE_IMAGES["attack"],
        utc_time=utc_time,
    )
    event["EventData"]["ProcessId"] = "5555"
    return event


def test_two_records_of_the_planned_program_in_the_window_are_not_told_apart(
    tmp_path: Path,
) -> None:
    # A second child of the provider host, the same program, a second later.
    # Nothing picks one of the two: not the process id, not the order.
    errors = _attack(
        tmp_path, events=[*wmi_events("attack"), _same_program(32, "2030-01-02 00:00:04.000")]
    )

    assert "2 process-create record(s) of cmd.exe with a context WmiPrvSE.exe as their parent" in (
        errors
    )
    assert "(RecordId ['30', '32']); A01 created exactly one" in errors


def test_the_same_program_started_by_another_parent_is_not_a_candidate(tmp_path: Path) -> None:
    # Its ParentProcessGuid is not the provider host, whatever its ParentImage says.
    other = _same_program(32, "2030-01-02 00:00:04.000", parent_guid=SERVICE_GUID)
    other["EventData"]["ParentImage"] = ROOT_IMAGE

    errors = _attack(tmp_path, events=[*wmi_events("attack"), other])

    # the one more record changes the counts of the export and nothing about the created process
    assert "process-create record(s) of cmd.exe" not in errors
    assert "candidate_record_ids is" not in errors
    assert "record_counts is" in errors


@pytest.mark.parametrize(
    "utc_time",
    ["2030-01-02 00:00:02.999", "2030-01-02 00:00:05.001", "2030-01-01 23:59:58.000"],
    ids=["a_millisecond_before_the_call", "a_millisecond_after_the_window", "before_the_run"],
)
def test_a_record_outside_the_window_of_the_policy_is_not_the_created_process(
    tmp_path: Path, utc_time: str
) -> None:
    events = wmi_events("attack")
    events[4]["EventData"]["UtcTime"] = utc_time

    errors = _attack(tmp_path, events=events)

    assert "0 process-create record(s) of cmd.exe with a context WmiPrvSE.exe as their parent" in (
        errors
    )
    assert "candidate_record_ids is ['30'], the raw export shows []" in errors


def _candidates(processes: list, **replaced: object) -> list:
    arguments = {
        "target_host": TARGET_HOST,
        "image_name": "cmd.exe",
        "root_image": "WmiPrvSE.exe",
        "observation_start": START,
        "not_before": parse_stamp(ACTION_STAMP),
        "not_after": parse_stamp(WINDOW_END_STAMP),
    }
    return wmi_created_candidates(processes, **(arguments | replaced))


def test_a_record_at_either_end_of_the_window_is_a_candidate(tmp_path: Path) -> None:
    processes, _ = _read(wmi_events("attack"), tmp_path)

    for moment in (ACTION_STAMP, WINDOW_END_STAMP):
        at_the_edge = replace(processes[4], event_utc_time=moment.replace("T", " ").rstrip("Z"))
        found = _candidates([*processes[:4], at_the_edge, *processes[5:]])
        assert [record.record_id for record in found] == [CREATED_RECORD_ID]


def test_a_candidate_is_found_without_its_process_id_and_whatever_the_case_of_its_image(
    tmp_path: Path,
) -> None:
    processes, _ = _read(wmi_events("attack"), tmp_path)

    found = _candidates(processes, image_name="CMD.EXE", root_image="wmiprvse.exe")

    assert [record.record_id for record in found] == [CREATED_RECORD_ID]
    assert _candidates(processes, image_name="wscript.exe") == []
    assert _candidates(processes, target_host="TARGET-B") == []


def test_a_provider_host_that_was_created_in_the_run_is_not_a_context_parent(
    tmp_path: Path,
) -> None:
    # The parent has its own record and the right program, but it was created
    # after the start of the run: it is not a context record.
    events = wmi_events("attack")
    events[1]["EventData"]["UtcTime"] = "2030-01-02 00:00:01.000"
    processes, _ = _read(events, tmp_path)

    assert _candidates(processes) == []
    assert "0 process-create record(s) of cmd.exe with a context WmiPrvSE.exe as their parent" in (
        _attack(tmp_path, events=events)
    )


@pytest.mark.parametrize(
    ("root_utc_time", "found"),
    [("2030-01-01 23:59:59.999", ["30"]), ("2030-01-02 00:00:00.000", [])],
    ids=["one_millisecond_before_the_run", "at_the_start_of_the_run"],
)
def test_the_start_of_the_run_is_the_boundary_of_a_context_parent(
    tmp_path: Path, root_utc_time: str, found: list[str]
) -> None:
    # The start of the run belongs to the run: a provider host created at that
    # moment is no context record, one created a millisecond earlier is.
    events = wmi_events("attack")
    events[1]["EventData"]["UtcTime"] = root_utc_time
    processes, _ = _read(events, tmp_path)

    assert [record.record_id for record in _candidates(processes)] == found


def test_a_candidate_whose_utc_time_cannot_be_read_is_not_placed_by_another_field(
    tmp_path: Path,
) -> None:
    processes, _ = _read(wmi_events("attack"), tmp_path)
    # TimeCreated of the record is readable and inside the window
    unreadable = replace(processes[4], event_utc_time=None, time_created=CREATED_STAMP)

    with pytest.raises(R1CollectionWindowError):
        _candidates([*processes[:4], unreadable, *processes[5:]])


def test_an_attack_run_whose_created_record_has_no_readable_utc_time_fails(
    tmp_path: Path,
) -> None:
    events = wmi_events("attack")
    events[4]["EventData"]["UtcTime"] = CREATED_STAMP

    errors = _attack(tmp_path, events=events)

    assert "carries no readable EventData.UtcTime" in errors
    assert "TimeCreated is not used in its place" in errors
    assert "1 record(s) carry no readable EventData.UtcTime" in errors


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            _set(("created_process", "candidate_record_ids"), ["30", "31"]),
            "candidate_record_ids is ['30', '31'], the raw export shows ['30']",
        ),
        (
            _set(("created_process", "candidate_record_ids"), []),
            "candidate_record_ids is [], the raw export shows ['30']",
        ),
        (
            _set(("created_process", "selected_record_id"), "31"),
            "created_process.selected_record_id is '31', the one candidate is RecordId '30'",
        ),
        (
            _set(("created_process", "parent_record_id"), "5"),
            "created_process.parent_record_id is '5', the root of the lineage is RecordId '10'",
        ),
        (
            _set(("created_process", "action_utc"), "2030-01-02T00:00:02.900Z"),
            f"the execution record of {ATTACK_REFERENCE} says '{ACTION_STAMP}'",
        ),
        (
            _set(("created_process", "action_utc"), CREATED_UTC_TIME),
            "created_process.action_utc is not a UTC stamp",
        ),
        (
            _set(("created_process", "window_start_utc"), "2030-01-02T00:00:01.000Z"),
            "created_process.window_start_utc is",
        ),
        (
            _set(("created_process", "window_end_utc"), "2030-01-02T00:05:00.000Z"),
            f"the reference policy gives {WINDOW_END_STAMP}",
        ),
        (
            _set(("created_process", "action_id"), action_id("attack", TOOL_START_INDEX)),
            f"created_process.action_id is 'A02', expected '{ATTACK_REFERENCE}'",
        ),
        (
            _set(("created_process", "expected_image"), "wscript.exe"),
            "created_process.expected_image is 'wscript.exe', expected 'cmd.exe'",
        ),
        (_drop(("created_process", "return_value")), "created_process must hold exactly"),
        (
            _set(("created_process", "parent_image"), "WmiPrvSE.exe"),
            "created_process must hold exactly",
        ),
        (_set(("created_process",), None), "created_process must hold exactly"),
    ],
    ids=[
        "one_candidate_too_many",
        "no_candidate_listed",
        "another_record_selected",
        "another_parent_named",
        "the_call_before_its_action",
        "the_call_in_the_form_of_sysmon",
        "a_window_that_starts_before_the_call",
        "a_wider_window",
        "another_action",
        "another_program",
        "no_return_value",
        "an_unknown_key",
        "not_stated",
    ],
)
def test_a_statement_about_the_created_process_that_is_not_the_one_of_the_run_is_refused(
    tmp_path: Path, change: Callable[[dict], None], message: str
) -> None:
    assert message in _attack(tmp_path, change=change)


def test_a_reference_that_is_another_record_than_the_created_one_is_refused(
    tmp_path: Path,
) -> None:
    # RunMetadata names the final tool. It is a record of the run, and it is not
    # the record the first action created.
    errors = _attack(tmp_path, metadata={"reference_source_event_id": "31"})

    assert "reference_source_event_id is '31', but the EID 1 of the process" in errors


# ---------------------------------------------------------------------------
# Fail closed on what the raw export holds
# ---------------------------------------------------------------------------


def test_a_run_whose_root_is_not_in_the_raw_export_fails(tmp_path: Path) -> None:
    # What a run window would have exported: the provider host is missing. The
    # intermediate still names it as ParentImage, which restores nothing.
    events = [event for event in wmi_events() if event["RecordId"] not in (5, 10, 11)]
    events[1]["EventData"]["ParentImage"] = ROOT_IMAGE

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "no final tool instance has the lineage this run was designed with" in errors_of(report)
    assert ROOT_GUID in errors_of(report)


def test_an_attack_run_whose_created_process_has_another_parent_fails(tmp_path: Path) -> None:
    # The record carries the returned process id and the right Image, and names
    # the provider host as ParentImage. Its ParentProcessGuid is another process,
    # so it is not in a lineage that reaches the root, and it is not a reference.
    events = wmi_events("attack")
    events[4]["EventData"]["ParentProcessGuid"] = SERVICE_GUID
    events[4]["EventData"]["ParentImage"] = ROOT_IMAGE

    errors = _attack(tmp_path, events=events)

    assert "no final tool instance has the lineage this run was designed with" in errors


def test_a_run_whose_root_is_recorded_twice_fails(tmp_path: Path) -> None:
    events = wmi_events()
    events.append(copy.deepcopy(events[1]) | {"RecordId": 12})

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "duplicate EID 1 for the same host and ProcessGuid" in errors_of(report)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_a_run_without_the_connection_of_the_scenario_fails(tmp_path: Path, run_type: str) -> None:
    events = [event for event in wmi_events(run_type) if event["EventId"] != 3]

    report = validate(build_wmi_run(tmp_path, events=events, run_type=run_type))

    assert not report.ok
    assert "0 connection(s) of the target reach the internal destination in the run" in errors_of(
        report
    )


def _early_connection(guid: str) -> dict:
    event = connection_event(record_id=12, guid=guid)
    event["EventData"]["UtcTime"] = "2030-01-01 23:59:30.000"
    return event


@pytest.mark.parametrize("guid", [UNRELATED_GUID, ROOT_GUID], ids=["another_process", "the_root"])
def test_a_connection_to_the_destination_before_the_run_fails_the_run(
    tmp_path: Path, guid: str
) -> None:
    # What a readiness probe from the target would leave in a raw export that
    # starts at the boot. It does not stand in for the connection of the run.
    report = validate(build_wmi_run(tmp_path, events=[*wmi_events(), _early_connection(guid)]))

    assert "connected to the internal destination before the start of the run" in errors_of(report)
    assert "RecordId ['12']" in errors_of(report)


def test_an_earlier_connection_does_not_replace_the_missing_one(tmp_path: Path) -> None:
    events = [event for event in wmi_events() if event["EventId"] != 3]
    events.append(_early_connection(FINAL_GUID))

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "before the start of the run" in errors_of(report)
    assert "0 connection(s) of the target reach the internal destination in the run" in errors_of(
        report
    )


def test_two_connections_to_the_destination_in_the_run_are_ambiguous(tmp_path: Path) -> None:
    second = connection_event(record_id=41, guid=UNRELATED_GUID)

    report = validate(build_wmi_run(tmp_path, events=[*wmi_events(), second]))

    assert "2 connection(s) of the target reach the internal destination in the run" in errors_of(
        report
    )


def test_a_record_with_an_unreadable_utc_time_fails_the_run(tmp_path: Path) -> None:
    events = wmi_events()
    # TimeCreated is still readable; it is not read in place of UtcTime
    events[2]["EventData"]["UtcTime"] = "2030-01-01T23:59:55.000Z"

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "carry no readable EventData.UtcTime" in errors_of(report)
    assert "no other field is read in its place" in errors_of(report)


def test_a_lineage_record_with_an_unreadable_utc_time_fails_the_run(tmp_path: Path) -> None:
    # The root is found by ProcessGuid, but it cannot be placed before or in the run.
    events = wmi_events()
    events[1]["EventData"]["UtcTime"] = "at boot"

    report = validate(build_wmi_run(tmp_path, events=events))

    assert not report.ok
    assert "1 record(s) carry no readable EventData.UtcTime" in errors_of(report)
    assert "['10']" in errors_of(report)


def test_a_raw_export_that_is_not_json_is_not_judged(tmp_path: Path) -> None:
    run = build_wmi_run(tmp_path)
    jsonl_path = run[0] / "raw" / RUN_ID / "telemetry" / "sysmon-0001.jsonl"
    jsonl_path.write_text(jsonl_text(wmi_events()) + "{not json\n", encoding="utf-8", newline="\n")
    write_manifest(run[0])

    report = validate(run)

    assert not report.ok
    assert "sysmon-0001.jsonl is not readable" in errors_of(report)


# ---------------------------------------------------------------------------
# The provenance check, with what a validator hands over
# ---------------------------------------------------------------------------

HASHES = {"scenario_sha256": "1" * 64, "manifest_sha256": "2" * 64, "jsonl_sha256": "3" * 64}


def _inputs(tmp_path: Path, run_type: str, **replaced: object) -> tuple:
    """What a validator hands over for an intact run of `run_type`, and its provenance."""
    events = wmi_events(run_type)
    processes, connections = _read(events, tmp_path)
    nodes, reaching = _lineage(processes, connections)
    attack = run_type == "attack"
    inputs = R1ProvenanceInputs(
        run_id=RUN_ID,
        family_id=WMI_FAMILY,
        profile=read_collection_profile(wmi_scenario()),
        target_host=TARGET_HOST,
        start_time=START,
        end_time=parse_stamp(END_TIMES[run_type]),
        reference_time=CREATED_MOMENT if attack else None,
        evaluation_horizon_sec=HORIZON_SEC,
        destination_ip=DESTINATION_IP,
        destination_port=str(DESTINATION_PORT),
        scenario_sha256=HASHES["scenario_sha256"],
        manifest_sha256=HASHES["manifest_sha256"],
        sysmon_config_sha256=CONFIG_SHA256,
        lineage_nodes=nodes,
        lineage_connections=reaching,
        reference_action_id=ATTACK_REFERENCE if attack else None,
        reference_source_event_id=CREATED_RECORD_ID if attack else None,
        actions=tuple(
            (action_id(run_type, index), step, action_type, offset_sec, parse_stamp(recorded))
            for index, ((step, action_type, offset_sec), recorded) in enumerate(
                zip(WMI_STEPS, WMI_RECORDED_TIMES, strict=True)
            )
        ),
        created_action_id=action_id(run_type, LAUNCH_INDEX),
        created_action_time=parse_stamp(ACTION_STAMP),
        intermediate_image=PLANNED_INTERMEDIATE[run_type],
        candidate_start_offset_sec=0,
        candidate_window_sec=2,
        jsonl_sha256=HASHES["jsonl_sha256"],
        raw_log_id="RAW-002",
        process_ids=_process_ids(events),
        scenario_id="R1",
        variation_id=SYNTHETIC_VARIATION,
        scenario_version="v1",
        reference_policy_id="synthetic-reference",
        reference_policy_version="synthetic-reference-policy",
        reference_policy_config_hash="b2" * 32,
    )
    provenance = wmi_provenance(run_type, processes, connections, **HASHES)
    return replace(inputs, **replaced), processes, connections, provenance


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_both_planned_lineages_are_three_records_whose_root_is_context(
    tmp_path: Path, run_type: str
) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, run_type)

    assert [node.image for node in inputs.lineage_nodes] == [
        FINAL_IMAGE,
        INTERMEDIATE_IMAGES[run_type],
        ROOT_IMAGE,
    ]
    assert check_collection_provenance(provenance, inputs, processes, connections) == []
    # the two runs of a Pair differ in one Image and in nothing the windows are made of
    assert provenance["record_counts"] == {
        "total": 7,
        "context": 3,
        "observation": 4,
        "after_observation": 0,
    }
    assert provenance["lineage"]["context_record_ids"] == ["10"]


def test_the_evaluation_window_is_the_reference_plus_the_horizon_whatever_the_raw_window_is(
    tmp_path: Path,
) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, "attack")

    assert provenance["evaluation_window_end"] == EVALUATION_END_STAMP
    assert parse_stamp(provenance["evaluation_window_end"]) - CREATED_MOMENT == timedelta(
        seconds=600
    )
    # neither end of the raw window is an end of the evaluation window
    assert provenance["raw_collection_start"] != provenance["evaluation_window_start"]
    assert provenance["raw_collection_end"] != provenance["evaluation_window_end"]

    for name, value, message in (
        ("evaluation_window_end", END_TIMES["attack"], "expected the reference time plus 600 s"),
        ("evaluation_window_start", BOOT_STAMP, "evaluation_window_start is"),
        ("evaluation_window_start", ACTION_STAMP, "evaluation_window_start is"),
        ("evaluation_window_start", None, "evaluation_window_start is None"),
    ):
        broken = copy.deepcopy(provenance)
        broken[name] = value
        problems = check_collection_provenance(broken, inputs, processes, connections)
        assert any(message in problem for problem in problems), name


def test_the_evaluation_window_never_ends_after_the_run(tmp_path: Path) -> None:
    # min(reference + horizon, end of the run). A collection run reaches the
    # horizon, so this only shows where the end comes from when it does not.
    early_end = "2030-01-02T00:09:00.000Z"
    inputs, processes, connections, provenance = _inputs(
        tmp_path, "attack", end_time=parse_stamp(early_end)
    )
    provenance["raw_collection_end"] = provenance["observation_end"] = early_end

    problems = check_collection_provenance(provenance, inputs, processes, connections)
    assert any(f"no later than the end of the run, {early_end}" in problem for problem in problems)

    provenance["evaluation_window_end"] = early_end
    assert check_collection_provenance(provenance, inputs, processes, connections) == []


def test_the_time_of_the_call_is_not_the_reference_time(tmp_path: Path) -> None:
    # The call is made before the process exists. The reference time is the
    # EventData.UtcTime of the record of that process, not the time of the call.
    _, _, _, provenance = _inputs(tmp_path, "attack")
    created = provenance["created_process"]

    assert created["action_utc"] == ACTION_STAMP != provenance["evaluation_window_start"]
    assert provenance["evaluation_window_start"] == CREATED_STAMP
    assert parse_stamp(created["action_utc"]) < CREATED_MOMENT


def test_the_time_of_the_call_is_read_as_utc_and_only_when_it_says_so(tmp_path: Path) -> None:
    moment = parse_stamp(ACTION_STAMP)

    assert moment is not None and moment.tzinfo is UTC and moment.utcoffset() == timedelta(0)
    assert parse_event_utc_time(CREATED_UTC_TIME).tzinfo is UTC
    # a time that does not say UTC, or states another offset, is not a stamp
    not_utc = (
        "2030-01-02T00:00:03.000",
        "2030-01-02T09:00:03.000+09:00",
        "2030-01-02T00:00:03.000+00:00",
    )
    for value in (*not_utc, CREATED_UTC_TIME, "", None):
        assert parse_stamp(value) is None, value
    # and a provenance that states the call that way is refused
    for index, value in enumerate(not_utc):
        change = _set(("created_process", "action_utc"), value)
        errors = _attack(tmp_path / str(index), change=change)
        assert "created_process.action_utc is not a UTC stamp" in errors, value


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_the_provenance_states_what_was_planned_and_when_each_action_was_started(
    tmp_path: Path, run_type: str
) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, run_type)

    assert [(a["planned_offset_sec"], a["actual_utc"]) for a in provenance["actions"]] == [
        (0, "2030-01-02T00:00:03.000Z"),
        (300, "2030-01-02T00:05:00.200Z"),
        (480, "2030-01-02T00:08:00.300Z"),
        (720, "2030-01-02T00:12:00.400Z"),
    ]
    assert [a["action_type"] for a in provenance["actions"]] == [
        "wmi_process_create",
        "process_create",
        "network_connection",
        "run_end",
    ]
    assert provenance["actions"] == expected_actions(inputs)
    # the plan is not written where the run was: an offset in place of a time is noticed
    broken = copy.deepcopy(provenance)
    broken["actions"][1]["actual_utc"] = "2030-01-02T00:05:00.000Z"
    problems = check_collection_provenance(broken, inputs, processes, connections)
    assert any(problem.startswith("actions is") for problem in problems)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("run_start_inclusive", False, "run_start_inclusive must be true"),
        ("run_start_inclusive", "true", "run_start_inclusive must be true"),
        ("time_fallback", "TimeCreated", "time_fallback is 'TimeCreated', expected 'none'"),
        ("context_rule_version", "another", "context_rule_version is 'another'"),
        ("selector_raw_input_scope", "observation_only", "selector_raw_input_scope is"),
        ("target_boot_utc", None, "target_boot_utc is None"),
        ("target_boot_utc", START_TIME, "target_boot_utc is"),
        ("context_events", [], "context_events is []"),
        ("boot_session_id", 7, "boot_session_id must be a string or null"),
    ],
)
def test_a_statement_of_the_contract_that_says_something_else_is_refused(
    tmp_path: Path, name: str, value: object, message: str
) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, "normal")
    provenance[name] = value

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert any(message in problem for problem in problems), problems


def test_the_context_events_are_the_records_the_lineage_was_restored_from(
    tmp_path: Path,
) -> None:
    _, _, _, provenance = _inputs(tmp_path, "attack")

    # one record: the provider host, named by RecordId and by its line in the raw file
    assert provenance["context_events"] == [
        {"record_id": "10", "record_no": 2, "role": "root", "reason": CONTEXT_REASON}
    ]
    # the host, the channel and the file those two numbers belong to
    assert provenance["raw_source"]["host"] == TARGET_HOST
    assert provenance["raw_source"]["jsonl_sha256"] == HASHES["jsonl_sha256"]


def test_a_context_record_cannot_be_the_reference_of_an_evaluation(tmp_path: Path) -> None:
    # the provider host was created at boot; its record is before the start of the run
    boot_record = parse_event_utc_time("2030-01-01 23:50:22.000")
    inputs, processes, connections, provenance = _inputs(
        tmp_path, "attack", reference_time=boot_record, reference_source_event_id="10"
    )
    provenance["evaluation_window_start"] = "2030-01-01T23:50:22.000Z"
    provenance["evaluation_window_end"] = "2030-01-02T00:00:22.000Z"

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert any(
        problem.startswith("the reference time of the run is before its start")
        and "a context record cannot be the reference of an evaluation" in problem
        for problem in problems
    )


def test_a_created_process_whose_parent_is_not_the_root_of_the_lineage_is_refused(
    tmp_path: Path,
) -> None:
    # The lineage handed over ends in a record that is not the parent of the
    # created process by ProcessGuid, whatever Image it carries.
    inputs, processes, connections, provenance = _inputs(tmp_path, "attack")
    final, intermediate, root = inputs.lineage_nodes
    other_root = replace(root, key=replace(root.key, process_guid=UNRELATED_GUID))
    inputs = replace(inputs, lineage_nodes=(final, intermediate, other_root))

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert (
        "the ParentProcessGuid of the created process is not the ProcessGuid of the root of the "
        "lineage"
    ) in problems


def test_a_created_process_that_is_not_the_intermediate_of_the_lineage_is_refused(
    tmp_path: Path,
) -> None:
    inputs, processes, connections, provenance = _inputs(tmp_path, "attack")
    final, intermediate, root = inputs.lineage_nodes
    inputs = replace(inputs, lineage_nodes=(final, replace(intermediate, record_id="33"), root))

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert any(
        "the intermediate of the ProcessGuid lineage is RecordId '33'" in problem
        for problem in problems
    )


def test_without_the_window_of_a_registered_policy_no_created_process_is_established(
    tmp_path: Path,
) -> None:
    inputs, processes, connections, provenance = _inputs(
        tmp_path, "attack", candidate_window_sec=None
    )

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert any("carries no policy_provenance.reference" in problem for problem in problems)


def test_another_window_of_the_policy_is_another_set_of_candidates(tmp_path: Path) -> None:
    # The window is a value of the registered policy, not of this code: with a
    # window that ends before the record was written there is no candidate.
    inputs, processes, connections, provenance = _inputs(tmp_path, "attack", candidate_window_sec=0)
    provenance["created_process"]["window_end_utc"] = ACTION_STAMP

    problems = check_collection_provenance(provenance, inputs, processes, connections)

    assert any("0 process-create record(s) of cmd.exe" in problem for problem in problems)


def test_a_provenance_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    inputs, processes, connections, _ = _inputs(tmp_path, "normal")

    assert check_collection_provenance([], inputs, processes, connections) == [
        "the collection provenance is not a JSON object"
    ]


# ---------------------------------------------------------------------------
# The four actions of a run through WMI and the records they leave
# ---------------------------------------------------------------------------

FINAL_INDEX, INTERMEDIATE_INDEX, CONNECTION_INDEX = 5, 4, 6


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_each_process_of_a_run_through_wmi_is_created_by_its_action(
    tmp_path: Path, run_type: str
) -> None:
    report = validate(build_wmi_run(tmp_path, run_type=run_type))

    assert report.ok, errors_of(report)
    assert (
        "the intermediate was created after the invoke action was started and the final tool "
        "after the launch action was"
    ) in "\n".join(report.checks)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_a_final_tool_that_existed_before_its_action_was_not_started_by_it(
    tmp_path: Path, run_type: str
) -> None:
    # What a run leaves when the intermediate starts the final tool at once
    # instead of waiting for the action that is 300 s later.
    events = wmi_events(run_type)
    events[FINAL_INDEX]["EventData"]["UtcTime"] = "2030-01-02 00:00:03.300"

    report = validate(build_wmi_run(tmp_path, events=events, run_type=run_type))

    assert (
        "the final tool of the lineage (RecordId 31) was created at 2030-01-02 00:00:03.300, "
        "before the launch action that starts it was started (2030-01-02T00:05:00.200Z)"
    ) in errors_of(report)


def test_a_final_tool_created_after_the_connect_action_is_refused(tmp_path: Path) -> None:
    events = wmi_events()
    events[FINAL_INDEX]["EventData"]["UtcTime"] = "2030-01-02 00:08:01.000"

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "the final tool of the lineage (RecordId 31) was created at" in errors_of(report)
    assert "after the connect action was started (2030-01-02T00:08:00.300Z)" in errors_of(report)


@pytest.mark.parametrize(
    ("utc_time", "message"),
    [
        ("2030-01-02 00:00:02.500", "before the invoke action that starts it was started"),
        ("2030-01-02 00:05:00.220", "after the launch action was started"),
    ],
    ids=["before_its_action", "after_the_next_action"],
)
def test_an_intermediate_that_was_not_created_by_the_launch_action_is_refused(
    tmp_path: Path, utc_time: str, message: str
) -> None:
    events = wmi_events()
    events[INTERMEDIATE_INDEX]["EventData"]["UtcTime"] = utc_time

    report = validate(build_wmi_run(tmp_path, events=events))

    assert "the intermediate of the lineage (RecordId 30) was created at" in errors_of(report)
    assert message in errors_of(report)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_the_connection_of_the_run_carries_the_process_guid_of_the_final_tool_it_started(
    tmp_path: Path, run_type: str
) -> None:
    report = validate(build_wmi_run(tmp_path, run_type=run_type))

    assert report.ok, errors_of(report)
    final_tool = report.lineage.nodes[0]
    assert [c.record_id for c in report.lineage.connections] == ["40"]
    assert report.lineage.connections[0].key.process_guid == final_tool.key.process_guid
    assert final_tool.key.process_guid == FINAL_GUID and final_tool.record_id == "31"


@pytest.mark.parametrize(
    "guid",
    [INTERMEDIATE_GUID, ROOT_GUID, UNRELATED_GUID],
    ids=["the_intermediate", "the_root", "an_unrelated_process"],
)
@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_a_connection_that_carries_another_process_guid_is_not_the_one_of_the_run(
    tmp_path: Path, run_type: str, guid: str
) -> None:
    # One connection reaches the destination in the run, at the right time. It
    # was not made by the final tool the run started, so the run has none.
    events = wmi_events(run_type)
    events[CONNECTION_INDEX] = connection_event(record_id=40, guid=guid)

    report = validate(build_wmi_run(tmp_path, events=events, run_type=run_type))

    assert not report.ok
    assert (
        f"no EID 3 record carries the anchor host and ProcessGuid: host={TARGET_HOST} "
        f"ProcessGuid={FINAL_GUID}"
    ) in errors_of(report)


# ---------------------------------------------------------------------------
# remote_management is validated as before
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_a_run_whose_scenario_declares_no_collection_block_needs_no_provenance(
    tmp_path: Path, run_type: str
) -> None:
    run = build_run(tmp_path, run_type=run_type)

    report = validate(run)

    assert report.ok, errors_of(report)
    assert not (trace_dir(run[0]) / PROVENANCE_FILENAME).exists()
    assert report.lineage.roles == ("final tool", "intermediate", "session host")
    assert not any("collection provenance" in check for check in report.checks)


def test_the_reference_of_a_session_entry_run_is_still_its_session_host(tmp_path: Path) -> None:
    report = validate(build_run(tmp_path, run_type="attack"))

    assert report.ok, errors_of(report)
    checks = "\n".join(report.checks)
    assert "the reference of the run is the EID 1 of its session host: RecordId 1" in checks
    assert "the process its reference action created" not in checks


def test_the_validator_reads_the_run_events_of_today_the_same_way(tmp_path: Path) -> None:
    # The records of a run window: the session host is the root and is in the run.
    processes, connections = _read(run_events("attack"), tmp_path)
    records = [*processes, *connections]

    assert context_records(records, START) == []
    assert len(observation_records(records, START, OBSERVATION_END)) == 4
