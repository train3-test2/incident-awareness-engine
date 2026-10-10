"""Validate the artifacts of one R1-V02 Pilot run and extract its lineage record.

The R1 runner (`scenarios/R1/`) writes the artifacts an S0 run writes:

    raw/<run_id>/telemetry/sysmon-0001.evtx
    raw/<run_id>/telemetry/sysmon-0001.jsonl
    raw/<run_id>/manifest.json
    ground_truth/<run_id>/execution_record.csv
    ground_truth/<run_id>/run_metadata.json

Next to them it keeps the operator trace of the run, which no contract and no
Manifest lists:

    operator_trace/<run_id>/r1_run_trace.json
    operator_trace/<run_id>/scenario.json

This module is run on the host, after the artifacts were copied off the
Controller. It does three things.

1. It checks the contract files the way the S0 validator does: `RunMetadata`,
   `ExecutionRecordRow`, the Manifest with recomputed SHA-256, and one `run_id`
   across all of them. A normal run records no reference. An attack run records
   the reference action its scenario names, and its `reference_time` and
   `reference_source_event_id` have to be the EventData.UtcTime and the RecordId
   of the EID 1 of the session host of the lineage found in step 3; a collection
   run also has to end at or after `reference_time` plus the evaluation horizon
   of the scenario.
2. It checks the operator trace. The scenario given to this validator, the
   scenario copy the run kept and the SHA-256 the trace records have to be the
   same bytes, and the trace has to name this run and state the dataset tier
   that scenario states for its Pair. A scenario edited after the run can
   therefore not be the plan the run is judged against, and a run without a
   usable trace is not validated at all.
3. It finds the final management tool instance of the run in the raw Sysmon
   JSONL and hands it to `r1_lineage.verify_r1_lineage`, which checks the parent
   chain by host and ProcessGuid and the EID 3 carrying the same host and
   ProcessGuid to the approved destination, recorded as TCP.

What the run was planned to leave - the three Images of its planned lineage, the
internal destination, the Target-A name and the family, variation and repetition
of its Pair - is read from the scenario JSON that was rendered for the run
(`tools/r1_scenario_to_json.py`), never from this code. The bytes are read once:
what is compared with the operator trace is what the plan is parsed from.

The dataset tier belongs to the Pair. The rendered scenario states it once -
`pilot`, `development` or `holdout`, and always `pilot` for a rehearsal - and
the runner copies it to the operator trace of each run. This validator reads
the expected tier from the scenario and accepts a run only when its trace states
exactly that tier. The caller cannot choose the expectation, and a scenario that
states no tier validates nothing. Neither does a scenario in which a run block
states a tier, a family, a variation or a repetition of its own: both blocks
are read, whichever run is validated. What a formal selector has to check on
top of this is in `scenarios/R1/README.md` section 1-3.

This is a conformance check of one collected run against its own plan. It
detects nothing, builds no Evidence and produces no Fusion input. `run_type` is
read from Ground Truth for one purpose: to know which of the two planned
lineages this run was meant to leave. An Image name is compared with the plan
of that run, in a full three step chain tied together by ProcessGuid; it is
never used to decide what a run is.

Whether a lineage is approved is a question for Evidence extraction, not for
collection. The approved lineage policy of a family is not part of the scenario
and is not read here (`scenarios/R1/README.md` section 1-1), so nothing in this
module judges a run by it.

`R1PilotValidationReport.ok` means the contract files, the operator trace and
the planned lineage held for this one run. It is not the Pilot verdict of
`docs/scenarios/r1.md` section 8-2: the comparison of the two runs of a pair
(S-1, and the Image and lineage comparison of S-2 and S-3) and the t+5 and t+8
windows (S-7) are not checked here.

The rendered report is the lineage record r1.md section 6 asks to keep "in the
run record, extracted from the source telemetry". No contract file has a place
for it, so it is not written under `raw/` or `ground_truth/`; `write_report`
stores it next to the operator evidence of the run instead.

No time is compared between telemetry records, for the reason `r1_lineage`
gives. Ground Truth times are only checked against each other.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath

from incident_awareness.collection.r1_destination import (
    validate_internal_port,
    validate_internal_target,
    validate_lab_cidr,
)
from incident_awareness.collection.r1_lineage import (
    ConnectionRecord,
    LineageChain,
    ProcessKey,
    ProcessRecord,
    R1LineageReport,
    build_process_tree,
    connection_uses_protocol,
    read_r1_lineage_records,
    resolve_lineage,
    select_connections,
    verify_r1_lineage,
)
from incident_awareness.collection.r1_pair_identity import (
    DATASET_TIERS,
    REHEARSAL_DATASET_TIER,
    R1PairIdentity,
    R1PairIdentityError,
    read_dataset_tier,
    read_pair_identity,
)

# The contract checks below are the S0 ones, reused as issue #73 asks. They only
# call `fail` and `passed` on the report they are given. Moving them to a shared
# module would change the S0 validator and is left to a separate change.
from incident_awareness.collection.s0_validation import (
    EVTX_FILENAME,
    JSONL_FILENAME,
    REHEARSAL_DIRNAME,
    REHEARSAL_MARKER,
    _check_manifest,
    _read_execution_records,
    _read_run_metadata,
    check_run_id,
)
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.run import RunMetadata

SCENARIO_ID = "R1"
RUN_TYPES = ("normal", "attack")
CONNECT_STEP = "connect"
# The action an attack run takes its reference from: the one that opens the
# session (docs/scenarios/r1.md section 4-2). The time of a record is
# EventData.UtcTime in the form Sysmon writes it; TimeCreated is never read in
# its place.
REFERENCE_STEP = "session_begin"
EVENT_UTC_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
# The connection an R1 run makes is TCP: the runner refuses a scenario stating
# another protocol and the task attempts nothing else. This is the spelling
# Sysmon records; the comparison ignores case.
CONNECTION_PROTOCOL = "tcp"
PLANNED_LINEAGE_KEY = "planned_lineage"
LINEAGE_ROLES = ("final tool", "intermediate", "session host")
REFERENCE_FIELDS = ("reference_time", "reference_action_id", "reference_source_event_id")
WMI_REFERENCE_CANDIDATE_WINDOW_SEC = 2
IDENTITY_FIELDS = ("family_id", "variation_id", "repetition")
# What a Pair states once, at the top level of its rendered scenario, for both
# of its runs. The renderer and the runner refuse a run block that states one of
# them. The validator refuses it too: the artifacts it is handed need not have
# come from either.
PAIR_FIELDS = (*IDENTITY_FIELDS, "dataset_tier")

# The operator trace the runner writes next to raw/ and ground_truth/
# (scenarios/R1/run-common.ps1, Write-R1RunTrace).
TRACE_DIRNAME = "operator_trace"
TRACE_FILENAME = "r1_run_trace.json"
TRACE_SCENARIO_FILENAME = "scenario.json"
TRACE_VERSION = "v1"
# The tier of a Pair is a value of its rendered scenario (`DATASET_TIERS` of
# incident_awareness.collection.r1_pair_identity); the runner copies it to the
# trace. A rehearsal is never part of a formal pool and always carries this one.
REHEARSAL_TIER = REHEARSAL_DATASET_TIER
TRACE_MODES = {False: "collection", True: "rehearsal"}
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class R1ScenarioError(ValueError):
    """Raised when the rendered scenario cannot be used to validate a run."""


class R1ReportError(ValueError):
    """Raised when the report cannot be stored where it was asked to be."""


@dataclass(frozen=True)
class R1ScenarioAction:
    """One designed action of a run."""

    action_id: str
    step: str
    action_type: str
    offset_sec: int


@dataclass(frozen=True)
class R1PilotExpectation:
    """What one run type was planned to leave on Target-A, and for which Pair.

    The three Images are the planned lineage of that run type.
    """

    target_host: str
    final_image: str
    intermediate_image: str
    session_host_image: str
    actions: tuple[R1ScenarioAction, ...]
    destination_ip: str | None
    destination_port: str | None
    identity: R1PairIdentity
    dataset_tier: str
    reference_action_id: str | None
    evaluation_horizon_sec: int
    reference_policy_version: str | None

    @property
    def images(self) -> tuple[str, ...]:
        """Lowercased file names, closest first: the order a parent walk returns."""
        return (
            self.final_image.lower(),
            self.intermediate_image.lower(),
            self.session_host_image.lower(),
        )


@dataclass(frozen=True)
class R1ObservedLineage:
    """The lineage and the connection found for the final tool, as recorded facts."""

    host: str
    nodes: tuple[ProcessRecord, ...]
    connections: tuple[ConnectionRecord, ...]

    @property
    def process_guids(self) -> tuple[str, ...]:
        return tuple(node.key.process_guid for node in self.nodes)

    @property
    def images(self) -> tuple[str | None, ...]:
        return tuple(node.image for node in self.nodes)


@dataclass(frozen=True)
class R1RunTrace:
    """What the operator trace of a run states, once every value of it was checked."""

    dataset_tier: str
    mode: str
    scenario_sha256: str


@dataclass
class R1PilotValidationReport:
    """Everything one validation run found.

    `errors` is the verdict: an empty list means the contract files, the
    operator trace and the planned lineage held for this run. `checks` records
    what was verified; `action_times`, `lineage`, `identity` and `trace` are
    recorded facts with no verdict of their own.
    """

    run_id: str
    rehearsal: bool
    run_type: str | None = None
    errors: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    action_times: list[str] = field(default_factory=list)
    lineage: R1ObservedLineage | None = None
    identity: R1PairIdentity | None = None
    trace: R1RunTrace | None = None
    scenario_dataset_tier: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def passed(self, message: str) -> None:
        self.checks.append(message)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise R1ScenarioError(f"{label} must be a non-empty string")
    return value


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise R1ScenarioError(f"{label} must be an object")
    return value


def _load_actions(run: dict, label: str) -> tuple[R1ScenarioAction, ...]:
    raw_actions = run.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise R1ScenarioError(f"{label}.actions must be a non-empty array")

    actions: list[R1ScenarioAction] = []
    for index, raw_action in enumerate(raw_actions):
        item = f"{label}.actions[{index}]"
        action = _mapping(raw_action, item)
        offset = action.get("offset_sec")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise R1ScenarioError(f"{item}.offset_sec must be a non-negative integer")

        actions.append(
            R1ScenarioAction(
                action_id=_text(action.get("action_id"), f"{item}.action_id"),
                step=_text(action.get("step"), f"{item}.step"),
                action_type=_text(action.get("action_type"), f"{item}.action_type"),
                offset_sec=offset,
            )
        )

    action_ids = [action.action_id for action in actions]
    if len(action_ids) != len(set(action_ids)):
        raise R1ScenarioError(f"{label}.actions repeats an action_id")
    if [action.step for action in actions].count(CONNECT_STEP) != 1:
        raise R1ScenarioError(f"{label}.actions must hold exactly one {CONNECT_STEP!r} step")

    return tuple(actions)


def _load_destination(internal: dict) -> tuple[str | None, str | None]:
    """The approved destination, or two Nones when the scenario was rendered without one.

    A destination that is not an approved internal address is refused here as
    well, so a run toward one cannot be reported as passing.
    """
    target = internal.get("target")
    port = internal.get("port")
    lab_cidr = internal.get("lab_cidr")
    given = [value is not None for value in (target, port, lab_cidr)]
    if not any(given):
        return None, None
    if not all(given):
        raise R1ScenarioError(
            "internal_connection.target, .port and .lab_cidr must be set together or all be null"
        )

    try:
        network = validate_lab_cidr(lab_cidr)
        return validate_internal_target(target, network), str(validate_internal_port(port))
    except (TypeError, ValueError) as error:
        raise R1ScenarioError(
            f"internal_connection is not an approved internal destination: {error}"
        ) from error


def _check_run_blocks(scenario: dict) -> None:
    """Refuse a scenario whose run block states a value that belongs to its Pair.

    Both run blocks are read, whichever run is being validated: a value in the
    other block lets the two runs of the Pair disagree just the same. A field
    counts for being there, so one that is null or repeats the top-level value
    is refused like one that differs. A `runs` or a run block that is not an
    object states nothing, and is reported where the plan is read.
    """
    runs = scenario.get("runs")
    if not isinstance(runs, dict):
        return

    for run_type in RUN_TYPES:
        block = runs.get(run_type)
        if not isinstance(block, dict):
            continue
        stated = sorted(name for name in PAIR_FIELDS if name in block)
        if stated:
            raise R1ScenarioError(
                f"runs.{run_type} states {stated}; a Pair states them once at the top level"
            )


def _parse_scenario(scenario_bytes: bytes) -> dict:
    """The rendered scenario the bytes hold, once it is known to be an R1 scenario.

    Everything the validator reads of a scenario comes through here, so a run
    block that states a value of the Pair is refused before the tier or the plan
    is taken from it.
    """
    try:
        scenario = json.loads(scenario_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R1ScenarioError(f"scenario is not readable JSON: {error}") from error

    scenario = _mapping(scenario, "scenario")
    if scenario.get("scenario_id") != SCENARIO_ID:
        raise R1ScenarioError(
            f"scenario_id must be {SCENARIO_ID!r}, found {scenario.get('scenario_id')!r}"
        )
    _check_run_blocks(scenario)
    return scenario


def _load_dataset_tier(scenario: dict) -> str:
    """The dataset tier a scenario states for its Pair. It has to be stated."""
    try:
        return read_dataset_tier(scenario)
    except R1PairIdentityError as error:
        raise R1ScenarioError(
            f"{error}. The rendered scenario states the tier of its Pair "
            "(tools/r1_scenario_to_json.py --dataset-tier); nothing given to the validator "
            "replaces it"
        ) from error


def _load_reference_policy_version(scenario: dict, run_metadata: dict) -> str | None:
    """The reference policy version both runs of the Pair record.

    A scenario whose attack run names a reference action has to state it as a
    non-blank string. A reference recorded next to a missing version could not be
    read later, and two missing values would compare as equal. Which version is
    current is a value of the scenario: none is expected here.
    """
    version = run_metadata.get("reference_policy_version")
    attack = _mapping(scenario.get("runs"), "runs").get("attack")
    names_reference = isinstance(attack, dict) and attack.get("reference_action_id") is not None
    if names_reference and (not isinstance(version, str) or not version.strip()):
        raise R1ScenarioError(
            "run_metadata.reference_policy_version must be a non-blank string when "
            f"runs.attack.reference_action_id is set, found {version!r}"
        )
    return version


def _load_identity(scenario: dict) -> R1PairIdentity:
    """The Pair a scenario was rendered for: its family, variation and repetition."""
    try:
        return read_pair_identity(scenario)
    except R1PairIdentityError as error:
        raise R1ScenarioError(str(error)) from error


def load_r1_pilot_expectation(scenario_path: Path, run_type: str) -> R1PilotExpectation:
    """Read the plan of one run type from the scenario JSON rendered for the run."""
    if run_type not in RUN_TYPES:
        raise R1ScenarioError(f"run_type must be one of {RUN_TYPES}, found {run_type!r}")

    try:
        scenario_bytes = scenario_path.read_bytes()
    except OSError as error:
        raise R1ScenarioError(f"scenario is not readable JSON: {error}") from error

    return _read_expectation(scenario_bytes, run_type)


def _read_expectation(scenario_bytes: bytes, run_type: str) -> R1PilotExpectation:
    """Read the plan of one run type from the bytes of a rendered scenario.

    The validator hands over the bytes it compared with the operator trace, so
    the plan is parsed from exactly what was proven to be the run's scenario.
    """
    if run_type not in RUN_TYPES:
        raise R1ScenarioError(f"run_type must be one of {RUN_TYPES}, found {run_type!r}")

    scenario = _parse_scenario(scenario_bytes)

    # The lineage a run is checked against is the planned one of its run type.
    key = PLANNED_LINEAGE_KEY
    lineage = _mapping(scenario.get(key), key)
    intermediate = _mapping(
        _mapping(lineage.get("intermediate"), f"{key}.intermediate").get(run_type),
        f"{key}.intermediate.{run_type}",
    )
    run = _mapping(_mapping(scenario.get("runs"), "runs").get(run_type), f"runs.{run_type}")
    destination_ip, destination_port = _load_destination(
        _mapping(scenario.get("internal_connection"), "internal_connection")
    )
    identity = _load_identity(scenario)
    actions = _load_actions(run, f"runs.{run_type}")
    run_metadata = _mapping(scenario.get("run_metadata"), "run_metadata")

    return R1PilotExpectation(
        target_host=_text(run_metadata.get("target_host"), "run_metadata.target_host"),
        final_image=_text(
            _mapping(lineage.get("final_tool"), f"{key}.final_tool").get("image"),
            f"{key}.final_tool.image",
        ),
        intermediate_image=_text(intermediate.get("image"), f"{key}.intermediate.{run_type}.image"),
        session_host_image=_text(
            _mapping(lineage.get("session_host"), f"{key}.session_host").get("image"),
            f"{key}.session_host.image",
        ),
        actions=actions,
        destination_ip=destination_ip,
        destination_port=destination_port,
        identity=identity,
        dataset_tier=_load_dataset_tier(scenario),
        reference_action_id=_load_reference_action(
            run,
            run_type,
            actions,
            identity.family_id,
        ),
        evaluation_horizon_sec=_load_horizon(scenario),
        reference_policy_version=_load_reference_policy_version(scenario, run_metadata),
    )


def _load_reference_action(
    run: dict,
    run_type: str,
    actions: tuple[R1ScenarioAction, ...],
    family_id: str,
) -> str | None:
    """Load the family-specific attack reference, or require no normal reference."""
    stated = run.get("reference_action_id")
    if run_type != "attack":
        if stated is not None:
            raise R1ScenarioError(
                f"runs.{run_type}.reference_action_id must be null, found {stated!r}: only an "
                "attack run records a reference"
            )
        return None

    if family_id == "wmi_management":
        a01 = [action for action in actions if action.action_id == "A01"]
        if stated != "A01":
            raise R1ScenarioError(
                f"runs.attack.reference_action_id must be the WMI action 'A01', found {stated!r}"
            )
        if len(a01) != 1 or a01[0].action_type != "wmi_process_create":
            raise R1ScenarioError(
                "runs.attack A01 must exist exactly once with action_type 'wmi_process_create'"
            )
        return "A01"

    begin = [action.action_id for action in actions if action.step == REFERENCE_STEP]
    if len(begin) != 1:
        raise R1ScenarioError(f"runs.attack.actions must hold exactly one {REFERENCE_STEP!r} step")
    if stated != begin[0]:
        raise R1ScenarioError(
            f"runs.attack.reference_action_id must be the {REFERENCE_STEP} action {begin[0]!r}, "
            f"found {stated!r}"
        )
    return begin[0]


def _load_horizon(scenario: dict) -> int:
    horizon = _mapping(scenario.get("run_length"), "run_length").get("evaluation_horizon_sec")
    if isinstance(horizon, bool) or not isinstance(horizon, int) or horizon < 1:
        raise R1ScenarioError(
            f"run_length.evaluation_horizon_sec must be an integer of 1 or more, found {horizon!r}"
        )
    return horizon


def _check_run_trace(
    artifact_root: Path,
    run_id: str,
    scenario_bytes: bytes,
    rehearsal: bool,
    dataset_tier: str,
    report: R1PilotValidationReport,
) -> R1RunTrace | None:
    """Check that the scenario given to the validator is the one the run executed.

    The runner keeps the scenario bytes its plan was built from, and their
    SHA-256, under `operator_trace/<run_id>/`. Three digests have to agree: the
    one the trace records, the one of the kept copy and the one of the scenario
    this validator was given. The trace also has to name this run, its mode and
    `dataset_tier`, the tier that scenario states for its Pair.

    Returns the trace when everything held and None after reporting what did
    not. Nothing is repaired or guessed: a run without a usable trace is not
    judged against any scenario.
    """
    trace_dir = artifact_root / TRACE_DIRNAME / run_id
    trace_label = f"{TRACE_DIRNAME}/{run_id}/{TRACE_FILENAME}"
    kept_label = f"{TRACE_DIRNAME}/{run_id}/{TRACE_SCENARIO_FILENAME}"

    trace_path = trace_dir / TRACE_FILENAME
    if not trace_path.is_file():
        report.fail(
            f"operator trace is missing: {trace_label}. Without it the run cannot be tied to "
            "the scenario it executed"
        )
        return None
    try:
        trace = json.loads(trace_path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        report.fail(f"operator trace is not readable JSON ({trace_label}): {error}")
        return None
    if not isinstance(trace, dict):
        report.fail(f"operator trace is not a JSON object ({trace_label})")
        return None

    problems_before = len(report.errors)
    expected = {
        "trace_version": TRACE_VERSION,
        "run_id": run_id,
        "dataset_tier": dataset_tier,
        "mode": TRACE_MODES[rehearsal],
    }
    for name, wanted in expected.items():
        stated = trace.get(name)
        if not isinstance(stated, str) or stated != wanted:
            source = "the rendered scenario states" if name == "dataset_tier" else "expected"
            report.fail(f"operator trace {name} is {stated!r}, {source} {wanted!r} ({trace_label})")

    recorded = trace.get("scenario_sha256")
    if not isinstance(recorded, str) or _SHA256_HEX.fullmatch(recorded) is None:
        report.fail(
            "operator trace scenario_sha256 is not a SHA-256 in lower case hex: "
            f"{recorded!r} ({trace_label})"
        )
        return None

    kept_path = trace_dir / TRACE_SCENARIO_FILENAME
    try:
        kept_sha256 = hashlib.sha256(kept_path.read_bytes()).hexdigest()
    except OSError as error:
        report.fail(f"the scenario the run kept is missing or not readable ({kept_label}): {error}")
    else:
        if kept_sha256 != recorded:
            report.fail(
                f"the scenario the run kept ({kept_label}) does not have the SHA-256 its trace "
                f"records: {kept_sha256}, recorded {recorded}. One of them was changed after "
                "the run"
            )

    given_sha256 = hashlib.sha256(scenario_bytes).hexdigest()
    if given_sha256 != recorded:
        report.fail(
            "the scenario given to the validator is not the one this run executed: its SHA-256 "
            f"is {given_sha256}, the operator trace records {recorded}"
        )

    if len(report.errors) != problems_before:
        return None

    report.passed(
        "the operator trace, the scenario the run kept and the scenario given to the validator "
        f"are the same bytes: sha256={recorded}"
    )
    report.passed(
        "the operator trace names this run and carries the tier its scenario states: "
        f"dataset_tier={dataset_tier} mode={expected['mode']}"
    )
    return R1RunTrace(dataset_tier=dataset_tier, mode=expected["mode"], scenario_sha256=recorded)


def _check_rehearsal_isolation(
    artifact_root: Path, rehearsal: bool, report: R1PilotValidationReport
) -> None:
    has_marker = (artifact_root / REHEARSAL_MARKER).is_file()
    in_rehearsal_dir = REHEARSAL_DIRNAME in artifact_root.resolve().parts
    detected = has_marker or in_rehearsal_dir

    if not rehearsal:
        if detected:
            report.fail(
                "rehearsal artifacts cannot be validated as an R1 collection; "
                f"marker={has_marker} path_isolated={in_rehearsal_dir}. Re-run with --rehearsal."
            )
        else:
            report.passed("no rehearsal marker or _rehearsal path component")
        return

    if not has_marker:
        report.fail(f"--rehearsal given but {REHEARSAL_MARKER} is missing under {artifact_root}")
    if not in_rehearsal_dir:
        report.fail(
            f"--rehearsal given but {artifact_root} is not under a {REHEARSAL_DIRNAME} directory"
        )
    if has_marker and in_rehearsal_dir:
        report.passed(
            f"{REHEARSAL_MARKER} present and artifact root is isolated under {REHEARSAL_DIRNAME}"
        )


def _check_run_metadata(
    metadata: RunMetadata, expectation: R1PilotExpectation, report: R1PilotValidationReport
) -> None:
    if metadata.target_host.lower() != expectation.target_host.lower():
        report.fail(
            f"run_metadata.json target_host is {metadata.target_host!r}, the scenario rendered "
            f"for this run names {expectation.target_host!r}"
        )

    # Both runs of a Pair are rendered once and record what that scenario states.
    # A run that records another family, variation or repetition was not made
    # from it, and the family is what the data is split by.
    stated = expectation.identity
    differing = [
        f"{name} is {getattr(metadata, name)!r}, the scenario states {getattr(stated, name)!r}"
        for name in IDENTITY_FIELDS
        if type(getattr(metadata, name)) is not type(getattr(stated, name))
        or getattr(metadata, name) != getattr(stated, name)
    ]
    for message in differing:
        report.fail(f"run_metadata.json does not record the Pair of the scenario: {message}")
    if not differing:
        report.passed(
            f"run_metadata.json records the Pair the scenario states: family_id="
            f"{stated.family_id} variation_id={stated.variation_id} repetition={stated.repetition}"
        )

    # A normal run has no reference by contract. An attack run records the
    # reference action its scenario names, with a time and a source record.
    # Whether those two are the right record is checked against the telemetry
    # once the lineage of the run is known (_check_reference).
    recorded = [name for name in REFERENCE_FIELDS if getattr(metadata, name) is not None]
    wanted = expectation.reference_action_id
    if wanted is None:
        if recorded:
            report.fail(
                f"run_metadata.json records {recorded}, but a normal run records no reference "
                "(docs/scenarios/r1.md section 4-2)"
            )
        else:
            report.passed("run_metadata.json records no reference, as a normal run does")
    else:
        absent = [name for name in REFERENCE_FIELDS if getattr(metadata, name) is None]
        if absent:
            report.fail(
                f"run_metadata.json of an attack run does not record {absent}; its reference is "
                f"the action {wanted} (docs/scenarios/r1.md section 4-2)"
            )
        elif metadata.reference_action_id != wanted:
            report.fail(
                f"run_metadata.json reference_action_id is {metadata.reference_action_id!r}, the "
                f"scenario names {wanted!r}"
            )
        else:
            report.passed(
                f"run_metadata.json records the reference action the scenario names: {wanted}"
            )

    if metadata.reference_policy_version != expectation.reference_policy_version:
        report.fail(
            f"run_metadata.json reference_policy_version is {metadata.reference_policy_version!r}, "
            f"the scenario states {expectation.reference_policy_version!r}"
        )

    if not (metadata.vm_snapshot or "").strip():
        report.fail("run_metadata.json vm_snapshot is empty; r1.md section 6 records it per run")
    if metadata.end_time is None:
        report.fail("run_metadata.json end_time is null; a finished run records it")


def _check_actions(
    metadata: RunMetadata,
    records: list[ExecutionRecordRow],
    expectation: R1PilotExpectation,
    rehearsal: bool,
    report: R1PilotValidationReport,
) -> None:
    # Only a rehearsal rendered without a destination leaves the connection out.
    skip_connect = rehearsal and expectation.destination_ip is None
    designed = [
        action
        for action in expectation.actions
        if not (skip_connect and action.step == CONNECT_STEP)
    ]

    recorded_ids = [record.action_id for record in records]
    designed_ids = [action.action_id for action in designed]
    if recorded_ids != designed_ids:
        report.fail(
            f"execution_record.csv records the actions {recorded_ids}, the scenario designs "
            f"{designed_ids} in this order for the {metadata.run_type.value} run"
        )
        return

    mismatched = [
        f"{record.action_id} is {record.action_type!r}, scenario says {action.action_type!r}"
        for record, action in zip(records, designed, strict=True)
        if record.action_type != action.action_type
    ]
    for message in mismatched:
        report.fail(f"execution_record action_type does not match the scenario: {message}")
    if not mismatched:
        note = " (the connection is skipped: no destination was rendered)" if skip_connect else ""
        report.passed(f"execution_record.csv records the actions {recorded_ids} in order{note}")

    timestamps = [record.timestamp for record in records]
    in_order = timestamps == sorted(timestamps)
    if not in_order:
        report.fail("execution_record.csv timestamps go backwards")

    outside = [
        record.action_id
        for record in records
        if record.timestamp < metadata.start_time
        or (metadata.end_time is not None and record.timestamp > metadata.end_time)
    ]
    if outside:
        report.fail(f"execution_record.csv holds action(s) outside the run window: {outside}")
    if in_order and not outside:
        report.passed("every execution_record timestamp is in order and inside the run window")

    # Recorded as facts. r1.md section 4 makes the recorded time authoritative
    # and section 11 has not decided a t+5 or t+8 window, so nothing is judged.
    for record, action in zip(records, designed, strict=True):
        elapsed = (record.timestamp - metadata.start_time).total_seconds()
        report.action_times.append(
            f"{record.action_id} {action.step}: designed t+{action.offset_sec} s, "
            f"recorded {elapsed:.3f} s after start_time"
        )


def _image_name(image: str | None) -> str:
    return PureWindowsPath(image).name.lower() if image else ""


def _describe_chain(chain: LineageChain) -> str:
    names = " <- ".join(
        _image_name(node.image) or "(no Image)" for node in chain.nodes[: len(LINEAGE_ROLES)]
    )
    if chain.status == "cycle":
        return f"{names} (the parent chain loops)"
    if chain.status == "truncated" and chain.depth < len(LINEAGE_ROLES):
        return f"{names} (parent {chain.missing_parent_process_guid} is not in the capture)"
    return names


def _conforms(chain: LineageChain, expectation: R1PilotExpectation) -> bool:
    if chain.status == "cycle" or chain.depth < len(LINEAGE_ROLES):
        return False
    names = tuple(_image_name(node.image) for node in chain.nodes[: len(LINEAGE_ROLES)])
    return names == expectation.images


def _reaches(connection: ConnectionRecord, expectation: R1PilotExpectation) -> bool:
    """Whether one record is the connection of the run: its destination, as TCP."""
    return (
        connection.destination_ip == expectation.destination_ip
        and connection.destination_port == expectation.destination_port
        and connection_uses_protocol(connection, CONNECTION_PROTOCOL)
    )


def _report_broken_candidates(
    jsonl_path: Path,
    candidates: list[tuple[ProcessRecord, LineageChain]],
    report: R1PilotValidationReport,
) -> None:
    """Pass on why a final tool instance has no three step lineage.

    A chain that loops, or that stops before the third step because a parent is
    not in the capture, is a finding of `r1_lineage` and is reported in its own
    words. The parent the chain stops at is named by the child's own
    ParentProcessGuid, so it is given to the validator as the link R1 requires.
    """
    for process, chain in candidates:
        if chain.status == "cycle":
            required = None
        elif chain.status == "truncated" and chain.depth < len(LINEAGE_ROLES):
            required = [*chain.process_guids[1:], chain.missing_parent_process_guid]
        else:
            continue

        verdict = verify_r1_lineage(
            jsonl_path, anchor=process.key, expected_parent_process_guids=required
        )
        # Only the lineage finding, which is the first one the validator makes.
        # Without a conforming instance no connection was looked for, so what it
        # says about connections does not apply.
        report.errors.extend(verdict.errors[:1])


def _check_lineage(
    jsonl_path: Path,
    expectation: R1PilotExpectation,
    rehearsal: bool,
    report: R1PilotValidationReport,
) -> None:
    """Find the final tool instance of this run and verify its lineage and link.

    A duplicate ProcessGuid, a loop, a missing parent, a wrong destination or a
    connection that was not recorded as TCP is a failure, never something to
    work around: each one is found by `r1_lineage` and passed on unchanged.
    """
    if expectation.destination_ip is None and not rehearsal:
        report.fail(
            "the scenario rendered for this run carries no internal destination; a "
            "collection run cannot be validated without it"
        )
        return

    reading = R1LineageReport()
    loaded = read_r1_lineage_records(jsonl_path, reading)
    tree = None if loaded is None else build_process_tree(loaded[0], reading)
    if loaded is None or tree is None:
        report.errors.extend(reading.errors)
        return

    processes, connections = loaded
    final_image, intermediate_image, session_host_image = expectation.images
    designed = f"{final_image} <- {intermediate_image} <- {session_host_image}"
    target_host = expectation.target_host.lower()

    candidates: list[tuple[ProcessRecord, LineageChain]] = []
    for process in processes:
        if process.key.host.lower() != target_host or _image_name(process.image) != final_image:
            continue
        chain = resolve_lineage(tree, process.key)
        if chain is not None:
            candidates.append((process, chain))

    if not candidates:
        hosts = sorted({process.key.host for process in processes})
        report.fail(
            f"{JSONL_FILENAME} holds no EID 1 of the final tool {final_image!r} on "
            f"{expectation.target_host}; hosts in the capture: {hosts}"
        )
        return

    conforming = [
        (process, chain) for process, chain in candidates if _conforms(chain, expectation)
    ]
    if not conforming:
        observed = sorted({_describe_chain(chain) for _, chain in candidates})
        report.fail(
            f"no final tool instance has the lineage this run was designed with ({designed}); "
            f"observed: {observed}"
        )
        _report_broken_candidates(jsonl_path, candidates, report)
        return

    # The run starts its intermediate once. A second instance with the designed
    # lineage means the capture holds more than this run, and which instance is
    # the run's own is not something to guess.
    if len(conforming) != 1:
        report.fail(
            f"{len(conforming)} final tool instances have the designed lineage ({designed}); "
            "a run starts exactly one"
        )
        return

    process, chain = conforming[0]
    if expectation.destination_ip is None:
        _record_lineage_only(process, chain, reading, report)
        return

    _verify_anchor(jsonl_path, process.key, chain, connections, expectation, report)


def _record_lineage_only(
    process: ProcessRecord,
    chain: LineageChain,
    reading: R1LineageReport,
    report: R1PilotValidationReport,
) -> None:
    """A rehearsal rendered without a destination makes no connection to check."""
    report.checks.extend(reading.checks)
    report.passed(
        f"the final tool on {process.key.host} has the designed lineage: {_describe_chain(chain)}"
    )
    report.passed(
        "the scenario carries no internal destination, so the EID 1 -> EID 3 link was not "
        "checked (rehearsal)"
    )
    report.lineage = R1ObservedLineage(
        host=process.key.host, nodes=chain.nodes[: len(LINEAGE_ROLES)], connections=()
    )


def _verify_anchor(
    jsonl_path: Path,
    anchor: ProcessKey,
    chain: LineageChain,
    connections: list[ConnectionRecord],
    expectation: R1PilotExpectation,
    report: R1PilotValidationReport,
) -> None:
    """Hand one final tool instance to the lineage validator and pass its verdict on."""
    verdict = verify_r1_lineage(
        jsonl_path,
        anchor=anchor,
        expected_parent_process_guids=chain.process_guids[1:],
        expected_destination_ip=expectation.destination_ip,
        expected_destination_port=expectation.destination_port,
        expected_protocol=CONNECTION_PROTOCOL,
    )
    report.errors.extend(verdict.errors)
    if not verdict.ok:
        return

    report.checks.extend(verdict.checks)
    report.passed(
        f"the final tool on {anchor.host} has the designed lineage: {_describe_chain(chain)}"
    )
    # The record keeps what the verdict rests on: a record that reaches the
    # destination with another Protocol, or with none, is left out.
    report.lineage = R1ObservedLineage(
        host=anchor.host,
        nodes=chain.nodes[: len(LINEAGE_ROLES)],
        connections=tuple(
            connection
            for connection in select_connections(connections, anchor)
            if _reaches(connection, expectation)
        ),
    )


def _stamp(moment: datetime) -> str:
    return (
        moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    )


def _check_reference(
    metadata: RunMetadata,
    records: list[ExecutionRecordRow],
    expectation: R1PilotExpectation,
    rehearsal: bool,
    report: R1PilotValidationReport,
) -> None:
    """Check that the reference of an attack run is the EID 1 of the session host of its lineage.

    The lineage was found in the original JSONL by ProcessGuid, starting from the
    final tool. Its last node is the session host the first action created, and
    that record is what the reference has to name: its RecordId as
    `reference_source_event_id` and its EventData.UtcTime as `reference_time`.
    TimeCreated is not read. A run whose lineage was not established, or whose
    reference fields are incomplete, was reported already and is not judged here.
    """
    if expectation.reference_action_id is None or report.lineage is None:
        return
    if any(getattr(metadata, name) is None for name in REFERENCE_FIELDS):
        return
    if metadata.reference_action_id != expectation.reference_action_id:
        return

    reference_node = (
        report.lineage.nodes[1]
        if expectation.identity.family_id == "wmi_management"
        else report.lineage.nodes[-1]
    )
    role = (
        "A01-attributed intermediate"
        if expectation.identity.family_id == "wmi_management"
        else "session host"
    )
    described = f"the EID 1 of the {role} of this run ({reference_node.key.process_guid})"
    before = len(report.errors)

    if (
        reference_node.record_id is None
        or metadata.reference_source_event_id != reference_node.record_id
    ):
        report.fail(
            f"run_metadata.json reference_source_event_id is "
            f"{metadata.reference_source_event_id!r}, but {described} is RecordId "
            f"{reference_node.record_id!r}"
        )

    try:
        recorded = datetime.strptime(reference_node.event_utc_time or "", EVENT_UTC_FORMAT).replace(
            tzinfo=UTC
        )
    except ValueError:
        report.fail(
            f"{described} carries no readable EventData.UtcTime ({reference_node.event_utc_time!r}); "
            "TimeCreated is not used in its place"
        )
        return
    reference_time = metadata.reference_time
    if reference_time != recorded:
        report.fail(
            f"run_metadata.json reference_time is {_stamp(reference_time)}, but the "
            f"EventData.UtcTime of {described} is {reference_node.event_utc_time}"
        )

    if len(report.errors) == before:
        if expectation.identity.family_id == "wmi_management":
            report.passed(
                f"the reference of the run is {described}: RecordId "
                f"{reference_node.record_id}, ProcessGuid {reference_node.key.process_guid}, "
                f"EventData.UtcTime {reference_node.event_utc_time}"
            )
        else:
            report.passed(
                "the reference of the run is the EID 1 of its session host: RecordId "
                f"{reference_node.record_id}, ProcessGuid {reference_node.key.process_guid}, "
                f"EventData.UtcTime {reference_node.event_utc_time}"
            )

    # The session host is created by the reference action and exists before the
    # next action runs in it.
    by_action = [record.action_id for record in records]
    if expectation.reference_action_id in by_action:
        index = by_action.index(expectation.reference_action_id)
        started = records[index].timestamp
        if reference_time < started:
            report.fail(
                f"reference_time {_stamp(reference_time)} is earlier than the recorded start of "
                f"{expectation.reference_action_id} ({_stamp(started)})"
            )
        if expectation.identity.family_id == "wmi_management":
            latest = started + timedelta(seconds=WMI_REFERENCE_CANDIDATE_WINDOW_SEC)
            if reference_time > latest:
                report.fail(
                    f"reference_time {_stamp(reference_time)} is later than the WMI A01 "
                    f"candidate window ending at {_stamp(latest)}"
                )
        if index + 1 < len(records) and reference_time > records[index + 1].timestamp:
            report.fail(
                f"reference_time {_stamp(reference_time)} is later than the next recorded action "
                f"{records[index + 1].action_id} ({_stamp(records[index + 1].timestamp)})"
            )

    # The evaluation window of an attack run is its reference_time plus the
    # horizon. A rehearsal does not wait and is not held to it.
    horizon = expectation.evaluation_horizon_sec
    if rehearsal or metadata.end_time is None:
        return
    observed = (metadata.end_time - reference_time).total_seconds()
    if metadata.end_time < reference_time + timedelta(seconds=horizon):
        report.fail(
            f"end_time {_stamp(metadata.end_time)} is earlier than reference_time + {horizon} s: "
            f"the collection observed {observed:.3f} s after the reference"
        )
    else:
        report.passed(
            f"the collection reached the evaluation horizon: end_time is {observed:.3f} s after "
            f"reference_time, the horizon is {horizon} s"
        )


def validate_r1_pilot_run(
    *,
    artifact_root: Path,
    run_id: str,
    scenario_path: Path,
    rehearsal: bool = False,
) -> R1PilotValidationReport:
    """Validate one R1 run under `artifact_root` and report everything found.

    `scenario_path` is the scenario JSON that was rendered for this run. It holds
    the designed lineage and the injected destination and host, and it has to be
    the scenario the operator trace of the run records: the run is judged
    against no other.

    The dataset tier is not an input. The scenario states the tier of its Pair,
    and the run passes only when its operator trace states exactly that tier. A
    scenario that states no tier validates nothing, and the scenario and the
    trace of a rehearsal both have to say `pilot`.
    """
    report = R1PilotValidationReport(run_id=run_id, rehearsal=rehearsal)

    # run_id becomes a path segment, so it is checked before anything touches the
    # file system. Nothing below this point runs for a rejected value.
    run_id_problem = check_run_id(run_id)
    if run_id_problem is not None:
        report.fail(run_id_problem)
        return report

    _check_rehearsal_isolation(artifact_root, rehearsal, report)

    telemetry_dir = artifact_root / "raw" / run_id / "telemetry"
    ground_truth_dir = artifact_root / "ground_truth" / run_id
    manifest_path = artifact_root / "raw" / run_id / "manifest.json"
    jsonl_path = telemetry_dir / JSONL_FILENAME
    csv_path = ground_truth_dir / "execution_record.csv"
    metadata_path = ground_truth_dir / "run_metadata.json"

    required_files = (
        telemetry_dir / EVTX_FILENAME,
        jsonl_path,
        manifest_path,
        csv_path,
        metadata_path,
    )
    absent = [str(path) for path in required_files if not path.is_file()]
    if absent:
        for path in absent:
            report.fail(f"required artifact is missing: {path}")
        return report

    report.passed("all five required artifacts exist")

    metadata = _read_run_metadata(metadata_path, report)
    records = _read_execution_records(csv_path, report)
    if metadata is None or records is None:
        return report

    report.run_type = metadata.run_type.value

    if metadata.run_id != run_id:
        report.fail(f"run_metadata.json run_id is {metadata.run_id!r}, expected {run_id!r}")

    mismatched = sorted({record.run_id for record in records} - {metadata.run_id})
    if mismatched:
        report.fail(
            f"execution_record.csv carries run_id(s) other than {metadata.run_id!r}: {mismatched}"
        )
    else:
        report.passed(f"every execution_record row carries run_id {metadata.run_id}")

    _check_manifest(manifest_path, telemetry_dir, run_id, report)

    if metadata.scenario_id != SCENARIO_ID:
        report.fail(
            f"run_metadata.json scenario_id is {metadata.scenario_id!r}, expected {SCENARIO_ID!r}"
        )
        return report

    # The scenario is read once. The bytes compared with the operator trace are
    # the bytes the plan is parsed from, so no other scenario can stand in.
    try:
        scenario_bytes = scenario_path.read_bytes()
    except OSError as error:
        report.fail(
            f"scenario definition is not usable ({scenario_path}): scenario is not readable "
            f"JSON: {error}"
        )
        return report

    # The tier a run is held to is the one its scenario states for the Pair. The
    # caller gives none, and a scenario without one validates nothing. Neither
    # does one whose run block states a tier or an identity of its own.
    try:
        scenario_tier = _load_dataset_tier(_parse_scenario(scenario_bytes))
    except R1ScenarioError as error:
        report.fail(f"scenario definition is not usable ({scenario_path}): {error}")
        return report
    report.scenario_dataset_tier = scenario_tier
    if rehearsal and scenario_tier != REHEARSAL_TIER:
        report.fail(
            f"a rehearsal is not formal data: its scenario has to state dataset_tier "
            f"{REHEARSAL_TIER!r}, this one states {scenario_tier!r}"
        )
        return report

    trace = _check_run_trace(
        artifact_root, run_id, scenario_bytes, rehearsal, scenario_tier, report
    )
    if trace is None:
        return report
    report.trace = trace

    try:
        expectation = _read_expectation(scenario_bytes, metadata.run_type.value)
    except R1ScenarioError as error:
        report.fail(f"scenario definition is not usable ({scenario_path}): {error}")
        return report

    report.identity = expectation.identity

    _check_run_metadata(metadata, expectation, report)
    _check_actions(metadata, records, expectation, rehearsal, report)
    _check_lineage(jsonl_path, expectation, rehearsal, report)
    _check_reference(metadata, records, expectation, rehearsal, report)
    return report


def _lineage_lines(lineage: R1ObservedLineage) -> list[str]:
    lines = [f"lineage record (extracted from {JSONL_FILENAME})", f"  host: {lineage.host}"]
    for role, node in zip(LINEAGE_ROLES, lineage.nodes, strict=True):
        lines.append(f"  {role}: {_image_name(node.image) or '(no Image)'}")
        lines.append(f"    Image             : {node.image}")
        lines.append(f"    ProcessGuid       : {node.key.process_guid}")
        lines.append(f"    ParentProcessGuid : {node.parent_process_guid}")
        lines.append(f"    RecordId          : {node.record_id}")

    for connection in lineage.connections:
        lines.append(
            f"  connection: {connection.destination_ip}:{connection.destination_port} "
            f"{connection.protocol or '(no Protocol)'}"
        )
        lines.append(f"    Image             : {connection.image}")
        lines.append(f"    ProcessGuid       : {connection.key.process_guid}")
        lines.append(f"    RecordId          : {connection.record_id}")
        lines.append(f"    TimeCreated       : {connection.time_created}")
        lines.append(f"    UtcTime           : {connection.event_utc_time}")

    return lines


def format_report(report: R1PilotValidationReport) -> str:
    """Render the report for a terminal and for the lineage record of the run."""
    lines = [f"run_id      : {report.run_id}"]
    lines.append(f"run_type    : {report.run_type or 'unknown'}")
    lines.append(f"mode        : {'REHEARSAL' if report.rehearsal else 'collection'}")
    if report.identity is not None:
        lines.append(
            f"pair        : family_id={report.identity.family_id} "
            f"variation_id={report.identity.variation_id} repetition={report.identity.repetition}"
        )
    if report.trace is not None:
        lines.append(f"tier        : {report.trace.dataset_tier}")
        lines.append(f"scenario    : sha256={report.trace.scenario_sha256}")
    lines.append("")

    for check in report.checks:
        lines.append(f"[+] {check}")
    for error in report.errors:
        lines.append(f"[!] {error}")

    if report.action_times:
        lines.append("")
        lines.append("action times (execution_record.csv against run_metadata.json start_time)")
        lines.extend(f"  {line}" for line in report.action_times)
        if report.rehearsal:
            lines.append("  a rehearsal does not wait for the designed offsets")

    if report.lineage is not None:
        lines.append("")
        lines.extend(_lineage_lines(report.lineage))

    lines.append("")
    lines.append(
        "not checked here: the comparison of the two runs of a pair and the t+5 and t+8 "
        "windows (r1.md section 8-1: S-1, the pair part of S-2 and S-3, S-7)"
    )
    lines.append(
        "not judged here: whether the lineage is approved. The run was checked against its "
        "planned lineage; no approved lineage policy is read here"
    )
    if report.trace is None:
        lines.append(
            "dataset tier: not established for this run, the operator trace was not accepted "
            f"(the scenario states {report.scenario_dataset_tier!r})"
        )
    elif report.trace.dataset_tier == REHEARSAL_TIER:
        lines.append(
            "not a formal run: the scenario of its Pair and its operator trace say "
            "dataset_tier=pilot, and a formal selector has to leave such a run out"
        )
    else:
        lines.append(
            "dataset tier: the scenario of the Pair and the operator trace both say "
            f"dataset_tier={report.trace.dataset_tier}. Whether the Pair is selected as formal "
            "data is not decided here (scenarios/R1/README.md section 1-3)"
        )
    lines.append("")
    if report.ok:
        verdict = (
            "PASS (one run: contract files, operator trace and planned lineage; "
            "not the Pilot verdict)"
        )
        if report.rehearsal:
            verdict += " (REHEARSAL - not a valid R1 collection, do not use as an R1 Pair)"
        lines.append(verdict)
    else:
        lines.append(f"FAIL: {len(report.errors)} problem(s)")

    return "\n".join(lines)


def write_report(
    report: R1PilotValidationReport, destination: Path, *, artifact_root: Path
) -> Path:
    """Store the rendered report as the lineage record of the run.

    The record is operator evidence, not a contract artifact: it is refused
    inside the run's `raw/` and `ground_truth/` trees, which hold exactly the
    files the Manifest and the contracts describe. An existing file is never
    replaced, so an earlier record cannot be lost to a second validation.
    """
    resolved = destination.resolve()
    for name in ("raw", "ground_truth"):
        contract_dir = (artifact_root / name).resolve()
        if resolved == contract_dir or contract_dir in resolved.parents:
            raise R1ReportError(
                "the lineage record is not a contract artifact and cannot be written under "
                f"{contract_dir}"
            )

    if not resolved.parent.is_dir():
        raise R1ReportError(
            f"the directory for the lineage record does not exist: {resolved.parent}"
        )

    try:
        with resolved.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(format_report(report) + "\n")
    except FileExistsError as error:
        raise R1ReportError(f"the lineage record already exists: {resolved}") from error

    return resolved


__all__ = [
    "DATASET_TIERS",
    "R1ObservedLineage",
    "R1PilotExpectation",
    "R1PilotValidationReport",
    "R1ReportError",
    "R1RunTrace",
    "R1ScenarioAction",
    "R1ScenarioError",
    "format_report",
    "load_r1_pilot_expectation",
    "validate_r1_pilot_run",
    "write_report",
]
