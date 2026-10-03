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
   across all of them.
2. It checks the operator trace. The scenario given to this validator, the
   scenario copy the run kept and the SHA-256 the trace records have to be the
   same bytes, and the trace has to name this run and mark it
   `dataset_tier=pilot`. A scenario edited after the run can therefore not be
   the plan the run is judged against, and a run without a usable trace is not
   validated at all.
3. It finds the final management tool instance of the run in the raw Sysmon
   JSONL and hands it to `r1_lineage.verify_r1_lineage`, which checks the parent
   chain by host and ProcessGuid and the EID 3 carrying the same host and
   ProcessGuid to the approved destination, recorded as TCP.

What the run was planned to leave - the three Images of its planned lineage, the
internal destination, the Target-A name and the family, variation and repetition
of its Pair - is read from the scenario JSON that was rendered for the run
(`tools/r1_scenario_to_json.py`), never from this code. The bytes are read once:
what is compared with the operator trace is what the plan is parsed from.

Every run the R1 Pilot runner writes is a Pilot run, a rehearsal included, and
its trace says so. A formal evaluation selector has to leave out every run whose
trace says `dataset_tier=pilot`; this validator accepts no other tier.

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
    R1PairIdentity,
    R1PairIdentityError,
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
# The connection an R1 run makes is TCP: the runner refuses a scenario stating
# another protocol and the task attempts nothing else. This is the spelling
# Sysmon records; the comparison ignores case.
CONNECTION_PROTOCOL = "tcp"
PLANNED_LINEAGE_KEY = "planned_lineage"
LINEAGE_ROLES = ("final tool", "intermediate", "session host")
REFERENCE_FIELDS = ("reference_time", "reference_action_id", "reference_source_event_id")
IDENTITY_FIELDS = ("family_id", "variation_id", "repetition")

# The operator trace the runner writes next to raw/ and ground_truth/
# (scenarios/R1/run-common.ps1, Write-R1RunTrace).
TRACE_DIRNAME = "operator_trace"
TRACE_FILENAME = "r1_run_trace.json"
TRACE_SCENARIO_FILENAME = "scenario.json"
TRACE_VERSION = "v1"
# The only tier the Pilot runner writes, for a rehearsal as well.
DATASET_TIER = "pilot"
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

    try:
        scenario = json.loads(scenario_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R1ScenarioError(f"scenario is not readable JSON: {error}") from error

    scenario = _mapping(scenario, "scenario")
    if scenario.get("scenario_id") != SCENARIO_ID:
        raise R1ScenarioError(
            f"scenario_id must be {SCENARIO_ID!r}, found {scenario.get('scenario_id')!r}"
        )

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

    return R1PilotExpectation(
        target_host=_text(
            _mapping(scenario.get("run_metadata"), "run_metadata").get("target_host"),
            "run_metadata.target_host",
        ),
        final_image=_text(
            _mapping(lineage.get("final_tool"), f"{key}.final_tool").get("image"),
            f"{key}.final_tool.image",
        ),
        intermediate_image=_text(intermediate.get("image"), f"{key}.intermediate.{run_type}.image"),
        session_host_image=_text(
            _mapping(lineage.get("session_host"), f"{key}.session_host").get("image"),
            f"{key}.session_host.image",
        ),
        actions=_load_actions(run, f"runs.{run_type}"),
        destination_ip=destination_ip,
        destination_port=destination_port,
        identity=identity,
    )


def _check_run_trace(
    artifact_root: Path,
    run_id: str,
    scenario_bytes: bytes,
    rehearsal: bool,
    report: R1PilotValidationReport,
) -> R1RunTrace | None:
    """Check that the scenario given to the validator is the one the run executed.

    The runner keeps the scenario bytes its plan was built from, and their
    SHA-256, under `operator_trace/<run_id>/`. Three digests have to agree: the
    one the trace records, the one of the kept copy and the one of the scenario
    this validator was given. The trace also has to name this run, its mode and
    the Pilot tier.

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
        "dataset_tier": DATASET_TIER,
        "mode": TRACE_MODES[rehearsal],
    }
    for name, wanted in expected.items():
        stated = trace.get(name)
        if not isinstance(stated, str) or stated != wanted:
            report.fail(f"operator trace {name} is {stated!r}, expected {wanted!r} ({trace_label})")

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
        f"the operator trace names this run: dataset_tier={DATASET_TIER} mode={expected['mode']}"
    )
    return R1RunTrace(dataset_tier=DATASET_TIER, mode=expected["mode"], scenario_sha256=recorded)


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

    # A normal run has no reference by contract. An attack run of the Pilot has
    # none either, because r1.md section 11-5 has not decided the reference
    # action. A value here could not be traced to telemetry by this validator, so
    # it is refused rather than reported as passing unchecked.
    recorded = [name for name in REFERENCE_FIELDS if getattr(metadata, name) is not None]
    if recorded:
        report.fail(
            f"run_metadata.json records {recorded}, but the R1 Pilot records no reference "
            "action (docs/scenarios/r1.md section 11-5) and this validator cannot trace one"
        )
    else:
        report.passed("run_metadata.json records no reference, as the Pilot does")

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


def validate_r1_pilot_run(
    *,
    artifact_root: Path,
    run_id: str,
    scenario_path: Path,
    rehearsal: bool = False,
) -> R1PilotValidationReport:
    """Validate one R1 Pilot run under `artifact_root` and report everything found.

    `scenario_path` is the scenario JSON that was rendered for this run. It holds
    the designed lineage and the injected destination and host, and it has to be
    the scenario the operator trace of the run records: the run is judged
    against no other.
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

    trace = _check_run_trace(artifact_root, run_id, scenario_bytes, rehearsal, report)
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
    lines.append(
        "not a formal run: only a run whose operator trace says dataset_tier=pilot is accepted "
        "here, and a formal evaluation selector has to leave such a run out"
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
