"""How the raw telemetry of one R1 family is collected, as its scenario states it.

A scenario may state three things next to its planned lineage. Each of them is
optional, and a scenario that states none is collected exactly as before:

    planned_lineage:
      entry:
        kind: remoting_session | wmi_process
        root_image: <Image the intermediate is expected to be started by>
    collection:
      raw_window: run_window | target_boot_to_run_end
      readiness_method: out_of_band
    reference_rule:
      action_step: <step of the action an attack run takes its reference from>
      source: <which record that reference is>

`entry` says how the intermediate process is started. With `remoting_session`
the remote session host starts it, so the session host is the root of the
lineage. With `wmi_process` it is started through WMI: its parent is the WMI
provider host, a process that is created while the target boots. Its
process-create record is therefore older than the window a run exports, and the
three records of the lineage are only complete when the raw export reaches back
to the boot of the target. That is what `raw_window` states.

A raw export that starts at the boot also holds everything the target did
before the run. A connection opened from the target to the internal destination
to check that it is ready would be in it, as one more connection to that
destination. A family with the extended window therefore states
`readiness_method: out_of_band`: readiness is established from outside the
target and handed to the runner as a record, and nothing connects before the
run.

`reference_rule` says where an attack run takes its reference from. Each entry
kind has one source. `session_host_process_create` is the process-create record
of the session host the session action creates; it needs the session host to be
in the lineage and is the rule of a scenario that states none.
`wmi_created_process_create` is the process-create record of the process the
invoke action creates through WMI: the one record that carries the process id
the call returned, was written at or after the time of the call, and is the
intermediate of the lineage found by ProcessGuid. A scenario whose entry is
`wmi_process` has no rule by default and has to state it.

A run of a `wmi_process` scenario has four actions, in both run types: the call
through WMI that starts the intermediate (`invoke`, recorded as
`wmi_process_create`), the start of the final tool by that intermediate
(`launch`, `process_create`), the connection of the final tool (`connect`,
`network_connection`) and the end of the run (`run_end`). The four action
types were handed over as decided. The step names are the ones the tests
of this family already use; nothing here fixes them as a contract.

Nothing here reads an approved lineage policy. `root_image` is a value of the
collection plan, compared with what a run left; it does not say which lineage is
approved.
"""

import re
from dataclasses import dataclass

ENTRY_REMOTING_SESSION = "remoting_session"
ENTRY_WMI_PROCESS = "wmi_process"
ENTRY_KINDS = (ENTRY_REMOTING_SESSION, ENTRY_WMI_PROCESS)

RAW_WINDOW_RUN = "run_window"
RAW_WINDOW_BOOT = "target_boot_to_run_end"
RAW_WINDOWS = (RAW_WINDOW_RUN, RAW_WINDOW_BOOT)
# Why a raw window reaches back before the run. Recorded with the window, never alone.
RAW_WINDOW_EXTENSION_REASON = "lineage_root_created_before_run"

READINESS_OUT_OF_BAND = "out_of_band"
READINESS_METHODS = (READINESS_OUT_OF_BAND,)

REFERENCE_STEP_SESSION_BEGIN = "session_begin"
REFERENCE_STEP_INVOKE = "invoke"
REFERENCE_SOURCE_SESSION_HOST = "session_host_process_create"
REFERENCE_SOURCE_WMI_CREATED = "wmi_created_process_create"
# The reference source implemented for each entry kind, and the step it belongs to.
REFERENCE_SOURCES = {
    ENTRY_REMOTING_SESSION: {REFERENCE_SOURCE_SESSION_HOST: REFERENCE_STEP_SESSION_BEGIN},
    ENTRY_WMI_PROCESS: {REFERENCE_SOURCE_WMI_CREATED: REFERENCE_STEP_INVOKE},
}
# The steps of a run, in order, by entry kind. The five of the session entry are
# the ones every R1 run has had.
STEP_ORDERS = {
    ENTRY_REMOTING_SESSION: ("session_begin", "prepare", "launch", "connect", "session_end"),
    ENTRY_WMI_PROCESS: ("invoke", "launch", "connect", "run_end"),
}
# The action type each step of an entry kind is recorded with. None leaves the
# types to the scenario, as it always was for the session entry.
STEP_ACTION_TYPES = {
    ENTRY_REMOTING_SESSION: None,
    ENTRY_WMI_PROCESS: {
        "invoke": "wmi_process_create",
        "launch": "process_create",
        "connect": "network_connection",
        "run_end": "run_end",
    },
}

_ENTRY_KEYS = ("kind", "root_image")
_COLLECTION_KEYS = ("raw_window", "readiness_method")
_REFERENCE_RULE_KEYS = ("action_step", "source")
_FILE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class R1CollectionProfileError(ValueError):
    """Raised when a scenario states a collection profile that cannot be used."""


@dataclass(frozen=True)
class R1ReferenceRule:
    """Where an attack run takes its reference from: the step of the action and the record."""

    action_step: str
    source: str


@dataclass(frozen=True)
class R1CollectionProfile:
    """The collection profile of one scenario.

    `collection_declared` is whether the scenario states a `collection` block.
    Only then does a run write, and a validator require, a collection
    provenance record.
    """

    entry_kind: str
    root_image: str
    session_host_image: str
    raw_window: str
    readiness_method: str | None
    reference_rule: R1ReferenceRule
    collection_declared: bool

    @property
    def root_is_session_host(self) -> bool:
        return self.entry_kind == ENTRY_REMOTING_SESSION

    @property
    def raw_window_extended(self) -> bool:
        return self.raw_window == RAW_WINDOW_BOOT


def _mapping(value: object, label: str, keys: tuple[str, ...]) -> dict:
    if not isinstance(value, dict):
        raise R1CollectionProfileError(f"{label} must be a mapping")
    unknown = sorted(str(key) for key in value if key not in keys)
    if unknown:
        raise R1CollectionProfileError(f"{label} states unknown key(s) {unknown}")
    missing = [key for key in keys if key not in value]
    if missing:
        raise R1CollectionProfileError(f"{label} is missing {missing}")
    return value


def _file_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not _FILE_NAME.fullmatch(value):
        raise R1CollectionProfileError(f"{label} must be a plain file name, found {value!r}")
    return value


def _read_entry(lineage: dict, session_host_image: str) -> tuple[str, str]:
    if "entry" not in lineage:
        return ENTRY_REMOTING_SESSION, session_host_image

    entry = _mapping(lineage["entry"], "planned_lineage.entry", _ENTRY_KEYS)
    kind = entry["kind"]
    if kind not in ENTRY_KINDS:
        raise R1CollectionProfileError(
            f"planned_lineage.entry.kind must be one of {ENTRY_KINDS}, found {kind!r}"
        )
    root_image = _file_name(entry["root_image"], "planned_lineage.entry.root_image")

    same = root_image.lower() == session_host_image.lower()
    if kind == ENTRY_REMOTING_SESSION and not same:
        raise R1CollectionProfileError(
            "planned_lineage.entry.root_image must be planned_lineage.session_host.image for "
            f"{ENTRY_REMOTING_SESSION}: the session host starts the intermediate; found "
            f"{root_image!r} and {session_host_image!r}"
        )
    if kind != ENTRY_REMOTING_SESSION and same:
        raise R1CollectionProfileError(
            f"planned_lineage.entry.root_image must not be the session host image for {kind}: "
            f"the intermediate is not started by the session host; found {root_image!r}"
        )
    return kind, root_image


def _read_collection(scenario: dict, entry_kind: str) -> tuple[str, str | None, bool]:
    if "collection" not in scenario:
        raw_window, readiness_method, declared = RAW_WINDOW_RUN, None, False
    else:
        collection = _mapping(scenario["collection"], "collection", _COLLECTION_KEYS)
        raw_window, readiness_method, declared = (
            collection["raw_window"],
            collection["readiness_method"],
            True,
        )
        if raw_window not in RAW_WINDOWS:
            raise R1CollectionProfileError(
                f"collection.raw_window must be one of {RAW_WINDOWS}, found {raw_window!r}"
            )
        if readiness_method is not None and readiness_method not in READINESS_METHODS:
            raise R1CollectionProfileError(
                f"collection.readiness_method must be one of {READINESS_METHODS} or null, found "
                f"{readiness_method!r}"
            )

    # The root of a lineage that is not started in the run is created at boot.
    # Its record is only in a raw export that starts there.
    if entry_kind == ENTRY_WMI_PROCESS and raw_window != RAW_WINDOW_BOOT:
        raise R1CollectionProfileError(
            f"collection.raw_window must be {RAW_WINDOW_BOOT!r} for {ENTRY_WMI_PROCESS}: the "
            "provider host is created when the target boots, so a run window does not hold the "
            f"root of the lineage; found {raw_window!r}"
        )
    # A family whose root is created in the run has no reason to collect more.
    if entry_kind == ENTRY_REMOTING_SESSION and raw_window != RAW_WINDOW_RUN:
        raise R1CollectionProfileError(
            f"collection.raw_window must be {RAW_WINDOW_RUN!r} for {ENTRY_REMOTING_SESSION}: "
            f"the session host is created in the run; found {raw_window!r}"
        )
    # Everything before the run is in an extended window, a readiness connection included.
    if raw_window == RAW_WINDOW_BOOT and readiness_method != READINESS_OUT_OF_BAND:
        raise R1CollectionProfileError(
            f"collection.readiness_method must be {READINESS_OUT_OF_BAND!r} when "
            f"collection.raw_window is {RAW_WINDOW_BOOT!r}: a connection opened from the target "
            f"before the run would be collected; found {readiness_method!r}"
        )
    return raw_window, readiness_method, declared


def _read_reference_rule(scenario: dict, entry_kind: str) -> R1ReferenceRule:
    implemented = REFERENCE_SOURCES[entry_kind]
    if "reference_rule" not in scenario:
        if entry_kind == ENTRY_REMOTING_SESSION:
            return R1ReferenceRule(REFERENCE_STEP_SESSION_BEGIN, REFERENCE_SOURCE_SESSION_HOST)
        raise R1CollectionProfileError(
            f"reference_rule must be stated for {entry_kind}: the session host is not in the "
            "lineage, so the rule of a scenario that states none does not apply; implemented: "
            f"{sorted(implemented)}"
        )

    rule = _mapping(scenario["reference_rule"], "reference_rule", _REFERENCE_RULE_KEYS)
    action_step, source = rule["action_step"], rule["source"]
    if source not in implemented:
        raise R1CollectionProfileError(
            f"reference_rule.source {source!r} is not implemented for {entry_kind}; implemented: "
            f"{sorted(implemented)}"
        )
    if action_step != implemented[source]:
        raise R1CollectionProfileError(
            f"reference_rule.action_step must be {implemented[source]!r} for the source "
            f"{source!r}, found {action_step!r}"
        )
    return R1ReferenceRule(action_step, source)


def read_collection_profile(scenario: dict) -> R1CollectionProfile:
    """The collection profile a scenario states, with the values of one that states none.

    Raises `R1CollectionProfileError` for a value or a combination that cannot be
    collected as stated. `planned_lineage.session_host.image` has to be a
    non-blank string; the rest of the planned lineage is checked where it is read.
    """
    lineage = scenario.get("planned_lineage")
    if not isinstance(lineage, dict):
        raise R1CollectionProfileError("planned_lineage must be a mapping")
    session_host = lineage.get("session_host")
    session_host_image = session_host.get("image") if isinstance(session_host, dict) else None
    if not isinstance(session_host_image, str) or not session_host_image.strip():
        raise R1CollectionProfileError(
            "planned_lineage.session_host.image must be a non-empty string"
        )

    entry_kind, root_image = _read_entry(lineage, session_host_image)
    raw_window, readiness_method, declared = _read_collection(scenario, entry_kind)
    return R1CollectionProfile(
        entry_kind=entry_kind,
        root_image=root_image,
        session_host_image=session_host_image,
        raw_window=raw_window,
        readiness_method=readiness_method,
        reference_rule=_read_reference_rule(scenario, entry_kind),
        collection_declared=declared,
    )


def check_run_steps(scenario: dict, profile: R1CollectionProfile) -> None:
    """Hold both runs of a scenario to the steps and the action types of its entry kind.

    Both runs do the same things in the same order, so they record them with
    the same types. An entry kind that fixes no types leaves its steps and its
    types to whoever reads the scenario next, as it always was.
    """
    expected = STEP_ACTION_TYPES[profile.entry_kind]
    if expected is None:
        return

    order = STEP_ORDERS[profile.entry_kind]
    runs = scenario.get("runs")
    for run_type, run in runs.items() if isinstance(runs, dict) else ():
        actions = run.get("actions") if isinstance(run, dict) else None
        actions = [action for action in actions if isinstance(action, dict)] if actions else []
        steps = tuple(action.get("step") for action in actions)
        if steps != order:
            raise R1CollectionProfileError(
                f"runs.{run_type} steps must be {list(order)} in that order for a "
                f"{profile.entry_kind} scenario, found {list(steps)}"
            )
        for action in actions:
            step = action["step"]
            if action.get("action_type") != expected[step]:
                raise R1CollectionProfileError(
                    f"runs.{run_type}: the {step} action of a {profile.entry_kind} scenario "
                    f"is recorded as {expected[step]!r}, found {action.get('action_type')!r}"
                )
