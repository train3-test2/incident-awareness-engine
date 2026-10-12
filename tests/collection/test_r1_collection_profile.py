"""The collection profile a scenario states: entry, raw window, readiness and reference rule.

Every scenario here is a synthetic mapping holding only the keys the profile
reads. The names stand for "a session host", "a provider host" and so on, and
the action ids are made up.
"""

import copy
from collections.abc import Callable

import pytest

from incident_awareness.collection.r1_collection_profile import (
    ENTRY_REMOTING_SESSION,
    ENTRY_WMI_PROCESS,
    RAW_WINDOW_BOOT,
    RAW_WINDOW_RUN,
    READINESS_OUT_OF_BAND,
    REFERENCE_SOURCE_SESSION_HOST,
    REFERENCE_SOURCE_WMI_CREATED,
    REFERENCE_STEP_INVOKE,
    REFERENCE_STEP_SESSION_BEGIN,
    STEP_ACTION_TYPES,
    STEP_ORDERS,
    R1CollectionProfileError,
    R1ReferenceRule,
    check_run_steps,
    read_collection_profile,
)

SESSION_HOST = "wsmprovhost.exe"
PROVIDER_HOST = "WmiPrvSE.exe"


def _actions(entry_kind: str = ENTRY_REMOTING_SESSION) -> list[dict]:
    """The actions of one run: the steps of the entry kind, with the types it fixes."""
    types = STEP_ACTION_TYPES[entry_kind] or {}
    return [
        {"action_id": f"X{index}", "step": step, "action_type": types.get(step, "synthetic")}
        for index, step in enumerate(STEP_ORDERS[entry_kind], start=1)
    ]


def _stating_nothing() -> dict:
    """What a scenario that predates the profile holds of the keys read here."""
    return {
        "planned_lineage": {"session_host": {"image": SESSION_HOST}},
        "runs": {
            "attack": {"actions": _actions()},
            "normal": {"actions": _actions()},
        },
    }


def _through_wmi() -> dict:
    scenario = _stating_nothing()
    scenario["planned_lineage"]["entry"] = {"kind": ENTRY_WMI_PROCESS, "root_image": PROVIDER_HOST}
    scenario["collection"] = {
        "raw_window": RAW_WINDOW_BOOT,
        "readiness_method": READINESS_OUT_OF_BAND,
    }
    scenario["reference_rule"] = {
        "action_step": REFERENCE_STEP_INVOKE,
        "source": REFERENCE_SOURCE_WMI_CREATED,
    }
    for run in scenario["runs"].values():
        run["actions"] = _actions(ENTRY_WMI_PROCESS)
    return scenario


def _changed(base: Callable[[], dict], change: Callable[[dict], None]) -> dict:
    scenario = copy.deepcopy(base())
    change(scenario)
    return scenario


# ---------------------------------------------------------------------------
# A scenario that states nothing is collected as before
# ---------------------------------------------------------------------------


def test_a_scenario_that_states_no_profile_gets_the_values_of_today() -> None:
    scenario = _stating_nothing()
    profile = read_collection_profile(scenario)

    assert profile.entry_kind == ENTRY_REMOTING_SESSION
    assert profile.root_image == SESSION_HOST == profile.session_host_image
    assert profile.root_is_session_host
    assert profile.raw_window == RAW_WINDOW_RUN and not profile.raw_window_extended
    assert profile.readiness_method is None
    assert profile.collection_declared is False
    assert profile.reference_rule == R1ReferenceRule(
        REFERENCE_STEP_SESSION_BEGIN, REFERENCE_SOURCE_SESSION_HOST
    )
    # its steps and their action types are the scenario's own
    assert STEP_ACTION_TYPES[ENTRY_REMOTING_SESSION] is None
    check_run_steps(scenario, profile)


def test_stating_the_profile_of_today_changes_nothing_but_the_declaration() -> None:
    def state_it(scenario: dict) -> None:
        scenario["planned_lineage"]["entry"] = {
            "kind": ENTRY_REMOTING_SESSION,
            "root_image": SESSION_HOST.upper(),
        }
        scenario["collection"] = {"raw_window": RAW_WINDOW_RUN, "readiness_method": None}
        scenario["reference_rule"] = {
            "action_step": REFERENCE_STEP_SESSION_BEGIN,
            "source": REFERENCE_SOURCE_SESSION_HOST,
        }

    profile = read_collection_profile(_changed(_stating_nothing, state_it))

    assert profile.entry_kind == ENTRY_REMOTING_SESSION and profile.root_is_session_host
    assert profile.raw_window == RAW_WINDOW_RUN and profile.readiness_method is None
    assert profile.reference_rule.source == REFERENCE_SOURCE_SESSION_HOST
    assert profile.collection_declared is True


# ---------------------------------------------------------------------------
# An intermediate started through WMI
# ---------------------------------------------------------------------------


def test_the_wmi_entry_needs_the_boot_window_and_out_of_band_readiness() -> None:
    profile = read_collection_profile(_through_wmi())

    assert profile.entry_kind == ENTRY_WMI_PROCESS
    assert profile.root_image == PROVIDER_HOST and profile.session_host_image == SESSION_HOST
    assert not profile.root_is_session_host
    assert profile.raw_window == RAW_WINDOW_BOOT and profile.raw_window_extended
    assert profile.readiness_method == READINESS_OUT_OF_BAND
    assert profile.collection_declared is True


def test_the_reference_of_the_wmi_entry_is_the_process_its_launch_action_creates() -> None:
    profile = read_collection_profile(_through_wmi())

    assert profile.reference_rule == R1ReferenceRule(
        REFERENCE_STEP_INVOKE, REFERENCE_SOURCE_WMI_CREATED
    )
    # not the session host: it is not in this lineage
    assert profile.reference_rule.source != REFERENCE_SOURCE_SESSION_HOST


def _no_collection(scenario: dict) -> None:
    del scenario["collection"]


def _run_window(scenario: dict) -> None:
    scenario["collection"]["raw_window"] = RAW_WINDOW_RUN


def _no_readiness(scenario: dict) -> None:
    scenario["collection"]["readiness_method"] = None


def _root_is_the_session_host(scenario: dict) -> None:
    scenario["planned_lineage"]["entry"]["root_image"] = SESSION_HOST


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_no_collection, "collection.raw_window must be 'target_boot_to_run_end'"),
        (_run_window, "collection.raw_window must be 'target_boot_to_run_end'"),
        (_no_readiness, "collection.readiness_method must be 'out_of_band'"),
        (_root_is_the_session_host, "must not be the session host image"),
    ],
    ids=["no_collection_block", "run_window", "no_readiness_method", "root_is_the_session_host"],
)
def test_a_wmi_entry_that_could_not_be_collected_is_refused(
    change: Callable[[dict], None], message: str
) -> None:
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_through_wmi, change))


# ---------------------------------------------------------------------------
# Values and combinations that are refused
# ---------------------------------------------------------------------------


def _entry(kind: object, root_image: object) -> Callable[[dict], None]:
    def change(scenario: dict) -> None:
        scenario["planned_lineage"]["entry"] = {"kind": kind, "root_image": root_image}

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_entry("scheduled_task", SESSION_HOST), "entry.kind must be one of"),
        (_entry(None, SESSION_HOST), "entry.kind must be one of"),
        (_entry(ENTRY_REMOTING_SESSION, "other.exe"), "must be planned_lineage.session_host.image"),
        (_entry(ENTRY_REMOTING_SESSION, "C:\\dir\\wsmprovhost.exe"), "must be a plain file name"),
        (_entry(ENTRY_REMOTING_SESSION, "two words.exe"), "must be a plain file name"),
        (_entry(ENTRY_REMOTING_SESSION, ""), "must be a plain file name"),
        (_entry(ENTRY_REMOTING_SESSION, None), "must be a plain file name"),
    ],
    ids=[
        "kind_not_implemented",
        "kind_null",
        "session_entry_with_another_root",
        "root_is_a_path",
        "root_with_a_space",
        "root_empty",
        "root_null",
    ],
)
def test_an_entry_that_is_not_usable_is_refused(
    change: Callable[[dict], None], message: str
) -> None:
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_stating_nothing, change))


def _collection(raw_window: object, readiness_method: object) -> Callable[[dict], None]:
    def change(scenario: dict) -> None:
        scenario["collection"] = {"raw_window": raw_window, "readiness_method": readiness_method}

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_collection(RAW_WINDOW_BOOT, READINESS_OUT_OF_BAND), "must be 'run_window' for"),
        (_collection("whole_log", None), "collection.raw_window must be one of"),
        (_collection(None, None), "collection.raw_window must be one of"),
        (_collection(RAW_WINDOW_RUN, "active_tcp_from_target"), "readiness_method must be one of"),
    ],
    ids=["session_entry_with_the_boot_window", "unknown_window", "window_null", "unknown_method"],
)
def test_a_collection_block_that_is_not_usable_is_refused(
    change: Callable[[dict], None], message: str
) -> None:
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_stating_nothing, change))


def _extra_entry_key(scenario: dict) -> None:
    scenario["planned_lineage"]["entry"]["parent_image_fallback"] = True


def _extra_collection_key(scenario: dict) -> None:
    scenario["collection"]["active_tcp_probe"] = True


def _extra_rule_key(scenario: dict) -> None:
    scenario["reference_rule"]["config_hash"] = "0" * 64


def _entry_without_root(scenario: dict) -> None:
    del scenario["planned_lineage"]["entry"]["root_image"]


def _collection_without_method(scenario: dict) -> None:
    del scenario["collection"]["readiness_method"]


def _entry_is_a_list(scenario: dict) -> None:
    scenario["planned_lineage"]["entry"] = [ENTRY_WMI_PROCESS, PROVIDER_HOST]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_extra_entry_key, "planned_lineage.entry states unknown key"),
        (_extra_collection_key, "collection states unknown key"),
        (_extra_rule_key, "reference_rule states unknown key"),
        (_entry_without_root, "planned_lineage.entry is missing"),
        (_collection_without_method, "collection is missing"),
        (_entry_is_a_list, "planned_lineage.entry must be a mapping"),
    ],
    ids=[
        "unknown_entry_key",
        "unknown_collection_key",
        "unknown_rule_key",
        "entry_without_root",
        "collection_without_method",
        "entry_not_a_mapping",
    ],
)
def test_a_block_with_an_unknown_or_a_missing_key_is_refused(
    change: Callable[[dict], None], message: str
) -> None:
    # A key the profile does not know could be read as a switch it does not have.
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_through_wmi, change))


def test_a_scenario_without_a_session_host_image_has_no_profile() -> None:
    with pytest.raises(R1CollectionProfileError, match="session_host.image must be a non-empty"):
        read_collection_profile({"planned_lineage": {"session_host": {"image": " "}}})
    with pytest.raises(R1CollectionProfileError, match="planned_lineage must be a mapping"):
        read_collection_profile({})


# ---------------------------------------------------------------------------
# The reference rule
# ---------------------------------------------------------------------------


def _rule(action_step: object, source: object) -> Callable[[dict], None]:
    def change(scenario: dict) -> None:
        scenario["reference_rule"] = {"action_step": action_step, "source": source}

    return change


def _no_rule(scenario: dict) -> None:
    del scenario["reference_rule"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_no_rule, "reference_rule must be stated for wmi_process"),
        (
            _rule(REFERENCE_STEP_SESSION_BEGIN, REFERENCE_SOURCE_SESSION_HOST),
            "is not implemented for wmi_process",
        ),
        (_rule(REFERENCE_STEP_INVOKE, "lineage_root_process_create"), "is not implemented for"),
        (_rule(None, None), "is not implemented for wmi_process"),
        (
            _rule(REFERENCE_STEP_SESSION_BEGIN, REFERENCE_SOURCE_WMI_CREATED),
            "action_step must be 'invoke'",
        ),
        (_rule("connect", REFERENCE_SOURCE_WMI_CREATED), "action_step must be 'invoke'"),
    ],
    ids=[
        "not_stated",
        "the_session_host_source",
        "an_unknown_source",
        "left_undecided",
        "the_session_step",
        "the_connect_step",
    ],
)
def test_the_wmi_entry_takes_its_reference_from_its_launch_action_only(
    change: Callable[[dict], None], message: str
) -> None:
    # The session host is not in this lineage, so its record cannot be tied to
    # the lineage by ProcessGuid; the root was created before the run.
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_through_wmi, change))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_rule(None, None), "is not implemented for remoting_session"),
        (_rule("launch", REFERENCE_SOURCE_SESSION_HOST), "action_step must be 'session_begin'"),
        (
            _rule(REFERENCE_STEP_INVOKE, REFERENCE_SOURCE_WMI_CREATED),
            "is not implemented for remoting_session",
        ),
    ],
    ids=["left_undecided", "another_step", "the_source_of_the_wmi_entry"],
)
def test_the_rule_of_the_session_entry_cannot_be_replaced(
    change: Callable[[dict], None], message: str
) -> None:
    with pytest.raises(R1CollectionProfileError, match=message):
        read_collection_profile(_changed(_stating_nothing, change))


# ---------------------------------------------------------------------------
# The steps of a run and their action types
# ---------------------------------------------------------------------------


def test_the_session_entry_keeps_its_five_steps() -> None:
    assert STEP_ORDERS[ENTRY_REMOTING_SESSION] == (
        "session_begin",
        "prepare",
        "launch",
        "connect",
        "session_end",
    )


def test_a_run_through_wmi_has_four_actions_with_the_types_that_were_decided() -> None:
    scenario = _through_wmi()
    profile = read_collection_profile(scenario)

    assert STEP_ORDERS[ENTRY_WMI_PROCESS] == ("invoke", "launch", "connect", "run_end")
    assert [STEP_ACTION_TYPES[ENTRY_WMI_PROCESS][s] for s in STEP_ORDERS[ENTRY_WMI_PROCESS]] == [
        "wmi_process_create",
        "process_create",
        "network_connection",
        "run_end",
    ]
    # the reference is taken at the first of them
    assert STEP_ORDERS[ENTRY_WMI_PROCESS][0] == profile.reference_rule.action_step
    check_run_steps(scenario, profile)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize(
    ("step", "other_type"),
    [
        ("invoke", "process_create"),
        ("launch", "wmi_process_create"),
        ("connect", "process_create"),
        ("run_end", "process_terminate"),
        ("run_end", "remote_session"),
    ],
)
def test_a_wmi_run_that_records_a_step_with_another_type_is_refused(
    run_type: str, step: str, other_type: str
) -> None:
    # Both runs do the same things and record them the same way.
    scenario = _through_wmi()
    for action in scenario["runs"][run_type]["actions"]:
        if action["step"] == step:
            action["action_type"] = other_type
    profile = read_collection_profile(scenario)

    with pytest.raises(R1CollectionProfileError, match=f"runs.{run_type}: the {step} action"):
        check_run_steps(scenario, profile)


def _five_steps(run: dict) -> None:
    run["actions"] = _actions(ENTRY_REMOTING_SESSION)


def _no_run_end(run: dict) -> None:
    del run["actions"][-1]


def _swapped(run: dict) -> None:
    run["actions"][1], run["actions"][2] = run["actions"][2], run["actions"][1]


def _a_fifth_action(run: dict) -> None:
    run["actions"].append({"action_id": "X5", "step": "session_end", "action_type": "synthetic"})


@pytest.mark.parametrize("run_type", ["normal", "attack"])
@pytest.mark.parametrize(
    "change",
    [_five_steps, _no_run_end, _swapped, _a_fifth_action],
    ids=["the_steps_of_the_session_entry", "no_run_end", "another_order", "a_fifth_action"],
)
def test_a_wmi_run_with_other_steps_is_refused(
    run_type: str, change: Callable[[dict], None]
) -> None:
    scenario = _through_wmi()
    change(scenario["runs"][run_type])
    profile = read_collection_profile(scenario)

    with pytest.raises(R1CollectionProfileError, match=f"runs.{run_type} steps must be"):
        check_run_steps(scenario, profile)
