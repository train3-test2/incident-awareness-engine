"""The approved lineage policy of an R1 family.

The canonical scenario is read as it is in the repository; every other policy
here is written by hand. The tests fix two things: what the first Pilot
approves, and that a policy is read without a run type or a label.
"""

import copy
import inspect
from pathlib import Path

import pytest
import yaml

from incident_awareness.collection.r1_lineage_policy import (
    POLICY_KEY,
    STATUS_FROZEN,
    STATUS_PROVISIONAL,
    ApprovedLineagePolicy,
    R1LineagePolicyError,
    read_approved_lineage_policy,
)

CANONICAL_SCENARIO = Path("scenarios/R1/scenario.yaml")
RUN_TYPES = ("normal", "attack")
LABEL_KEYS = ("normal", "attack", "run_type", "label", "benign", "malicious")


def _canonical() -> dict:
    return yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))


def _policy(**changes: object) -> dict:
    """A scenario that holds one valid policy and nothing else."""
    block: dict[str, object] = {
        "policy_id": "synthetic-approved-lineage",
        "policy_version": "v0.1",
        "family_id": "family_x7",
        "status": STATUS_PROVISIONAL,
        "frozen_at": None,
        "approved_chains": [["session_host.exe", "approved_wrapper.exe", "admin_tool.exe"]],
    }
    block.update(changes)
    return {POLICY_KEY: block}


def _planned_chain(scenario: dict, run_type: str) -> tuple[str, str, str]:
    planned = scenario["planned_lineage"]
    return (
        planned["session_host"]["image"],
        planned["intermediate"][run_type]["image"],
        planned["final_tool"]["image"],
    )


# ---------------------------------------------------------------------------
# The first Pilot
# ---------------------------------------------------------------------------


def test_first_pilot_policy_approves_the_cmd_lineage() -> None:
    policy = read_approved_lineage_policy(_canonical())

    assert policy.approved_chains == (("wsmprovhost.exe", "cmd.exe", "powershell.exe"),)
    assert policy.family_id == "remote_management"
    assert policy.policy_id
    assert policy.policy_version


def test_first_pilot_policy_is_not_frozen_yet() -> None:
    policy = read_approved_lineage_policy(_canonical())

    assert policy.status == STATUS_PROVISIONAL
    assert policy.frozen is False
    assert policy.frozen_at is None


def test_attack_planned_lineage_of_the_first_pilot_is_the_cscript_lineage() -> None:
    scenario = _canonical()

    assert _planned_chain(scenario, "attack") == (
        "wsmprovhost.exe",
        "cscript.exe",
        "powershell.exe",
    )
    assert _planned_chain(scenario, "normal") == ("wsmprovhost.exe", "cmd.exe", "powershell.exe")


def test_planned_lineage_and_approved_policy_are_separate_blocks() -> None:
    # Given
    scenario = _canonical()

    # Then: two top level blocks, and only the planned one is keyed by run type
    assert "planned_lineage" in scenario
    assert POLICY_KEY in scenario
    assert set(scenario["planned_lineage"]["intermediate"]) == set(RUN_TYPES)
    assert not set(scenario[POLICY_KEY]) & set(LABEL_KEYS)
    assert "lineage" not in scenario

    # And: the planned lineage holds both plans, the policy one approved chain
    policy = read_approved_lineage_policy(scenario)
    assert _planned_chain(scenario, "normal") in policy.approved_chains
    assert _planned_chain(scenario, "attack") not in policy.approved_chains
    assert len(policy.approved_chains) == 1


# ---------------------------------------------------------------------------
# Reading a policy takes no run type and no label
# ---------------------------------------------------------------------------


def test_reader_takes_the_scenario_and_nothing_else() -> None:
    parameters = list(inspect.signature(read_approved_lineage_policy).parameters)

    assert parameters == ["scenario"]


def test_policy_is_the_same_without_the_runs_and_the_planned_lineage() -> None:
    # Given: the canonical scenario, and a copy stripped of everything keyed by
    # run type and of every Ground Truth value
    scenario = _canonical()
    stripped = {POLICY_KEY: copy.deepcopy(scenario[POLICY_KEY])}

    # Then: the policy does not depend on any of it
    assert read_approved_lineage_policy(stripped) == read_approved_lineage_policy(scenario)


@pytest.mark.parametrize("run_type", RUN_TYPES)
def test_policy_does_not_change_with_the_run_being_processed(run_type: str) -> None:
    # Given: the scenario as a reader that knows the run type would see it
    scenario = _canonical()
    seen_by_run = {**scenario, "runs": {run_type: scenario["runs"][run_type]}}

    assert read_approved_lineage_policy(seen_by_run) == read_approved_lineage_policy(scenario)


@pytest.mark.parametrize("key", LABEL_KEYS)
def test_policy_keyed_by_a_run_type_or_a_label_is_refused(key: str) -> None:
    scenario = _policy()
    scenario[POLICY_KEY][key] = [["session_host.exe", "other_middle.exe", "admin_tool.exe"]]

    with pytest.raises(R1LineagePolicyError, match="and nothing else"):
        read_approved_lineage_policy(scenario)


@pytest.mark.parametrize("field", ["policy_id", "policy_version", "family_id"])
@pytest.mark.parametrize("value", ["normal-policy", "ATTACK_v1", "benign", "x-malicious"])
def test_policy_named_after_a_run_type_is_refused(field: str, value: str) -> None:
    with pytest.raises(R1LineagePolicyError, match="must not name a run type"):
        read_approved_lineage_policy(_policy(**{field: value}))


# ---------------------------------------------------------------------------
# What a policy has to state
# ---------------------------------------------------------------------------


def test_valid_policy_is_read_as_stated() -> None:
    policy = read_approved_lineage_policy(_policy())

    assert policy == ApprovedLineagePolicy(
        policy_id="synthetic-approved-lineage",
        policy_version="v0.1",
        family_id="family_x7",
        status=STATUS_PROVISIONAL,
        frozen_at=None,
        approved_chains=(("session_host.exe", "approved_wrapper.exe", "admin_tool.exe"),),
        sha256=policy.sha256,
    )


def test_family_may_approve_more_than_one_chain_of_any_depth() -> None:
    chains = [
        ["session_host.exe", "admin_tool.exe"],
        ["session_host.exe", "wrapper_a.exe", "wrapper_b.exe", "admin_tool.exe"],
    ]

    policy = read_approved_lineage_policy(_policy(approved_chains=chains))

    assert policy.approved_chains == tuple(tuple(chain) for chain in chains)


@pytest.mark.parametrize("scenario", [{}, {POLICY_KEY: None}, {POLICY_KEY: []}, {POLICY_KEY: "x"}])
def test_scenario_without_a_policy_block_is_refused(scenario: dict) -> None:
    with pytest.raises(R1LineagePolicyError, match="must be an object"):
        read_approved_lineage_policy(scenario)


@pytest.mark.parametrize(
    "field",
    ["policy_id", "policy_version", "family_id", "status", "frozen_at", "approved_chains"],
)
def test_policy_missing_a_field_is_refused(field: str) -> None:
    scenario = _policy()
    del scenario[POLICY_KEY][field]

    with pytest.raises(R1LineagePolicyError, match="is missing"):
        read_approved_lineage_policy(scenario)


@pytest.mark.parametrize("field", ["policy_id", "policy_version", "family_id"])
@pytest.mark.parametrize("value", ["", " ", None, 7, " padded", "padded "])
def test_policy_identifier_that_is_not_plain_text_is_refused(field: str, value: object) -> None:
    with pytest.raises(R1LineagePolicyError):
        read_approved_lineage_policy(_policy(**{field: value}))


@pytest.mark.parametrize("status", ["draft", "approved", "", None, "Frozen", ["frozen"]])
def test_unknown_status_is_refused(status: object) -> None:
    with pytest.raises(R1LineagePolicyError, match="status must be one of"):
        read_approved_lineage_policy(_policy(status=status))


@pytest.mark.parametrize("frozen_at", ["2030-01-01T00:00:00Z", "2030-01-01T00:00:00.123Z"])
def test_frozen_policy_states_when_it_was_frozen(frozen_at: str) -> None:
    policy = read_approved_lineage_policy(_policy(status=STATUS_FROZEN, frozen_at=frozen_at))

    assert policy.frozen is True
    assert policy.frozen_at == frozen_at


@pytest.mark.parametrize(
    "frozen_at",
    [
        None,
        "",
        "2030-01-01",
        "2030-01-01Z",
        "2030-01-01T00:00:00",
        "2030-01-01T00:00:00+09:00",
        "2030-01-01T00:00:00+09:00Z",
        "not a timeZ",
        20300101,
    ],
)
def test_frozen_policy_without_a_utc_freeze_time_is_refused(frozen_at: object) -> None:
    with pytest.raises(R1LineagePolicyError, match="frozen_at"):
        read_approved_lineage_policy(_policy(status=STATUS_FROZEN, frozen_at=frozen_at))


def test_provisional_policy_with_a_freeze_time_is_refused() -> None:
    with pytest.raises(R1LineagePolicyError, match="frozen_at must be null"):
        read_approved_lineage_policy(_policy(frozen_at="2030-01-01T00:00:00Z"))


@pytest.mark.parametrize(
    "approved_chains",
    [
        None,
        [],
        "session_host.exe",
        [[]],
        [["admin_tool.exe"]],
        ["session_host.exe", "admin_tool.exe"],
        [["session_host.exe", ""]],
        [["session_host.exe", None]],
        [["session_host.exe", " admin_tool.exe"]],
        [["C:\\Windows\\session_host.exe", "admin_tool.exe"]],
        [["session_host.exe", "bin/admin_tool.exe"]],
        [["session_host.exe", "admin_tool.exe"], ["SESSION_HOST.EXE", "Admin_Tool.exe"]],
        [["session_host.exe", "attack_tool.exe"]],
    ],
)
def test_malformed_approved_chains_are_refused(approved_chains: object) -> None:
    with pytest.raises(R1LineagePolicyError):
        read_approved_lineage_policy(_policy(approved_chains=approved_chains))


# ---------------------------------------------------------------------------
# Following a policy through its freeze
# ---------------------------------------------------------------------------


def test_fingerprint_does_not_depend_on_the_order_of_the_fields() -> None:
    scenario = _policy()
    reordered = {POLICY_KEY: dict(reversed(list(scenario[POLICY_KEY].items())))}

    first = read_approved_lineage_policy(scenario)
    second = read_approved_lineage_policy(reordered)

    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64
    assert set(first.sha256) <= set("0123456789abcdef")


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_version": "v0.2"},
        {"approved_chains": [["session_host.exe", "other_wrapper.exe", "admin_tool.exe"]]},
        {"status": STATUS_FROZEN, "frozen_at": "2030-01-01T00:00:00Z"},
        {"family_id": "family_y1"},
    ],
)
def test_fingerprint_changes_when_the_policy_changes(changes: dict) -> None:
    original = read_approved_lineage_policy(_policy())
    changed = read_approved_lineage_policy(_policy(**changes))

    assert changed.sha256 != original.sha256


def test_policy_error_is_a_value_error() -> None:
    assert issubclass(R1LineagePolicyError, ValueError)
