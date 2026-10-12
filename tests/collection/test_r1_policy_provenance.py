"""The policies a scenario names, resolved through their loaders.

The two registries are replaced by stand-ins here: every policy identity, hash,
path and window below is made up and is not the registered one. The tests at
the end read the registered configuration through the real loaders and are
skipped where those cannot be imported.
"""

import copy
import importlib
from dataclasses import dataclass, replace

import pytest

from incident_awareness.collection import r1_policy_provenance as module
from incident_awareness.collection.r1_policy_provenance import (
    APPROVED_PROVENANCE_FIELDS,
    POLICIES_KEY,
    REFERENCE_PROVENANCE_FIELDS,
    R1PolicyProvenanceError,
    check_policy_provenance,
    resolve_policy_provenance,
)

SYNTHETIC_FAMILY = "wmi_management"
SYNTHETIC_APPROVED_PATH = "configs/synthetic_approved_lineage_policies.yaml"


@dataclass(frozen=True)
class StubApprovedPolicy:
    policy_id: str = "synthetic-approved-lineage"
    version: str = "v9.9"
    family_id: str = SYNTHETIC_FAMILY
    lifecycle: str = "development"
    config_hash: str = "a1" * 32


@dataclass(frozen=True)
class StubReferencePolicy:
    policy_id: str = "synthetic-reference"
    version: str = "synthetic-reference-policy"
    family_id: str = SYNTHETIC_FAMILY
    canonical_path: str = "configs/synthetic_reference_policies.yaml"
    config_hash: str = "b2" * 32
    reference_action_id: str = "A01"
    action_type: str = "wmi_process_create"
    reference_process_name: str = "cmd.exe"
    candidate_start_offset_sec: int = 0
    candidate_window_sec: int = 2
    success_return_value: int = 0
    require_process_id: bool = True
    expected_evaluation_horizon_sec: int = 600


STUB_LOADER_VERSION = "synthetic-loader-v0"


def install_stub_policy_loaders(
    monkeypatch: pytest.MonkeyPatch,
    *,
    approved: StubApprovedPolicy | None = None,
    reference: StubReferencePolicy | None = None,
) -> tuple[StubApprovedPolicy, StubReferencePolicy]:
    """Replace the two registries by one made-up policy each, looked up by identity as the real ones are."""
    approved = approved or StubApprovedPolicy()
    reference = reference or StubReferencePolicy()

    def load_approved(policy_id: str, version: str, family_id: object) -> tuple:
        if (policy_id, version) != (approved.policy_id, approved.version):
            raise ValueError(f"R1 approved lineage policy was not found: {policy_id}/{version}")
        if family_id != approved.family_id:
            raise ValueError("scenario family_id does not match approved policy family_id")
        return approved, SYNTHETIC_APPROVED_PATH

    def load_reference(policy_id: str, version: str) -> tuple:
        if (policy_id, version) != (reference.policy_id, reference.version):
            raise ValueError(f"R1 reference policy was not found: {policy_id}/{version}")
        return reference, STUB_LOADER_VERSION

    monkeypatch.setattr(module, "_load_approved_policy", load_approved)
    monkeypatch.setattr(module, "_load_reference_policy", load_reference)
    return approved, reference


def stub_policy_names() -> dict:
    """The `policies` block of a scenario that names the two made-up policies."""
    return {
        "approved_lineage": {"policy_id": "synthetic-approved-lineage", "version": "v9.9"},
        "reference": {"policy_id": "synthetic-reference"},
    }


def naming_scenario() -> dict:
    """The part of a scenario the resolution reads."""
    return {
        "family_id": SYNTHETIC_FAMILY,
        "run_metadata": {"reference_policy_version": "synthetic-reference-policy"},
        "run_length": {"evaluation_horizon_sec": 600},
        "planned_lineage": {"intermediate": {"attack": {"image": "CMD.exe"}}},
        "runs": {
            "attack": {
                "reference_action_id": "A01",
                "actions": [
                    {"action_id": "A01", "action_type": "wmi_process_create"},
                    {"action_id": "A02", "action_type": "process_create"},
                ],
            }
        },
        POLICIES_KEY: stub_policy_names(),
    }


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_a_scenario_that_names_no_policy_has_no_policy_provenance() -> None:
    scenario = naming_scenario()
    del scenario[POLICIES_KEY]

    assert resolve_policy_provenance(scenario) is None
    assert check_policy_provenance(scenario, None, "policy_provenance") == []
    assert check_policy_provenance(scenario, {"reference": {}}, "policy_provenance") == [
        "policy_provenance must be null: the scenario names no policy"
    ]


def test_every_value_of_the_provenance_is_what_the_loaders_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved, reference = install_stub_policy_loaders(monkeypatch)

    resolved = resolve_policy_provenance(naming_scenario())

    assert sorted(resolved) == ["approved_lineage", "reference"]
    assert sorted(resolved["approved_lineage"]) == sorted(APPROVED_PROVENANCE_FIELDS)
    assert sorted(resolved["reference"]) == sorted(REFERENCE_PROVENANCE_FIELDS)
    assert resolved["approved_lineage"]["config_hash"] == approved.config_hash
    assert resolved["approved_lineage"]["config_path"] == SYNTHETIC_APPROVED_PATH
    assert resolved["approved_lineage"]["lifecycle"] == approved.lifecycle
    assert resolved["reference"]["config_hash"] == reference.config_hash
    assert resolved["reference"]["config_path"] == reference.canonical_path
    assert resolved["reference"]["loader"] == STUB_LOADER_VERSION
    assert resolved["reference"]["candidate_start_offset_sec"] == 0
    assert resolved["reference"]["candidate_window_sec"] == 2
    assert resolved["reference"]["reference_process_name"] == "cmd.exe"


def test_another_registered_value_is_another_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nothing is typed here: a registry that states another window or another
    # hash gives another provenance for the same scenario.
    install_stub_policy_loaders(
        monkeypatch,
        reference=replace(StubReferencePolicy(), candidate_window_sec=5, config_hash="c3" * 32),
    )

    resolved = resolve_policy_provenance(naming_scenario())

    assert resolved["reference"]["candidate_window_sec"] == 5
    assert resolved["reference"]["config_hash"] == "c3" * 32


def _names(path: tuple, value: object):
    def change(scenario: dict) -> None:
        target = scenario
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return change


def _drop(path: tuple):
    def change(scenario: dict) -> None:
        target = scenario
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_names((POLICIES_KEY, "approved_lineage", "policy_id"), "another"), "was not found"),
        (_names((POLICIES_KEY, "approved_lineage", "version"), "v0.0"), "was not found"),
        (_names((POLICIES_KEY, "reference", "policy_id"), "another"), "was not found"),
        (_names(("run_metadata", "reference_policy_version"), "another"), "was not found"),
        (_names(("run_metadata", "reference_policy_version"), None), "must be stated"),
        (_names(("family_id",), "remote_management"), "does not match approved policy family_id"),
        (_names(("runs", "attack", "reference_action_id"), "A02"), "states reference_action_id"),
        (
            _names(("runs", "attack", "actions", 0, "action_type"), "process_create"),
            "states action_type 'wmi_process_create'",
        ),
        (
            _names(("run_length", "evaluation_horizon_sec"), 601),
            "states expected_evaluation_horizon_sec 600",
        ),
        (
            _names(("planned_lineage", "intermediate", "attack", "image"), "wscript.exe"),
            "states reference_process_name 'cmd.exe'",
        ),
        (_names((POLICIES_KEY, "reference", "version"), "typed"), "must state exactly"),
        (_names((POLICIES_KEY, "reference", "config_hash"), "0" * 64), "must state exactly"),
        (_drop((POLICIES_KEY, "approved_lineage", "version")), "must state exactly"),
        (_drop((POLICIES_KEY, "reference")), "must state exactly"),
        (_names((POLICIES_KEY, "approved_lineage", "policy_id"), " padded "), "non-blank string"),
        (_names((POLICIES_KEY, "approved_lineage"), None), "must state exactly"),
    ],
    ids=[
        "an_approved_policy_that_is_not_registered",
        "an_approved_version_that_is_not_registered",
        "a_reference_policy_that_is_not_registered",
        "a_reference_version_that_is_not_registered",
        "no_reference_version",
        "an_approved_policy_of_another_family",
        "another_reference_action",
        "another_action_type",
        "another_horizon",
        "another_program",
        "a_version_typed_twice",
        "a_hash_typed_by_hand",
        "no_approved_version",
        "no_reference_policy",
        "an_identity_with_spaces",
        "no_approved_policy",
    ],
)
def test_a_scenario_that_does_not_fit_the_policies_it_names_is_refused(
    monkeypatch: pytest.MonkeyPatch, change, message: str
) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()
    change(scenario)

    with pytest.raises(R1PolicyProvenanceError, match=message):
        resolve_policy_provenance(scenario)


def test_a_reference_policy_of_another_family_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub_policy_loaders(
        monkeypatch, reference=replace(StubReferencePolicy(), family_id="remote_management")
    )

    with pytest.raises(R1PolicyProvenanceError, match="states family_id 'remote_management'"):
        resolve_policy_provenance(naming_scenario())


# ---------------------------------------------------------------------------
# A recorded provenance is held to the loaders, not to itself
# ---------------------------------------------------------------------------


def test_the_provenance_the_loaders_give_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()

    assert check_policy_provenance(scenario, resolve_policy_provenance(scenario), "p") == []


@pytest.mark.parametrize(
    ("block", "field", "value"),
    [
        ("reference", "config_hash", "0" * 64),
        ("reference", "policy_id", "another"),
        ("reference", "version", "another"),
        ("reference", "config_path", "configs/another.yaml"),
        ("reference", "loader", "another-loader"),
        ("reference", "candidate_window_sec", 3),
        ("reference", "candidate_window_sec", "2"),
        ("reference", "candidate_start_offset_sec", -2),
        ("reference", "candidate_start_offset_sec", False),
        ("reference", "reference_process_name", "wscript.exe"),
        ("reference", "require_process_id", 1),
        ("reference", "success_return_value", None),
        ("approved_lineage", "config_hash", "0" * 64),
        ("approved_lineage", "lifecycle", "frozen"),
        ("approved_lineage", "family_id", "remote_management"),
        ("approved_lineage", "version", "v0.0"),
    ],
)
def test_a_recorded_value_that_is_not_the_registered_one_is_reported(
    monkeypatch: pytest.MonkeyPatch, block: str, field: str, value: object
) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()
    recorded = resolve_policy_provenance(scenario)
    recorded[block][field] = value

    problems = check_policy_provenance(scenario, recorded, "policy_provenance")

    assert len(problems) == 1
    assert problems[0].startswith(f"policy_provenance.{block}.{field} is {value!r}")
    assert "the registered policy states" in problems[0]


def test_a_record_with_another_shape_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()
    intact = resolve_policy_provenance(scenario)

    without_block = {"reference": intact["reference"]}
    assert "must hold exactly" in check_policy_provenance(scenario, without_block, "p")[0]
    assert "must hold exactly" in check_policy_provenance(scenario, None, "p")[0]
    extra_field = copy.deepcopy(intact)
    extra_field["reference"]["approved"] = True
    assert "p.reference must hold exactly" in check_policy_provenance(scenario, extra_field, "p")[0]
    missing_field = copy.deepcopy(intact)
    del missing_field["approved_lineage"]["config_hash"]
    assert (
        "p.approved_lineage must hold exactly"
        in (check_policy_provenance(scenario, missing_field, "p")[0])
    )


def test_a_registry_that_changed_after_the_record_was_written_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()
    recorded = resolve_policy_provenance(scenario)
    # the registered policy is edited: the same identity, another content
    install_stub_policy_loaders(
        monkeypatch, reference=replace(StubReferencePolicy(), config_hash="d4" * 32)
    )

    problems = check_policy_provenance(scenario, recorded, "policy_provenance")

    expected = (
        f"policy_provenance.reference.config_hash is {'b2' * 32!r}, the registered policy "
        f"states {'d4' * 32!r}"
    )
    assert problems == [expected]


def test_a_policy_that_can_no_longer_be_resolved_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_stub_policy_loaders(monkeypatch)
    scenario = naming_scenario()
    recorded = resolve_policy_provenance(scenario)
    install_stub_policy_loaders(
        monkeypatch, reference=replace(StubReferencePolicy(), policy_id="renamed")
    )

    problems = check_policy_provenance(scenario, recorded, "policy_provenance")

    assert len(problems) == 1 and "cannot be resolved" in problems[0]


# ---------------------------------------------------------------------------
# The real loaders and the registered configuration
# ---------------------------------------------------------------------------

TEMPLATE_NAMES = {
    "approved_lineage": {"policy_id": "r1-wmi-management-approved-lineage", "version": "v0.1"},
    "reference": {"policy_id": "r1-wmi-a01-reference"},
}


def _real_loaders():
    """The two loader modules, or a skip where this checkout or interpreter cannot import them."""
    try:
        approved = importlib.import_module(module.APPROVED_LOADER_MODULE)
        reference = importlib.import_module(module.REFERENCE_LOADER_MODULE)
    except (ImportError, SyntaxError) as error:
        pytest.skip(f"the policy loaders cannot be imported here: {type(error).__name__}")
    return approved, reference


def _registered_scenario() -> dict:
    scenario = naming_scenario()
    scenario["run_metadata"]["reference_policy_version"] = "wmi-ref-v0.1"
    scenario[POLICIES_KEY] = copy.deepcopy(TEMPLATE_NAMES)
    return scenario


def test_where_a_loader_cannot_be_imported_no_policy_is_resolved() -> None:
    try:
        importlib.import_module(module.REFERENCE_LOADER_MODULE)
        importlib.import_module(module.APPROVED_LOADER_MODULE)
    except (ImportError, SyntaxError):
        with pytest.raises(R1PolicyProvenanceError, match="cannot be imported here"):
            resolve_policy_provenance(_registered_scenario())
    else:
        pytest.skip("both loaders can be imported here")


def test_the_registered_policies_are_read_through_their_loaders_and_nothing_is_typed() -> None:
    approved_module, reference_module = _real_loaders()

    resolved = resolve_policy_provenance(_registered_scenario())

    reference = reference_module.load_r1_reference_policy("r1-wmi-a01-reference", "wmi-ref-v0.1")
    approved = approved_module.load_r1_approved_lineage_policy(
        "r1-wmi-management-approved-lineage",
        "v0.1",
        config_path=approved_module.DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )
    assert resolved["reference"]["config_hash"] == reference.config_hash
    assert resolved["reference"]["config_path"] == reference.canonical_path
    assert resolved["reference"]["loader"] == reference_module.R1_REFERENCE_POLICY_LOADER_VERSION
    assert resolved["reference"]["candidate_window_sec"] == reference.candidate_window_sec
    assert resolved["reference"]["candidate_start_offset_sec"] == (
        reference.candidate_start_offset_sec
    )
    assert resolved["reference"]["reference_process_name"] == reference.reference_process_name
    assert resolved["approved_lineage"]["config_hash"] == approved.config_hash
    assert resolved["approved_lineage"]["lifecycle"] == approved.lifecycle
    assert resolved["approved_lineage"]["family_id"] == "wmi_management"
    assert check_policy_provenance(_registered_scenario(), resolved, "policy_provenance") == []


def test_the_registered_reference_policy_is_refused_for_another_family() -> None:
    _real_loaders()
    scenario = _registered_scenario()
    scenario["family_id"] = "remote_management"

    with pytest.raises(R1PolicyProvenanceError):
        resolve_policy_provenance(scenario)
