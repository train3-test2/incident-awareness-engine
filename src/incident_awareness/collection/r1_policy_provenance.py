"""Which registered policies an R1 scenario names, resolved through their loaders.

A scenario may name two policies next to its collection profile:

    policies:
      approved_lineage:
        policy_id: <id in the family-bound approved lineage registry>
        version: <its version>
      reference:
        policy_id: <id in the reference policy registry>

The version of the reference policy is the one the scenario already states as
`run_metadata.reference_policy_version`: it is not stated twice.

Nothing about a policy is written down here. Its identity, its hash and the
values a run needs from it are read from the canonical configuration through
the loader of each registry, when a scenario is rendered. The result is put into
the rendered scenario as `policy_provenance`, the runner copies it into the
collection provenance of each run, and a validator resolves the same names
again and holds both copies to what the loaders say then. A value that was
typed by hand, or a configuration that changed after rendering, does not match.

An approved lineage policy is only named and identified. Which lineage it
approves is not read here and is not compared with the planned lineage of the
scenario: the plan says what a run leaves, the policy says what an evaluation
accepts, and collection keeps the two apart.

A scenario that states no `policies` block has no `policy_provenance`, as every
scenario before this module.
"""

from pathlib import Path
from typing import Protocol

POLICIES_KEY = "policies"
POLICY_PROVENANCE_KEY = "policy_provenance"
APPROVED_LOADER_MODULE = "incident_awareness.evidence.r1_approved_lineage_policy"
APPROVED_LOADER_NAME = "load_r1_approved_lineage_policy"
REFERENCE_LOADER_MODULE = "incident_awareness.evidence.r1_reference_policy"

_POLICIES_KEYS = ("approved_lineage", "reference")
_APPROVED_KEYS = ("policy_id", "version")
_REFERENCE_KEYS = ("policy_id",)
APPROVED_PROVENANCE_FIELDS = (
    "policy_id",
    "version",
    "family_id",
    "lifecycle",
    "config_path",
    "config_hash",
    "loader",
)
REFERENCE_PROVENANCE_FIELDS = (
    "policy_id",
    "version",
    "family_id",
    "config_path",
    "config_hash",
    "loader",
    "reference_action_id",
    "action_type",
    "reference_process_name",
    "candidate_start_offset_sec",
    "candidate_window_sec",
    "success_return_value",
    "require_process_id",
    "expected_evaluation_horizon_sec",
)
_REPOSITORY_ROOT = Path(__file__).parents[3]


class R1PolicyProvenanceError(ValueError):
    """Raised when a scenario names a policy that cannot be resolved or does not fit it."""


class _ReferencePolicy(Protocol):
    policy_id: str
    version: str
    family_id: str
    canonical_path: str
    config_hash: str
    reference_action_id: str
    action_type: str
    reference_process_name: str
    candidate_start_offset_sec: int
    candidate_window_sec: int
    success_return_value: int
    require_process_id: bool
    expected_evaluation_horizon_sec: int


class _ApprovedPolicy(Protocol):
    policy_id: str
    version: str
    family_id: str | None
    lifecycle: str | None
    config_hash: str


# The two loaders are imported where they are called. A scenario that names no
# policy needs neither, and is rendered and validated without them; a checkout
# or an interpreter that cannot import a loader resolves no policy with it, and
# nothing stands in for the loader.


def _load_approved_policy(
    policy_id: str, version: str, family_id: object
) -> tuple[_ApprovedPolicy, str]:
    """The family-bound approved lineage policy with this identity, and where it is registered."""
    try:
        from incident_awareness.evidence import r1_approved_lineage_policy as registry
    except (ImportError, SyntaxError) as error:
        raise R1PolicyProvenanceError(
            f"the approved lineage policy loader ({APPROVED_LOADER_MODULE}) cannot be imported "
            f"here, so the policy {policy_id}/{version} cannot be read: {error}"
        ) from error
    path = registry.DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH
    policy = registry.load_r1_approved_lineage_policy(policy_id, version, config_path=path)
    registry.validate_r1_policy_family_binding(family_id, policy)
    return policy, _repository_path(path)


def _load_reference_policy(policy_id: str, version: str) -> tuple[_ReferencePolicy, str]:
    """The reference policy with this identity and the version of the loader that read it."""
    try:
        from incident_awareness.evidence import r1_reference_policy as registry
    except (ImportError, SyntaxError) as error:
        raise R1PolicyProvenanceError(
            f"the reference policy loader ({REFERENCE_LOADER_MODULE}) cannot be imported here, "
            f"so the reference policy {policy_id}/{version} cannot be read: {error}"
        ) from error
    policy = registry.load_r1_reference_policy(policy_id, version)
    return policy, registry.R1_REFERENCE_POLICY_LOADER_VERSION


def _block(value: object, label: str, keys: tuple[str, ...], *, strings: bool = True) -> dict:
    if not isinstance(value, dict) or sorted(value) != sorted(keys):
        raise R1PolicyProvenanceError(f"{label} must state exactly {list(keys)}")
    for key in keys if strings else ():
        stated = value[key]
        if not isinstance(stated, str) or not stated.strip() or stated != stated.strip():
            raise R1PolicyProvenanceError(f"{label}.{key} must be a non-blank string")
    return value


def _repository_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(_REPOSITORY_ROOT.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _attack_reference(scenario: dict) -> tuple[object, object]:
    """The reference action an attack run names, and the action type of that action."""
    runs = scenario.get("runs")
    attack = runs.get("attack") if isinstance(runs, dict) else None
    stated = attack.get("reference_action_id") if isinstance(attack, dict) else None
    actions = attack.get("actions") if isinstance(attack, dict) else None
    types = [
        action.get("action_type")
        for action in (actions if isinstance(actions, list) else [])
        if isinstance(action, dict) and action.get("action_id") == stated
    ]
    return stated, (types[0] if len(types) == 1 else None)


def resolve_policy_provenance(scenario: dict) -> dict | None:
    """The provenance of the policies a scenario names, or None when it names none.

    Raises `R1PolicyProvenanceError` when a named policy is not registered, is
    bound to another family, or states a version, a reference action, an action
    type or an evaluation horizon the scenario does not state.
    """
    if POLICIES_KEY not in scenario:
        return None
    stated = _block(scenario[POLICIES_KEY], POLICIES_KEY, _POLICIES_KEYS, strings=False)
    approved_stated = _block(
        stated["approved_lineage"], f"{POLICIES_KEY}.approved_lineage", _APPROVED_KEYS
    )
    reference_stated = _block(stated["reference"], f"{POLICIES_KEY}.reference", _REFERENCE_KEYS)
    family_id = scenario.get("family_id")

    try:
        approved, approved_path = _load_approved_policy(
            approved_stated["policy_id"], approved_stated["version"], family_id
        )
    except R1PolicyProvenanceError:
        raise
    except (ValueError, TypeError, OSError) as error:
        raise R1PolicyProvenanceError(
            f"{POLICIES_KEY}.approved_lineage cannot be used: {error}"
        ) from error

    run_metadata = scenario.get("run_metadata")
    version = (
        run_metadata.get("reference_policy_version") if isinstance(run_metadata, dict) else None
    )
    if not isinstance(version, str) or not version.strip():
        raise R1PolicyProvenanceError(
            "run_metadata.reference_policy_version must be stated when a reference policy is named"
        )
    try:
        reference, loader_version = _load_reference_policy(reference_stated["policy_id"], version)
    except R1PolicyProvenanceError:
        raise
    except (ValueError, TypeError, OSError) as error:
        raise R1PolicyProvenanceError(
            f"{POLICIES_KEY}.reference cannot be used: {error}"
        ) from error

    reference_action, reference_action_type = _attack_reference(scenario)
    run_length = scenario.get("run_length")
    horizon = run_length.get("evaluation_horizon_sec") if isinstance(run_length, dict) else None
    # The record the policy takes the reference from is the process-create record
    # of a program. It has to be the program the attack run is planned to start.
    lineage = scenario.get("planned_lineage")
    intermediate = lineage.get("intermediate") if isinstance(lineage, dict) else None
    attack = intermediate.get("attack") if isinstance(intermediate, dict) else None
    planned = attack.get("image") if isinstance(attack, dict) else None
    planned_name = planned.casefold() if isinstance(planned, str) else planned
    for label, policy_value, scenario_value in (
        ("family_id", reference.family_id, family_id),
        ("reference_action_id", reference.reference_action_id, reference_action),
        ("action_type", reference.action_type, reference_action_type),
        ("expected_evaluation_horizon_sec", reference.expected_evaluation_horizon_sec, horizon),
        ("reference_process_name", reference.reference_process_name.casefold(), planned_name),
    ):
        if policy_value != scenario_value:
            raise R1PolicyProvenanceError(
                f"the reference policy {reference.policy_id}/{reference.version} states {label} "
                f"{policy_value!r}, the scenario states {scenario_value!r}"
            )

    return {
        "approved_lineage": {
            "policy_id": approved.policy_id,
            "version": approved.version,
            "family_id": approved.family_id,
            "lifecycle": approved.lifecycle,
            "config_path": approved_path,
            "config_hash": approved.config_hash,
            "loader": APPROVED_LOADER_NAME,
        },
        "reference": {
            "policy_id": reference.policy_id,
            "version": reference.version,
            "family_id": reference.family_id,
            "config_path": reference.canonical_path,
            "config_hash": reference.config_hash,
            "loader": loader_version,
            "reference_action_id": reference.reference_action_id,
            "action_type": reference.action_type,
            "reference_process_name": reference.reference_process_name,
            "candidate_start_offset_sec": reference.candidate_start_offset_sec,
            "candidate_window_sec": reference.candidate_window_sec,
            "success_return_value": reference.success_return_value,
            "require_process_id": reference.require_process_id,
            "expected_evaluation_horizon_sec": reference.expected_evaluation_horizon_sec,
        },
    }


def check_policy_provenance(scenario: dict, recorded: object, label: str) -> list[str]:
    """What is wrong with a recorded policy provenance. An empty list when nothing is.

    `recorded` is the `policy_provenance` a rendered scenario or a collection
    provenance carries. The names the scenario states are resolved again, through
    the loaders, and the record has to be exactly that: no value is taken from
    the record itself.
    """
    if POLICIES_KEY not in scenario:
        if recorded is not None:
            return [f"{label} must be null: the scenario names no policy"]
        return []
    try:
        expected = resolve_policy_provenance(scenario)
    except R1PolicyProvenanceError as error:
        return [f"the policies the scenario names cannot be resolved: {error}"]
    if not isinstance(recorded, dict) or sorted(recorded) != sorted(_POLICIES_KEYS):
        return [f"{label} must hold exactly {list(_POLICIES_KEYS)}"]

    problems: list[str] = []
    for name, fields in (
        ("approved_lineage", APPROVED_PROVENANCE_FIELDS),
        ("reference", REFERENCE_PROVENANCE_FIELDS),
    ):
        block = recorded[name]
        if not isinstance(block, dict) or sorted(block) != sorted(fields):
            problems.append(f"{label}.{name} must hold exactly {list(fields)}")
            continue
        problems += [
            f"{label}.{name}.{field} is {block[field]!r}, the registered policy states "
            f"{expected[name][field]!r}"
            for field in fields
            if block[field] != expected[name][field]
            or type(block[field]) is not type(expected[name][field])
        ]
    return problems
