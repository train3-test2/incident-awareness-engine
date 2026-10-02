"""The approved lineage policy of one R1 family.

A rendered R1 scenario says two different things about process lineage and this
module reads only one of them.

- `planned_lineage` is what each run is planned to execute. It is selected by
  run type and belongs to the runner and to the collection validator, which
  checks that a run left the lineage it was planned to leave.
- `approved_lineage_policy` is the lineage approved for the family before any
  run of that family is evaluated. It is one block per family. Nothing in it is
  keyed by a run type or a label, and reading it takes neither.

The policy is what a later Evidence extractor compares the lineage it actually
observes with. This module only reads and checks the block; it compares nothing,
builds no Evidence and produces no Fusion input. Process names appear here as
policy data of one family. They are not a rule for telling runs apart, and they
are not handed to Fusion.

A policy carries an identifier, a version and a status so that its freeze can be
followed: `provisional` until it is frozen, `frozen` with the time of the freeze
afterwards. A policy has to be frozen before any Test Run of its family is
looked at, a hold-out family included. `sha256` fingerprints the block as it was
read, so a policy that changed after a run was made can be told from the one
the run was made under.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from incident_awareness.collection.r1_pair_identity import exposed_label_word

POLICY_KEY = "approved_lineage_policy"
STATUS_PROVISIONAL = "provisional"
STATUS_FROZEN = "frozen"
STATUSES = (STATUS_PROVISIONAL, STATUS_FROZEN)

_FIELDS = ("policy_id", "policy_version", "family_id", "status", "frozen_at", "approved_chains")
_MIN_CHAIN_LENGTH = 2
_PATH_SEPARATORS = ("/", "\\")


class R1LineagePolicyError(ValueError):
    """Raised when a scenario carries no usable approved lineage policy."""


@dataclass(frozen=True)
class ApprovedLineagePolicy:
    """One family's approved lineage, as stated in a rendered scenario.

    Each chain lists Image file names from the remote session host down to the
    final tool, the order the processes are started in.
    """

    policy_id: str
    policy_version: str
    family_id: str
    status: str
    frozen_at: str | None
    approved_chains: tuple[tuple[str, ...], ...]
    sha256: str

    @property
    def frozen(self) -> bool:
        return self.status == STATUS_FROZEN


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise R1LineagePolicyError(f"{POLICY_KEY}.{name} must be a non-empty string")
    if value != value.strip():
        raise R1LineagePolicyError(f"{POLICY_KEY}.{name} must not have surrounding whitespace")

    word = exposed_label_word(value)
    if word is not None:
        raise R1LineagePolicyError(
            f"{POLICY_KEY}.{name} must not name a run type: {value!r} contains {word!r}"
        )

    return value


def _frozen_at(value: object, status: str) -> str | None:
    if status == STATUS_PROVISIONAL:
        if value is not None:
            raise R1LineagePolicyError(
                f"{POLICY_KEY}.frozen_at must be null while the policy is {STATUS_PROVISIONAL}"
            )
        return None

    # A string, so that it survives YAML and JSON unchanged, and UTC by its 'Z'.
    if not isinstance(value, str) or not value.endswith("Z") or "T" not in value:
        raise R1LineagePolicyError(
            f"{POLICY_KEY}.frozen_at must be the UTC date and time of the freeze as text "
            "ending in 'Z'"
        )
    try:
        moment = datetime.fromisoformat(value.removesuffix("Z"))
    except ValueError as error:
        raise R1LineagePolicyError(
            f"{POLICY_KEY}.frozen_at is not an ISO 8601 time: {value!r}"
        ) from error
    if moment.tzinfo is not None:
        raise R1LineagePolicyError(
            f"{POLICY_KEY}.frozen_at must carry no offset besides its 'Z': {value!r}"
        )

    return value


def _chains(value: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, list) or not value:
        raise R1LineagePolicyError(f"{POLICY_KEY}.approved_chains must be a non-empty list")

    chains: list[tuple[str, ...]] = []
    for index, raw_chain in enumerate(value):
        name = f"approved_chains[{index}]"
        if not isinstance(raw_chain, list) or len(raw_chain) < _MIN_CHAIN_LENGTH:
            raise R1LineagePolicyError(
                f"{POLICY_KEY}.{name} must list at least {_MIN_CHAIN_LENGTH} Images, from the "
                "session host down to the final tool"
            )

        chain = tuple(_text(image, f"{name}[{step}]") for step, image in enumerate(raw_chain))
        for image in chain:
            if any(separator in image for separator in _PATH_SEPARATORS):
                raise R1LineagePolicyError(
                    f"{POLICY_KEY}.{name} must hold Image file names, not paths: {image!r}"
                )
        chains.append(chain)

    lowered = [tuple(image.lower() for image in chain) for chain in chains]
    if len(set(lowered)) != len(lowered):
        raise R1LineagePolicyError(f"{POLICY_KEY}.approved_chains repeats a chain")

    return tuple(chains)


def read_approved_lineage_policy(scenario: Mapping[str, object]) -> ApprovedLineagePolicy:
    """Read the approved lineage policy of the family a scenario was rendered for.

    The scenario is the only input. No run type, no label and no Ground Truth is
    asked for, and the block may hold nothing but the fields of a policy, so
    there is nowhere in it to key anything by run type.
    """
    block = scenario.get(POLICY_KEY)
    if not isinstance(block, Mapping):
        raise R1LineagePolicyError(f"{POLICY_KEY} must be an object")

    missing = [name for name in _FIELDS if name not in block]
    if missing:
        raise R1LineagePolicyError(f"{POLICY_KEY} is missing {sorted(missing)}")
    unknown = sorted(str(name) for name in block if name not in _FIELDS)
    if unknown:
        raise R1LineagePolicyError(
            f"{POLICY_KEY} holds {unknown}; a policy is {list(_FIELDS)} and nothing else"
        )

    status = block["status"]
    if status not in STATUSES:
        raise R1LineagePolicyError(
            f"{POLICY_KEY}.status must be one of {list(STATUSES)}, found {status!r}"
        )

    policy_id = _text(block["policy_id"], "policy_id")
    policy_version = _text(block["policy_version"], "policy_version")
    family_id = _text(block["family_id"], "family_id")
    frozen_at = _frozen_at(block["frozen_at"], status)
    approved_chains = _chains(block["approved_chains"])

    # Every value is checked text by now, so the block serialises the same way
    # wherever it is read.
    canonical = json.dumps(block, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return ApprovedLineagePolicy(
        policy_id=policy_id,
        policy_version=policy_version,
        family_id=family_id,
        status=status,
        frozen_at=frozen_at,
        approved_chains=approved_chains,
        sha256=hashlib.sha256(canonical.encode("ascii")).hexdigest(),
    )


__all__ = [
    "POLICY_KEY",
    "STATUSES",
    "STATUS_FROZEN",
    "STATUS_PROVISIONAL",
    "ApprovedLineagePolicy",
    "R1LineagePolicyError",
    "read_approved_lineage_policy",
]
