"""The identity of one R1 Pair - family, variation and repetition - and its dataset tier.

R1 data is planned and split by family. Development and hold-out sets are made
of whole families, a repetition is another Pair of the same family and never
stands in for an independent family, and the Events of one Run are never shared
between the sets. A Run therefore has to say which family, which variation and
which repetition it belongs to, and the two runs of a Pair have to say the same.

`RunMetadata` already carries the three values, so no contract changes. A
rendered R1 scenario states them once, at its top level, for both runs of the
Pair it was rendered for. The runner writes them to RunMetadata unchanged and
the validator compares the two. They are Ground Truth bookkeeping: nothing here
is handed to Evidence extraction or to Fusion.

The values must not give the run type away. Both runs of a Pair carry the same
three values, so a label in one of them could only mislead; a family or a
variation named after a label is refused.

The dataset tier of a Pair is stated the same way: once, at the top level of the
rendered scenario, for both runs. It says which pool the Pair belongs to
(`scenarios/R1/README.md` section 1-3). No contract has a field for it, so the
runner writes it to the operator trace of each run and the validator compares
the trace with the scenario. A run has no way to state its own tier.
"""

from collections.abc import Mapping
from dataclasses import dataclass

# Words that would give the run type away. The same list guards everything the
# runner puts in front of Sysmon on Target-A.
#
# The labels are refused in English and in Korean (normal, attack, malicious),
# because the project writes them in both. `$R1_LABEL_WORDS` in
# scenarios/R1/run-common.ps1 is the same list in the same order, and both are
# checked against scenarios/R1/tests/label_shortcut_cases.json so that one side
# cannot change without the other.
LABEL_WORDS = ("normal", "attack", "benign", "malicious", "정상", "공격", "악성")

# The pool a Pair belongs to. `$R1_DATASET_TIERS` in scenarios/R1/run-common.ps1
# is the same list in the same order. A rehearsal is never part of a formal pool:
# its scenario states the first one.
DATASET_TIERS = ("pilot", "development", "holdout")
REHEARSAL_DATASET_TIER = "pilot"


class R1PairIdentityError(ValueError):
    """Raised when a family, a variation, a repetition or a dataset tier of a Pair is not usable."""


@dataclass(frozen=True)
class R1PairIdentity:
    """What both runs of one Pair record in RunMetadata."""

    family_id: str
    variation_id: str
    repetition: int


def exposed_label_word(value: str) -> str | None:
    """The label word a value contains, compared without case, or None.

    A word counts wherever it stands in the value, so a longer word that holds a
    label is refused as well. The first word of `LABEL_WORDS` that is found is
    the one returned.
    """
    lowered = value.lower()
    for word in LABEL_WORDS:
        if word in lowered:
            return word
    return None


def _validate_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise R1PairIdentityError(f"{name} must be a non-empty string, found {value!r}")
    if value != value.strip():
        raise R1PairIdentityError(f"{name} must not have surrounding whitespace: {value!r}")

    word = exposed_label_word(value)
    if word is not None:
        raise R1PairIdentityError(f"{name} would expose the run type: {value!r} contains {word!r}")

    return value


def validate_family_id(value: object) -> str:
    """Return the family a Pair belongs to, or raise."""
    return _validate_identifier(value, "family_id")


def validate_variation_id(value: object) -> str:
    """Return the variation a Pair belongs to, or raise."""
    return _validate_identifier(value, "variation_id")


def validate_repetition(value: object) -> int:
    """Return which Pair of its family this is: an integer of 1 or more.

    A boolean, a float and a numeric string are refused even when they would
    convert, so the value is written to RunMetadata exactly as it was stated.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise R1PairIdentityError(f"repetition must be an integer of 1 or more, found {value!r}")
    if value < 1:
        raise R1PairIdentityError(f"repetition must be 1 or more, found {value}")
    return value


def read_pair_identity(scenario: Mapping[str, object]) -> R1PairIdentity:
    """Read the three values from a rendered scenario. All of them must be stated."""
    return R1PairIdentity(
        family_id=validate_family_id(scenario.get("family_id")),
        variation_id=validate_variation_id(scenario.get("variation_id")),
        repetition=validate_repetition(scenario.get("repetition")),
    )


def validate_dataset_tier(value: object) -> str:
    """Return the dataset tier of a Pair: exactly one of `DATASET_TIERS`.

    The comparison is exact. `Pilot`, ` development` and an empty string are not
    tiers, and nothing stands in for a value that is missing.
    """
    if not isinstance(value, str) or value not in DATASET_TIERS:
        raise R1PairIdentityError(
            f"dataset_tier must be one of {list(DATASET_TIERS)}, found {value!r}"
        )
    return value


def read_dataset_tier(scenario: Mapping[str, object]) -> str:
    """Read the tier a rendered scenario states for its Pair. It must be stated."""
    return validate_dataset_tier(scenario.get("dataset_tier"))


__all__ = [
    "DATASET_TIERS",
    "LABEL_WORDS",
    "REHEARSAL_DATASET_TIER",
    "R1PairIdentity",
    "R1PairIdentityError",
    "exposed_label_word",
    "read_dataset_tier",
    "read_pair_identity",
    "validate_dataset_tier",
    "validate_family_id",
    "validate_repetition",
    "validate_variation_id",
]
