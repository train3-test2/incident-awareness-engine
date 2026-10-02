"""The identity of an R1 Pair: family, variation and repetition.

The values used here are synthetic. They are not the families of any planned
data set.
"""

import pytest

from incident_awareness.collection.r1_pair_identity import (
    LABEL_WORDS,
    R1PairIdentity,
    R1PairIdentityError,
    exposed_label_word,
    read_pair_identity,
    validate_family_id,
    validate_repetition,
    validate_variation_id,
)


@pytest.mark.parametrize("value", ["remote_management", "family_x7", "F1", "holdout-b", "a"])
def test_family_id_accepts_any_non_empty_text(value: str) -> None:
    assert validate_family_id(value) == value


@pytest.mark.parametrize("value", ["V02", "v1", "V09", "lineage-axis"])
def test_variation_id_accepts_any_non_empty_text(value: str) -> None:
    assert validate_variation_id(value) == value


@pytest.mark.parametrize("value", ["", " ", "\t", None, 7, 1.5, True, ["family"], {"id": "family"}])
def test_identifier_that_is_not_non_empty_text_is_refused(value: object) -> None:
    with pytest.raises(R1PairIdentityError, match="must be a non-empty string"):
        validate_family_id(value)
    with pytest.raises(R1PairIdentityError, match="must be a non-empty string"):
        validate_variation_id(value)


@pytest.mark.parametrize("value", [" family", "family ", "\tfamily", "family\n"])
def test_identifier_with_surrounding_whitespace_is_refused(value: str) -> None:
    with pytest.raises(R1PairIdentityError, match="surrounding whitespace"):
        validate_family_id(value)
    with pytest.raises(R1PairIdentityError, match="surrounding whitespace"):
        validate_variation_id(value)


@pytest.mark.parametrize(
    ("value", "word"),
    [
        ("normal", "normal"),
        ("attack_family", "attack"),
        ("V02-Normal", "normal"),
        ("ATTACK2", "attack"),
        ("benign-set", "benign"),
        ("x_malicious", "malicious"),
        ("abnormal_lineage", "normal"),
    ],
)
def test_identifier_that_contains_a_label_word_is_refused(value: str, word: str) -> None:
    # A label word is found wherever it sits and whatever its case
    assert exposed_label_word(value) == word
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_family_id(value)
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_variation_id(value)


def test_label_words_cover_both_run_types() -> None:
    assert "normal" in LABEL_WORDS
    assert "attack" in LABEL_WORDS
    assert exposed_label_word("remote_management") is None


@pytest.mark.parametrize("value", [1, 2, 3, 5, 100])
def test_repetition_accepts_an_integer_of_one_or_more(value: int) -> None:
    assert validate_repetition(value) == value


@pytest.mark.parametrize("value", [0, -1, -5])
def test_repetition_below_one_is_refused(value: int) -> None:
    with pytest.raises(R1PairIdentityError, match="repetition must be 1 or more"):
        validate_repetition(value)


@pytest.mark.parametrize("value", [1.0, 1.5, "1", "one", True, False, None, [1]])
def test_repetition_that_is_not_an_integer_is_refused(value: object) -> None:
    with pytest.raises(R1PairIdentityError, match="repetition must be an integer of 1 or more"):
        validate_repetition(value)


def test_identity_is_read_from_the_top_level_of_a_scenario() -> None:
    scenario = {"family_id": "family_x7", "variation_id": "V09", "repetition": 4, "runs": {}}

    assert read_pair_identity(scenario) == R1PairIdentity(
        family_id="family_x7", variation_id="V09", repetition=4
    )


@pytest.mark.parametrize("missing", ["family_id", "variation_id", "repetition"])
def test_scenario_that_does_not_state_all_three_values_is_refused(missing: str) -> None:
    scenario = {"family_id": "family_x7", "variation_id": "V09", "repetition": 4}
    del scenario[missing]

    with pytest.raises(R1PairIdentityError, match=missing):
        read_pair_identity(scenario)


def test_identity_error_is_a_value_error() -> None:
    # Callers that validate inputs catch ValueError, as they do for the destination.
    assert issubclass(R1PairIdentityError, ValueError)
