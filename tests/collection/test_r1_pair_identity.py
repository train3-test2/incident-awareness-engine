"""The identity of an R1 Pair: family, variation and repetition.

The values used here are synthetic. They are not the families of any planned
data set.
"""

import json
import re
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Korean labels, and the list shared with the PowerShell runner
# ---------------------------------------------------------------------------

LABEL_CASES = Path("scenarios/R1/tests/label_shortcut_cases.json")
RUN_COMMON = Path("scenarios/R1/run-common.ps1")


def _shared() -> dict:
    """The case table the PowerShell guard reads as well."""
    return json.loads(LABEL_CASES.read_text(encoding="ascii"))


def _powershell_label_words() -> list[str]:
    """The words of `$R1_LABEL_WORDS`, read from the PowerShell source without running it.

    The runner is ASCII only, so it writes a Korean word as the code points of
    its characters; those are turned back into the word here.
    """
    source = RUN_COMMON.read_text(encoding="ascii")
    block = re.search(r"^\$R1_LABEL_WORDS = @\(\n(.*?)^\)\n", source, re.DOTALL | re.MULTILINE)
    assert block is not None

    words: list[str] = []
    for token in re.finditer(r'"([^"]*)"|\(-join \[char\[\]\]\(([^)]*)\)\)', block.group(1)):
        if token.group(1) is not None:
            words.append(token.group(1))
        else:
            words.append("".join(chr(int(code, 16)) for code in token.group(2).split(",")))
    return words


@pytest.mark.parametrize("label", ["정상", "공격", "악성"])
def test_korean_label_is_refused_as_a_family_and_as_a_variation(label: str) -> None:
    assert exposed_label_word(label) == label
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_family_id(label)
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_variation_id(label)
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        read_pair_identity({"family_id": label, "variation_id": "V02", "repetition": 1})
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        read_pair_identity({"family_id": "family_x7", "variation_id": label, "repetition": 1})


@pytest.mark.parametrize(
    ("value", "word"),
    [
        ("정상_family", "정상"),
        ("V02-공격", "공격"),
        ("r1_악성_set", "악성"),
        ("비정상", "정상"),
        ("공격자", "공격"),
    ],
)
def test_identifier_that_contains_a_korean_label_is_refused(value: str, word: str) -> None:
    # A Korean label is found wherever it sits, as an English one is
    assert exposed_label_word(value) == word
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_family_id(value)
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        validate_variation_id(value)


@pytest.mark.parametrize(
    "value", ["원격관리", "관리도구_V02", "실험군A", "상정", "성악", "정 상", "정규", "공개"]
)
def test_korean_identifier_without_a_label_is_accepted(value: str) -> None:
    # The check refuses three words, not Korean text
    assert exposed_label_word(value) is None
    assert validate_family_id(value) == value
    assert validate_variation_id(value) == value
    assert read_pair_identity(
        {"family_id": value, "variation_id": value, "repetition": 2}
    ) == R1PairIdentity(value, value, 2)


def test_label_words_are_the_shared_list() -> None:
    shared = _shared()["label_words"]

    assert list(LABEL_WORDS) == shared
    assert shared[4:] == ["정상", "공격", "악성"]


def test_powershell_runner_holds_the_same_label_words_in_the_same_order() -> None:
    # Read from the source, so the ubuntu job notices a change on either side
    # even though it cannot run Windows PowerShell.
    assert _powershell_label_words() == list(LABEL_WORDS)
    assert _powershell_label_words() == _shared()["label_words"]


def test_shared_label_cases_hold_on_the_python_side() -> None:
    # The PowerShell guard checks Get-R1ExposedLabelWord against the same cases.
    cases = _shared()["cases"]
    assert len(cases) >= 20
    assert any(case["word"] is None for case in cases)

    for case in cases:
        value, word = case["value"], case["word"]
        assert exposed_label_word(value) == word, case["note"]
        if word is None:
            assert validate_family_id(value) == value, case["note"]
            assert validate_variation_id(value) == value, case["note"]
        else:
            with pytest.raises(R1PairIdentityError, match="would expose the run type"):
                validate_family_id(value)
            with pytest.raises(R1PairIdentityError, match="would expose the run type"):
                validate_variation_id(value)


def test_shared_label_cases_file_is_ascii() -> None:
    # Windows PowerShell 5.1 reads it too; Korean is written as escapes.
    raw = LABEL_CASES.read_bytes()

    assert raw.isascii()
    assert not raw.startswith(b"\xef\xbb\xbf")


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
