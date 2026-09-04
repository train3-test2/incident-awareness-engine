import pytest

from incident_awareness.decision.fusion.simple_score import SimpleScorer


def test_uses_fixed_profile_denominator() -> None:
    # Given
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    # When
    denominator = scorer.denominator

    # Then
    assert denominator == 4


def test_rejects_empty_profile() -> None:
    # Given
    evidence_types: list[str] = []

    # When
    with pytest.raises(ValueError) as exc_info:
        SimpleScorer(evidence_types)

    # Then
    assert str(exc_info.value) == "evidence_types must not be empty"


def test_rejects_duplicate_profile_types() -> None:
    # Given
    evidence_types = ["type_a", "type_a"]

    # When
    with pytest.raises(ValueError) as exc_info:
        SimpleScorer(evidence_types)

    # Then
    assert str(exc_info.value) == "evidence_types must not contain duplicates"
