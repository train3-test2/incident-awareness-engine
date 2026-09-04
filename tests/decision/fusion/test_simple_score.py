import pytest

from incident_awareness.decision.fusion.simple_score import SimpleScorer


def test_uses_fixed_profile_denominator() -> None:
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    assert scorer.denominator == 4


def test_rejects_empty_profile() -> None:
    with pytest.raises(
        ValueError,
        match="evidence_types must not be empty",
    ):
        SimpleScorer([])


def test_rejects_duplicate_profile_types() -> None:
    with pytest.raises(
        ValueError,
        match="evidence_types must not contain duplicates",
    ):
        SimpleScorer(["type_a", "type_a"])
