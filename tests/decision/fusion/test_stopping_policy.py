from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.decision.fusion.stopping_policy import (
    ScorePoint,
    ThresholdStoppingPolicy,
)


def make_point(
    seconds: int,
    score: float,
) -> ScorePoint:
    start = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    return ScorePoint(
        timestamp=start + timedelta(seconds=seconds),
        score=score,
    )


def test_detects_after_k_consecutive_scores_above_threshold() -> None:
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=3,
    )

    trajectory = [
        make_point(0, 0.73),
        make_point(10, 0.78),
        make_point(20, 0.81),
    ]

    result = policy.evaluate(trajectory)

    assert result.fusion_status == "detected"
    assert result.fusion_time == trajectory[2].timestamp
    assert result.score_at_decision == 0.81


def test_resets_persistence_when_score_falls_below_threshold() -> None:
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=3,
    )

    trajectory = [
        make_point(0, 0.73),
        make_point(10, 0.78),
        make_point(20, 0.60),
        make_point(30, 0.81),
        make_point(40, 0.82),
        make_point(50, 0.83),
    ]

    result = policy.evaluate(trajectory)

    assert result.fusion_status == "detected"
    assert result.fusion_time == trajectory[5].timestamp


def test_returns_miss_when_condition_is_never_satisfied() -> None:
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=3,
    )

    trajectory = [
        make_point(0, 0.50),
        make_point(10, 0.72),
        make_point(20, 0.60),
        make_point(30, 0.75),
    ]

    result = policy.evaluate(trajectory)

    assert result.fusion_status == "miss"
    assert result.fusion_time is None
    assert result.score_at_decision is None


def test_same_input_produces_same_fusion_time() -> None:
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=3,
    )

    trajectory = [
        make_point(0, 0.71),
        make_point(10, 0.72),
        make_point(20, 0.73),
    ]

    first = policy.evaluate(trajectory)
    second = policy.evaluate(trajectory)

    assert first == second


def test_rejects_out_of_order_score_points() -> None:
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=2,
    )

    trajectory = [
        make_point(10, 0.8),
        make_point(0, 0.8),
    ]

    with pytest.raises(
        ValueError,
        match="ScorePoint timestamps must be non-decreasing",
    ):
        policy.evaluate(trajectory)


def test_rejects_invalid_threshold() -> None:
    with pytest.raises(
        ValueError,
        match="threshold_on must be between",
    ):
        ThresholdStoppingPolicy(
            threshold_on=1.1,
            persistence_k=3,
        )


def test_rejects_invalid_persistence() -> None:
    with pytest.raises(
        ValueError,
        match="persistence_k must be at least 1",
    ):
        ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=0,
        )
