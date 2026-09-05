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
    start = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    return ScorePoint(
        timestamp=start + timedelta(seconds=seconds),
        score=score,
    )


def test_accepts_valid_stopping_policy_configuration() -> None:
    # Given
    threshold_on = 0.7
    threshold_off = 0.5
    persistence_k = 3

    # When
    policy = ThresholdStoppingPolicy(
        threshold_on=threshold_on,
        threshold_off=threshold_off,
        persistence_k=persistence_k,
    )

    # Then
    assert policy.threshold_on == threshold_on
    assert policy.threshold_off == threshold_off
    assert policy.persistence_k == persistence_k


@pytest.mark.parametrize(
    "threshold_on",
    [
        -0.1,
        1.1,
    ],
)
def test_rejects_invalid_threshold_on(threshold_on: float) -> None:
    # Given
    threshold_off = 0.2
    persistence_k = 3

    # When
    with pytest.raises(ValueError) as exc_info:
        ThresholdStoppingPolicy(
            threshold_on=threshold_on,
            threshold_off=threshold_off,
            persistence_k=persistence_k,
        )

    # Then
    assert str(exc_info.value) == "threshold_on must be between 0.0 and 1.0"


@pytest.mark.parametrize(
    "threshold_off",
    [
        -0.1,
        1.1,
    ],
)
def test_rejects_invalid_threshold_off(threshold_off: float) -> None:
    # Given
    threshold_on = 0.7
    persistence_k = 3

    # When
    with pytest.raises(ValueError) as exc_info:
        ThresholdStoppingPolicy(
            threshold_on=threshold_on,
            threshold_off=threshold_off,
            persistence_k=persistence_k,
        )

    # Then
    assert str(exc_info.value) == "threshold_off must be between 0.0 and 1.0"


@pytest.mark.parametrize(
    ("threshold_on", "threshold_off"),
    [
        (0.7, 0.7),
        (0.7, 0.8),
    ],
)
def test_rejects_invalid_hysteresis(
    threshold_on: float,
    threshold_off: float,
) -> None:
    # Given
    persistence_k = 3

    # When
    with pytest.raises(ValueError) as exc_info:
        ThresholdStoppingPolicy(
            threshold_on=threshold_on,
            threshold_off=threshold_off,
            persistence_k=persistence_k,
        )

    # Then
    assert str(exc_info.value) == "threshold_off must be less than threshold_on"


@pytest.mark.parametrize(
    "persistence_k",
    [
        0,
        -1,
    ],
)
def test_rejects_invalid_persistence(persistence_k: int) -> None:
    # Given
    threshold_on = 0.7
    threshold_off = 0.5

    # When
    with pytest.raises(ValueError) as exc_info:
        ThresholdStoppingPolicy(
            threshold_on=threshold_on,
            threshold_off=threshold_off,
            persistence_k=persistence_k,
        )

    # Then
    assert str(exc_info.value) == "persistence_k must be at least 1"


def test_enters_active_after_k_consecutive_scores() -> None:
    # Given
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        threshold_off=0.5,
        persistence_k=3,
    )
    trajectory = [
        make_point(0, 0.73),
        make_point(10, 0.78),
        make_point(20, 0.81),
    ]
    run_end = make_point(60, 0.0).timestamp

    # When
    result = policy.evaluate(
        trajectory,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_end=run_end,
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == trajectory[2].timestamp
    assert result.score_at_decision == 0.81
    assert len(result.fusion_episodes) == 1

    episode = result.fusion_episodes[0]
    assert episode.start_time == trajectory[2].timestamp
    assert episode.score_at_start == 0.81
    assert episode.end_time == run_end
    assert episode.end_reason == "run_end"


def test_resets_persistence_when_score_falls_below_threshold() -> None:
    # Given
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        threshold_off=0.5,
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

    # When
    result = policy.evaluate(
        trajectory,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_end=make_point(60, 0.0).timestamp,
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == trajectory[5].timestamp


def test_threshold_on_equality_counts_toward_persistence() -> None:
    # Given
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        threshold_off=0.5,
        persistence_k=2,
    )
    trajectory = [
        make_point(0, 0.7),
        make_point(10, 0.7),
    ]

    # When
    result = policy.evaluate(
        trajectory,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_end=make_point(20, 0.0).timestamp,
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == trajectory[1].timestamp


def test_returns_miss_when_active_condition_is_never_satisfied() -> None:
    # Given
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        threshold_off=0.5,
        persistence_k=3,
    )
    trajectory = [
        make_point(0, 0.50),
        make_point(10, 0.72),
        make_point(20, 0.60),
        make_point(30, 0.75),
    ]

    # When
    result = policy.evaluate(
        trajectory,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_end=make_point(40, 0.0).timestamp,
    )

    # Then
    assert result.fusion_status == "miss"
    assert result.fusion_time is None
    assert result.score_at_decision is None
    assert result.fusion_episodes == ()


def test_continues_processing_after_first_active_entry() -> None:
    # Given
    policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        threshold_off=0.5,
        persistence_k=2,
    )
    trajectory = [
        make_point(0, 0.75),
        make_point(10, 0.80),
        make_point(20, 0.90),
        make_point(30, 0.85),
    ]

    # When
    result = policy.evaluate(
        trajectory,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_end=make_point(40, 0.0).timestamp,
    )

    # Then
    assert result.fusion_time == trajectory[1].timestamp
    assert result.fusion_episodes[0].peak_score == 0.90
