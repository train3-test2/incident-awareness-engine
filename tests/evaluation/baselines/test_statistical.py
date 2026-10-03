from datetime import UTC, datetime, timedelta, timezone

import pytest

from incident_awareness.decision.fusion.stopping_policy import ScorePoint, ThresholdStoppingPolicy
from incident_awareness.evaluation.baselines.statistical import cusum_trajectory, ewma_trajectory

START = datetime(2026, 10, 2, tzinfo=UTC)
STEP = timedelta(seconds=10)


def points(values):
    return [ScorePoint(START + index * STEP, value) for index, value in enumerate(values)]


def ewma(rows, **overrides):
    config = {"baseline_mean": 0.0, "alpha": 0.5, "step_size": STEP}
    return ewma_trajectory(rows, **(config | overrides))


def cusum(rows, **overrides):
    config = {"baseline_mean": 0.25, "allowance": 0.25, "scale": 1.0, "step_size": STEP}
    return cusum_trajectory(rows, **(config | overrides))


def test_ewma_known_values_and_alpha_one():
    # Given
    rows = points([0, 1, 1, 0])

    # When
    smoothed = ewma(rows)
    identity = ewma(rows, alpha=1)

    # Then
    assert [p.score for p in smoothed] == [0, 0.5, 0.75, 0.375]
    assert identity == tuple(rows)


def test_cusum_clipping_does_not_discard_accumulated_history():
    # Given
    rows = points([1, 1, 1, 0, 0, 0])

    # When
    trajectory = cusum(rows)

    # Then
    assert [p.score for p in trajectory] == [0.5, 1, 1, 1, 0.5, 0]


@pytest.mark.parametrize("transform", [ewma, cusum])
def test_prefix_invariance_and_run_reset(transform):
    # Given
    rows = points([0, 1, 1, 0])

    zero_rows = points([0, 0])

    # When
    prefix = transform(rows[:2])
    full = transform(rows)
    from_iterator = transform(iter(rows))
    repeated = transform(rows)
    reset = transform(zero_rows)
    empty = transform([])

    # Then
    assert prefix == full[:2]
    assert from_iterator == repeated
    assert reset == tuple(zero_rows)
    assert empty == ()


@pytest.mark.parametrize("transform", [ewma, cusum])
@pytest.mark.parametrize("value", [True, "1", float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_scores(transform, value):
    # Given
    rows = points([value])

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        transform(rows)

    # Then
    assert error.type in (TypeError, ValueError)


@pytest.mark.parametrize("transform", [ewma, cusum])
@pytest.mark.parametrize(
    "timestamps",
    [
        [START, START],
        [START + STEP, START],
        [START, START + 2 * STEP],
        [START.replace(tzinfo=None)],
        [START.astimezone(timezone(timedelta(hours=9)))],
    ],
)
def test_invalid_cadence_or_timezone(transform, timestamps):
    # Given
    rows = [ScorePoint(t, 0.5) for t in timestamps]

    # When
    with pytest.raises(ValueError) as error:
        transform(rows)

    # Then
    assert error.type is ValueError


@pytest.mark.parametrize("transform", [ewma, cusum])
@pytest.mark.parametrize(
    "config",
    [
        {"step_size": timedelta(0)},
        {"baseline_mean": -1},
        {"baseline_mean": True},
        {"baseline_mean": float("nan")},
    ],
)
def test_invalid_common_config_even_for_empty_input(transform, config):
    # Given
    rows = []
    overrides = config

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        transform(rows, **overrides)

    # Then
    assert error.type in (TypeError, ValueError)


@pytest.mark.parametrize("config", [{"alpha": 0}, {"alpha": 1.1}, {"alpha": False}])
def test_invalid_ewma_config(config):
    # Given
    rows = []
    overrides = config

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        ewma(rows, **overrides)

    # Then
    assert error.type in (TypeError, ValueError)


@pytest.mark.parametrize(
    "config", [{"scale": 0}, {"scale": float("inf")}, {"allowance": -1}, {"allowance": "1"}]
)
def test_invalid_cusum_config(config):
    # Given
    rows = []
    overrides = config

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        cusum(rows, **overrides)

    # Then
    assert error.type in (TypeError, ValueError)


def test_transformed_trajectory_uses_existing_episode_policy():
    # Given
    rows = points([0, 1, 1, 0, 0])
    policy = ThresholdStoppingPolicy(threshold_on=0.7, threshold_off=0.4, persistence_k=1)

    # When
    trajectory = ewma(rows)
    result = policy.evaluate(
        list(trajectory), run_id="RUN-20261002-001", entity_id="HOST-01", run_end=START + 4 * STEP
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == START + 2 * STEP
    assert len(result.fusion_episodes) == 1
    assert result.fusion_episodes[0].end_time == START + 3 * STEP


def test_ewma_starts_from_nonzero_baseline():
    # Given
    rows = points([0, 1])

    # When
    result = ewma(rows, baseline_mean=0.4, alpha=0.5)

    # Then
    assert [point.score for point in result] == [0.2, 0.6]


def test_zero_cusum_baseline_and_allowance_never_release_on_zero_input():
    # Given
    rows = points([1, 0, 0, 0])
    policy = ThresholdStoppingPolicy(threshold_on=0.8, threshold_off=0.4, persistence_k=1)

    # When
    trajectory = cusum(rows, baseline_mean=0.0, allowance=0.0)
    result = policy.evaluate(
        list(trajectory), run_id="RUN-20261002-001", entity_id="HOST-01", run_end=START + 3 * STEP
    )

    # Then
    assert [point.score for point in trajectory] == [1, 1, 1, 1]
    assert result.fusion_episodes[0].end_reason == "run_end"
