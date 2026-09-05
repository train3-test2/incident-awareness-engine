import pytest

from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
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
