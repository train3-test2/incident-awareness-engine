"""Causal, run-local transforms of a fixed-cadence score trajectory."""

import math
from collections.abc import Iterable
from datetime import datetime, timedelta

from incident_awareness.decision.fusion.stopping_policy import ScorePoint


def _number(value: float, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{name} must be finite")


def _unit(value: float, name: str) -> None:
    _number(value, name)
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be between 0 and 1")


def _points(points: Iterable[ScorePoint], step_size: timedelta) -> Iterable[ScorePoint]:
    if not isinstance(step_size, timedelta):
        raise TypeError("step_size must be a timedelta")
    if step_size <= timedelta(0):
        raise ValueError("step_size must be positive")
    previous = None
    for point in points:
        timestamp = point.timestamp
        if not isinstance(timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if timestamp.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be timezone-aware UTC")
        if previous is not None and timestamp - previous != step_size:
            raise ValueError("trajectory must be strictly increasing at the configured cadence")
        _unit(point.score, "score")
        yield point
        previous = timestamp


def ewma_trajectory(
    points: Iterable[ScorePoint], *, baseline_mean: float, alpha: float, step_size: timedelta
) -> tuple[ScorePoint, ...]:
    """Return EWMA scores, initialized from an externally fitted baseline mean."""
    _unit(baseline_mean, "baseline_mean")
    _unit(alpha, "alpha")
    if alpha == 0:
        raise ValueError("alpha must be positive")
    state = baseline_mean
    output = []
    for point in _points(points, step_size):
        state = alpha * point.score + (1 - alpha) * state
        output.append(ScorePoint(timestamp=point.timestamp, score=state))
    return tuple(output)


def cusum_trajectory(
    points: Iterable[ScorePoint],
    *,
    baseline_mean: float,
    allowance: float,
    scale: float,
    step_size: timedelta,
) -> tuple[ScorePoint, ...]:
    """Return an upper one-sided CUSUM scaled/clipped into the score contract.

    Internal accumulation is not clipped or reset at an alarm. Scale is an
    explicit configuration value, not a threshold learned from this run.
    """
    _unit(baseline_mean, "baseline_mean")
    _number(allowance, "allowance")
    _number(scale, "scale")
    if allowance < 0 or scale <= 0:
        raise ValueError("allowance must be nonnegative and scale must be positive")
    state = 0.0
    output = []
    for point in _points(points, step_size):
        state = max(0.0, state + (point.score - baseline_mean) - allowance)
        if not math.isfinite(state):
            raise ValueError("CUSUM accumulation overflow")
        score = 1.0 if state >= scale else state / scale
        output.append(ScorePoint(timestamp=point.timestamp, score=score))
    return tuple(output)
