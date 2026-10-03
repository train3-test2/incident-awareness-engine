from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from incident_awareness.evaluation.baselines.provenance import (
    StatisticalConfig,
    StatisticalInput,
)


def source(**overrides):
    data = {
        "run_id": "RUN-20261002-001",
        "entity_id": "HOST-01",
        "input_config_version": "input-v1",
        "source_artifact_sha256": "a" * 64,
        "points": [
            {
                "timestamp": datetime(2026, 10, 2, tzinfo=UTC) + timedelta(seconds=10 * i),
                "score": score,
                "evidence_ids": ids,
            }
            for i, (score, ids) in enumerate([(1.0, ["E-001"]), (0.0, [])])
        ],
    }
    return StatisticalInput.model_validate(data | overrides)


def config(**overrides):
    data = {
        "method": "ewma",
        "config_version": "ewma-v1",
        "calibration_sha256": "b" * 64,
        "step_seconds": 10.0,
        "baseline_mean": 0.0,
        "alpha": 0.5,
    }
    return StatisticalConfig.model_validate(data | overrides)


@pytest.mark.parametrize(
    "changes",
    [
        {"run_id": "RUN-20260230-001"},
        {"run_id": " RUN-20261002-001"},
        {"points": []},
        {"source_artifact_sha256": "bad"},
    ],
)
def test_invalid_source(changes):
    # Given
    overrides = changes

    # When
    with pytest.raises(ValidationError) as error:
        source(**overrides)

    # Then
    assert error.type is ValidationError


@pytest.mark.parametrize(
    "changes",
    [
        {"alpha": 0.0},
        {"alpha": True},
        {"scale": 1.0},
        {"calibration_sha256": "bad"},
        {"baseline_mean": float("nan")},
    ],
)
def test_invalid_config(changes):
    # Given
    overrides = changes

    # When
    with pytest.raises(ValidationError) as error:
        config(**overrides)

    # Then
    assert error.type is ValidationError


@pytest.mark.parametrize(
    "timestamp", [123, "123", "2026-10-02T00:00:00", "2026-10-02T09:00:00+09:00"]
)
def test_no_numeric_or_naive_or_non_utc_times(timestamp):
    # Given
    points = [{"timestamp": timestamp, "score": 0.0, "evidence_ids": []}]

    # When
    with pytest.raises(ValidationError) as error:
        source(points=points)

    # Then
    assert error.type is ValidationError


@pytest.mark.parametrize("offsets", [[10, 0], [0, 0]])
def test_rejects_non_increasing_points(offsets):
    # Given
    points = [
        {
            "timestamp": datetime(2026, 10, 2, tzinfo=UTC) + timedelta(seconds=t),
            "score": 0.0,
            "evidence_ids": [],
        }
        for t in offsets
    ]

    # When
    with pytest.raises(ValidationError) as error:
        source(points=points)

    # Then
    assert "strictly increasing" in str(error.value)


@pytest.mark.parametrize("identifier", ["E1", "EVD-001", "evt-001", "E-"])
def test_rejects_noncanonical_evidence_ids(identifier):
    # Given
    points = [
        {"timestamp": datetime(2026, 10, 2, tzinfo=UTC), "score": 0.0, "evidence_ids": [identifier]}
    ]

    # When
    with pytest.raises(ValidationError) as error:
        source(points=points)

    # Then
    assert "canonical E-" in str(error.value)


def test_canonical_evidence_ids_remain_sorted_and_unique():
    # Given
    points = [
        {
            "timestamp": datetime(2026, 10, 2, tzinfo=UTC),
            "score": 0.0,
            "evidence_ids": ["E-002", "E-001", "E-002"],
        }
    ]

    # When
    value = source(points=points)

    # Then
    assert value.points[0].evidence_ids == ("E-001", "E-002")


@pytest.mark.parametrize("step", [1e-10, 1e20])
def test_rejects_unusable_duration(step):
    # Given
    step_seconds = step

    # When
    with pytest.raises(ValidationError) as error:
        config(step_seconds=step_seconds)

    # Then
    assert "step_seconds" in str(error.value)


@pytest.mark.parametrize("step", [0.000001, 10.0])
def test_accepts_representable_positive_duration(step):
    # Given
    step_seconds = step

    # When
    result = config(step_seconds=step_seconds)

    # Then
    assert result.step_seconds == step
