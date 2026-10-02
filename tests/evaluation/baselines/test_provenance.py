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
            for i, (score, ids) in enumerate([(1.0, ["E1"]), (0.0, [])])
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
    with pytest.raises(ValidationError):
        source(**changes)


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
    with pytest.raises(ValidationError):
        config(**changes)


@pytest.mark.parametrize(
    "timestamp", [123, "123", "2026-10-02T00:00:00", "2026-10-02T09:00:00+09:00"]
)
def test_no_numeric_or_naive_or_non_utc_times(timestamp):
    with pytest.raises(ValidationError):
        source(points=[{"timestamp": timestamp, "score": 0.0, "evidence_ids": []}])
