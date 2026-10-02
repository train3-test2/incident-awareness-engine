import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from incident_awareness.evaluation.baselines.provenance import (
    StatisticalConfig,
    StatisticalInput,
    run_statistical_comparison,
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


def test_json_roundtrip_and_historical_reference():
    first = run_statistical_comparison(source(), config())
    encoded = json.loads(json.dumps(first))
    second = run_statistical_comparison(
        StatisticalInput.model_validate(encoded["input"]),
        StatisticalConfig.model_validate(encoded["config"]),
    )
    assert first == second
    assert [p["score"] for p in first["output"]] == [0.5, 0.25]
    assert first["output"][1]["input_prefix_length"] == 2
    assert first["input"]["points"][0]["evidence_ids"] == ["E1"]
    assert first["input"]["points"][1]["evidence_ids"] == []


def test_input_and_config_hashes_track_changes():
    original = run_statistical_comparison(source(), config())
    changed_input = run_statistical_comparison(source(entity_id="HOST-02"), config())
    changed_config = run_statistical_comparison(source(), config(alpha=0.25))
    assert original["input_sha256"] != changed_input["input_sha256"]
    assert original["config_sha256"] == changed_input["config_sha256"]
    assert original["config_sha256"] != changed_config["config_sha256"]


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


def test_cusum_execution():
    result = run_statistical_comparison(
        source(), config(method="cusum", alpha=None, allowance=0.0, scale=2.0)
    )
    assert [p["score"] for p in result["output"]] == [0.5, 0.5]


def test_bad_cadence_is_rejected_at_execution():
    with pytest.raises(ValueError, match="cadence"):
        run_statistical_comparison(source(), config(step_seconds=20.0))


@pytest.mark.parametrize(
    "timestamp", [123, "123", "2026-10-02T00:00:00", "2026-10-02T09:00:00+09:00"]
)
def test_no_numeric_or_naive_or_non_utc_times(timestamp):
    with pytest.raises(ValidationError):
        source(points=[{"timestamp": timestamp, "score": 0.0, "evidence_ids": []}])
