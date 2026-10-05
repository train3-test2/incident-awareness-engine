import json
from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.evaluation.baselines.provenance import StatisticalConfig, StatisticalInput
from incident_awareness.evaluation.baselines.statistical_execution import run_statistical_comparison


@pytest.fixture
def source():
    return StatisticalInput(
        run_id="RUN-20261004-001",
        entity_id="HOST-01",
        input_config_version="score-v1",
        source_artifact_sha256="a" * 64,
        points=[
            {
                "timestamp": datetime(2026, 10, 4, tzinfo=UTC) + timedelta(seconds=i * 10),
                "score": score,
                "evidence_ids": ids,
            }
            for i, (score, ids) in enumerate([(1.0, ["E-001"]), (0.0, [])])
        ],
    )


@pytest.fixture
def config():
    return StatisticalConfig(
        method="ewma",
        config_version="ewma-v1",
        calibration_sha256="b" * 64,
        step_seconds=10.0,
        baseline_mean=0.0,
        alpha=0.5,
    )


def test_json_roundtrip_preserves_results_and_historical_reference(source, config):
    # Given
    input_source = source
    settings = config

    # When
    result = run_statistical_comparison(input_source, settings)
    stored = json.loads(json.dumps(result, allow_nan=False))
    rerun = run_statistical_comparison(
        StatisticalInput.model_validate(stored["input"]),
        StatisticalConfig.model_validate(stored["config"]),
    )

    # Then
    assert rerun == result
    assert [p["score"] for p in result["output"]] == [0.5, 0.25]
    assert [p["input_prefix_length"] for p in result["output"]] == [1, 2]
    assert result["input"]["points"][0]["evidence_ids"] == ["E-001"]
    assert result["input"]["points"][1]["evidence_ids"] == []


def test_cusum_uses_validated_parameters(source, config):
    # Given
    settings = StatisticalConfig.model_validate(
        config.model_dump()
        | {
            "method": "cusum",
            "alpha": None,
            "allowance": 0.0,
            "scale": 2.0,
        }
    )
    # When
    result = run_statistical_comparison(source, settings)

    # Then
    assert [p["score"] for p in result["output"]] == [0.5, 0.5]


def test_input_and_config_changes_have_separate_hashes(source, config):
    # Given
    other_source = source.model_copy(update={"entity_id": "HOST-02"})
    other_config = config.model_copy(update={"alpha": 0.25})

    # When
    original = run_statistical_comparison(source, config)
    other = run_statistical_comparison(other_source, config)
    changed = run_statistical_comparison(source, other_config)

    # Then
    assert original["input_sha256"] != other["input_sha256"]
    assert original["config_sha256"] == other["config_sha256"]
    assert original["input_sha256"] == changed["input_sha256"]
    assert original["config_sha256"] != changed["config_sha256"]


def test_evidence_history_changes_input_digest(source, config):
    # Given
    points = [source.points[0].model_copy(update={"evidence_ids": ("E-002",)}), source.points[1]]
    changed_source = source.model_copy(update={"points": tuple(points)})

    # When
    original = run_statistical_comparison(source, config)
    changed = run_statistical_comparison(changed_source, config)

    # Then
    assert original["output"] == changed["output"]
    assert original["input_sha256"] != changed["input_sha256"]


def test_bad_cross_contract_cadence_fails(source, config):
    # Given
    invalid_config = config.model_copy(update={"step_seconds": 20.0})

    # When
    with pytest.raises(ValueError) as error:
        run_statistical_comparison(source, invalid_config)

    # Then
    assert "cadence" in str(error.value)


@pytest.mark.parametrize("updates", [{"run_id": "bad"}, {"points": ()}])
def test_unchecked_source_copy_is_revalidated(source, config, updates):
    # Given
    invalid_source = source.model_copy(update=updates)

    # When
    with pytest.raises(ValueError) as error:
        run_statistical_comparison(invalid_source, config)

    # Then
    assert next(iter(updates)) in str(error.value)


def test_unchecked_config_copy_is_revalidated(source, config):
    # Given
    invalid_config = config.model_copy(update={"alpha": 0.0})

    # When
    with pytest.raises(ValueError) as error:
        run_statistical_comparison(source, invalid_config)

    # Then
    assert "alpha" in str(error.value)


def test_identical_calls_do_not_share_state_or_mutate_inputs(source, config):
    # Given
    before = source.model_dump(), config.model_dump()

    # When
    first = run_statistical_comparison(source, config)
    first["input"]["points"][0]["evidence_ids"].append("E-999")
    second = run_statistical_comparison(source, config)

    # Then
    assert second["input"]["points"][0]["evidence_ids"] == ["E-001"]
    assert (source.model_dump(), config.model_dump()) == before
    assert [p["score"] for p in second["output"]] == [0.5, 0.25]
