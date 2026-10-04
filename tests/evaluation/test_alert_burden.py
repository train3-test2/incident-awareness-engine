import json
from pathlib import Path

import pytest

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.evaluation.alert_burden import evaluate_normal_alert_burden
from incident_awareness.evaluation.result_inputs import EvaluationSnapshot


@pytest.fixture
def payload():
    data = json.loads(
        Path("tests/fixtures/evaluation/result_snapshot.json").read_text(encoding="utf-8")
    )
    data["runs"][2]["fast_episodes"]["start_times"].append("2026-09-20T00:04:59Z")
    return data


def evaluate(payload):
    return evaluate_normal_alert_burden(EvaluationSnapshot.model_validate(payload))


def test_normal_hours_include_zero_alert_runs_and_exclude_attacks(payload):
    # Given
    # payload fixture provides the prepared snapshot.

    # When
    result = evaluate(payload)

    # Then
    assert result["comparison_ready"]
    assert result["metrics"]["Fast"]["false_alert_episodes"] == 2
    assert result["metrics"]["Fast"]["benign_run_hours"] == pytest.approx(1 / 6)
    assert result["metrics"]["Fast"]["false_alerts_per_benign_run_hour"] == 12
    assert result["metrics"]["Fusion"]["false_alerts_per_benign_run_hour"] == 0
    assert len(result["normal_run_ids"]) == 2


def test_weight_by_duration_not_average_run_rates(payload):
    # Given
    run = payload["runs"][3]
    end = "2026-09-20T00:15:00Z"
    run["run_metadata"]["end_time"] = end
    run["fast_episodes"]["observation_end"] = end
    run["fusion_observation"]["observation_end"] = end

    # When
    result = evaluate(payload)

    # Then
    assert result["metrics"]["Fast"]["false_alerts_per_benign_run_hour"] == 6


def test_no_normal_runs_has_no_denominator(payload):
    # Given
    payload["runs"] = payload["runs"][:2]
    payload["plan"]["decision_ids"] = {
        r["run_metadata"]["run_id"]: r["decision"]["decision_id"] for r in payload["runs"]
    }

    # When
    result = evaluate(payload)

    # Then
    assert not result["comparison_ready"]
    assert result["metrics"]["Fast"]["false_alerts_per_benign_run_hour"] is None


@pytest.mark.parametrize("field", ["detection", "fusion", "fast_episodes", "fusion_observation"])
def test_missing_results_or_coverage_are_errors(payload, field):
    # Given
    payload["runs"][2][field] = None
    expected_message = {
        "detection": "missing detection result",
        "fusion": "missing fusion result",
        "fast_episodes": "evaluated Fast requires complete versioned episode starts, not raw hits",
        "fusion_observation": "evaluated Fusion requires explicit observation coverage",
    }[field]

    # When
    with pytest.raises(ValueError) as error:
        evaluate(payload)

    # Then
    assert expected_message in str(error.value)


def test_same_time_fast_episode_entries_are_counted_separately(payload):
    # Given
    starts = payload["runs"][2]["fast_episodes"]["start_times"]
    starts.append(starts[0])

    # When
    result = evaluate(payload)

    # Then
    assert result["metrics"]["Fast"]["false_alert_episodes"] == 3
    assert result["metrics"]["Fast"]["false_alerts_per_benign_run_hour"] == 18


def test_zero_duration_evaluated_run_is_error(payload):
    # Given
    run = payload["runs"][3]
    start = run["run_metadata"]["start_time"]
    run["run_metadata"]["end_time"] = start
    run["fast_episodes"]["observation_end"] = start
    run["fusion_observation"]["observation_end"] = start

    # When
    with pytest.raises(ValueError) as error:
        evaluate(payload)

    # Then
    assert str(error.value) == "evaluated normal Run must have positive observation duration"


def test_episode_at_observation_end_follows_existing_inclusive_contract(payload):
    # Given
    run = payload["runs"][2]
    run["fast_episodes"]["start_times"].append(run["run_metadata"]["end_time"])

    # When
    result = evaluate(payload)

    # Then
    assert result["metrics"]["Fast"]["false_alert_episodes"] == 3


def recombine(run):
    run["decision"] = combine_results(
        DetectionResult.model_validate(run["detection"]),
        FusionResult.model_validate(run["fusion"]),
        decision_id=run["decision"]["decision_id"],
        config_version="parallel-v1",
        parallel_required=True,
    ).model_dump(mode="json")


def test_not_evaluated_is_excluded_from_numerator_and_hours(payload):
    # Given
    run = payload["runs"][2]
    run["detection"].update(detector_status="not_evaluated", detector_time=None, detector_id=None)
    run["fast_episodes"] = None
    recombine(run)

    # When
    result = evaluate(payload)

    # Then
    assert not result["comparison_ready"]
    assert result["metrics"]["Fast"]["benign_run_hours"] == pytest.approx(1 / 12)
    assert result["metrics"]["Fast"]["false_alert_episodes"] == 0
    assert result["exclusions"] == [
        {"run_id": run["run_metadata"]["run_id"], "method": "Fast", "reason": "not_evaluated"}
    ]


def test_fusion_counts_all_episodes_not_just_latched_detection(payload):
    # Given
    run = payload["runs"][2]
    fused = json.loads(json.dumps(payload["runs"][0]["fusion"]))
    fused["run_id"] = run["run_metadata"]["run_id"]
    for episode in fused["fusion_episodes"]:
        episode["run_id"] = fused["run_id"]
    run["fusion"] = fused
    recombine(run)

    # When
    result = evaluate(payload)

    # Then
    assert result["metrics"]["Fusion"]["false_alert_episodes"] == 2


def test_duplicate_fusion_starts_are_rejected(payload):
    # Given
    run = payload["runs"][2]
    fused = json.loads(json.dumps(payload["runs"][0]["fusion"]))
    fused["run_id"] = run["run_metadata"]["run_id"]
    for episode in fused["fusion_episodes"]:
        episode["run_id"] = fused["run_id"]
    first, second = fused["fusion_episodes"]
    first["end_time"] = first["start_time"]
    second["start_time"] = first["start_time"]
    run["fusion"] = fused
    recombine(run)

    # When
    with pytest.raises(ValueError) as error:
        evaluate(payload)

    # Then
    assert str(error.value) == "duplicate Fusion episode starts are ambiguous"


@pytest.mark.parametrize("method", ["Fast", "Fusion"])
@pytest.mark.parametrize(
    "provenance",
    [
        {"family_id": "family-1", "variation_id": "variation-2", "repetition": 3},
        {"family_id": None, "variation_id": None, "repetition": None},
    ],
)
def test_per_run_preserves_experiment_provenance(payload, method, provenance):
    # Given
    run = payload["runs"][2]["run_metadata"]
    run.update(provenance)

    # When
    result = evaluate(payload)

    # Then
    row = next(
        row for row in result["metrics"][method]["per_run"] if row["run_id"] == run["run_id"]
    )
    assert {key: row[key] for key in provenance} == provenance
