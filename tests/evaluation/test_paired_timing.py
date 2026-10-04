import json
from copy import deepcopy
from pathlib import Path

import pytest

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.evaluation.paired_timing import compare_paired_timing
from incident_awareness.evaluation.result_inputs import EvaluationSnapshot


@pytest.fixture
def payload():
    return json.loads(
        Path("tests/fixtures/evaluation/result_snapshot.json").read_text(encoding="utf-8")
    )


def report(payload):
    return compare_paired_timing(EvaluationSnapshot.model_validate(payload))


def recombine(run):
    run["decision"] = combine_results(
        DetectionResult.model_validate(run["detection"]),
        FusionResult.model_validate(run["fusion"]),
        decision_id=run["decision"]["decision_id"],
        config_version="parallel-v1",
        parallel_required=True,
    ).model_dump(mode="json")


def test_uses_eligible_episodes_not_latched_times_and_excludes_normal(payload):
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    result = report(payload)
    first = result["per_run"][0]
    json.dumps(result, allow_nan=False)

    # Then
    assert first["paths"]["Fast"]["ttsd_sec"] == 40
    assert first["paths"]["Fusion"]["ttsd_sec"] == 70
    assert first["fusion_minus_fast_sec"] == 30
    assert first["earlier_eligible_path"] == "Fast"
    assert result["counts"] == {
        "both_detected": 1,
        "fast_only": 0,
        "fusion_only": 0,
        "both_miss": 1,
        "not_evaluated": 0,
    }
    assert result["both_detected_summary"]["run_count"] == 1
    assert result["paired_coverage_complete"]


@pytest.mark.parametrize("horizon,outcome", [(0, "both_miss"), (40, "fast_only")])
def test_horizon_inclusive_boundary_and_one_sided_miss(payload, horizon, outcome):
    # Given
    payload["plan"]["evaluation_horizon_sec"] = horizon

    # When
    result = report(payload)

    # Then
    assert result["per_run"][0]["outcome"] == outcome
    assert result["per_run"][0]["fusion_minus_fast_sec"] is None
    assert result["both_detected_summary"]["median_fusion_minus_fast_sec"] is None


def test_fusion_only_does_not_impute_fast_time(payload):
    # Given
    payload["runs"][0]["fast_episodes"]["start_times"] = ["2026-09-20T00:00:20Z"]

    # When
    result = report(payload)

    # Then
    assert result["per_run"][0]["outcome"] == "fusion_only"
    assert result["per_run"][0]["paths"]["Fast"]["eligible_status"] == "miss"
    assert result["per_run"][0]["fusion_minus_fast_sec"] is None


@pytest.mark.parametrize(
    "time,delta,earlier",
    [
        ("2026-09-20T00:02:10Z", 0, "tie"),
        ("2026-09-20T00:02:20Z", -10, "Fusion"),
        ("2026-09-20T00:02:09.999Z", 0.001, "Fast"),
    ],
)
def test_delta_sign_and_millisecond_precision(payload, time, delta, earlier):
    # Given
    payload["runs"][0]["fast_episodes"]["start_times"][1] = time

    # When
    result = report(payload)

    # Then
    assert result["per_run"][0]["fusion_minus_fast_sec"] == pytest.approx(delta)
    assert result["per_run"][0]["earlier_eligible_path"] == earlier


def test_not_evaluated_is_distinct_from_miss(payload):
    # Given
    run = payload["runs"][0]
    run["detection"].update(detector_status="not_evaluated", detector_time=None, detector_id=None)
    run["fast_episodes"] = None
    recombine(run)

    # When
    result = report(payload)

    # Then
    assert result["counts"]["not_evaluated"] == 1
    assert result["counts"]["both_miss"] == 1
    assert not result["paired_coverage_complete"]
    assert result["per_run"][0]["paths"]["Fusion"]["ttsd_sec"] == 70
    assert result["exclusions"][0]["reason"] == "not_evaluated"


def test_missing_result_is_error_not_exclusion(payload):
    # Given
    payload["runs"][0]["detection"] = None

    # When
    with pytest.raises(ValueError) as error_1:
        report(payload)

    # Then
    assert "missing detection" in str(error_1.value)


def test_no_attack_runs_has_no_timing_denominator(payload):
    # Given
    payload["runs"] = payload["runs"][2:]
    payload["plan"]["decision_ids"] = {
        run["run_metadata"]["run_id"]: run["decision"]["decision_id"] for run in payload["runs"]
    }

    # When
    result = report(payload)

    # Then
    assert not result["paired_coverage_complete"]
    assert result["both_detected_summary"]["run_count"] == 0


def test_input_order_and_provenance(payload):
    # Given
    payload["runs"][0]["run_metadata"].update(family_id="family-1", variation_id="v1", repetition=2)

    reordered = deepcopy(payload)
    reordered["runs"].reverse()

    # When
    expected = report(payload)
    actual_3 = report(reordered)

    # Then
    assert actual_3 == expected
    assert expected["per_run"][0]["repetition"] == 2
    assert expected["per_run"][0]["decision_id"] == "D-1"


@pytest.mark.parametrize("fraction", ["000", "999"])
def test_json_timestamps_are_canonical_utc_milliseconds(payload, fraction):
    # Given
    run = payload["runs"][0]
    run["run_metadata"]["reference_time"] = f"2026-09-20T00:01:00.{fraction}Z"
    run["fast_episodes"]["start_times"][1] = f"2026-09-20T00:01:40.{fraction}Z"
    run["fusion"]["fusion_episodes"][1]["start_time"] = f"2026-09-20T00:02:10.{fraction}Z"

    # When
    result = report(payload)["per_run"][0]

    # Then
    assert result["reference_time"] == f"2026-09-20T00:01:00.{fraction}Z"
    assert result["paths"]["Fast"]["eligible_time"] == f"2026-09-20T00:01:40.{fraction}Z"
    assert result["paths"]["Fusion"]["eligible_time"] == f"2026-09-20T00:02:10.{fraction}Z"
