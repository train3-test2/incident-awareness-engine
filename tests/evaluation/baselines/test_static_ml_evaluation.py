import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evaluation.baselines.static_ml import StaticModel, TrainingConfig
from incident_awareness.evaluation.baselines.static_ml_episodes import (
    EpisodeConfig,
    TimedFeatureRow,
)
from incident_awareness.evaluation.baselines.static_ml_evaluation import evaluate_static_model
from incident_awareness.evaluation.split_manifest import SplitManifest, audit_split_manifest


def model():
    return StaticModel(
        feature_names=("encoded_powershell_command",),
        feature_config_version="features-v1",
        coefficients=(10.0,),
        intercept=-5.0,
        config=TrainingConfig(
            model_version="synthetic",
            label_policy_version="v1",
            c=1.0,
            tolerance=0.001,
            max_iter=100,
        ),
        sklearn_version="synthetic",
        training_sha256="a" * 64,
        split_sha256="b" * 64,
        training_run_ids=("RUN-20261004-001",),
        training_row_count=2,
    )


def rows(values):
    return [
        TimedFeatureRow(
            sample_id=f"s-{i}",
            run_id="RUN-20261004-002",
            entity_id="HOST",
            feature_config_version="features-v1",
            feature_names=("encoded_powershell_command",),
            values=(value,),
            timestamp=datetime(2026, 10, 4, tzinfo=UTC) + timedelta(seconds=i * 10),
        )
        for i, value in enumerate(values)
    ]


def config():
    return EpisodeConfig(
        policy_version="probe-v1",
        step_seconds=10,
        threshold_on=0.8,
        threshold_off=0.4,
        persistence_k=2,
    )


def run(number, values, normal=False):
    points = rows(values)
    identifier = f"RUN-20261004-{number:03d}"
    points = [p.model_copy(update={"run_id": identifier}) for p in points]
    payload = json.loads(
        Path("tests/fixtures/pipeline/first_cycle/run_metadata.json").read_text(encoding="utf-8")
    )
    payload.update(
        run_id=identifier,
        target_host="HOST",
        run_type="normal" if normal else "attack",
        start_time=points[0].timestamp,
        end_time=points[-1].timestamp,
        reference_time=None if normal else points[0].timestamp + timedelta(seconds=20),
    )
    return RunMetadata.model_validate(payload), points


def evaluate(runs, mapping, **kwargs):
    return evaluate_static_model(
        model(),
        runs,
        mapping,
        config(),
        coverage_sha256_by_run={
            key: "a" * 64 for key, value in mapping.items() if value is not None
        },
        evaluation_horizon_sec=20,
        purpose=kwargs.pop("purpose", "smoke"),
        **kwargs,
    )


def test_end_to_end_episode_metrics_and_burden():
    # Given
    attack, a = run(2, [0, 1, 1, 0, 0])
    normal, n = run(3, [0, 1, 1, 0, 0], True)

    # When
    report = evaluate([attack, normal], {attack.run_id: a, normal.run_id: n})

    # Then
    assert report["metrics"]["run_recall"] == 1
    assert report["metrics"]["median_ttsd_sec"] == 0
    assert report["metrics"]["benign_run_fpr"] == 1
    assert report["per_run"][0]["pre_reference_false_alerts"] == 0
    assert report["per_run"][1]["pre_reference_false_alerts"] is None
    assert report["alert_burden"]["pre_reference_false_alerts"] == 0
    assert report["alert_burden"]["false_alerts_per_benign_run_hour"] == 90
    assert report["replays"][attack.run_id]["episodes"][0]["source_sample_id"] == "s-2"


def test_pre_reference_episode_is_not_new_detection():
    # Given
    attack, a = run(2, [1, 1, 1, 1, 1])

    # When
    report = evaluate([attack], {attack.run_id: a})

    # Then
    assert report["metrics"]["run_recall"] == 0
    assert report["per_run"][0]["pre_reference_false_alerts"] == 1
    assert report["alert_burden"]["pre_reference_false_alerts"] == 1
    assert report["alert_burden"]["false_alerts_per_benign_run_hour"] is None


def test_not_evaluated_is_excluded_not_miss():
    # Given
    attack, _ = run(2, [0, 0, 0])

    # When
    report = evaluate([attack], {attack.run_id: None})

    # Then
    assert report["metrics"] is None
    assert not report["comparison_ready"]
    assert report["exclusions"][0]["reason"] == "not_evaluated"


@pytest.mark.parametrize("case", ["missing", "empty", "partial", "host", "duplicate"])
def test_bad_inventory_and_coverage_fail(case):
    # Given
    attack, a = run(2, [0, 0, 0, 0, 0])
    inventory, mapping = [attack], {attack.run_id: a}
    if case == "missing":
        mapping = {}
    elif case == "empty":
        mapping[attack.run_id] = []
    elif case == "partial":
        mapping[attack.run_id] = a[:-1]
    elif case == "host":
        mapping[attack.run_id][0] = a[0].model_copy(update={"entity_id": "OTHER"})
    else:
        inventory.append(attack)

    # When
    with pytest.raises(ValueError) as error:
        evaluate(inventory, mapping)

    # Then
    assert str(error.value)


def test_coverage_reference_required():
    # Given
    attack, a = run(2, [0, 0, 0])

    # When
    with pytest.raises(ValueError) as error:
        evaluate_static_model(
            model(),
            [attack],
            {attack.run_id: a},
            config(),
            coverage_sha256_by_run={},
            evaluation_horizon_sec=20,
            purpose="smoke",
        )

    # Then
    assert "coverage artifact" in str(error.value)


def test_s0_cannot_be_performance():
    # Given
    attack, a = run(2, [0, 0, 0])

    # When
    with pytest.raises(ValueError) as error:
        evaluate_static_model(
            model(),
            [attack],
            {attack.run_id: a},
            config(),
            coverage_sha256_by_run={attack.run_id: "a" * 64},
            evaluation_horizon_sec=20,
            purpose="performance",
        )

    # Then
    assert "smoke-only" in str(error.value)


def test_unicode_model_hash_matches_nested_replay():
    # Given
    attack, points = run(2, [0, 1, 1])
    original = model()
    unicode_model = original.model_copy(
        update={"config": original.config.model_copy(update={"model_version": "모델-v1"})}
    )

    # When
    report = evaluate_static_model(
        unicode_model,
        [attack],
        {attack.run_id: points},
        config(),
        coverage_sha256_by_run={attack.run_id: "a" * 64},
        evaluation_horizon_sec=20,
        purpose="smoke",
    )

    # Then
    assert report["model_sha256"] == report["replays"][attack.run_id]["model_sha256"]


@pytest.mark.parametrize("evaluated", [True, False])
def test_performance_rejects_training_run_in_inventory(evaluated):
    # Given
    attack, points = run(1, [0, 1, 1])
    attack.scenario_id = "R1"
    mapping = {attack.run_id: points if evaluated else None}

    # When
    with pytest.raises(ValueError) as error:
        evaluate([attack], mapping, purpose="performance")

    # Then
    assert "performance evaluation must not reuse training Runs" in str(error.value)


def test_smoke_allows_training_replay_and_preserves_provenance():
    # Given
    attack, points = run(1, [0, 1, 1])
    expected_model = model()

    # When
    report = evaluate([attack], {attack.run_id: points})

    # Then
    assert report["schema_version"] == "static-ml-evaluation-v0.2"
    assert report["evaluation_split"] is None
    assert report["usage_sha256"] is None
    assert report["usage_policy_version"] is None
    assert report["training_run_ids"] == list(expected_model.training_run_ids)
    assert report["split_sha256"] == expected_model.split_sha256


def test_performance_accepts_disjoint_training_runs():
    # Given
    attack, points = run(2, [0, 1, 1])
    attack.scenario_id = "R1"

    payload = json.loads(
        Path("tests/fixtures/evaluation/static_ml/split.json").read_text(encoding="utf-8")
    )
    # Move the non-training Run to the test split without reusing model training IDs.
    payload["assignments"][1]["split"] = "test"
    payload["assignments"][3]["split"] = "train"
    payload["inventory_family_ids"][attack.run_id] = "held-out-family"
    manifest = SplitManifest.model_validate(payload)
    trained = model().model_copy(
        update={"split_sha256": audit_split_manifest(manifest)["manifest_sha256"]}
    )
    # When
    report = evaluate_static_model(
        trained,
        [attack],
        {attack.run_id: points},
        config(),
        coverage_sha256_by_run={attack.run_id: "a" * 64},
        evaluation_horizon_sec=20,
        purpose="performance",
        split_manifest=manifest,
        evaluation_split="test",
    )

    with pytest.raises(ValueError) as provenance_error:
        evaluate_static_model(
            model(),
            [attack],
            {attack.run_id: points},
            config(),
            coverage_sha256_by_run={attack.run_id: "a" * 64},
            evaluation_horizon_sec=20,
            purpose="performance",
            split_manifest=manifest,
            evaluation_split="test",
        )
    with pytest.raises(ValueError) as inventory_error:
        evaluate_static_model(
            trained,
            [attack],
            {attack.run_id: points},
            config(),
            coverage_sha256_by_run={attack.run_id: "a" * 64},
            evaluation_horizon_sec=20,
            purpose="performance",
            split_manifest=manifest,
            evaluation_split="validation",
        )

    # Then
    assert report["schema_version"] == "static-ml-evaluation-v0.2"
    assert report["evaluation_split"] == "test"
    assert report["metrics"]["run_recall"] == 1
    assert report["usage_policy_version"] == "synthetic-v1"
    assert len(report["usage_sha256"]) == 64
    assert "split provenance" in str(provenance_error.value)
    assert "exactly cover" in str(inventory_error.value)


@pytest.mark.parametrize("evaluated", [True, False])
@pytest.mark.parametrize("side", ["before", "after"])
def test_reference_outside_measured_run_is_rejected(evaluated, side):
    # Given
    attack, points = run(2, [0, 1, 1])
    reference = (
        attack.start_time - timedelta(milliseconds=1)
        if side == "before"
        else attack.end_time + timedelta(milliseconds=1)
    )
    attack = attack.model_copy(update={"reference_time": reference})
    mapping = {attack.run_id: points if evaluated else None}

    # When
    with pytest.raises(ValueError) as error:
        evaluate([attack], mapping)

    # Then
    assert "reference_time must be within the measured Run" in str(error.value)


@pytest.mark.parametrize("side", ["start_time", "end_time"])
def test_reference_at_run_boundary_is_allowed(side):
    # Given
    attack, points = run(2, [0, 1, 1])
    attack.reference_time = getattr(attack, side)

    # When
    report = evaluate([attack], {attack.run_id: points})

    # Then
    assert report["metrics"]["run_recall"] == 1


@pytest.mark.parametrize("milliseconds", [0, 999])
def test_eligible_time_is_canonical_utc_milliseconds(milliseconds):
    # Given
    attack, points = run(2, [0, 1, 1])
    shift = timedelta(milliseconds=milliseconds)
    attack = attack.model_copy(
        update={
            key: getattr(attack, key) + shift
            for key in ("start_time", "end_time", "reference_time")
        }
    )
    points = [p.model_copy(update={"timestamp": p.timestamp + shift}) for p in points]

    # When
    report = evaluate([attack], {attack.run_id: points})

    # Then
    assert report["per_run"][0]["eligible_time"] == f"2026-10-04T00:00:20.{milliseconds:03d}Z"


@pytest.mark.parametrize("values", [[1, 1, 1, 1, 1], [1, 1, 1, 0, 0]])
def test_post_reference_release_does_not_change_pre_reference_count(values):
    # Given
    attack, points = run(2, values)

    # When
    report = evaluate([attack], {attack.run_id: points})

    # Then
    assert report["alert_burden"]["pre_reference_false_alerts"] == 1
    assert report["per_run"][0]["pre_reference_false_alerts"] == 1
    assert (
        report["replays"][attack.run_id]["episodes"][0]["start_time"] == "2026-10-04T00:00:10.000Z"
    )
    assert report["replays"][attack.run_id]["episodes"][0]["end_time"] > "2026-10-04T00:00:20.000Z"
    assert report["alert_burden"]["false_alert_episodes"] == 0


@pytest.mark.parametrize("reference_seconds,expected", [(0, 0), (1, 1), (21, 2)])
def test_pre_reference_counts_use_half_open_start_interval(reference_seconds, expected):
    # Given
    attack, points = run(2, [1, 0, 1, 0, 0])
    attack.reference_time = attack.start_time + timedelta(seconds=reference_seconds)
    policy = config().model_copy(update={"persistence_k": 1})

    # When
    report = evaluate_static_model(
        model(),
        [attack],
        {attack.run_id: points},
        policy,
        coverage_sha256_by_run={attack.run_id: "a" * 64},
        evaluation_horizon_sec=20,
        purpose="smoke",
    )

    # Then
    assert report["per_run"][0]["pre_reference_false_alerts"] == expected
    assert report["alert_burden"]["pre_reference_false_alerts"] == expected


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "scenario_id": "R1",
            "family_id": "family-a",
            "variation_id": "variation-2",
            "repetition": 3,
        },
        {"scenario_id": "S0", "family_id": None, "variation_id": None, "repetition": None},
    ],
)
def test_per_run_preserves_analysis_metadata_in_json(metadata):
    # Given
    attack, points = run(2, [0, 1, 1])
    attack = attack.model_copy(update=metadata)

    # When
    report = evaluate([attack], {attack.run_id: points})
    persisted = json.loads(json.dumps(report))

    # Then
    assert {key: persisted["per_run"][0][key] for key in metadata} == metadata


def test_performance_cannot_skip_usage_manifest():
    # Given
    attack, points = run(2, [0, 1, 1])
    attack.scenario_id = "R1"
    # When / Then
    with pytest.raises(ValueError, match="usage-validated manifest"):
        evaluate([attack], {attack.run_id: points}, purpose="performance")


@pytest.mark.parametrize("excluded_run", ["RUN-20261005-912", "RUN-20261005-913"])
def test_tuning_pair_cannot_enter_performance_without_manifest(excluded_run):
    # Given
    attack, points = run(2, [0, 1, 1])
    attack.scenario_id = "R1"
    attack.run_id = excluded_run
    points = [p.model_copy(update={"run_id": excluded_run}) for p in points]
    # When / Then
    with pytest.raises(ValueError, match="usage-validated manifest"):
        evaluate([attack], {excluded_run: points}, purpose="performance")
