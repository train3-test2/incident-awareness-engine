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
    payload = json.loads(Path("tests/fixtures/pipeline/first_cycle/run_metadata.json").read_text())
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
        purpose="smoke",
        **kwargs,
    )


def test_end_to_end_episode_metrics_and_burden():
    attack, a = run(2, [0, 1, 1, 0, 0])
    normal, n = run(3, [0, 1, 1, 0, 0], True)
    report = evaluate([attack, normal], {attack.run_id: a, normal.run_id: n})
    assert report["metrics"]["run_recall"] == 1
    assert report["metrics"]["median_ttsd_sec"] == 0
    assert report["metrics"]["benign_run_fpr"] == 1
    assert report["alert_burden"]["false_alerts_per_benign_run_hour"] == 90
    assert report["replays"][attack.run_id]["episodes"][0]["source_sample_id"] == "s-2"


def test_pre_reference_episode_is_not_new_detection():
    attack, a = run(2, [1, 1, 1, 1, 1])
    report = evaluate([attack], {attack.run_id: a})
    assert report["metrics"]["run_recall"] == 0
    assert report["alert_burden"]["false_alerts_per_benign_run_hour"] is None


def test_not_evaluated_is_excluded_not_miss():
    attack, _ = run(2, [0, 0, 0])
    report = evaluate([attack], {attack.run_id: None})
    assert report["metrics"] is None
    assert not report["comparison_ready"]
    assert report["exclusions"][0]["reason"] == "not_evaluated"


@pytest.mark.parametrize("case", ["missing", "empty", "partial", "host", "duplicate"])
def test_bad_inventory_and_coverage_fail(case):
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
    with pytest.raises(ValueError):
        evaluate(inventory, mapping)


def test_coverage_reference_required():
    attack, a = run(2, [0, 0, 0])
    with pytest.raises(ValueError, match="coverage artifact"):
        evaluate_static_model(
            model(),
            [attack],
            {attack.run_id: a},
            config(),
            coverage_sha256_by_run={},
            evaluation_horizon_sec=20,
            purpose="smoke",
        )


def test_s0_cannot_be_performance():
    attack, a = run(2, [0, 0, 0])
    with pytest.raises(ValueError, match="smoke-only"):
        evaluate_static_model(
            model(),
            [attack],
            {attack.run_id: a},
            config(),
            coverage_sha256_by_run={attack.run_id: "a" * 64},
            evaluation_horizon_sec=20,
            purpose="performance",
        )
