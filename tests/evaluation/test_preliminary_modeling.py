"""Offline development models must not masquerade as formal evaluation models."""

import pytest
from pydantic import ValidationError

from incident_awareness.evaluation.baselines.preliminary import (
    PreliminaryPlan,
    predict_preliminary_model,
    train_preliminary_model,
)
from incident_awareness.evaluation.baselines.static_ml import (
    FeatureRow,
    StaticModel,
    TrainingConfig,
    TrainingRow,
)


def inputs():
    """Return a synthetic two-class development pool with explicit pins."""
    rows = [
        TrainingRow(
            sample_id=f"sample-{i}",
            run_id=f"RUN-20300101-00{i + 1}",
            entity_id="HOST",
            feature_config_version="presence-v1",
            feature_names=("remote_session_process_lineage_deviation",),
            values=(i,),
            label=i,
        )
        for i in range(2)
    ]
    plan = PreliminaryPlan(
        purpose="offline_development_only",
        feature_scope="whole_observation_binary_presence",
        usage_record_sha256="a" * 64,
        input_inventory_sha256="b" * 64,
        run_ids=tuple(r.run_id for r in rows),
    )
    config = TrainingConfig(
        model_version="demo-v1",
        label_policy_version="run-label-v1",
        c=1.0,
        tolerance=1e-8,
        max_iter=1000,
    )
    return rows, plan, config


def test_fit_is_deterministic_and_not_a_formal_model():
    """Ordering cannot change a fit and formal loaders reject the result."""
    rows, plan, config = inputs()
    model = train_preliminary_model(rows, plan, config)
    assert model == train_preliminary_model(rows[::-1], plan, config)
    result = predict_preliminary_model(
        model, [FeatureRow.model_validate(r.model_dump(exclude={"label"})) for r in rows]
    )
    assert result["performance_metrics"] is None
    assert all(r["training_overlap"] for r in result["predictions"])
    assert result["predictions"][0]["probability"] < result["predictions"][1]["probability"]
    with pytest.raises(ValidationError):
        StaticModel.model_validate(model.model_dump(mode="json"))


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "labels", "features", "extra"])
def test_invalid_training_membership_or_contract_is_rejected(mutation):
    """Missing, duplicated, unplanned or incompatible samples cannot be fitted."""
    rows, plan, config = inputs()
    if mutation == "missing":
        rows = rows[:1]
    elif mutation == "duplicate":
        rows = [rows[0], rows[0]]
    elif mutation == "labels":
        rows[1] = rows[1].model_copy(update={"label": 0})
    elif mutation == "features":
        rows[1] = rows[1].model_copy(update={"feature_config_version": "other"})
    else:
        rows[1] = rows[1].model_copy(update={"run_id": "RUN-20300101-099"})
    with pytest.raises(ValueError):
        train_preliminary_model(rows, plan, config)


def test_purpose_cannot_be_promoted():
    """Changing the permission scope to final evaluation is rejected."""
    _, plan, _ = inputs()
    with pytest.raises(ValidationError):
        PreliminaryPlan.model_validate({**plan.model_dump(), "purpose": "final_evaluation"})
