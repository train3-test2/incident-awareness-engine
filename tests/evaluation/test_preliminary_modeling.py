"""Offline development models must not masquerade as formal evaluation models."""

import warnings

import pytest
from pydantic import ValidationError
from sklearn.exceptions import ConvergenceWarning

from incident_awareness.evaluation.baselines.preliminary import (
    PreliminaryInventoryRun,
    PreliminaryModel,
    PreliminaryPlan,
    predict_preliminary_model,
    preliminary_inventory_digest,
    train_preliminary_model,
)
from incident_awareness.evaluation.baselines.static_ml import (
    FeatureRow,
    StaticModel,
    TrainingConfig,
    TrainingRow,
)
from incident_awareness.evaluation.dataset_usage import RunUsage, UsagePolicy, usage_digest


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
    usage = UsagePolicy(
        schema_version="dataset-usage-v0.1",
        policy_version="usage-v1",
        source_sha256=("a" * 64,),
        runs=tuple(
            RunUsage(
                run_id=r.run_id,
                pair_id=None,
                eligible_splits=("train", "validation", "test"),
                used_for_tuning=False,
                reason="synthetic",
            )
            for r in rows
        ),
    )
    inventory = [PreliminaryInventoryRun(assignment="development", row=r) for r in rows]
    plan = PreliminaryPlan(
        purpose="offline_development_only",
        feature_scope="whole_observation_binary_presence",
        usage_record_sha256=usage_digest(usage),
        input_inventory_sha256=preliminary_inventory_digest(inventory),
        run_ids=tuple(r.run_id for r in rows),
    )
    config = TrainingConfig(
        model_version="demo-v1",
        label_policy_version="run-label-v1",
        c=1.0,
        tolerance=1e-8,
        max_iter=1000,
    )
    return rows, plan, config, {"usage": usage, "inventory": inventory}


def test_fit_is_deterministic_and_not_a_formal_model():
    # Given
    rows, plan, config, permissions = inputs()
    # When
    model = train_preliminary_model(rows, plan, config, **permissions)
    reordered = train_preliminary_model(rows[::-1], plan, config, **permissions)
    result = predict_preliminary_model(
        model, [FeatureRow.model_validate(r.model_dump(exclude={"label"})) for r in rows]
    )
    with pytest.raises(ValidationError) as error:
        StaticModel.model_validate(model.model_dump(mode="json"))
    # Then
    assert model == reordered
    assert result["performance_metrics"] is None
    assert all(r["training_overlap"] for r in result["predictions"])
    assert result["predictions"][0]["probability"] < result["predictions"][1]["probability"]
    assert result["probability_interpretation"] == "uncalibrated_P_label_1_not_attack_likelihood"
    assert "validation error" in str(error.value)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("missing", "one row"),
        ("duplicate", "one row"),
        ("labels", "both labels"),
        ("features", "feature contract"),
        ("extra", "one row"),
        ("sample_id", "duplicate sample_id"),
    ],
)
def test_invalid_training_membership_or_contract_is_rejected(mutation, message):
    # Given
    rows, plan, config, permissions = inputs()
    if mutation == "missing":
        rows = rows[:1]
    elif mutation == "duplicate":
        rows = [rows[0], rows[0]]
    else:
        updates = {
            "labels": {"label": 0},
            "features": {"feature_config_version": "other"},
            "extra": {"run_id": "RUN-20300101-099"},
            "sample_id": {"sample_id": rows[0].sample_id},
        }
        rows[1] = rows[1].model_copy(update=updates[mutation])
    # When
    with pytest.raises(ValueError) as error:
        train_preliminary_model(rows, plan, config, **permissions)
    # Then
    assert message in str(error.value)


@pytest.mark.parametrize(
    "update, message",
    [
        ({"purpose": "final_evaluation"}, "purpose"),
        ({"run_ids": ("RUN-20300101-001",) * 2}, "duplicate planned Run"),
    ],
)
def test_invalid_plan_is_rejected(update, message):
    # Given
    _, plan, _, _ = inputs()
    data = {**plan.model_dump(), **update}
    # When
    with pytest.raises(ValidationError) as error:
        PreliminaryPlan.model_validate(data)
    # Then
    assert message in str(error.value)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("usage_pin", "usage digest"),
        ("missing", "missing Run usage"),
        ("denied", "does not permit"),
        ("validation", "holdout Run"),
        ("test", "holdout Run"),
        ("tuning_holdout", "holdout Run"),
        ("inventory_pin", "inventory digest"),
        ("inventory_rows", "inventory training rows"),
        ("inventory_missing", "exactly cover"),
    ],
)
def test_training_permission_and_inventory_guards(mutation, message):
    # Given
    rows, plan, config, permissions = inputs()
    usage = permissions["usage"]
    inventory = permissions["inventory"]
    if mutation == "missing":
        usage = usage.model_copy(update={"runs": usage.runs[:1]})
    elif mutation in ("denied", "tuning_holdout"):
        record = usage.runs[0].model_copy(
            update={"eligible_splits": (), "used_for_tuning": mutation == "tuning_holdout"}
        )
        usage = usage.model_copy(update={"runs": (record, usage.runs[1])})
    if mutation in ("validation", "test", "tuning_holdout"):
        inventory[0] = inventory[0].model_copy(
            update={"assignment": "test" if mutation == "tuning_holdout" else mutation}
        )
    elif mutation == "inventory_rows":
        inventory[0] = inventory[0].model_copy(
            update={"row": rows[0].model_copy(update={"entity_id": "OTHER"})}
        )
    elif mutation == "inventory_missing":
        inventory = inventory[:1]
    plan = plan.model_copy(
        update={
            "usage_record_sha256": "f" * 64 if mutation == "usage_pin" else usage_digest(usage),
            "input_inventory_sha256": "f" * 64
            if mutation == "inventory_pin"
            else preliminary_inventory_digest(inventory),
        }
    )
    # When
    with pytest.raises(ValueError) as error:
        train_preliminary_model(rows, plan, config, usage=usage, inventory=inventory)
    # Then
    assert message in str(error.value)


def test_tuning_only_development_is_permitted():
    # Given
    rows, plan, config, permissions = inputs()
    usage = permissions["usage"].model_copy(
        update={
            "runs": tuple(
                r.model_copy(update={"eligible_splits": (), "used_for_tuning": True})
                for r in permissions["usage"].runs
            )
        }
    )
    plan = plan.model_copy(update={"usage_record_sha256": usage_digest(usage)})
    # When
    model = train_preliminary_model(
        rows, plan, config, usage=usage, inventory=permissions["inventory"]
    )
    # Then
    assert model.plan == plan


@pytest.mark.parametrize(
    "names, coefficients, message",
    [
        ((), (), "at least 1"),
        (("remote_session_process_lineage_deviation",) * 2, (1.0, 1.0), "duplicate feature"),
        (("not_managed",), (1.0,), "not_managed"),
        (("remote_session_process_lineage_deviation",), (1.0, 2.0), "coefficient dimensions"),
    ],
)
def test_model_load_rejects_invalid_contract(names, coefficients, message):
    # Given
    rows, plan, config, permissions = inputs()
    model = train_preliminary_model(rows, plan, config, **permissions)
    data = model.model_dump(mode="json") | {"feature_names": names, "coefficients": coefficients}
    # When
    with pytest.raises(ValueError) as error:
        PreliminaryModel.model_validate(data)
    # Then
    assert message in str(error.value)


@pytest.mark.parametrize("mutation", ["order", "version"])
def test_prediction_rejects_feature_contract_mismatch(mutation):
    # Given
    rows, plan, config, permissions = inputs()
    model = train_preliminary_model(rows, plan, config, **permissions).model_copy(
        update={
            "feature_names": (
                "remote_session_process_lineage_deviation",
                "remote_process_network_follow_on",
            ),
            "coefficients": (1.0, 1.0),
        }
    )
    row = FeatureRow(
        sample_id="p",
        run_id=rows[0].run_id,
        entity_id="HOST",
        feature_config_version="other" if mutation == "version" else model.feature_config_version,
        feature_names=model.feature_names[::-1] if mutation == "order" else model.feature_names,
        values=(0, 1),
    )
    # When
    with pytest.raises(ValueError) as error:
        predict_preliminary_model(model, [row])
    # Then
    assert "feature contract mismatch" in str(error.value)


def test_convergence_failure_is_rejected(monkeypatch):
    # Given
    rows, plan, config, permissions = inputs()

    def fail_fit(*args, **kwargs):
        warnings.warn("synthetic non-convergence", ConvergenceWarning)

    monkeypatch.setattr(
        "incident_awareness.evaluation.baselines.preliminary.LogisticRegression.fit", fail_fit
    )
    # When
    with pytest.raises(ValueError) as error:
        train_preliminary_model(rows, plan, config, **permissions)
    # Then
    assert "training did not converge" in str(error.value)


def test_prediction_input_digest_tracks_validated_rows():
    # Given
    rows, plan, config, permissions = inputs()
    model = train_preliminary_model(rows, plan, config, **permissions)
    features = [FeatureRow.model_validate(r.model_dump(exclude={"label"})) for r in rows]
    changed = [features[0].model_copy(update={"values": (1,)}), features[1]]
    # When
    original = predict_preliminary_model(model, features)
    repeated = predict_preliminary_model(model, features)
    different = predict_preliminary_model(model, changed)
    # Then
    assert original["input_sha256"] == repeated["input_sha256"]
    assert original["input_sha256"] != different["input_sha256"]
    assert original["model_sha256"] == different["model_sha256"]


@pytest.mark.parametrize("missing", ["usage", "inventory"])
def test_training_requires_permission_inputs(missing):
    # Given
    rows, plan, config, permissions = inputs()
    del permissions[missing]
    # When
    with pytest.raises(TypeError) as error:
        train_preliminary_model(rows, plan, config, **permissions)
    # Then
    assert missing in str(error.value)


def test_tuning_only_cannot_be_formal_train():
    # Given
    rows, plan, config, permissions = inputs()
    usage = permissions["usage"].model_copy(
        update={
            "runs": tuple(
                r.model_copy(update={"eligible_splits": (), "used_for_tuning": True})
                for r in permissions["usage"].runs
            )
        }
    )
    inventory = [
        item.model_copy(update={"assignment": "train"}) for item in permissions["inventory"]
    ]
    plan = plan.model_copy(
        update={
            "usage_record_sha256": usage_digest(usage),
            "input_inventory_sha256": preliminary_inventory_digest(inventory),
        }
    )
    # When
    with pytest.raises(ValueError) as error:
        train_preliminary_model(rows, plan, config, usage=usage, inventory=inventory)
    # Then
    assert "tuning-only Run cannot be assigned to formal train" in str(error.value)
