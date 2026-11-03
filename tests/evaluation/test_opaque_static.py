"""Synthetic fixtures only: never open sealed evaluation candidates."""

import pytest
from pydantic import ValidationError
from test_preliminary_modeling import inputs

from incident_awareness.evaluation.baselines.opaque import (
    OpaqueFeatureRow,
    OpaquePlan,
    ReleasedLabel,
    ScoringRelease,
    feature_rows_digest,
    infer_opaque,
    score_opaque,
)
from incident_awareness.evaluation.baselines.preliminary import train_preliminary_model
from incident_awareness.evaluation.baselines.static_ml import _digest


@pytest.fixture
def bundle():
    training, training_plan, config, permissions = inputs()
    model = train_preliminary_model(training, training_plan, config, **permissions)
    rows = [
        OpaqueFeatureRow(
            item_id=f"EC-{i:016x}",
            feature_config_version=r.feature_config_version,
            feature_names=r.feature_names,
            values=r.values,
            extraction_status="validated",
        )
        for i, r in enumerate(training)
    ]
    plan = OpaquePlan(
        purpose="offline_preliminary_development",
        model_sha256=_digest(model.model_dump(mode="json")),
        feature_rows_sha256=feature_rows_digest(rows),
        source_package_sha256="a" * 64,
        code_sha256="b" * 64,
        environment_sha256="c" * 64,
        usage_approval_sha256="d" * 64,
        label_policy_version=config.label_policy_version,
        item_ids=tuple(r.item_id for r in rows),
    )
    predictions = infer_opaque(model, rows, plan)
    labels = [ReleasedLabel(item_id=r.item_id, label=i) for i, r in enumerate(rows)]
    release = ScoringRelease(
        prediction_sha256=_digest(predictions),
        labels_sha256=_digest([x.model_dump(mode="json") for x in labels]),
        approval_record_sha256="e" * 64,
        label_policy_version=config.label_policy_version,
        authorization="approved_offline_preliminary_scoring",
    )
    return model, rows, plan, predictions, labels, release


def test_round_trip_and_order_independence(bundle):
    model, rows, plan, predictions, labels, release = bundle
    assert infer_opaque(model, rows[::-1], plan) == predictions
    result = score_opaque(model, rows, plan, predictions, labels[::-1], release)
    assert result["counts"] == {"tp": 1, "tn": 1, "fp": 0, "fn": 0}
    assert result["recall"] == result["fpr"] + 1 == 1
    assert result["ttsd"] is None and not result["holdout_final_eligible"]
    assert predictions["training_overlap"] == "unknown_until_mapping_release"


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "RUN-20300101-001"),
        ("label", 1),
        ("extraction_status", "selector_failed"),
        ("values", [True]),
        ("values", [2]),
        ("item_id", "RUN-20300101-001"),
    ],
)
def test_reject_invalid_or_gt_fields(bundle, field, value):
    row = bundle[1][0].model_dump()
    row[field] = value
    with pytest.raises(ValidationError):
        OpaqueFeatureRow.model_validate(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_sha256", "f" * 64),
        ("feature_rows_sha256", "f" * 64),
        ("label_policy_version", "different"),
        ("item_ids", ("EC-ffffffffffffffff",)),
    ],
)
def test_reject_plan_mismatch(bundle, field, value):
    model, rows, plan, *_ = bundle
    changed = OpaquePlan.model_validate({**plan.model_dump(), field: value})
    with pytest.raises(ValueError):
        infer_opaque(model, rows, changed)


def test_reject_duplicate_missing_or_tampered_predictions(bundle):
    model, rows, plan, predictions, labels, release = bundle
    for bad_rows in [rows[:1], rows + rows[:1]]:
        with pytest.raises(ValueError):
            infer_opaque(model, bad_rows, plan)
    predictions["predictions"][0]["label"] = 1
    with pytest.raises(ValueError, match="prediction digest"):
        score_opaque(model, rows, plan, predictions, labels, release)
    forged = release.model_copy(update={"prediction_sha256": _digest(predictions)})
    with pytest.raises(ValueError, match="frozen inference"):
        score_opaque(model, rows, plan, predictions, labels, forged)


def test_labels_must_exactly_match_and_be_pinned(bundle):
    model, rows, plan, predictions, labels, release = bundle
    for bad in [
        labels[:1],
        labels + labels[:1],
        [labels[0], ReleasedLabel(item_id=labels[1].item_id, label=0)],
    ]:
        with pytest.raises(ValueError):
            score_opaque(model, rows, plan, predictions, bad, release)


def test_threshold_tie_and_single_class_scoring(bundle):
    model, rows, plan, _, _, _ = bundle
    model = model.model_copy(update={"coefficients": (0.0,), "intercept": 0.0})
    plan = plan.model_copy(update={"model_sha256": _digest(model.model_dump(mode="json"))})
    predictions = infer_opaque(model, rows, plan)
    assert all(p["probability"] == 0.5 and p["label"] == 1 for p in predictions["predictions"])
    labels = [ReleasedLabel(item_id=r.item_id, label=1) for r in rows]
    release = ScoringRelease(
        prediction_sha256=_digest(predictions),
        labels_sha256=_digest([x.model_dump(mode="json") for x in labels]),
        approval_record_sha256="e" * 64,
        label_policy_version=plan.label_policy_version,
        authorization="approved_offline_preliminary_scoring",
    )
    assert score_opaque(model, rows, plan, predictions, labels, release)["fpr"] is None
