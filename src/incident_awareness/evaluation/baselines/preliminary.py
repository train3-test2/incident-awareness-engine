"""Offline development fitting, deliberately separate from formal split/model contracts."""

import math
import warnings
from typing import Literal

import sklearn
from pydantic import Field
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from incident_awareness.evaluation.baselines.static_ml import (
    Digest,
    FeatureRow,
    Finite,
    FrozenModel,
    Identifier,
    TrainingConfig,
    TrainingRow,
    _digest,
)


class PreliminaryPlan(FrozenModel):
    """Exact Run membership and input/usage pins for one offline development execution."""

    schema_version: Literal["preliminary-training-plan-v0.1"] = "preliminary-training-plan-v0.1"
    purpose: Literal["offline_development_only"]
    feature_scope: Literal["whole_observation_binary_presence"]
    usage_record_sha256: Digest
    input_inventory_sha256: Digest
    run_ids: tuple[Identifier, ...] = Field(min_length=2)


class PreliminaryModel(FrozenModel):
    """Not accepted by the formal StaticModel loader; no invented split digest."""

    schema_version: Literal["preliminary-logistic-v0.1"] = "preliminary-logistic-v0.1"
    plan: PreliminaryPlan
    config: TrainingConfig
    feature_names: tuple[Identifier, ...]
    feature_config_version: Identifier
    coefficients: tuple[Finite, ...]
    intercept: Finite
    training_sha256: Digest
    sklearn_version: Identifier


def train_preliminary_model(
    rows: list[TrainingRow], plan: PreliminaryPlan, config: TrainingConfig
) -> PreliminaryModel:
    """Fit one sample per explicitly permitted Run; do not claim validation or tuning."""
    plan = PreliminaryPlan.model_validate(plan.model_dump(mode="json"))
    config = TrainingConfig.model_validate(config.model_dump(mode="json"))
    rows = sorted(
        (TrainingRow.model_validate(row.model_dump(mode="json")) for row in rows),
        key=lambda row: row.sample_id,
    )
    if len(set(plan.run_ids)) != len(plan.run_ids):
        raise ValueError("duplicate planned Run")
    if len(rows) != len(plan.run_ids) or {row.run_id for row in rows} != set(plan.run_ids):
        raise ValueError("exactly one row per planned Run required")
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("duplicate sample_id")
    if {row.label for row in rows} != {0, 1}:
        raise ValueError("both labels required")
    first = rows[0]
    if any(
        (r.feature_names, r.feature_config_version)
        != (first.feature_names, first.feature_config_version)
        for r in rows
    ):
        raise ValueError("feature contract mismatch")
    estimator = LogisticRegression(
        solver="lbfgs",
        C=config.c,
        tol=config.tolerance,
        max_iter=config.max_iter,
        fit_intercept=True,
        class_weight=None,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        try:
            estimator.fit([r.values for r in rows], [r.label for r in rows])
        except ConvergenceWarning as exc:
            raise ValueError("training did not converge") from exc
    return PreliminaryModel(
        plan=plan,
        config=config,
        feature_names=first.feature_names,
        feature_config_version=first.feature_config_version,
        coefficients=tuple(float(x) for x in estimator.coef_[0]),
        intercept=float(estimator.intercept_[0]),
        training_sha256=_digest([r.model_dump(mode="json") for r in rows]),
        sklearn_version=sklearn.__version__,
    )


def predict_preliminary_model(model: PreliminaryModel, rows: list[FeatureRow]) -> dict:
    """Return offline probabilities, with explicit training overlap and no metric claim."""
    model = PreliminaryModel.model_validate(model.model_dump(mode="json"))
    if len(model.coefficients) != len(model.feature_names):
        raise ValueError("coefficient dimensions mismatch")
    rows = [FeatureRow.model_validate(r.model_dump(mode="json")) for r in rows]
    if len({r.sample_id for r in rows}) != len(rows):
        raise ValueError("duplicate sample_id")
    result = []
    for row in rows:
        if (row.feature_names, row.feature_config_version) != (
            model.feature_names,
            model.feature_config_version,
        ):
            raise ValueError("feature contract mismatch")
        score = math.fsum(
            [model.intercept, *(w * x for w, x in zip(model.coefficients, row.values, strict=True))]
        )
        probability = (
            1 / (1 + math.exp(-score)) if score >= 0 else math.exp(score) / (1 + math.exp(score))
        )
        result.append(
            {
                "run_id": row.run_id,
                "sample_id": row.sample_id,
                "entity_id": row.entity_id,
                "probability": probability,
                "training_overlap": row.run_id in model.plan.run_ids,
            }
        )
    return {
        "purpose": "offline_development_only",
        "model_sha256": _digest(model.model_dump(mode="json")),
        "predictions": result,
        "performance_metrics": None,
    }
