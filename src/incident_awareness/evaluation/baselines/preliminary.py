"""Offline development fitting, deliberately separate from formal split/model contracts."""

import math
import warnings
from typing import Literal

import sklearn
from pydantic import Field, model_validator
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from incident_awareness.common.models.run import RunMetadata
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
from incident_awareness.evaluation.dataset_usage import UsagePolicy, usage_digest


class PreliminaryInventoryRun(FrozenModel):
    """Caller-verified actual allocation and exact training sample for one Run."""

    assignment: Literal["development", "train", "validation", "test"]
    row: TrainingRow


def preliminary_inventory_digest(inventory: list[PreliminaryInventoryRun]) -> str:
    """Pin actual allocations and samples in canonical Run order."""
    checked = [PreliminaryInventoryRun.model_validate(item) for item in inventory]
    return _digest(
        [item.model_dump(mode="json") for item in sorted(checked, key=lambda x: x.row.run_id)]
    )


class PreliminaryPlan(FrozenModel):
    """Exact Run membership and input/usage pins for one offline development execution."""

    schema_version: Literal["preliminary-training-plan-v0.1"] = "preliminary-training-plan-v0.1"
    purpose: Literal["offline_development_only"]
    feature_scope: Literal["whole_observation_binary_presence"]
    usage_record_sha256: Digest
    input_inventory_sha256: Digest
    run_ids: tuple[Identifier, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def valid_runs(self) -> "PreliminaryPlan":
        """Reject duplicate and malformed planned Run identifiers at load time."""
        if len(set(self.run_ids)) != len(self.run_ids):
            raise ValueError("duplicate planned Run")
        for run_id in self.run_ids:
            RunMetadata.validate_run_id(run_id)
        return self


class PreliminaryModel(FrozenModel):
    """Not accepted by the formal StaticModel loader; no invented split digest."""

    schema_version: Literal["preliminary-logistic-v0.1"] = "preliminary-logistic-v0.1"
    plan: PreliminaryPlan
    config: TrainingConfig
    feature_names: tuple[Identifier, ...] = Field(min_length=1)
    feature_config_version: Identifier
    coefficients: tuple[Finite, ...] = Field(min_length=1)
    intercept: Finite
    training_sha256: Digest
    sklearn_version: Identifier

    @model_validator(mode="after")
    def valid_contract(self) -> "PreliminaryModel":
        """Validate managed vocabulary and coefficient dimensions on construction/load."""
        FeatureRow.valid_names(self.feature_names)
        if len(self.feature_names) != len(self.coefficients):
            raise ValueError("coefficient dimensions mismatch")
        return self


def train_preliminary_model(
    rows: list[TrainingRow],
    plan: PreliminaryPlan,
    config: TrainingConfig,
    *,
    usage: UsagePolicy,
    inventory: list[PreliminaryInventoryRun],
) -> PreliminaryModel:
    """Fit one sample per explicitly permitted Run; do not claim validation or tuning."""
    plan = PreliminaryPlan.model_validate(plan.model_dump(mode="json"))
    config = TrainingConfig.model_validate(config.model_dump(mode="json"))
    rows = sorted(
        (TrainingRow.model_validate(row.model_dump(mode="json")) for row in rows),
        key=lambda row: row.sample_id,
    )
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
    usage = UsagePolicy.model_validate(usage)
    inventory = [PreliminaryInventoryRun.model_validate(item) for item in inventory]
    if usage_digest(usage) != plan.usage_record_sha256:
        raise ValueError("usage digest mismatch")
    if preliminary_inventory_digest(inventory) != plan.input_inventory_sha256:
        raise ValueError("inventory digest mismatch")
    if len(inventory) != len(rows) or {item.row.run_id for item in inventory} != set(plan.run_ids):
        raise ValueError("inventory must exactly cover planned Runs")
    inventory_rows = sorted((item.row for item in inventory), key=lambda row: row.sample_id)
    if inventory_rows != rows:
        raise ValueError("inventory training rows mismatch")
    permissions = {record.run_id: record for record in usage.runs}
    for item in inventory:
        record = permissions.get(item.row.run_id)
        if record is None:
            raise ValueError("missing Run usage permission")
        if item.assignment in ("validation", "test"):
            raise ValueError("holdout Run cannot be used for preliminary training")
        if not (record.used_for_tuning or "train" in record.eligible_splits):
            raise ValueError("Run usage does not permit training")
        if item.assignment == "train" and "train" not in record.eligible_splits:
            raise ValueError("tuning-only Run cannot be assigned to formal train")
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
        "input_sha256": _digest([row.model_dump(mode="json") for row in rows]),
        "probability_interpretation": "uncalibrated_P_label_1_not_attack_likelihood",
        "predictions": result,
        "performance_metrics": None,
    }
