"""Train-only binary logistic baseline with portable JSON inference."""

import hashlib
import json
import math
import warnings
from typing import Annotated, Literal

import sklearn
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import validate_managed_evidence_types
from incident_awareness.evaluation.split_manifest import SplitManifest, audit_split_manifest

Identifier = Annotated[str, Field(strict=True, min_length=1, pattern=r"^\S(?:.*\S)?$")]
Finite = Annotated[float, Field(strict=True, allow_inf_nan=False)]
Positive = Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
Binary = Annotated[int, Field(strict=True, ge=0, le=1)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")


class FeatureRow(FrozenModel):
    sample_id: Identifier
    run_id: Identifier
    entity_id: Identifier
    feature_config_version: Identifier
    feature_names: tuple[Identifier, ...] = Field(min_length=1)
    values: tuple[Binary, ...] = Field(min_length=1)

    @field_validator("run_id")
    @classmethod
    def valid_run(cls, value: str) -> str:
        return RunMetadata.validate_run_id(value)

    @field_validator("feature_names")
    @classmethod
    def valid_names(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        if len(names) != len(set(names)):
            raise ValueError("duplicate feature names")
        validate_managed_evidence_types(names)
        return names

    @model_validator(mode="after")
    def valid_dimensions(self) -> "FeatureRow":
        if len(self.values) != len(self.feature_names):
            raise ValueError("feature dimensions do not match")
        return self


class TrainingRow(FeatureRow):
    label: Binary


class TrainingConfig(FrozenModel):
    model_version: Identifier
    label_policy_version: Identifier
    c: Positive
    tolerance: Positive
    max_iter: Annotated[int, Field(strict=True, gt=0)]


class StaticModel(FrozenModel):
    schema_version: Literal["static-logistic-v0.1"] = "static-logistic-v0.1"
    feature_names: tuple[Identifier, ...] = Field(min_length=1)
    feature_config_version: Identifier
    coefficients: tuple[Finite, ...] = Field(min_length=1)
    intercept: Finite
    config: TrainingConfig
    sklearn_version: Identifier
    training_sha256: Digest
    split_sha256: Digest
    training_run_ids: tuple[Identifier, ...] = Field(min_length=1)
    training_row_count: Annotated[int, Field(strict=True, ge=2)]

    @model_validator(mode="after")
    def valid_contract(self) -> "StaticModel":
        FeatureRow.valid_names(self.feature_names)
        if len(self.feature_names) != len(self.coefficients):
            raise ValueError("coefficient dimensions do not match")
        if len(set(self.training_run_ids)) != len(self.training_run_ids):
            raise ValueError("duplicate training Run")
        if len(self.training_run_ids) > self.training_row_count:
            raise ValueError("training Run count exceeds row count")
        for run_id in self.training_run_ids:
            RunMetadata.validate_run_id(run_id)
        return self


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def train_static_model(
    rows: list[TrainingRow], manifest: SplitManifest, config: TrainingConfig
) -> StaticModel:
    """Reject non-train rows; require both labels and every declared train Run."""
    config = TrainingConfig.model_validate(config)
    audit = audit_split_manifest(manifest)
    rows = [TrainingRow.model_validate(row) for row in rows]
    if not rows:
        raise ValueError("training rows must not be empty")
    rows.sort(key=lambda row: row.sample_id)
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("duplicate sample_id")
    train_ids = set(audit["splits"]["train"]["run_ids"])
    if {row.run_id for row in rows} != train_ids:
        raise ValueError("training rows must exactly cover train Runs; no validation/test rows")
    if {row.label for row in rows} != {0, 1}:
        raise ValueError("training requires both binary labels")
    first = rows[0]
    if any(
        (row.feature_names, row.feature_config_version)
        != (first.feature_names, first.feature_config_version)
        for row in rows
    ):
        raise ValueError("training feature contract mismatch")
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
            estimator.fit([row.values for row in rows], [row.label for row in rows])
        except ConvergenceWarning as exc:
            raise ValueError("training did not converge; model was not produced") from exc
    return StaticModel(
        feature_names=first.feature_names,
        feature_config_version=first.feature_config_version,
        coefficients=tuple(float(value) for value in estimator.coef_[0]),
        intercept=float(estimator.intercept_[0]),
        config=config,
        sklearn_version=sklearn.__version__,
        training_sha256=_digest([row.model_dump(mode="json") for row in rows]),
        split_sha256=audit["manifest_sha256"],
        training_run_ids=tuple(sorted(train_ids)),
        training_row_count=len(rows),
    )


def predict_static_model(model: StaticModel, rows: list[FeatureRow]) -> dict:
    """Emit P(label=1); thresholds/episodes and evaluation stay downstream."""
    model = StaticModel.model_validate(model)
    rows = [FeatureRow.model_validate(row) for row in rows]
    if len({row.sample_id for row in rows}) != len(rows):
        raise ValueError("duplicate sample_id")
    predictions = []
    for row in rows:
        if (row.feature_names, row.feature_config_version) != (
            model.feature_names,
            model.feature_config_version,
        ):
            raise ValueError("inference feature contract mismatch")
        score = math.fsum(
            [model.intercept, *(w * x for w, x in zip(model.coefficients, row.values, strict=True))]
        )
        probability = (
            1 / (1 + math.exp(-score)) if score >= 0 else math.exp(score) / (1 + math.exp(score))
        )
        predictions.append(
            {
                "sample_id": row.sample_id,
                "run_id": row.run_id,
                "entity_id": row.entity_id,
                "probability": probability,
            }
        )
    return {
        "model_sha256": _digest(model.model_dump(mode="json")),
        "input_sha256": _digest([row.model_dump(mode="json") for row in rows]),
        "predictions": predictions,
    }
