"""GT-free preliminary inference and separately authorized offline scoring.

Digests pin canonical JSON, not ZIP bytes. Release authorization is supplied by
an external approval boundary; this module cannot authenticate a human approver.
"""

import math
from typing import Annotated, Literal

from pydantic import Field, model_validator

from incident_awareness.evaluation.baselines.preliminary import PreliminaryModel
from incident_awareness.evaluation.baselines.static_ml import (
    Binary,
    Digest,
    FeatureRow,
    FrozenModel,
    Identifier,
    _digest,
)

OpaqueId = Annotated[str, Field(strict=True, pattern=r"^EC-[0-9a-f]{16}$")]


class OpaqueFeatureRow(FrozenModel):
    item_id: OpaqueId
    feature_config_version: Identifier
    feature_names: tuple[Identifier, ...] = Field(min_length=1)
    values: tuple[Binary, ...] = Field(min_length=1)
    extraction_status: Literal["validated"]

    @model_validator(mode="after")
    def dimensions(self) -> "OpaqueFeatureRow":
        FeatureRow.valid_names(self.feature_names)
        if len(self.feature_names) != len(self.values):
            raise ValueError("feature dimensions mismatch")
        return self


class OpaquePlan(FrozenModel):
    schema_version: Literal["opaque-static-plan-v0.1"] = "opaque-static-plan-v0.1"
    purpose: Literal["offline_preliminary_development"]
    model_sha256: Digest
    feature_rows_sha256: Digest
    source_package_sha256: Digest
    code_sha256: Digest
    environment_sha256: Digest
    usage_approval_sha256: Digest
    label_policy_version: Identifier
    threshold: Literal[0.5] = 0.5
    item_ids: tuple[OpaqueId, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique(self) -> "OpaquePlan":
        if len(set(self.item_ids)) != len(self.item_ids):
            raise ValueError("duplicate planned item")
        return self


def feature_rows_digest(rows: list[OpaqueFeatureRow]) -> str:
    checked = [OpaqueFeatureRow.model_validate(r) for r in rows]
    if not checked or len({r.item_id for r in checked}) != len(checked):
        raise ValueError("empty or duplicate feature items")
    return _digest([r.model_dump(mode="json") for r in sorted(checked, key=lambda r: r.item_id)])


def infer_opaque(model: PreliminaryModel, rows: list[OpaqueFeatureRow], plan: OpaquePlan) -> dict:
    """No GT, Run-ID synthesis, replay or formal-performance eligibility."""
    model = PreliminaryModel.model_validate(model)
    plan = OpaquePlan.model_validate(plan)
    rows = [OpaqueFeatureRow.model_validate(r) for r in rows]
    if _digest(model.model_dump(mode="json")) != plan.model_sha256:
        raise ValueError("model digest mismatch")
    if model.config.label_policy_version != plan.label_policy_version:
        raise ValueError("label policy mismatch")
    if feature_rows_digest(rows) != plan.feature_rows_sha256:
        raise ValueError("feature rows digest mismatch")
    if {r.item_id for r in rows} != set(plan.item_ids):
        raise ValueError("item membership mismatch")
    predictions = []
    for row in sorted(rows, key=lambda r: r.item_id):
        if (row.feature_names, row.feature_config_version) != (
            model.feature_names,
            model.feature_config_version,
        ):
            raise ValueError("feature contract mismatch")
        score = math.fsum(
            [model.intercept, *(w * x for w, x in zip(model.coefficients, row.values, strict=True))]
        )
        if not math.isfinite(score):
            raise ValueError("nonfinite logit")
        p = 1 / (1 + math.exp(-score)) if score >= 0 else math.exp(score) / (1 + math.exp(score))
        predictions.append({"item_id": row.item_id, "probability": p, "label": int(p >= 0.5)})
    return {
        "schema_version": "opaque-static-predictions-v0.1",
        "plan_sha256": _digest(plan.model_dump(mode="json")),
        "purpose": plan.purpose,
        "probability_interpretation": "uncalibrated_P_label_1_not_attack_likelihood",
        "training_overlap": "unknown_until_mapping_release",
        "predictions": predictions,
    }


class ReleasedLabel(FrozenModel):
    item_id: OpaqueId
    label: Binary


class ScoringRelease(FrozenModel):
    prediction_sha256: Digest
    labels_sha256: Digest
    approval_record_sha256: Digest
    label_policy_version: Identifier
    authorization: Literal["approved_offline_preliminary_scoring"]


def score_opaque(
    model: PreliminaryModel,
    rows: list[OpaqueFeatureRow],
    plan: OpaquePlan,
    predictions: dict,
    labels: list[ReleasedLabel],
    release: ScoringRelease,
) -> dict:
    """Verify frozen predictions before joining externally released labels by opaque ID."""
    plan = OpaquePlan.model_validate(plan)
    release = ScoringRelease.model_validate(release)
    if release.label_policy_version != plan.label_policy_version:
        raise ValueError("released label policy mismatch")
    if _digest(predictions) != release.prediction_sha256:
        raise ValueError("prediction digest mismatch")
    if predictions != infer_opaque(model, rows, plan):
        raise ValueError("predictions do not match frozen inference")
    labels = [ReleasedLabel.model_validate(x) for x in labels]
    if len({x.item_id for x in labels}) != len(labels):
        raise ValueError("duplicate released label")
    if {x.item_id for x in labels} != set(plan.item_ids):
        raise ValueError("released label membership mismatch")
    canonical = [x.model_dump(mode="json") for x in sorted(labels, key=lambda x: x.item_id)]
    if _digest(canonical) != release.labels_sha256:
        raise ValueError("labels digest mismatch")
    gt = {x.item_id: x.label for x in labels}
    counts = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for p in predictions["predictions"]:
        counts[
            {(1, 1): "tp", (1, 0): "fn", (0, 1): "fp", (0, 0): "tn"}[gt[p["item_id"]], p["label"]]
        ] += 1
    positive, negative = counts["tp"] + counts["fn"], counts["fp"] + counts["tn"]
    return {
        "purpose": plan.purpose,
        "counts": counts,
        "attack_items": positive,
        "normal_items": negative,
        "recall": counts["tp"] / positive if positive else None,
        "fpr": counts["fp"] / negative if negative else None,
        "ttsd": None,
        "fa_bh": None,
        "holdout_final_eligible": False,
        "release_sha256": _digest(release.model_dump(mode="json")),
        "prediction_sha256": release.prediction_sha256,
    }
