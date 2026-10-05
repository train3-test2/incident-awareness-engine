"""Static ML inference replay; never manufactures production FusionResult."""

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from incident_awareness.common.models.result import _serialize_utc_datetime
from incident_awareness.decision.fusion.stopping_policy import ScorePoint, ThresholdStoppingPolicy
from incident_awareness.evaluation.baselines.provenance import InputPoint
from incident_awareness.evaluation.baselines.static_ml import (
    FeatureRow,
    FrozenModel,
    Identifier,
    StaticModel,
    predict_static_model,
)


class TimedFeatureRow(FeatureRow):
    timestamp: datetime

    @field_validator("timestamp", mode="before")
    @classmethod
    def explicit_time(cls, value):
        return InputPoint.reject_numeric_time(value)

    @field_validator("timestamp")
    @classmethod
    def utc_time(cls, value):
        value = InputPoint.utc_only(value)
        if value.microsecond % 1000:
            raise ValueError("timestamp must have millisecond precision")
        return value


class EpisodeConfig(FrozenModel):
    policy_version: Identifier
    step_seconds: Annotated[int, Field(strict=True, gt=0)]
    threshold_on: Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
    threshold_off: Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]
    persistence_k: Annotated[int, Field(strict=True, ge=1)]

    @model_validator(mode="after")
    def valid_thresholds(self):
        if self.threshold_off >= self.threshold_on:
            raise ValueError("threshold_off must be below threshold_on")
        try:
            timedelta(seconds=self.step_seconds)
        except OverflowError as exc:
            raise ValueError("step_seconds exceeds supported range") from exc
        return self


def _hash(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def replay_static_model(
    model: StaticModel,
    rows: list[TimedFeatureRow],
    config: EpisodeConfig,
) -> dict:
    """Replay a single complete cadence grid; endpoints describe supplied replay only.

    Upstream observation coverage is not inferred. Empty, mixed and gapped inputs
    fail instead of creating a miss. No threshold tuning or labels are accepted.
    """
    config = EpisodeConfig.model_validate(config)
    rows = [TimedFeatureRow.model_validate(row) for row in rows]
    if not rows:
        raise ValueError("replay requires non-empty timed features")
    first = rows[0]
    if any((r.run_id, r.entity_id) != (first.run_id, first.entity_id) for r in rows):
        raise ValueError("replay requires one Run/entity")
    step = timedelta(seconds=config.step_seconds)
    if any(b.timestamp - a.timestamp != step for a, b in pairwise(rows)):
        raise ValueError("timestamps must follow the declared cadence without gaps")
    features = [FeatureRow.model_validate(r.model_dump(exclude={"timestamp"})) for r in rows]
    prediction = predict_static_model(model, features)
    points = [
        ScorePoint(r.timestamp, p["probability"])
        for r, p in zip(rows, prediction["predictions"], strict=True)
    ]
    result = ThresholdStoppingPolicy(
        threshold_on=config.threshold_on,
        threshold_off=config.threshold_off,
        persistence_k=config.persistence_k,
    ).evaluate(
        points,
        run_id=first.run_id,
        entity_id=first.entity_id,
        run_end=rows[-1].timestamp,
        boundary_end_reason="replay_end",
    )
    episodes = []
    sample_by_time = {r.timestamp: r.sample_id for r in rows}
    for episode in result.fusion_episodes:
        item = asdict(episode)
        item["start_time"] = _serialize_utc_datetime(episode.start_time)
        item["end_time"] = _serialize_utc_datetime(episode.end_time)
        item["source_sample_id"] = sample_by_time[episode.start_time]
        episodes.append(item)
    return {
        "schema_version": "static-ml-episodes-v0.1",
        "method": "StaticML",
        "run_id": first.run_id,
        "entity_id": first.entity_id,
        "model_sha256": prediction["model_sha256"],
        "input_sha256": _hash([r.model_dump(mode="json") for r in rows]),
        "config_sha256": _hash(config.model_dump(mode="json")),
        "config": config.model_dump(mode="json"),
        "replay_start": _serialize_utc_datetime(first.timestamp),
        "replay_end": _serialize_utc_datetime(rows[-1].timestamp),
        "status": result.fusion_status,
        "first_episode_time": _serialize_utc_datetime(result.fusion_time)
        if result.fusion_time
        else None,
        "episodes": episodes,
        "trajectory": [
            dict(p, timestamp=_serialize_utc_datetime(r.timestamp))
            for r, p in zip(rows, prediction["predictions"], strict=True)
        ],
    }
