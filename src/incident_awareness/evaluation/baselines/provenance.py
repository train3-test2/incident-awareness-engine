"""Reproducible statistical runs; separate from production FusionResult."""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.stopping_policy import ScorePoint
from incident_awareness.evaluation.baselines.statistical import cusum_trajectory, ewma_trajectory

Identifier = Annotated[str, StringConstraints(min_length=1, pattern=r"^\S(?:.*\S)?$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Unit = Annotated[float, Field(strict=True, ge=0, le=1, allow_inf_nan=False)]


class FrozenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InputPoint(FrozenRecord):
    timestamp: datetime
    score: Unit
    evidence_ids: tuple[Identifier, ...]

    @field_validator("timestamp", mode="before")
    @classmethod
    def reject_numeric_time(cls, value: object) -> object:
        if not isinstance(value, (datetime, str)):
            # Pydantic converts ValueError into a field-level ValidationError.
            raise ValueError("timestamp must be an explicit UTC datetime or ISO string")  # noqa: TRY004
        if isinstance(value, str) and "T" not in value:
            raise ValueError("timestamp must be an ISO datetime string")
        return value

    @field_validator("timestamp")
    @classmethod
    def utc_only(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be timezone-aware UTC")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def canonical_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))


class StatisticalInput(FrozenRecord):
    run_id: Identifier
    entity_id: Identifier
    input_config_version: Identifier
    source_artifact_sha256: Digest
    points: tuple[InputPoint, ...] = Field(min_length=1)

    @field_validator("run_id")
    @classmethod
    def canonical_run_id(cls, value: str) -> str:
        return RunMetadata.validate_run_id(value)


class StatisticalConfig(FrozenRecord):
    method: Literal["ewma", "cusum"]
    config_version: Identifier
    calibration_sha256: Digest
    step_seconds: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)]
    baseline_mean: Unit
    alpha: Unit | None = None
    allowance: Annotated[float, Field(strict=True, ge=0, allow_inf_nan=False)] | None = None
    scale: Annotated[float, Field(strict=True, gt=0, allow_inf_nan=False)] | None = None

    @model_validator(mode="after")
    def method_parameters(self) -> "StatisticalConfig":
        if self.method == "ewma":
            if (
                self.alpha is None
                or self.alpha == 0
                or self.allowance is not None
                or self.scale is not None
            ):
                raise ValueError("EWMA requires alpha > 0 and forbids allowance/scale")
        elif self.alpha is not None or self.allowance is None or self.scale is None:
            raise ValueError("CUSUM requires allowance/scale and forbids alpha")
        return self


def _digest(record: BaseModel) -> str:
    serialized = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def run_statistical_comparison(
    source: StatisticalInput, config: StatisticalConfig
) -> dict[str, object]:
    """Return JSON-serializable inputs, settings and output without inventing evidence attribution.

    Artifact/calibration hashes are caller-supplied references, not verification
    of files on disk. Input/config hashes below cover the actual embedded data.
    """
    # Revalidate even instances created through Pydantic's unchecked model_copy/construct.
    source = StatisticalInput.model_validate(source.model_dump(mode="json"))
    config = StatisticalConfig.model_validate(config.model_dump(mode="json"))
    points = [ScorePoint(point.timestamp, point.score) for point in source.points]
    common = {
        "baseline_mean": config.baseline_mean,
        "step_size": timedelta(seconds=config.step_seconds),
    }
    if config.method == "ewma":
        output = ewma_trajectory(points, alpha=config.alpha, **common)
    else:
        output = cusum_trajectory(points, allowance=config.allowance, scale=config.scale, **common)
    return {
        "schema_version": "statistical-comparison-v0.1",
        "implementation_version": "statistical-v0.1",
        "input_sha256": _digest(source),
        "config_sha256": _digest(config),
        "input": source.model_dump(mode="json"),
        "config": config.model_dump(mode="json"),
        "output": [
            {
                "timestamp": point.timestamp.isoformat(),
                "score": point.score,
                "input_prefix_length": index + 1,
            }
            for index, point in enumerate(output)
        ],
    }
