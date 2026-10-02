"""Reproducible statistical runs; separate from production FusionResult."""

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
