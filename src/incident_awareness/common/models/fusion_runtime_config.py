from datetime import timedelta
from decimal import Decimal
from math import isfinite
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
from pydantic_core import PydanticCustomError


def _reject_boolean_numeric(
    value: object,
    *,
    field_name: str,
) -> object:
    if isinstance(value, bool):
        raise PydanticCustomError(
            "boolean_not_allowed",
            "{field_name} must not be boolean",
            {"field_name": field_name},
        )

    return value


def _validate_positive_duration_seconds(
    value: float,
    *,
    field_name: str,
) -> float:
    if not isfinite(value):
        raise ValueError(f"{field_name} must be finite")

    try:
        duration = timedelta(seconds=value)
    except OverflowError as error:
        raise ValueError(f"{field_name} is outside timedelta supported range") from error

    if duration <= timedelta(0):
        raise ValueError(f"{field_name} must produce a positive timedelta")

    return value


class FusionRuntimeWindowSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_size_sec: float = Field(gt=0)

    @field_validator("window_size_sec", mode="before")
    @classmethod
    def reject_boolean_window_size(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        return _reject_boolean_numeric(value, field_name=info.field_name)

    @field_validator("window_size_sec")
    @classmethod
    def validate_window_size_sec(cls, value: float) -> float:
        return _validate_positive_duration_seconds(
            value,
            field_name="window_size_sec",
        )


class FusionRuntimeReplaySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_size_sec: float = Field(gt=0)

    @field_validator("step_size_sec", mode="before")
    @classmethod
    def reject_boolean_step_size(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        return _reject_boolean_numeric(value, field_name=info.field_name)

    @field_validator("step_size_sec")
    @classmethod
    def validate_step_size_sec(cls, value: float) -> float:
        value = _validate_positive_duration_seconds(
            value,
            field_name="step_size_sec",
        )

        milliseconds = Decimal(str(value)) * Decimal(1000)
        if milliseconds != milliseconds.to_integral_value():
            raise ValueError("step_size_sec must align to whole milliseconds")

        return value


class FusionRuntimeScoringSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["simple_score"]
    scorer_version: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    evidence_types: tuple[str, ...]

    @field_validator("scorer_version", "profile_id")
    @classmethod
    def validate_non_blank_string(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("scoring metadata values must not be blank")
        return value

    @field_validator("evidence_types")
    @classmethod
    def validate_evidence_types(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if not value:
            raise ValueError("evidence_types must not be empty")

        if any(not evidence_type.strip() for evidence_type in value):
            raise ValueError("evidence_types must not contain blank values")

        if any(evidence_type != evidence_type.strip() for evidence_type in value):
            raise ValueError("evidence_types must not contain leading or trailing whitespace")

        if len(set(value)) != len(value):
            raise ValueError("evidence_types must not contain duplicates")

        return value


class FusionRuntimeStoppingSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold_on: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    threshold_off: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    persistence_k: int = Field(ge=1)

    @field_validator(
        "threshold_on",
        "threshold_off",
        "persistence_k",
        mode="before",
    )
    @classmethod
    def reject_boolean_numeric_values(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        return _reject_boolean_numeric(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "FusionRuntimeStoppingSnapshot":
        if self.threshold_off >= self.threshold_on:
            raise ValueError("threshold_off must be less than threshold_on")

        return self


class FusionRuntimeConfigSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    config_version: str = Field(min_length=1)
    model_version: str | None = Field(default=None, min_length=1)
    window: FusionRuntimeWindowSnapshot
    replay: FusionRuntimeReplaySnapshot
    scoring: FusionRuntimeScoringSnapshot
    stopping: FusionRuntimeStoppingSnapshot

    @field_validator("run_id", "entity_id", "config_version")
    @classmethod
    def validate_non_blank_identifier(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Runtime config snapshot identifiers must not be blank")
        return value

    @field_validator("model_version")
    @classmethod
    def validate_model_version(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("model_version must not be blank")
        return value


__all__ = [
    "FusionRuntimeConfigSnapshot",
    "FusionRuntimeReplaySnapshot",
    "FusionRuntimeScoringSnapshot",
    "FusionRuntimeStoppingSnapshot",
    "FusionRuntimeWindowSnapshot",
]
