from datetime import timedelta
from decimal import Decimal
from functools import lru_cache
from math import isfinite
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)
from incident_awareness.decision.fusion.temporal_replay import (
    TemporalReplayRunner,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine

EVIDENCE_TYPE_VOCABULARY_PATH = Path(__file__).parents[4] / "configs" / "evidence_types_v0.2.yaml"


@lru_cache(maxsize=1)
def _load_allowed_evidence_types() -> frozenset[str]:
    vocabulary = yaml.safe_load(EVIDENCE_TYPE_VOCABULARY_PATH.read_text(encoding="utf-8"))

    if not isinstance(vocabulary, dict):
        raise TypeError("Evidence type vocabulary root must be a mapping")

    evidence_types = vocabulary.get("evidence_types")
    if not isinstance(evidence_types, list) or not evidence_types:
        raise RuntimeError("Evidence type vocabulary must define a non-empty evidence_types list")

    if any(
        not isinstance(evidence_type, str) or not evidence_type.strip()
        for evidence_type in evidence_types
    ):
        raise RuntimeError("Evidence type vocabulary must contain non-blank string values")

    return frozenset(evidence_types)


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
    except OverflowError as exc:
        raise ValueError(f"{field_name} is outside timedelta supported range") from exc

    if duration <= timedelta(0):
        raise ValueError(f"{field_name} must produce a positive timedelta")

    return value


class WindowConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_size_sec: float = Field(gt=0)

    @field_validator("window_size_sec", mode="before")
    @classmethod
    def reject_boolean_window_size(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        return _reject_boolean_numeric(
            value,
            field_name=info.field_name,
        )

    @field_validator("window_size_sec")
    @classmethod
    def validate_window_size_sec(cls, value: float) -> float:
        return _validate_positive_duration_seconds(
            value,
            field_name="window_size_sec",
        )


class ReplayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_size_sec: float = Field(gt=0)

    @field_validator("step_size_sec", mode="before")
    @classmethod
    def reject_boolean_step_size(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        return _reject_boolean_numeric(
            value,
            field_name=info.field_name,
        )

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


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["simple_score"]
    scorer_version: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    evidence_types: tuple[str, ...]

    @field_validator("method", "scorer_version", "profile_id")
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

        allowed_evidence_types = _load_allowed_evidence_types()
        unknown_evidence_types = sorted(set(value) - allowed_evidence_types)
        if unknown_evidence_types:
            raise ValueError(
                "evidence_types contains unmanaged values: " + ", ".join(unknown_evidence_types)
            )

        return value


class StoppingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold_on: float = Field(ge=0.0, le=1.0)
    threshold_off: float = Field(ge=0.0, le=1.0)
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
        return _reject_boolean_numeric(
            value,
            field_name=info.field_name,
        )

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "StoppingConfig":
        if self.threshold_off >= self.threshold_on:
            raise ValueError("threshold_off must be less than threshold_on")

        return self


class FusionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: str = Field(min_length=1)
    model_version: str | None = Field(default=None, min_length=1)
    window: WindowConfig
    replay: ReplayConfig
    scoring: ScoringConfig
    stopping: StoppingConfig

    @field_validator("config_version")
    @classmethod
    def validate_config_version(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("config_version must not be blank")
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

    def build_runner(self) -> TemporalReplayRunner:
        return TemporalReplayRunner(
            window_engine=WindowEngine(window_size=timedelta(seconds=self.window.window_size_sec)),
            scorer=SimpleScorer(
                evidence_types=self.scoring.evidence_types,
            ),
            stopping_policy=ThresholdStoppingPolicy(
                threshold_on=self.stopping.threshold_on,
                threshold_off=self.stopping.threshold_off,
                persistence_k=self.stopping.persistence_k,
            ),
            step_size=timedelta(seconds=self.replay.step_size_sec),
        )


def load_fusion_config(config_path: Path) -> FusionConfig:
    config_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    if not isinstance(config_data, dict):
        raise TypeError("Fusion config root must be a mapping")

    return FusionConfig.model_validate(config_data)
