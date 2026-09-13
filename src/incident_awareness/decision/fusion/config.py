from datetime import timedelta
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)
from incident_awareness.decision.fusion.temporal_replay import (
    TemporalReplayRunner,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine


class WindowConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_size_sec: float = Field(gt=0)


class ReplayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_size_sec: float = Field(gt=0)


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

        if len(set(value)) != len(value):
            raise ValueError("evidence_types must not contain duplicates")

        return value


class StoppingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold_on: float = Field(ge=0.0, le=1.0)
    threshold_off: float = Field(ge=0.0, le=1.0)
    persistence_k: int = Field(ge=1)

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
