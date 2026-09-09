from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FusionStatus = Literal["detected", "miss", "not_evaluated"]
FusionEndReason = Literal["released", "run_end"]


def _validate_utc_datetime(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")

    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")

    return value.astimezone(UTC)


class FusionEpisodeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    start_time: datetime
    end_time: datetime | None = None
    end_reason: FusionEndReason | None = None
    score_at_start: float
    peak_score: float
    contributing_evidence_ids: list[str] | None = None

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_timestamp(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return _validate_utc_datetime(
            value,
            field_name="FusionEpisode timestamp",
        )


class FusionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    fusion_time: datetime | None
    fusion_status: FusionStatus
    score_at_decision: float | None
    contributing_evidence_ids: list[str]
    scoring_config_version: str = Field(min_length=1)
    scoring_profile_id: str = Field(min_length=1)
    model_version: str | None = Field(default=None, min_length=1)
    scoring_method: str = Field(min_length=1)
    scorer_version: str = Field(min_length=1)
    fusion_episodes: list[FusionEpisodeResult]

    @field_validator("fusion_time")
    @classmethod
    def validate_fusion_time(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return _validate_utc_datetime(
            value,
            field_name="fusion_time",
        )

    @model_validator(mode="after")
    def validate_status_contract(self) -> "FusionResult":
        if self.fusion_status == "detected":
            if self.fusion_time is None:
                raise ValueError("detected FusionResult must include fusion_time")

            if self.score_at_decision is None:
                raise ValueError("detected FusionResult must include score_at_decision")

            if not self.contributing_evidence_ids:
                raise ValueError("detected FusionResult must include contributing_evidence_ids")

        elif self.fusion_status == "miss":
            if self.fusion_time is not None:
                raise ValueError("miss FusionResult must not include fusion_time")

        else:
            if self.fusion_time is not None:
                raise ValueError("not_evaluated FusionResult must not include fusion_time")

            if self.score_at_decision is not None:
                raise ValueError("not_evaluated FusionResult must not include score_at_decision")

        return self
