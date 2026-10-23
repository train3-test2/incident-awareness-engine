"""In-memory stage observations, separate from latest Runtime and record telemetry."""

from datetime import datetime
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.fusion import (
    _reject_numeric_timestamp,
    _serialize_utc_milliseconds,
)
from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_telemetry import _validate_telemetry_datetime

type StageTimingIssue = Literal[
    "utc_clock_error",
    "monotonic_clock_error",
    "invalid_duration",
    "wall_clock_regression",
    "internal_error",
    "observer_error",
    "buffer_limit",
]


class PipelineStageTimingRecord(BaseModel):
    """One ended operation; duration is never derived from UTC timestamps."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: PipelineStage
    invocation_index: int = Field(strict=True, ge=1)
    outcome: Literal["completed", "failed"]
    started_at: datetime | None
    ended_at: datetime | None
    duration_ns: int | None = Field(strict=True, ge=0)
    issues: tuple[StageTimingIssue, ...] = ()

    @field_validator("started_at", "ended_at", mode="before")
    @classmethod
    def reject_numeric_time(cls, value: object) -> object:
        return _reject_numeric_timestamp(value, field_name="stage timing")

    @field_validator("started_at", "ended_at")
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        return (
            _validate_telemetry_datetime(value, field_name="stage timing")
            if value is not None
            else None
        )

    @field_serializer("started_at", "ended_at", when_used="json")
    def serialize_time(self, value: datetime | None) -> str | None:
        return _serialize_utc_milliseconds(value)

    @model_validator(mode="after")
    def validate_quality(self) -> Self:
        if (
            self.started_at is None or self.ended_at is None
        ) and "utc_clock_error" not in self.issues:
            raise ValueError("missing UTC boundaries require utc_clock_error")
        if self.duration_ns is None and not {
            "monotonic_clock_error",
            "invalid_duration",
            "internal_error",
        }.intersection(self.issues):
            raise ValueError("missing duration requires an explicit measurement issue")
        if (
            self.started_at is not None
            and self.ended_at is not None
            and self.ended_at < self.started_at
            and "wall_clock_regression" not in self.issues
        ):
            raise ValueError("UTC regression must be reported independently of duration")
        return self


class PipelineStageTimingSnapshot(BaseModel):
    """Replacement snapshot of one local attempt; not a durable Pipeline outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pipeline_stage_timing_v1"] = "pipeline_stage_timing_v1"
    attempt_id: str = Field(min_length=1)
    execution_id: str | None
    run_id: str | None
    entity_id: str | None
    revision: int = Field(strict=True, ge=0)
    records: tuple[PipelineStageTimingRecord, ...]
    active_stage: PipelineStage | None
    active_invocation_index: int | None = Field(strict=True, ge=1)
    issues: tuple[StageTimingIssue, ...]
    quality_status: Literal["unavailable", "partial", "observed"]

    @field_validator("attempt_id", "execution_id", "run_id", "entity_id")
    @classmethod
    def validate_identity(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError("stage timing identity must be nonblank and trimmed")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if (self.run_id is None) != (self.entity_id is None):
            raise ValueError("validated Run and Entity must be bound together")
        if self.execution_id is not None and self.run_id is None:
            raise ValueError("Runtime execution identity requires validated Run scope")
        if (self.active_stage is None) != (self.active_invocation_index is None):
            raise ValueError("active stage and invocation must be present together")
        indices = [record.invocation_index for record in self.records]
        if indices != sorted(set(indices)):
            raise ValueError("stage invocations must be unique and ordered")
        if (
            indices
            and self.active_invocation_index is not None
            and self.active_invocation_index <= indices[-1]
        ):
            raise ValueError("active invocation must follow ended operations")
        expected = (
            "unavailable"
            if not self.records
            else "partial"
            if (self.issues or any(record.issues for record in self.records))
            else "observed"
        )
        if self.quality_status != expected:
            raise ValueError("quality must describe actual timing records, not Pipeline success")
        return self
