"""Runtime telemetry contract for one First Cycle pipeline invocation."""

from datetime import datetime
from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.fusion import (
    _reject_numeric_timestamp,
    _serialize_utc_milliseconds,
    _validate_utc_datetime,
)


class PipelineRuntimeState(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PipelineStage(str, Enum):
    ARTIFACT_VALIDATION = "artifact_validation"
    NORMALIZATION = "normalization"
    FUSION = "fusion"
    FAST_HANDOFF = "fast_handoff"
    HYBRID = "hybrid"
    PERSISTENCE = "persistence"


class PipelineRuntimeStatus(BaseModel):
    """Latest authoritative state of one scoped pipeline invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)

    status: PipelineRuntimeState
    current_stage: PipelineStage | None

    input_total: int = Field(strict=True, ge=1)
    normalization_processed_count: int = Field(strict=True, ge=0)

    started_at: datetime
    stage_started_at: datetime | None
    updated_at: datetime
    completed_at: datetime | None

    failed_stage: PipelineStage | None

    @field_validator("execution_id", "run_id", "entity_id")
    @classmethod
    def validate_identifier(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must not be blank")
        if value != value.strip():
            raise ValueError(f"{info.field_name} must not contain surrounding whitespace")
        return value

    @field_validator(
        "started_at",
        "stage_started_at",
        "updated_at",
        "completed_at",
        mode="before",
    )
    @classmethod
    def reject_numeric_datetime(cls, value: object, info: ValidationInfo) -> object:
        return _reject_numeric_timestamp(
            value,
            field_name=f"PipelineRuntimeStatus {info.field_name}",
        )

    @field_validator("started_at", "stage_started_at", "updated_at", "completed_at")
    @classmethod
    def validate_datetime(
        cls,
        value: datetime | None,
        info: ValidationInfo,
    ) -> datetime | None:
        validated = _validate_utc_datetime(
            value,
            field_name=f"PipelineRuntimeStatus {info.field_name}",
        )
        if validated is not None and validated.microsecond % 1000 != 0:
            raise ValueError(
                f"PipelineRuntimeStatus {info.field_name} must be aligned to millisecond precision"
            )
        return validated

    @field_serializer(
        "started_at",
        "stage_started_at",
        "updated_at",
        "completed_at",
        when_used="json",
    )
    def serialize_datetime(self, value: datetime | None) -> str | None:
        return _serialize_utc_milliseconds(value)

    @model_validator(mode="after")
    def validate_runtime_contract(self) -> "PipelineRuntimeStatus":
        if self.normalization_processed_count > self.input_total:
            raise ValueError("normalization_processed_count must not exceed input_total")

        if self.updated_at < self.started_at:
            raise ValueError("updated_at must not be earlier than started_at")

        if self.status is PipelineRuntimeState.RUNNING:
            if self.current_stage is None:
                raise ValueError("running PipelineRuntimeStatus requires current_stage")
            if self.stage_started_at is None:
                raise ValueError("running PipelineRuntimeStatus requires stage_started_at")
            if self.completed_at is not None:
                raise ValueError("running PipelineRuntimeStatus must not include completed_at")
            if self.failed_stage is not None:
                raise ValueError("running PipelineRuntimeStatus must not include failed_stage")
            if self.stage_started_at < self.started_at:
                raise ValueError("stage_started_at must not be earlier than started_at")
            if self.updated_at < self.stage_started_at:
                raise ValueError("updated_at must not be earlier than stage_started_at")

        elif self.status is PipelineRuntimeState.COMPLETED:
            if self.current_stage is not None:
                raise ValueError("completed PipelineRuntimeStatus must not include current_stage")
            if self.stage_started_at is not None:
                raise ValueError(
                    "completed PipelineRuntimeStatus must not include stage_started_at"
                )
            if self.completed_at is None:
                raise ValueError("completed PipelineRuntimeStatus requires completed_at")
            if self.failed_stage is not None:
                raise ValueError("completed PipelineRuntimeStatus must not include failed_stage")
            if self.normalization_processed_count != self.input_total:
                raise ValueError(
                    "completed PipelineRuntimeStatus requires "
                    "normalization_processed_count to equal input_total"
                )
            if self.completed_at < self.started_at:
                raise ValueError("completed_at must not be earlier than started_at")
            if self.updated_at < self.completed_at:
                raise ValueError("updated_at must not be earlier than completed_at")

        else:
            if self.current_stage is not None:
                raise ValueError("failed PipelineRuntimeStatus must not include current_stage")
            if self.stage_started_at is not None:
                raise ValueError("failed PipelineRuntimeStatus must not include stage_started_at")
            if self.completed_at is not None:
                raise ValueError("failed PipelineRuntimeStatus must not include completed_at")
            if self.failed_stage is None:
                raise ValueError("failed PipelineRuntimeStatus requires failed_stage")

        return self

    @property
    def remaining_count(self) -> int:
        return self.input_total - self.normalization_processed_count

    @property
    def has_error(self) -> bool:
        return self.status is PipelineRuntimeState.FAILED


__all__ = [
    "PipelineRuntimeState",
    "PipelineRuntimeStatus",
    "PipelineStage",
]
