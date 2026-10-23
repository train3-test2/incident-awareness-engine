"""Execution-scoped stored observations; never reconstruct durations or infer coverage."""

from datetime import datetime
from typing import Literal

import psycopg
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
)

from incident_awareness.common.models.fusion import _serialize_utc_milliseconds
from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_stage_timing import (
    PipelineStageTimingRecord,
    PipelineStageTimingSnapshot,
)
from incident_awareness.common.models.pipeline_telemetry import _validate_telemetry_datetime
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
    StageTimingIntegrityError,
)


class StageTimingReadError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def stage_timing_database_error(error: psycopg.Error) -> StageTimingReadError:
    if isinstance(error, psycopg.OperationalError):
        return StageTimingReadError(503, "Stage timing database is unavailable")
    return StageTimingReadError(500, "Stage timing read failed")


class StageTimingQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(min_length=1, max_length=512)

    @field_validator("execution_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("execution_id must be trimmed")
        return value


class StageTimingReadRecord(PipelineStageTimingRecord):
    @field_serializer("duration_ns", "invocation_index", when_used="json")
    def serialize_integer(self, value: int | None) -> str | None:
        return str(value) if value is not None else None


class StageTimingReadSnapshot(PipelineStageTimingSnapshot):
    records: tuple[StageTimingReadRecord, ...]

    @field_serializer("revision", "active_invocation_index", when_used="json")
    def serialize_integer(self, value: int | None) -> str | None:
        return str(value) if value is not None else None


class StageTimingReadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["pipeline_stage_timing_read_v1"] = "pipeline_stage_timing_read_v1"
    execution_id: str
    availability: Literal["recorded", "no_stage_timings"]
    snapshot: StageTimingReadSnapshot | None
    persisted_at: datetime | None
    duration_unit: Literal["ns"] = "ns"
    integer_encoding: Literal["decimal_string"] = "decimal_string"
    coverage_status: Literal["not_evaluable"] = "not_evaluable"
    execution_outcome: Literal["unknown"] = "unknown"
    ended_invocation_count: int
    operation_failure_recorded: bool
    unmeasured_stages: tuple[PipelineStage, ...]
    missing_stage_meaning: Literal["not_observed_not_proof_of_not_run"] = (
        "not_observed_not_proof_of_not_run"
    )

    @field_validator("persisted_at")
    @classmethod
    def validate_time(cls, value: datetime | None) -> datetime | None:
        return _validate_telemetry_datetime(value, field_name="persisted_at") if value else None

    @field_serializer("persisted_at", when_used="json")
    def serialize_time(self, value: datetime | None) -> str | None:
        return _serialize_utc_milliseconds(value)


class DashboardStageTimingReader:
    def __init__(self, repository: PipelineStageTimingRepository) -> None:
        self._repository = repository

    def read(self, execution_id: str) -> StageTimingReadResponse:
        try:
            snapshot, persisted_at, known = self._repository.read_execution(execution_id)
            if not known:
                raise StageTimingReadError(
                    404, "Execution is not present in stored observation records"
                )
            restored = (
                StageTimingReadSnapshot.model_validate(snapshot.model_dump()) if snapshot else None
            )
            records = restored.records if restored else ()
            return StageTimingReadResponse(
                execution_id=execution_id,
                availability="recorded" if records else "no_stage_timings",
                snapshot=restored,
                persisted_at=persisted_at,
                ended_invocation_count=len(records),
                operation_failure_recorded=any(r.outcome == "failed" for r in records),
                unmeasured_stages=tuple(
                    stage for stage in PipelineStage if not any(r.stage is stage for r in records)
                ),
            )
        except psycopg.Error as error:
            raise stage_timing_database_error(error) from error
        except (ValidationError, StageTimingIntegrityError, TypeError, ValueError) as error:
            raise StageTimingReadError(500, "Stored stage timing is invalid") from error
