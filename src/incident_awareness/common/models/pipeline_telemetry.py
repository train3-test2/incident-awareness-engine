"""Immutable, execution-attempt telemetry snapshots; no rates or inferred zero buckets."""

from datetime import datetime, timedelta
from enum import Enum
from itertools import pairwise
from typing import Literal, Self

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


class TelemetryObservationIssue(str, Enum):
    WALL_CLOCK_REGRESSION = "wall_clock_regression"
    MONOTONIC_CLOCK_ERROR = "monotonic_clock_error"
    INVALID_MONOTONIC_DURATION = "invalid_monotonic_duration"
    INVALID_CALLBACK = "invalid_callback"
    INTERNAL_ERROR = "internal_error"
    STORAGE_ERROR = "storage_error"
    BUFFER_LIMIT = "buffer_limit"


def _validate_telemetry_datetime(value: datetime, *, field_name: str) -> datetime:
    validated = _validate_utc_datetime(value, field_name=field_name)
    assert validated is not None
    if validated.microsecond % 1000 != 0:
        raise ValueError(f"{field_name} must be aligned to millisecond precision")
    return validated


class _TelemetryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object, info: ValidationInfo) -> object:
        if info.field_name.endswith("_at") or info.field_name in {"bucket_start", "bucket_end"}:
            return _reject_numeric_timestamp(value, field_name=info.field_name)
        return value

    @field_validator("*")
    @classmethod
    def validate_datetime(cls, value: object, info: ValidationInfo) -> object:
        if isinstance(value, datetime):
            return _validate_telemetry_datetime(value, field_name=info.field_name)
        return value


class PipelineTelemetryBucket(_TelemetryModel):
    """Sparse observed events in [bucket_start, bucket_end), not full-second coverage."""

    bucket_start: datetime
    bucket_end: datetime
    first_observed_at: datetime
    last_observed_at: datetime
    revision: int = Field(strict=True, ge=1)
    input_accepted_count: int = Field(default=0, strict=True, ge=0)
    processing_completed_count: int = Field(default=0, strict=True, ge=0)
    processing_failed_count: int = Field(default=0, strict=True, ge=0)
    latency_sample_count: int = Field(default=0, strict=True, ge=0)
    latency_sum_ns: int = Field(default=0, strict=True, ge=0)

    @field_serializer(
        "bucket_start", "bucket_end", "first_observed_at", "last_observed_at", when_used="json"
    )
    def serialize_datetime(self, value: datetime) -> str | None:
        return _serialize_utc_milliseconds(value)

    @model_validator(mode="after")
    def validate_bucket(self) -> Self:
        if self.bucket_start.microsecond != 0:
            raise ValueError("bucket_start must be aligned to a UTC second")
        if self.bucket_end != self.bucket_start + timedelta(seconds=1):
            raise ValueError("bucket_end must be exactly one second after bucket_start")
        if (
            not self.bucket_start
            <= self.first_observed_at
            <= self.last_observed_at
            < self.bucket_end
        ):
            raise ValueError("observations must be ordered within the half-open bucket")
        if self.latency_sample_count > self.processing_completed_count:
            raise ValueError("latency samples must not exceed successful records")
        if self.latency_sample_count == 0 and self.latency_sum_ns != 0:
            raise ValueError("latency sum requires a measured sample")
        if not (
            self.input_accepted_count
            or self.processing_completed_count
            or self.processing_failed_count
        ):
            raise ValueError("an unobserved bucket must not be generated")
        return self


class PipelineTelemetryInputIdentity(_TelemetryModel):
    """Opaque, versioned identity: content equality is not S3 object equality."""

    kind: Literal["file_content_sha256_v1", "s3_object_sha256_v1"]
    sha256: str = Field(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class PipelineTelemetrySnapshot(_TelemetryModel):
    """Frozen replacement snapshot; normal observations do not imply continuous coverage.

    snapshot_id is stable for an execution. A bucket's storage identity is
    (execution_id, bucket_start); its revision changes only when its counters change.
    Missing buckets remain unknown. Observed means recorded observations are intact,
    partial means a telemetry error occurred, and unavailable means none were recorded.
    """

    snapshot_id: str
    execution_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    input_identity: PipelineTelemetryInputIdentity | None = None
    aggregation_basis: Literal["execution_attempt"] = "execution_attempt"
    latency_scope: Literal["normalization_and_evidence"] = "normalization_and_evidence"
    revision: int = Field(strict=True, ge=0)
    input_total: int | None = Field(default=None, strict=True, ge=1)
    input_accepted_at: datetime | None = None
    last_observed_at: datetime | None = None
    observation_status: Literal["unavailable", "partial", "observed"]
    observation_issues: tuple[TelemetryObservationIssue, ...] = ()
    collection_disabled: bool = Field(default=False, strict=True)
    buckets: tuple[PipelineTelemetryBucket, ...] = ()

    @field_validator("execution_id", "run_id", "entity_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(
                "telemetry identifiers must be nonblank without surrounding whitespace"
            )
        return value

    @field_serializer("input_accepted_at", "last_observed_at", when_used="json")
    def serialize_datetime(self, value: datetime | None) -> str | None:
        return _serialize_utc_milliseconds(value)

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.snapshot_id != f"pipeline-telemetry:{self.execution_id}":
            raise ValueError("snapshot_id must identify the supplied execution")
        starts = [bucket.bucket_start for bucket in self.buckets]
        if any(previous >= current for previous, current in pairwise(starts)):
            raise ValueError("buckets must be unique and strictly increasing")
        if any(bucket.revision > self.revision for bucket in self.buckets):
            raise ValueError("bucket revision must not exceed snapshot revision")
        accepted = sum(bucket.input_accepted_count for bucket in self.buckets)
        processed = sum(
            bucket.processing_completed_count + bucket.processing_failed_count
            for bucket in self.buckets
        )
        if self.input_total is None:
            if self.buckets or self.input_accepted_at is not None:
                raise ValueError("observations require an accepted batch")
        elif accepted != self.input_total or processed > self.input_total:
            raise ValueError("batch counts must match admission and not exceed input_total")
        elif self.input_accepted_at is None:
            raise ValueError("an accepted batch requires input_accepted_at")
        if self.buckets:
            if self.last_observed_at != self.buckets[-1].last_observed_at:
                raise ValueError("last_observed_at must match the last bucket")
            admission = [bucket for bucket in self.buckets if bucket.input_accepted_count]
            if len(admission) != 1 or not (
                admission[0].bucket_start <= self.input_accepted_at < admission[0].bucket_end
            ):
                raise ValueError("batch admission must occur in exactly one bucket")
        elif self.last_observed_at is not None:
            raise ValueError("last_observed_at requires observations")
        expected_status = (
            "unavailable"
            if not self.buckets
            else "partial"
            if self.observation_issues
            else "observed"
        )
        if self.observation_status != expected_status:
            raise ValueError("observation_status must describe the recorded observations")
        if self.collection_disabled and not self.observation_issues:
            raise ValueError("disabled collection requires an observation issue")
        return self
