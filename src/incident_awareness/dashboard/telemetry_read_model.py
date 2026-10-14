"""Read-only sparse execution-attempt telemetry, never inferred stream/liveness data."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import pairwise
from typing import Literal, Protocol, Self

import psycopg
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.fusion import (
    _reject_numeric_timestamp,
    _serialize_utc_milliseconds,
)
from incident_awareness.common.models.pipeline_telemetry import (
    TelemetryObservationIssue,
    _validate_telemetry_datetime,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryIntegrityError,
)

_LOGGER = logging.getLogger(__name__)


class TelemetryUnavailableError(RuntimeError):
    """Connection or transient availability failure; never an empty observation result."""


class TelemetryReadDefectError(RuntimeError):
    """Non-transient SQL, schema, privilege, driver, or configuration defect."""


class StoredTelemetryInvalidError(RuntimeError):
    """Stored aggregate cannot satisfy the Read API contract."""


def translate_telemetry_database_error(error: psycopg.Error) -> RuntimeError:
    """Classify a psycopg failure without copying its message into the HTTP response.

    OperationalError covers connection loss and timeouts, server shutdown or startup,
    resource limits, authentication, statement cancellation, and lock or serialization
    conflicts. Every other psycopg error, such as a missing table or column, invalid SQL,
    missing privilege, or malformed connection string, is an internal defect.
    """
    if isinstance(error, psycopg.OperationalError):
        _LOGGER.warning("Pipeline telemetry database is unavailable", exc_info=error)
        return TelemetryUnavailableError("Telemetry database is unavailable")
    _LOGGER.error("Pipeline telemetry read failed", exc_info=error)
    return TelemetryReadDefectError("Telemetry read failed")


def telemetry_configuration_error(error: Exception) -> TelemetryReadDefectError:
    """A missing or malformed database URL is a deployment defect, not a transient outage."""
    _LOGGER.error("Pipeline telemetry database configuration is invalid", exc_info=error)
    return TelemetryReadDefectError("Telemetry read failed")


class _TelemetryReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_numeric_timestamp(cls, value: object, info: ValidationInfo) -> object:
        if info.field_name.endswith("_at") or info.field_name in {
            "bucket_start",
            "bucket_end",
            "range_start",
            "range_end",
        }:
            try:
                return _reject_numeric_timestamp(value, field_name=info.field_name)
            except TypeError as error:
                raise ValueError(str(error)) from error
        return value

    @field_validator("*")
    @classmethod
    def validate_datetime(cls, value: object, info: ValidationInfo) -> object:
        if isinstance(value, datetime):
            return _validate_telemetry_datetime(value, field_name=info.field_name)
        return value

    @field_serializer("*", when_used="json")
    def serialize_datetime(self, value: object) -> object:
        return _serialize_utc_milliseconds(value) if isinstance(value, datetime) else value


class TelemetryQuery(_TelemetryReadModel):
    scope: Literal["execution", "run", "reported"] = "reported"
    execution_id: str | None = Field(default=None, min_length=1, max_length=512)
    run_id: str | None = Field(default=None, min_length=1, max_length=512)
    entity_id: str | None = Field(default=None, min_length=1, max_length=512)
    end_at: datetime | None = None
    window_seconds: int = Field(default=300, ge=60, le=300)
    resolution_seconds: int = Field(default=1, ge=1, le=1)

    @field_validator("execution_id", "run_id", "entity_id")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError(
                "telemetry identifiers must be nonblank without surrounding whitespace"
            )
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        valid = (
            (
                self.scope == "execution"
                and self.execution_id is not None
                and self.run_id is None
                and self.entity_id is None
            )
            or (self.scope == "run" and self.run_id is not None and self.execution_id is None)
            or (
                self.scope == "reported"
                and self.execution_id is None
                and self.run_id is None
                and self.entity_id is None
            )
        )
        if not valid:
            raise ValueError("identifiers must match the requested telemetry scope")
        return self


class TelemetryPoint(_TelemetryReadModel):
    bucket_start: datetime
    bucket_end: datetime
    observed_at: datetime
    executions_count: int = Field(strict=True, ge=1)
    input_accepted_count: int = Field(strict=True, ge=0)
    processing_completed_count: int = Field(strict=True, ge=0)
    processing_failed_count: int = Field(strict=True, ge=0)
    processing_latency_sample_count: int = Field(strict=True, ge=0)
    processing_latency_sum_ns: int = Field(strict=True, ge=0)
    processing_latency_mean_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_point(self) -> Self:
        if self.bucket_start.microsecond or self.bucket_end != self.bucket_start + timedelta(
            seconds=1
        ):
            raise ValueError("point must describe a UTC-second half-open bucket")
        if not self.bucket_start <= self.observed_at < self.bucket_end:
            raise ValueError("observation must be inside its bucket")
        if self.processing_latency_sample_count > self.processing_completed_count:
            raise ValueError("latency sample count exceeds successful records")
        if not self.processing_latency_sample_count and self.processing_latency_sum_ns:
            raise ValueError("latency sum requires samples")
        if not (
            self.input_accepted_count
            or self.processing_completed_count
            or self.processing_failed_count
        ):
            raise ValueError("a stored point requires a real observation")
        return self


class TelemetrySummary(_TelemetryReadModel):
    range_start: datetime
    range_end: datetime
    observed_bucket_count: int = Field(strict=True, ge=0, le=60)
    missing_bucket_count: int = Field(strict=True, ge=0, le=60)
    continuous_coverage: Literal[False] = False
    input_accepted_count: int | None = Field(strict=True, ge=0)
    processing_completed_count: int | None = Field(strict=True, ge=0)
    processing_failed_count: int | None = Field(strict=True, ge=0)
    processing_latency_sample_count: int | None = Field(strict=True, ge=0)
    processing_latency_sum_ns: int | None = Field(strict=True, ge=0)
    processing_latency_mean_ms: float | None = Field(ge=0, allow_inf_nan=False)


class TelemetryQuality(_TelemetryReadModel):
    status: Literal["no_samples", "observed", "partial"]
    basis: Literal["latest_persisted_execution_snapshot"] = "latest_persisted_execution_snapshot"
    observed_executions: int = Field(strict=True, ge=0)
    partial_executions: int = Field(strict=True, ge=0)
    unavailable_executions: int = Field(strict=True, ge=0)
    disabled_executions: int = Field(strict=True, ge=0)
    observation_issues: tuple[TelemetryObservationIssue, ...]
    continuous_coverage: Literal[False] = False
    unreported_executions_included: Literal[False] = False


class TelemetryFreshness(_TelemetryReadModel):
    status: Literal["unknown", "recent", "stale"]
    reference_at: datetime
    threshold_seconds: Literal[15] = 15
    age_seconds: float | None
    process_liveness: Literal["unknown"] = "unknown"


class PipelineTelemetryResponse(_TelemetryReadModel):
    schema_version: Literal["pipeline_telemetry_read_v1"] = "pipeline_telemetry_read_v1"
    scope: Literal["execution", "run", "reported"]
    execution_id: str | None
    run_id: str | None
    entity_id: str | None
    aggregation_basis: Literal["execution_attempt"] = "execution_attempt"
    input_scope: Literal["validated_batch_admission"] = "validated_batch_admission"
    processing_scope: Literal["normalization_and_evidence"] = "normalization_and_evidence"
    count_unit: Literal["records_per_1s_bucket"] = "records_per_1s_bucket"
    latency_unit: Literal["ms"] = "ms"
    range_start: datetime
    range_end: datetime
    resolution_seconds: Literal[1] = 1
    executions_count: int = Field(strict=True, ge=0)
    points: tuple[TelemetryPoint, ...] = Field(max_length=300)
    recent_60s_summary: TelemetrySummary
    last_observed_at: datetime | None
    persisted_at: datetime | None
    response_generated_at: datetime
    observation_quality: TelemetryQuality
    freshness: TelemetryFreshness


class _Repository(Protocol):
    def read_window(self, **kwargs: object) -> dict[str, object]: ...


def telemetry_utc_now() -> datetime:
    now = datetime.now(UTC)
    return now.replace(microsecond=now.microsecond // 1000 * 1000)


def _mean_ms(total: int, count: int) -> float | None:
    # Integer sums remain exact until the final display-unit conversion.
    return float(Decimal(total) / Decimal(count) / Decimal(1_000_000)) if count else None


class DashboardTelemetryReader:
    def __init__(
        self, repository: _Repository, *, clock: Callable[[], datetime] = telemetry_utc_now
    ) -> None:
        self._repository = repository
        self._clock = clock

    def get_telemetry(self, query: TelemetryQuery) -> PipelineTelemetryResponse:
        now = _validate_telemetry_datetime(self._clock(), field_name="response_generated_at")
        if query.end_at is not None and query.end_at > now:
            raise ValueError("end_at must not be in the future")
        end = (query.end_at or now).replace(microsecond=0)
        try:
            start = end - timedelta(seconds=query.window_seconds)
        except OverflowError as error:
            raise ValueError("end_at is too early for the requested window") from error
        try:
            data = self._repository.read_window(
                start=start,
                end=end,
                execution_id=query.execution_id,
                run_id=query.run_id,
                entity_id=query.entity_id,
                reported=query.scope == "reported",
            )
        except psycopg.Error as error:
            raise translate_telemetry_database_error(error) from error
        except (PipelineTelemetryIntegrityError, ValueError, TypeError) as error:
            raise StoredTelemetryInvalidError("Stored telemetry is invalid") from error
        try:
            return self._build_response(query, data, start=start, end=end, now=now)
        except (ValueError, TypeError, KeyError) as error:
            raise StoredTelemetryInvalidError("Stored telemetry is invalid") from error

    @staticmethod
    def _build_response(
        query: TelemetryQuery,
        data: dict[str, object],
        *,
        start: datetime,
        end: datetime,
        now: datetime,
    ) -> PipelineTelemetryResponse:
        points = tuple(TelemetryPoint.model_validate(point) for point in data["points"])
        if (
            len(points) > query.window_seconds
            or any(not start <= point.bucket_start < end for point in points)
            or any(a.bucket_start >= b.bucket_start for a, b in pairwise(points))
        ):
            raise ValueError("duplicate, unordered or out-of-range telemetry buckets")
        points = tuple(
            TelemetryPoint.model_validate(
                {
                    **point.model_dump(),
                    "processing_latency_mean_ms": _mean_ms(
                        point.processing_latency_sum_ns, point.processing_latency_sample_count
                    ),
                }
            )
            for point in points
        )
        recent = tuple(p for p in points if p.bucket_start >= end - timedelta(seconds=60))
        totals = {
            name: sum(getattr(p, name) for p in recent) if recent else None
            for name in (
                "input_accepted_count",
                "processing_completed_count",
                "processing_failed_count",
                "processing_latency_sample_count",
                "processing_latency_sum_ns",
            )
        }
        summary = TelemetrySummary(
            range_start=end - timedelta(seconds=60),
            range_end=end,
            observed_bucket_count=len(recent),
            missing_bucket_count=60 - len(recent),
            **totals,
            processing_latency_mean_ms=_mean_ms(
                totals["processing_latency_sum_ns"], totals["processing_latency_sample_count"]
            )
            if recent
            else None,
        )
        quality = TelemetryQuality(
            status="partial"
            if (
                data["partial_executions"]
                or data["observation_issues"]
                or data["disabled_executions"]
                or data["unavailable_executions"]
            )
            else "observed"
            if points
            else "no_samples",
            partial_executions=data["partial_executions"],
            observed_executions=data["observed_executions"],
            unavailable_executions=data["unavailable_executions"],
            disabled_executions=data["disabled_executions"],
            observation_issues=data["observation_issues"],
        )
        # Freshness compares to the requested historical boundary, not today's time.
        last = TypeAdapter(datetime | None).validate_python(
            _reject_numeric_timestamp(data["last_observed_at"], field_name="last_observed_at")
        )
        if last is not None:
            _validate_telemetry_datetime(last, field_name="last_observed_at")
            if last >= end:
                raise ValueError("last observation must precede the completed-window end")
        age = (end - last).total_seconds() if last is not None else None
        return PipelineTelemetryResponse(
            scope=query.scope,
            execution_id=query.execution_id,
            run_id=query.run_id,
            entity_id=query.entity_id,
            range_start=start,
            range_end=end,
            points=points,
            recent_60s_summary=summary,
            executions_count=data["executions_count"],
            last_observed_at=last,
            persisted_at=data["persisted_at"],
            response_generated_at=now,
            observation_quality=quality,
            freshness=TelemetryFreshness(
                status="unknown" if age is None else "stale" if age > 15 else "recent",
                reference_at=end,
                age_seconds=age,
            ),
        )
