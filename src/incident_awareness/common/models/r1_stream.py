"""R1 incremental stream의 chunk 단위 입력 계약."""

from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from incident_awareness.common.models.event import NORMALIZED_EVENT_SCHEMA_VERSION, NormalizedEvent
from incident_awareness.common.models.run import RunMetadata

R1_INCREMENTAL_STREAM_SCHEMA = "r1-incremental-stream"
R1_INCREMENTAL_STREAM_CONTRACT_VERSION = "v0.1"


class R1StreamPartition(BaseModel):
    """하나의 source event-time frontier가 적용되는 전달 범위."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: StrictStr = Field(min_length=1)
    host_id: StrictStr = Field(min_length=1)
    source: StrictStr = Field(min_length=1)
    source_channel: StrictStr = Field(min_length=1)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("host_id", "source", "source_channel")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("partition identifier must not contain leading or trailing whitespace")
        return value


class R1EventChunk(BaseModel):
    """재전달되어도 같은 논리 입력으로 식별되는 immutable Event chunk."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-incremental-stream"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["event_chunk"]
    chunk_id: StrictStr = Field(min_length=1)
    partition: R1StreamPartition
    chunk_sequence: int = Field(strict=True, ge=1)
    chunk_content_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    event_contract_version: Literal["v0.3"]
    events: tuple[NormalizedEvent, ...] = Field(min_length=1)

    @field_validator("chunk_id")
    @classmethod
    def validate_chunk_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("chunk_id must not contain leading or trailing whitespace")
        return value

    @model_validator(mode="after")
    def validate_event_scope_and_identity(self) -> "R1EventChunk":
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("events must not contain duplicate event_id values")

        for event in self.events:
            if event.run_id != self.partition.run_id:
                raise ValueError("every Event run_id must match the chunk partition")
            if event.host_id != self.partition.host_id:
                raise ValueError("every Event host_id must match the chunk partition")
            if event.source != self.partition.source:
                raise ValueError("every Event source must match the chunk partition")

        return self


class R1SourceWatermark(BaseModel):
    """Collector가 한 partition의 event-time frontier를 선언하는 control message."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-incremental-stream"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["source_watermark"]
    watermark_id: StrictStr = Field(min_length=1)
    partition: R1StreamPartition
    watermark_sequence: int = Field(strict=True, ge=1)
    watermark_at: datetime
    allowed_lateness_ms: int = Field(strict=True, ge=0)
    covered_through_chunk_sequence: int = Field(strict=True, ge=1)
    emitted_at: datetime

    @field_validator("watermark_id")
    @classmethod
    def validate_watermark_id(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("watermark_id must not contain leading or trailing whitespace")
        return value

    @field_validator("watermark_at", "emitted_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("watermark datetime must not be a numeric Unix timestamp")
        return value

    @field_validator("watermark_at", "emitted_at")
    @classmethod
    def validate_utc_milliseconds(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("watermark datetime must include a timezone")
        if value.utcoffset() != timedelta(0):
            raise ValueError("watermark datetime must be UTC")
        if value.microsecond % 1000 != 0:
            raise ValueError("watermark datetime must use millisecond precision")
        return value.astimezone(UTC)


class R1LateEventDeadLetter(BaseModel):
    """Watermark 뒤에 새로 도착한 Event chunk의 fail-closed 기록."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-incremental-stream-dead-letter"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["late_event"]
    chunk_id: StrictStr = Field(min_length=1)
    partition: R1StreamPartition
    watermark_id: StrictStr = Field(min_length=1)
    watermark_at: datetime
    violating_event_ids: tuple[StrictStr, ...] = Field(min_length=1)
    rejected_at: datetime

    @field_validator("chunk_id", "watermark_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("dead-letter identity must not contain leading or trailing whitespace")
        return value

    @field_validator("violating_event_ids")
    @classmethod
    def validate_violating_event_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not event_id.strip() or event_id != event_id.strip() for event_id in value):
            raise ValueError("violating_event_ids must contain only non-blank unpadded values")
        if len(value) != len(set(value)):
            raise ValueError("violating_event_ids must not contain duplicates")
        return value

    @field_validator("watermark_at", "rejected_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("dead-letter datetime must not be a numeric Unix timestamp")
        return value

    @field_validator("watermark_at", "rejected_at")
    @classmethod
    def validate_utc_milliseconds(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("dead-letter datetime must include a timezone")
        if value.utcoffset() != timedelta(0):
            raise ValueError("dead-letter datetime must be UTC")
        if value.microsecond % 1000 != 0:
            raise ValueError("dead-letter datetime must use millisecond precision")
        return value.astimezone(UTC)


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


__all__ = [
    "NORMALIZED_EVENT_SCHEMA_VERSION",
    "R1_INCREMENTAL_STREAM_CONTRACT_VERSION",
    "R1_INCREMENTAL_STREAM_SCHEMA",
    "R1EventChunk",
    "R1LateEventDeadLetter",
    "R1SourceWatermark",
    "R1StreamPartition",
]
