import os
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

type EventSource = str
type EventType = str

_EVENT_TYPES_CONFIG_PATH_ENV = "INCIDENT_AWARENESS_EVENT_TYPES_PATH"


@cache
def _load_event_types(config_path: Path) -> frozenset[str]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    if not isinstance(config, dict):
        raise TypeError("Event type 설정은 객체여야 합니다.")

    event_types = config.get("event_types")
    if not isinstance(event_types, list) or not all(
        isinstance(event_type, str) for event_type in event_types
    ):
        raise TypeError("Event type 설정은 문자열 목록이어야 합니다.")

    return frozenset(event_types)


def _event_types_config_path() -> Path:
    configured_path = os.getenv(_EVENT_TYPES_CONFIG_PATH_ENV)
    if configured_path is None:
        raise RuntimeError(f"{_EVENT_TYPES_CONFIG_PATH_ENV} 환경 변수가 필요합니다.")

    config_path = Path(configured_path)
    if not config_path.is_file():
        raise RuntimeError(f"Event type 설정 파일을 찾을 수 없습니다: {config_path}")

    return config_path


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str | None = None
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)


class RawLogReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_log_id: str = Field(min_length=1)
    source_record_id: str | None = None
    segment_no: int = Field(strict=True, ge=1)
    record_no: int = Field(strict=True, ge=1)
    parser_id: str | None = None
    parser_version: str | None = None

    @field_validator("raw_log_id")
    @classmethod
    def validate_raw_log_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_log_id는 비어 있거나 공백만으로 구성될 수 없습니다.")

        return value


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    run_id: str

    timestamp: datetime
    timestamp_source: Literal[
        "event_time",
        "record_time",
        "ingest_time",
    ]
    event_time: datetime | None = None
    record_time: datetime | None = None
    ingest_time: datetime | None = None

    host_id: str
    source: str
    source_layer: Literal["raw_telemetry", "detector_output"]
    source_event_id: StrictStr
    event_type: str
    raw_ref: RawLogReference
    user: str | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: str) -> str:
        if value not in _load_event_types(_event_types_config_path()):
            raise ValueError("event_type은 v0.2 관리 어휘에 정의되어야 합니다.")

        return value

    @field_validator("timestamp", "event_time", "record_time", "ingest_time", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("datetime에 숫자형 Unix timestamp를 사용할 수 없습니다.")

        return value

    @field_validator("timestamp", "event_time", "record_time", "ingest_time")
    @classmethod
    def validate_utc_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime에는 시간대 정보가 포함되어야 합니다.")

        if value.utcoffset() != timedelta(0):
            raise ValueError("datetime은 UTC 시간대여야 합니다.")

        if value.microsecond % 1000 != 0:
            raise ValueError("datetime은 밀리초 단위여야 합니다.")

        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_timestamp_source(self) -> "NormalizedEvent":
        source_time = getattr(self, self.timestamp_source)

        if source_time is None:
            raise ValueError("timestamp_source가 가리키는 시간 필드는 반드시 존재해야 합니다.")

        if self.timestamp != source_time:
            raise ValueError("timestamp는 timestamp_source가 가리키는 시간과 동일해야 합니다.")

        return self


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False

    return True
