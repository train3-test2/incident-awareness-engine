from pydantic import BaseModel, ConfigDict, Field, field_validator

type EventSource = str
type EventType = str


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
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None


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
