from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EventSource(str, Enum):
    SYSMON = "sysmon"
    POWERSHELL = "powershell"
    SECURITY = "security"
    VELOCIRAPTOR = "velociraptor"


class EventType(str, Enum):
    PROCESS_CREATE = "process_create"
    NETWORK_CONNECTION = "network_connection"
    SCRIPT_BLOCK = "script_block"
    FILE_CREATE = "file_create"
    REGISTRY_CHANGE = "registry_change"


class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    pid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    protocol: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None


class RawLogReference(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    raw_log_id: str = Field(min_length=1)
    segment_no: int = Field(ge=1)
    record_no: int = Field(ge=1)
