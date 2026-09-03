from enum import Enum

from pydantic import BaseModel, ConfigDict


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
