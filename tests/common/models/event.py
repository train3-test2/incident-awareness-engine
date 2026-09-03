from enum import Enum


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
