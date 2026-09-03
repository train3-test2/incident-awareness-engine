from enum import Enum


class EventSource(str, Enum):
    SYSMON = "sysmon"
    POWERSHELL = "powershell"
    SECURITY = "security"
    VELOCIRAPTOR = "velociraptor"
