from pydantic import BaseModel

type EventSource = str
type EventType = str


class ProcessInfo(BaseModel):
    pid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None


class NetworkInfo(BaseModel):
    protocol: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None


class RawLogReference(BaseModel):
    raw_log_id: str
    source_record_id: str | None = None
    segment_no: int
    record_no: int
    parser_id: str | None = None
    parser_version: str | None = None
