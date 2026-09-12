"""Sysmon raw-record normalization for the First Cycle."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PureWindowsPath
from uuid import NAMESPACE_URL, uuid5

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent

_SYSMON_PROCESS_CREATE_EVENT_ID = 1
_SYSMON_NORMALIZER_ID = "sysmon-normalizer"
_SYSMON_NORMALIZER_VERSION = "v0.2"


@dataclass(frozen=True, slots=True)
class SysmonNormalizationContext:
    """Run-manifest context that is not contained in a raw Sysmon record."""

    run_id: str
    raw_log_id: str
    segment_no: int


def normalize_sysmon_process_create(
    record: SysmonJsonlRecord,
    *,
    context: SysmonNormalizationContext,
) -> NormalizedEvent:
    """Convert one Sysmon Event ID 1 record into a process_create Event."""
    event_id = _required_event_id(record)
    if event_id != _SYSMON_PROCESS_CREATE_EVENT_ID:
        raise ValueError("normalize_sysmon_process_create requires Sysmon Event ID 1")

    event_data = _required_mapping(record, "EventData")
    event_time = _parse_sysmon_utc_time(_required_string(event_data, "UtcTime"))
    record_time = _parse_iso_utc_time(_required_string(record.data, "TimeCreated"))
    image = _required_string(event_data, "Image")
    parent_image = _optional_string(event_data, "ParentImage")

    return NormalizedEvent(
        event_id=_normalized_event_id(record, context),
        run_id=context.run_id,
        timestamp=event_time,
        timestamp_source="event_time",
        event_time=event_time,
        record_time=record_time,
        ingest_time=None,
        host_id=_required_string(record.data, "Computer"),
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=str(_required_record_id(record)),
        event_type="process_create",
        user=_optional_string(event_data, "User"),
        process={
            "pid": _optional_integer(event_data, "ProcessId"),
            "name": PureWindowsPath(image).name,
            "path": image,
            "command_line": _optional_string(event_data, "CommandLine"),
            "parent_pid": _optional_integer(event_data, "ParentProcessId"),
            "parent_name": PureWindowsPath(parent_image).name if parent_image else None,
        },
        network=None,
        raw_ref={
            "raw_log_id": context.raw_log_id,
            "source_record_id": str(_required_record_id(record)),
            "segment_no": context.segment_no,
            "record_no": record.record_no,
            "parser_id": _SYSMON_NORMALIZER_ID,
            "parser_version": _SYSMON_NORMALIZER_VERSION,
        },
    )


def _required_event_id(record: SysmonJsonlRecord) -> int:
    value = record.data.get("EventId")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Sysmon EventId must be an integer")
    return value


def _required_record_id(record: SysmonJsonlRecord) -> int:
    value = record.data.get("RecordId")
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Sysmon RecordId must be an integer")
    return value


def _required_mapping(record: SysmonJsonlRecord, key: str) -> dict[str, object]:
    value = record.data.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"Sysmon {key} must be a JSON object")
    return value


def _required_string(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Sysmon {key} must be a non-blank string")
    return value


def _optional_string(mapping: dict[str, object], key: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Sysmon {key} must be a string when present")
    return value


def _optional_integer(mapping: dict[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, str) or not value.isdecimal():
        raise ValueError(f"Sysmon {key} must be a decimal integer when present")
    return int(value)


def _parse_sysmon_utc_time(value: str) -> datetime:
    parsed = _parse_datetime(value, field_name="UtcTime")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return _truncate_to_milliseconds(parsed.astimezone(UTC))


def _parse_iso_utc_time(value: str) -> datetime:
    parsed = _parse_datetime(value, field_name="TimeCreated")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Sysmon TimeCreated must include timezone information")
    return _truncate_to_milliseconds(parsed.astimezone(UTC))


def _parse_datetime(value: str, *, field_name: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"Sysmon {field_name} must be an ISO 8601 datetime") from error


def _truncate_to_milliseconds(value: datetime) -> datetime:
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


def _normalized_event_id(
    record: SysmonJsonlRecord,
    context: SysmonNormalizationContext,
) -> str:
    identity = json.dumps(
        [
            context.raw_log_id,
            context.segment_no,
            record.record_no,
            _required_record_id(record),
        ],
        separators=(",", ":"),
    )
    return f"evt-{uuid5(NAMESPACE_URL, identity)}"
