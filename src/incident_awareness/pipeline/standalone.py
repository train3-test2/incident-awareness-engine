"""Build First Cycle artifacts from a standalone Sysmon JSONL input."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.event import NORMALIZED_EVENT_SCHEMA_VERSION
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.normalization.sysmon import SysmonNormalizationContext

_STANDALONE_MANIFEST_ROOT = "generated/raw"
_SYSMON_JSONL_FILENAME = "sysmon-0001.jsonl"
_SYSMON_EVTX_FILENAME = "sysmon-0001.evtx"
_SYSMON_SEGMENT_NO = 1

DEFAULT_STANDALONE_SCHEMA_VERSIONS = SchemaVersions(
    run_metadata="v0.2",
    event=NORMALIZED_EVENT_SCHEMA_VERSION,
    evidence="v0.2",
    fast_hit="v0.2",
    detection_result="v0.2",
    fusion_result="v0.3",
    decision_result="v0.2",
    execution_record="v0.1",
    evaluation_input="v0.1",
)


@dataclass(frozen=True, slots=True)
class StandaloneSysmonArtifacts:
    """Generated Manifest and provenance context for one standalone JSONL."""

    manifest: dict[str, object]
    normalization_context: SysmonNormalizationContext


def build_run_metadata_from_sysmon_jsonl(
    path: Path,
    *,
    run_id: str,
    scenario_id: str,
    run_type: RunType,
    target_host: str,
    schema_versions: SchemaVersions | None = None,
) -> RunMetadata:
    """Build RunMetadata from the minimum and maximum Sysmon event times.

    ``EventData.UtcTime`` is the event-time source used by the Sysmon
    normalizer, so it owns the standalone Run window as well.  Input ordering
    and supported Event IDs are intentionally validated by later standalone
    preparation stages; this function only establishes the time range.
    """
    records = _read_records(path)
    event_times = tuple(_event_time(record) for record in records)

    return RunMetadata(
        run_id=run_id,
        scenario_id=scenario_id,
        run_type=run_type,
        target_host=target_host,
        start_time=min(event_times),
        end_time=max(event_times),
        schema_versions=(schema_versions or DEFAULT_STANDALONE_SCHEMA_VERSIONS).model_copy(
            deep=True
        ),
    )


def build_sysmon_artifacts_from_jsonl(
    path: Path,
    *,
    run_id: str,
) -> StandaloneSysmonArtifacts:
    """Build the manifest and Raw Log Provenance context for one JSONL source.

    The generated manifest records the expected First Cycle telemetry tail, not
    the caller's local source path.  This keeps the later materialized input
    directory portable while binding its JSONL bytes by SHA-256.
    """
    sha256 = _sha256(path)
    raw_log_id = f"RAW-{run_id}-SYSMON-001"
    evtx_raw_log_id = f"RAW-{run_id}-EVTX-001"
    telemetry_root = f"{_STANDALONE_MANIFEST_ROOT}/{run_id}/telemetry"
    evtx_path = f"{telemetry_root}/{_SYSMON_EVTX_FILENAME}"
    jsonl_path = f"{telemetry_root}/{_SYSMON_JSONL_FILENAME}"

    return StandaloneSysmonArtifacts(
        manifest={
            "run_id": run_id,
            "items": [
                {
                    "raw_log_id": evtx_raw_log_id,
                    "path": evtx_path,
                    "sha256": "0" * 64,
                    "layer": "raw_telemetry",
                    "source": "sysmon",
                },
                {
                    "raw_log_id": raw_log_id,
                    "path": jsonl_path,
                    "sha256": sha256,
                    "layer": "raw_telemetry",
                    "source": "sysmon",
                    "derived_from": evtx_path,
                },
            ],
        },
        normalization_context=SysmonNormalizationContext(
            run_id=run_id,
            raw_log_id=raw_log_id,
            segment_no=_SYSMON_SEGMENT_NO,
        ),
    )


def _read_records(path: Path) -> tuple[SysmonJsonlRecord, ...]:
    try:
        records = tuple(read_sysmon_jsonl(path))
    except (OSError, UnicodeDecodeError, SysmonJsonlReadError) as error:
        raise ValueError(f"standalone Sysmon JSONL is not readable: {path}") from error

    if not records:
        raise ValueError("standalone Sysmon JSONL must contain at least one record")
    return records


def _event_time(record: SysmonJsonlRecord) -> datetime:
    event_data = record.data.get("EventData")
    if not isinstance(event_data, dict):
        raise TypeError(f"Sysmon record {record.record_no} EventData must be a JSON object")

    value = event_data.get("UtcTime")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Sysmon record {record.record_no} EventData.UtcTime must be non-blank")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(
            f"Sysmon record {record.record_no} EventData.UtcTime must be an ISO 8601 datetime"
        ) from error

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC).replace(microsecond=parsed.microsecond // 1000 * 1000)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(f"standalone Sysmon JSONL is not readable: {path}") from error


__all__ = [
    "DEFAULT_STANDALONE_SCHEMA_VERSIONS",
    "StandaloneSysmonArtifacts",
    "build_run_metadata_from_sysmon_jsonl",
    "build_sysmon_artifacts_from_jsonl",
]
