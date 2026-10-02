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
from incident_awareness.decision.fusion.config import FusionConfig, load_fusion_config
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionAdapterResult,
    build_not_evaluated_detection_result,
)
from incident_awareness.normalization.sysmon import SysmonNormalizationContext

_STANDALONE_MANIFEST_ROOT = "raw"
_SYSMON_JSONL_FILENAME = "sysmon-0001.jsonl"
_SYSMON_EVTX_FILENAME = "sysmon-0001.evtx"
_SYSMON_SEGMENT_NO = 1
_SYSMON_PROCESS_CREATE_EVENT_ID = 1
_SYSMON_NETWORK_CONNECTION_EVENT_ID = 3
_SUPPORTED_SYSMON_EVENT_IDS = frozenset(
    {_SYSMON_PROCESS_CREATE_EVENT_ID, _SYSMON_NETWORK_CONNECTION_EVENT_ID}
)
DEFAULT_STANDALONE_FAST_MODE = "not_evaluated"
DEFAULT_STANDALONE_FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")
DEFAULT_STANDALONE_DECISION_CONFIG_VERSION = "parallel-v0.2"

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


@dataclass(frozen=True, slots=True)
class StandaloneExecutionConfig:
    """Validated Fusion and Hybrid policy selection for one standalone run."""

    fusion_config_path: Path
    fusion_config: FusionConfig
    decision_config_version: str


def build_default_standalone_fast_detection(
    *,
    run_id: str,
    entity_id: str,
) -> FastDetectionAdapterResult:
    """Build the standalone profile's explicitly unexecuted Fast result.

    A standalone Sysmon JSONL cannot establish that a Fast Runner was invoked,
    so this profile must not fabricate a handoff, hit, or Fast ``miss``.  Fast
    Runner execution remains a separately versioned integration contract.
    """
    return build_not_evaluated_detection_result(run_id=run_id, entity_id=entity_id)


def select_standalone_execution_config(
    *,
    fusion_config_path: Path | None = None,
    decision_config_version: str = DEFAULT_STANDALONE_DECISION_CONFIG_VERSION,
) -> StandaloneExecutionConfig:
    """Select the standalone Fusion profile and supported Hybrid policy.

    A caller may choose another readable, valid Fusion configuration.  Hybrid
    remains fixed to ``parallel-v0.2`` because the current Pipeline combiner
    implements only ``parallel_required=true``.
    """
    if decision_config_version != DEFAULT_STANDALONE_DECISION_CONFIG_VERSION:
        raise ValueError(
            "standalone execution supports only decision config "
            f"{DEFAULT_STANDALONE_DECISION_CONFIG_VERSION!r}"
        )

    selected_path = fusion_config_path or DEFAULT_STANDALONE_FUSION_CONFIG_PATH
    try:
        fusion_config = load_fusion_config(selected_path)
    except OSError as error:
        raise ValueError(f"standalone Fusion config is not readable: {selected_path}") from error

    return StandaloneExecutionConfig(
        fusion_config_path=selected_path,
        fusion_config=fusion_config,
        decision_config_version=decision_config_version,
    )


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
    normalizer, so it owns the standalone Run window as well.  Validate the
    Normalizer boundary before deriving any runnable artifacts from the input.
    """
    records = validate_standalone_sysmon_jsonl(path)
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
    validate_standalone_sysmon_jsonl(path)
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


def validate_standalone_sysmon_jsonl(path: Path) -> tuple[SysmonJsonlRecord, ...]:
    """Read one standalone JSONL and validate the current Normalizer boundary."""
    records = _read_records(path)
    for record in records:
        _validate_record_shape(record)
    return records


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


def _validate_record_shape(record: SysmonJsonlRecord) -> None:
    event_id = record.data.get("EventId")
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        raise TypeError(f"Sysmon record {record.record_no} EventId must be an integer")
    if event_id not in _SUPPORTED_SYSMON_EVENT_IDS:
        raise ValueError(
            f"Sysmon record {record.record_no} EventId {event_id} is unsupported; "
            "only EventId 1 and 3 are supported"
        )

    record_id = record.data.get("RecordId")
    if isinstance(record_id, bool) or not isinstance(record_id, int):
        raise TypeError(f"Sysmon record {record.record_no} RecordId must be an integer")

    _required_string(record.data, "Computer", record_no=record.record_no)
    _record_time(record)
    event_data = _event_data(record)
    _event_time(record)

    if event_id == _SYSMON_PROCESS_CREATE_EVENT_ID:
        _required_string(event_data, "Image", record_no=record.record_no)
    else:
        _optional_string(event_data, "Image", record_no=record.record_no)

    for field in ("User", "ProcessGuid", "CommandLine", "ParentImage", "ParentProcessGuid"):
        _optional_string(event_data, field, record_no=record.record_no)
    for field in ("ProcessId", "ParentProcessId"):
        _optional_decimal(event_data, field, record_no=record.record_no)

    if event_id == _SYSMON_NETWORK_CONNECTION_EVENT_ID:
        for field in ("Protocol", "SourceIp", "DestinationIp"):
            _optional_string(event_data, field, record_no=record.record_no)
        for field in ("SourcePort", "DestinationPort"):
            _optional_port(event_data, field, record_no=record.record_no)


def _event_data(record: SysmonJsonlRecord) -> dict[str, object]:
    event_data = record.data.get("EventData")
    if not isinstance(event_data, dict):
        raise TypeError(f"Sysmon record {record.record_no} EventData must be a JSON object")
    return event_data


def _record_time(record: SysmonJsonlRecord) -> datetime:
    value = _required_string(record.data, "TimeCreated", record_no=record.record_no)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(
            f"Sysmon record {record.record_no} TimeCreated must be an ISO 8601 datetime"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Sysmon record {record.record_no} TimeCreated must include timezone")
    return parsed.astimezone(UTC)


def _required_string(payload: dict[str, object], field: str, *, record_no: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Sysmon record {record_no} {field} must be a non-blank string")
    return value


def _optional_string(payload: dict[str, object], field: str, *, record_no: int) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Sysmon record {record_no} {field} must be a string when present")
    return value


def _optional_decimal(payload: dict[str, object], field: str, *, record_no: int) -> int | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.isdecimal():
        raise ValueError(
            f"Sysmon record {record_no} {field} must be a decimal integer when present"
        )
    return int(value)


def _optional_port(payload: dict[str, object], field: str, *, record_no: int) -> int | None:
    value = _optional_decimal(payload, field, record_no=record_no)
    if value is not None and not 0 <= value <= 65535:
        raise ValueError(f"Sysmon record {record_no} {field} must be between 0 and 65535")
    return value


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(f"standalone Sysmon JSONL is not readable: {path}") from error


__all__ = [
    "DEFAULT_STANDALONE_DECISION_CONFIG_VERSION",
    "DEFAULT_STANDALONE_FAST_MODE",
    "DEFAULT_STANDALONE_FUSION_CONFIG_PATH",
    "DEFAULT_STANDALONE_SCHEMA_VERSIONS",
    "StandaloneExecutionConfig",
    "StandaloneSysmonArtifacts",
    "build_default_standalone_fast_detection",
    "build_run_metadata_from_sysmon_jsonl",
    "build_sysmon_artifacts_from_jsonl",
    "select_standalone_execution_config",
    "validate_standalone_sysmon_jsonl",
]
