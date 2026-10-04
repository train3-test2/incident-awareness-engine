"""Build First Cycle artifacts from a standalone Sysmon JSONL input."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import psycopg

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
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.fusion import run_s0_fusion
from incident_awareness.pipeline.hybrid import combine_parallel_decision
from incident_awareness.pipeline.persistence import DatabaseConnection, persist_s0_results
from incident_awareness.pipeline.reporting import PipelineExecutionSummary, build_execution_summary
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts
from incident_awareness.storage.config import DatabaseConfig

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

_LOGGER = logging.getLogger(__name__)

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


@dataclass(frozen=True, slots=True)
class StandalonePreparedRun:
    """Materialized standalone artifacts and their ready-to-run Pipeline inputs."""

    output_dir: Path
    inputs: PipelineInputs


@dataclass(frozen=True, slots=True)
class StandaloneOutputReservation:
    """An output directory atomically reserved for one standalone execution."""

    run_id: str
    decision_id: str
    output_dir: Path


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


def prepare_standalone_run(
    *,
    sysmon_jsonl_path: Path,
    output_dir: Path,
    run_id: str,
    decision_id: str,
    scenario_id: str = "S0",
    run_type: RunType = RunType.ATTACK,
    target_host: str | None = None,
    entity_id: str | None = None,
    fusion_config_path: Path | None = None,
    output_dir_reserved: bool = False,
) -> StandalonePreparedRun:
    """Validate JSONL and materialize the minimum runnable First Cycle inputs."""
    records = validate_standalone_sysmon_jsonl(sysmon_jsonl_path)
    inferred_host = _required_string(records[0].data, "Computer", record_no=records[0].record_no)
    selected_target_host = target_host or inferred_host
    if selected_target_host != inferred_host:
        raise ValueError("target_host must match the single Computer value in the Sysmon JSONL")

    selected_entity_id = entity_id or selected_target_host
    if selected_entity_id != selected_target_host:
        raise ValueError("entity_id must match target_host for the standalone direct host mapping")
    _validate_identifier(decision_id, "decision_id")

    owns_output_dir = output_dir_reserved
    if output_dir_reserved:
        if not output_dir.is_dir():
            raise ValueError(f"reserved standalone output directory is unavailable: {output_dir}")
    else:
        try:
            output_dir.mkdir(parents=True)
        except FileExistsError as error:
            raise ValueError(f"standalone output directory already exists: {output_dir}") from error
        owns_output_dir = True

    try:
        execution_config = select_standalone_execution_config(fusion_config_path=fusion_config_path)
        telemetry_dir = output_dir / "telemetry"
        destination_jsonl = telemetry_dir / _SYSMON_JSONL_FILENAME
        telemetry_dir.mkdir()
        shutil.copyfile(sysmon_jsonl_path, destination_jsonl)
        metadata = build_run_metadata_from_sysmon_jsonl(
            destination_jsonl,
            run_id=run_id,
            scenario_id=scenario_id,
            run_type=run_type,
            target_host=selected_target_host,
        )
        generated = build_sysmon_artifacts_from_jsonl(destination_jsonl, run_id=run_id)
        run_metadata_path = output_dir / "run_metadata.json"
        manifest_path = output_dir / "manifest.json"
        run_metadata_path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
        manifest_path.write_text(json.dumps(generated.manifest, indent=2), encoding="utf-8")
    except Exception:
        if owns_output_dir:
            shutil.rmtree(output_dir, ignore_errors=True)
        raise

    return StandalonePreparedRun(
        output_dir=output_dir,
        inputs=PipelineInputs(
            run_metadata_path=run_metadata_path,
            manifest_path=manifest_path,
            sysmon_jsonl_path=destination_jsonl,
            # The standalone profile deliberately does not create Fast artifacts.
            # These paths are never read because it bypasses load_s0_fast_detection().
            fast_hits_path=output_dir / "fast" / "hits.jsonl",
            fast_trace_path=output_dir / "fast" / "trace.json",
            fast_selection_path=output_dir / "fast" / "selection.json",
            fusion_config_path=execution_config.fusion_config_path,
            entity_id=selected_entity_id,
            decision_id=decision_id,
            decision_config_version=execution_config.decision_config_version,
        ),
    )


def run_prepared_standalone_run(
    prepared: StandalonePreparedRun,
    *,
    connection: DatabaseConnection,
) -> PipelineExecutionSummary:
    """Run the existing First Cycle stages with standalone Fast semantics."""
    artifacts = load_s0_pipeline_artifacts(prepared.inputs)
    normalized_artifacts = normalize_sysmon_and_extract_evidence(artifacts)
    fusion_result = run_s0_fusion(prepared.inputs, artifacts, normalized_artifacts)
    fast_result = build_default_standalone_fast_detection(
        run_id=artifacts.run_metadata.run_id,
        entity_id=prepared.inputs.entity_id,
    )
    decision_result = combine_parallel_decision(
        prepared.inputs,
        fast_result,
        fusion_result,
    )
    persist_s0_results(
        artifacts,
        normalized_artifacts,
        fusion_result,
        fast_result,
        decision_result,
        connection=connection,
    )
    return build_execution_summary(
        artifacts,
        normalized_artifacts,
        fusion_result,
        fast_result,
        decision_result,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the standalone Sysmon JSONL CLI contract."""
    parser = argparse.ArgumentParser(
        prog="incident-awareness-standalone",
        description="Run First Cycle from one Sysmon JSONL file.",
    )
    parser.add_argument("--sysmon-jsonl", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--scenario-id", default="S0")
    parser.add_argument(
        "--run-type", choices=[run_type.value for run_type in RunType], default="attack"
    )
    parser.add_argument("--target-host")
    parser.add_argument("--entity-id")
    parser.add_argument("--fusion-config", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Create standalone artifacts and persist one First Cycle execution."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    namespace = build_parser().parse_args(argv)
    sysmon_jsonl_path = namespace.sysmon_jsonl.resolve()
    output_root = (
        namespace.output_dir or sysmon_jsonl_path.parent / ".incident-awareness" / "first-cycle"
    ).resolve()
    database_config = DatabaseConfig.from_environment()

    with psycopg.connect(database_config.url, autocommit=False) as connection:
        reservation = _allocate_identifiers(connection, output_root)
        try:
            prepared = prepare_standalone_run(
                sysmon_jsonl_path=sysmon_jsonl_path,
                output_dir=reservation.output_dir,
                run_id=reservation.run_id,
                decision_id=reservation.decision_id,
                scenario_id=_validate_identifier(namespace.scenario_id, "scenario_id"),
                run_type=RunType(namespace.run_type),
                target_host=namespace.target_host,
                entity_id=namespace.entity_id,
                fusion_config_path=namespace.fusion_config,
                output_dir_reserved=True,
            )
            summary = run_prepared_standalone_run(prepared, connection=connection)
        except Exception:
            shutil.rmtree(reservation.output_dir, ignore_errors=True)
            raise

    _LOGGER.info("Standalone First Cycle output: %s", prepared.output_dir)
    print(json.dumps(asdict(summary), sort_keys=True))
    return 0


def _allocate_identifiers(
    connection: DatabaseConnection,
    output_root: Path,
    *,
    now: datetime | None = None,
) -> StandaloneOutputReservation:
    """Atomically reserve the next unused UTC-date Run output directory."""
    date_part = (now or datetime.now(UTC)).strftime("%Y%m%d")
    for sequence in range(1, 1000):
        run_id = f"RUN-{date_part}-{sequence:03d}"
        decision_id = f"DEC-{run_id}"
        output_dir = output_root / run_id
        try:
            output_dir.mkdir(parents=True)
        except FileExistsError:
            continue
        try:
            row = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM runs WHERE run_id = %s) "
                "OR EXISTS (SELECT 1 FROM decisions WHERE decision_id = %s)",
                (run_id, decision_id),
            ).fetchone()
        except Exception:
            shutil.rmtree(output_dir, ignore_errors=True)
            raise
        exists = row[0] if isinstance(row, tuple) else row["exists"] if row else None
        if exists is False:
            return StandaloneOutputReservation(
                run_id=run_id,
                decision_id=decision_id,
                output_dir=output_dir,
            )
        shutil.rmtree(output_dir, ignore_errors=True)

    raise RuntimeError("no unused standalone run_id remains for the current UTC date")


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
    target_host: str | None = None
    previous_event_time: datetime | None = None
    for record in records:
        _validate_record_shape(record)
        host = _required_string(record.data, "Computer", record_no=record.record_no)
        event_time = _event_time(record)

        if target_host is None:
            target_host = host
        elif host != target_host:
            raise ValueError(
                "standalone Sysmon JSONL must contain exactly one Computer value; "
                f"record {record.record_no} is {host!r}, expected {target_host!r}"
            )

        if previous_event_time is not None and event_time < previous_event_time:
            raise ValueError(
                "standalone Sysmon JSONL EventData.UtcTime must be in non-decreasing order; "
                f"record {record.record_no} is earlier than record {record.record_no - 1}"
            )
        previous_event_time = event_time
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


def _validate_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-blank identifier without surrounding whitespace")
    return value


__all__ = [
    "DEFAULT_STANDALONE_DECISION_CONFIG_VERSION",
    "DEFAULT_STANDALONE_FAST_MODE",
    "DEFAULT_STANDALONE_FUSION_CONFIG_PATH",
    "DEFAULT_STANDALONE_SCHEMA_VERSIONS",
    "StandaloneExecutionConfig",
    "StandaloneOutputReservation",
    "StandalonePreparedRun",
    "StandaloneSysmonArtifacts",
    "build_default_standalone_fast_detection",
    "build_parser",
    "build_run_metadata_from_sysmon_jsonl",
    "build_sysmon_artifacts_from_jsonl",
    "prepare_standalone_run",
    "run_prepared_standalone_run",
    "select_standalone_execution_config",
    "validate_standalone_sysmon_jsonl",
]


if __name__ == "__main__":
    raise SystemExit(main())
