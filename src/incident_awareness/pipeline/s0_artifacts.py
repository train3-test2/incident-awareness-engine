"""Validate the S0 artifacts explicitly passed to the First Cycle CLI."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)
from incident_awareness.collection.s0_validation import ManifestPathError, manifest_artifact_name
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.cli import PipelineInputs

_SHA256_LENGTH = 64
_HEX_DIGITS = frozenset("0123456789abcdef")
_SYSMON_JSONL_FILENAME = "sysmon-0001.jsonl"
_SYSMON_SEGMENT_NO = 1


@dataclass(frozen=True, slots=True)
class S0PipelineArtifacts:
    """Validated S0 artifacts ready for the Pipeline normalization stage."""

    run_metadata: RunMetadata
    sysmon_records: tuple[SysmonJsonlRecord, ...]
    normalization_context: SysmonNormalizationContext


def load_s0_pipeline_artifacts(inputs: PipelineInputs) -> S0PipelineArtifacts:
    """Load the named S0 artifacts and bind Sysmon provenance to the manifest.

    The supplied paths are authoritative. In particular, a VM absolute path in
    manifest.json is never opened; its approved artifact filename is used only
    to identify the supplied JSONL and validate its recorded SHA-256.
    """
    run_metadata = _read_run_metadata(inputs.run_metadata_path)
    manifest = _read_json_object(inputs.manifest_path, "manifest")
    manifest_run_id = manifest.get("run_id")
    if manifest_run_id != run_metadata.run_id:
        raise ValueError(
            "manifest run_id must match run_metadata run_id: "
            f"{manifest_run_id!r} != {run_metadata.run_id!r}"
        )

    raw_log_id = _validate_sysmon_manifest_item(
        manifest,
        run_id=run_metadata.run_id,
        sysmon_jsonl_path=inputs.sysmon_jsonl_path,
    )
    records = _read_sysmon_records(inputs.sysmon_jsonl_path)

    return S0PipelineArtifacts(
        run_metadata=run_metadata,
        sysmon_records=records,
        normalization_context=SysmonNormalizationContext(
            run_id=run_metadata.run_id,
            raw_log_id=raw_log_id,
            segment_no=_SYSMON_SEGMENT_NO,
        ),
    )


def _read_run_metadata(path: Path) -> RunMetadata:
    try:
        return RunMetadata.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValidationError) as error:
        raise ValueError(f"run_metadata is not a valid RunMetadata artifact: {path}") from error


def _read_json_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON: {path}") from error

    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object: {path}")

    return value


def _validate_sysmon_manifest_item(
    manifest: dict[str, object],
    *,
    run_id: str,
    sysmon_jsonl_path: Path,
) -> str:
    items = manifest.get("items")
    if not isinstance(items, list):
        raise TypeError("manifest items must be an array")

    candidates: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        try:
            artifact_name = manifest_artifact_name(item.get("path"), run_id=run_id)
        except ManifestPathError as error:
            raise ValueError(f"manifest item path is invalid: {error}") from error

        if artifact_name == _SYSMON_JSONL_FILENAME:
            candidates.append(item)

    if len(candidates) != 1:
        raise ValueError("manifest must contain exactly one Sysmon JSONL item")

    item = candidates[0]
    if sysmon_jsonl_path.name != _SYSMON_JSONL_FILENAME:
        raise ValueError(f"sysmon_jsonl path must name {_SYSMON_JSONL_FILENAME}")
    if item.get("layer") != "raw_telemetry" or item.get("source") != "sysmon":
        raise ValueError("Sysmon JSONL manifest item must be raw_telemetry from sysmon")

    raw_log_id = item.get("raw_log_id")
    if (
        not isinstance(raw_log_id, str)
        or not raw_log_id.strip()
        or raw_log_id != raw_log_id.strip()
    ):
        raise ValueError("Sysmon JSONL manifest item must define a non-blank raw_log_id")

    try:
        derived_name = manifest_artifact_name(item.get("derived_from"), run_id=run_id)
    except ManifestPathError as error:
        raise ValueError("Sysmon JSONL manifest item must derive from sysmon-0001.evtx") from error
    if derived_name != "sysmon-0001.evtx":
        raise ValueError("Sysmon JSONL manifest item must derive from sysmon-0001.evtx")

    expected_sha256 = item.get("sha256")
    if not _is_sha256(expected_sha256):
        raise ValueError("Sysmon JSONL manifest item must define a SHA-256 value")
    actual_sha256 = hashlib.sha256(sysmon_jsonl_path.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError("Sysmon JSONL SHA-256 must match the manifest")

    return raw_log_id


def _read_sysmon_records(path: Path) -> tuple[SysmonJsonlRecord, ...]:
    try:
        records = tuple(read_sysmon_jsonl(path))
    except (OSError, UnicodeDecodeError, SysmonJsonlReadError) as error:
        raise ValueError(f"Sysmon JSONL is not readable: {path}") from error

    if not records:
        raise ValueError("Sysmon JSONL must contain at least one record")

    return records


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and set(value.lower()) <= _HEX_DIGITS
    )


__all__ = ["S0PipelineArtifacts", "load_s0_pipeline_artifacts"]
