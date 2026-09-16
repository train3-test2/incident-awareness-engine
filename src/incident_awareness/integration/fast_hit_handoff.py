"""Read and validate the FastHitRecord JSONL handoff produced by Fast Runner."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.result import (
    DetectionResult,
    DetectorStatus,
    Severity,
)
from incident_awareness.common.models.run import RunMetadata

Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, pattern=r"^\S+$")]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
_UTC_MILLIS_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class FastHitRecord(BaseModel):
    """Validated FastHitRecord v0.2 handoff item.

    This model preserves Fast Runner observations only. It does not decide whether
    a hit becomes a detected, miss, or not-evaluated DetectionResult.
    """

    model_config = ConfigDict(extra="forbid")

    hit_id: Identifier
    run_id: Identifier
    timestamp: datetime
    detector_engine: Identifier
    detector_engine_version: Identifier
    rule_id: Identifier
    rule_version: Identifier
    alert_key: Identifier
    native_host_id: Identifier | None
    native_record_ref: Identifier | None
    detector_config_version: Identifier

    @field_validator("timestamp", mode="before")
    @classmethod
    def require_utc_millis_string(cls, value: object) -> object:
        if not isinstance(value, str) or not _UTC_MILLIS_PATTERN.fullmatch(value):
            raise ValueError("timestamp must be a UTC ISO 8601 millisecond string")
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_utc_millis(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be UTC")
        if value.microsecond % 1000 != 0:
            raise ValueError("timestamp must have millisecond precision")
        return value.astimezone(UTC)


class FastHitTraceEntry(BaseModel):
    """Trace entry connecting a handoff hit to its Hayabusa source row."""

    model_config = ConfigDict(extra="forbid")

    hit_id: Identifier
    source_row_index: int = Field(strict=True, ge=1)
    rule_id: Identifier


class FastHitTrace(BaseModel):
    """Completion marker and provenance emitted beside a FastHitRecord JSONL file."""

    model_config = ConfigDict(extra="forbid")

    run_id: Identifier
    input_csv: str = Field(min_length=1)
    input_sha256: Sha256
    config_sha256: Sha256
    output_sha256: Sha256
    input_row_count: int = Field(strict=True, ge=0)
    hit_count: int = Field(strict=True, ge=0)
    hits: list[FastHitTraceEntry]


@dataclass(frozen=True, slots=True)
class FastHitHandoff:
    """One validated Fast Runner handoff, ready for the later Fast Adapter stage."""

    records: tuple[FastHitRecord, ...]
    trace: FastHitTrace


class FastDetectionSelection(BaseModel):
    """Role 5's already-decided Fast Detection outcome for one entity.

    Selecting a hit, assigning severity, and deciding the status are Fast
    Detection policy decisions. The adapter only validates and carries them
    across the Contract boundary.
    """

    model_config = ConfigDict(extra="forbid")

    detector_status: DetectorStatus
    selected_hit_id: Identifier | None = None
    severity: Severity | None = None

    @model_validator(mode="after")
    def validate_status_metadata(self) -> FastDetectionSelection:
        if self.detector_status is DetectorStatus.DETECTED and self.selected_hit_id is None:
            raise ValueError("detected selection requires selected_hit_id")
        if self.detector_status is not DetectorStatus.DETECTED and self.selected_hit_id is not None:
            raise ValueError("only detected selection may include selected_hit_id")
        if self.detector_status is not DetectorStatus.DETECTED and self.severity is not None:
            raise ValueError("only detected selection may include severity")
        return self


@dataclass(frozen=True, slots=True)
class FastDetectionAdapterResult:
    """A DetectionResult together with retained FastHitRecord provenance."""

    detection_result: DetectionResult
    source_hit_ids: tuple[str, ...]


def read_fast_hit_handoff(
    jsonl_path: str | Path,
    trace_path: str | Path,
    *,
    run_id: str,
) -> FastHitHandoff:
    """Read a completed handoff and reject tampered or inconsistent artifacts.

    A caller must provide the Run context instead of trusting the value contained
    in either artifact. This function intentionally stops before DetectionResult
    selection and Hybrid decision invocation.
    """
    _validate_run_id(run_id)
    jsonl_path = Path(jsonl_path)
    trace_path = Path(trace_path)

    records = _read_records(jsonl_path)
    trace = _read_trace(trace_path)
    _validate_handoff(records, trace, jsonl_path=jsonl_path, expected_run_id=run_id)

    return FastHitHandoff(records=tuple(records), trace=trace)


def adapt_fast_hit_handoff(
    handoff: FastHitHandoff,
    *,
    entity_id: str,
    selection: FastDetectionSelection,
) -> FastDetectionAdapterResult:
    """Convert a completed Fast Runner handoff into a DetectionResult.

    This does not select a qualifying hit, calculate detector_time, map entities,
    or invoke Hybrid. A detected outcome copies the timestamp and Rule metadata
    from Role 5's selected hit. A miss is valid only after a completed handoff.
    """
    _validate_entity_id(entity_id)
    if selection.detector_status is DetectorStatus.NOT_EVALUATED:
        raise ValueError("not_evaluated must be created without a completed Fast Runner handoff")

    source_hit_ids = tuple(record.hit_id for record in handoff.records)
    if selection.detector_status is DetectorStatus.MISS:
        return FastDetectionAdapterResult(
            detection_result=DetectionResult(
                run_id=handoff.trace.run_id,
                entity_id=entity_id,
                detector_time=None,
                detector_status=DetectorStatus.MISS,
                detector_id=None,
                rule_id=None,
                rule_version=None,
                severity=None,
            ),
            source_hit_ids=source_hit_ids,
        )

    records_by_id = {record.hit_id: record for record in handoff.records}
    assert selection.selected_hit_id is not None
    selected_record = records_by_id.get(selection.selected_hit_id)
    if selected_record is None:
        raise ValueError("selected_hit_id is not present in the validated FastHitRecord handoff")

    detection_result = DetectionResult(
        run_id=handoff.trace.run_id,
        entity_id=entity_id,
        detector_time=selected_record.timestamp,
        detector_status=DetectorStatus.DETECTED,
        detector_id=selected_record.detector_engine,
        rule_id=selected_record.rule_id,
        rule_version=selected_record.rule_version,
        severity=selection.severity or Severity.UNKNOWN,
    )
    return FastDetectionAdapterResult(
        detection_result=detection_result,
        source_hit_ids=source_hit_ids,
    )


def build_not_evaluated_detection_result(
    *,
    run_id: str,
    entity_id: str,
) -> FastDetectionAdapterResult:
    """Represent an explicitly unexecuted Fast evaluator without a handoff.

    Invalid or unreadable artifacts must still fail validation; they must not be
    converted into not_evaluated because Fast Runner execution did occur.
    """
    _validate_run_id(run_id)
    _validate_entity_id(entity_id)
    return FastDetectionAdapterResult(
        detection_result=DetectionResult(
            run_id=run_id,
            entity_id=entity_id,
            detector_time=None,
            detector_status=DetectorStatus.NOT_EVALUATED,
            detector_id=None,
            rule_id=None,
            rule_version=None,
            severity=None,
        ),
        source_hit_ids=(),
    )


def _validate_run_id(run_id: str) -> None:
    try:
        RunMetadata.validate_required_identifier(run_id)
        RunMetadata.validate_run_id(run_id)
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid expected run_id: {run_id!r}") from error


def _validate_entity_id(entity_id: str) -> None:
    if not isinstance(entity_id, str) or not entity_id.strip() or entity_id != entity_id.strip():
        raise ValueError("entity_id must be a non-blank identifier without surrounding whitespace")


def _read_records(jsonl_path: Path) -> list[FastHitRecord]:
    try:
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read FastHitRecord JSONL: {jsonl_path}") from error

    records = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValueError(f"FastHitRecord JSONL contains a blank line at {line_number}")
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid FastHitRecord JSON at line {line_number}") from error
        records.append(_validate_record(payload, line_number=line_number))
    return records


def _read_trace(trace_path: Path) -> FastHitTrace:
    try:
        payload = json.loads(trace_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read FastHit trace: {trace_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError("invalid FastHit trace JSON") from error

    try:
        return FastHitTrace.model_validate(payload)
    except ValidationError as error:
        raise ValueError("invalid FastHit trace") from error


def _validate_record(payload: object, *, line_number: int) -> FastHitRecord:
    try:
        return FastHitRecord.model_validate(payload)
    except ValidationError as error:
        raise ValueError(f"invalid FastHitRecord at line {line_number}") from error


def _validate_handoff(
    records: list[FastHitRecord],
    trace: FastHitTrace,
    *,
    jsonl_path: Path,
    expected_run_id: str,
) -> None:
    actual_sha256 = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
    if trace.output_sha256 != actual_sha256:
        raise ValueError("FastHitRecord JSONL SHA-256 does not match the trace")
    if trace.run_id != expected_run_id:
        raise ValueError("FastHit trace run_id does not match the expected run_id")
    if trace.hit_count != len(records) or len(trace.hits) != len(records):
        raise ValueError("FastHit trace hit_count does not match the JSONL records")

    records_by_id = {record.hit_id: record for record in records}
    if len(records_by_id) != len(records):
        raise ValueError("FastHitRecord JSONL contains duplicate hit_id values")
    if any(record.run_id != expected_run_id for record in records):
        raise ValueError("FastHitRecord run_id does not match the expected run_id")

    trace_by_id = {entry.hit_id: entry for entry in trace.hits}
    if len(trace_by_id) != len(trace.hits):
        raise ValueError("FastHit trace contains duplicate hit_id values")
    if set(records_by_id) != set(trace_by_id):
        raise ValueError("FastHit trace hit_id values do not match the JSONL records")
    if len({entry.source_row_index for entry in trace.hits}) != len(trace.hits):
        raise ValueError("FastHit trace contains duplicate source_row_index values")

    for hit_id, record in records_by_id.items():
        if trace_by_id[hit_id].rule_id != record.rule_id:
            raise ValueError(f"FastHit trace rule_id does not match record {hit_id}")
