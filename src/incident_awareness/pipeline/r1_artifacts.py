"""R1 candidate Evidence와 추출 상태를 Run 단위 artifact로 저장한다."""

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter, ValidationError

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evidence.r1_multi_event import (
    EXTRACTOR_VERSION,
    R1ExtractionDiagnostic,
)
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline_with_diagnostics,
)

R1_EVIDENCE_FILENAME = "r1_evidence.jsonl"
R1_EXTRACTION_SUMMARY_FILENAME = "r1_extraction_summary.json"

type R1ExtractionStatus = Literal["completed", "failed"]
type TelemetryCompleteness = Literal["not_provided"]


@dataclass(frozen=True, slots=True)
class R1LineageInputProvenance:
    """Artifact에 기록할 명시적 lineage input과 policy identity."""

    anchor_event_id: str
    terminal_event_id: str
    policy_id: str
    policy_version: str
    policy_config_hash: str


@dataclass(frozen=True, slots=True)
class R1ExtractionSummary:
    """한 Run의 R1 extraction 종료 상태를 나타내는 로컬 sidecar 값."""

    run_id: str
    extractor_version: str
    input_event_count: int | None
    evidence_count: int | None
    status: R1ExtractionStatus
    telemetry_completeness: TelemetryCompleteness
    lineage_inputs: tuple[R1LineageInputProvenance, ...] | None
    warnings: tuple[str, ...]
    diagnostics: tuple[R1ExtractionDiagnostic, ...]
    error_type: str | None
    error_message: str | None
    evidence_artifact_sha256: str | None


@dataclass(frozen=True, slots=True)
class R1EvidenceArtifactRun:
    """완료된 R1 extraction 결과와 게시된 artifact 경로."""

    evidences: tuple[Evidence, ...]
    summary: R1ExtractionSummary
    evidence_path: Path
    summary_path: Path


_SUMMARY_FIELD_NAMES = frozenset(field.name for field in fields(R1ExtractionSummary))
_LINEAGE_PROVENANCE_FIELD_NAMES = frozenset(
    field.name for field in fields(R1LineageInputProvenance)
)
_SUMMARY_TYPE_ADAPTER = TypeAdapter(R1ExtractionSummary)
_SHA256_LENGTH = 64
_HEX_DIGITS = frozenset("0123456789abcdef")


def run_and_write_r1_evidence_artifacts(
    events: Iterable[NormalizedEvent],
    *,
    run_id: str,
    output_directory: Path,
    lineage_inputs: Iterable[R1LineageInput] = (),
) -> R1EvidenceArtifactRun:
    """명시적 R1 입력을 추출하고 immutable JSONL/summary artifact로 게시한다."""
    _validate_run_id(run_id)
    evidence_path, summary_path = _prepare_output_paths(output_directory)
    event_batch: tuple[NormalizedEvent, ...] | None = None
    lineage_input_batch: tuple[R1LineageInput, ...] | None = None
    lineage_provenance: tuple[R1LineageInputProvenance, ...] | None = None

    try:
        event_batch = tuple(events)
        lineage_input_batch = tuple(lineage_inputs)
        lineage_provenance = _lineage_input_provenance(lineage_input_batch)
        _validate_event_run_scope(event_batch, run_id=run_id)
        pipeline_result = run_r1_evidence_pipeline_with_diagnostics(
            event_batch,
            lineage_inputs=lineage_input_batch,
        )
    except Exception as error:
        failed_summary = R1ExtractionSummary(
            run_id=run_id,
            extractor_version=EXTRACTOR_VERSION,
            input_event_count=len(event_batch) if event_batch is not None else None,
            evidence_count=None,
            status="failed",
            telemetry_completeness="not_provided",
            lineage_inputs=lineage_provenance,
            warnings=(),
            diagnostics=(),
            error_type=type(error).__name__,
            error_message=str(error),
            evidence_artifact_sha256=None,
        )
        try:
            _publish_files(
                ((summary_path, _serialize_summary(failed_summary)),),
            )
        except OSError as publication_error:
            error.add_note(
                "R1 failed summary publication also failed: "
                f"{type(publication_error).__name__}: {publication_error}"
            )
        raise

    evidences = pipeline_result.evidences
    evidence_content = _serialize_evidences(evidences)
    completed_summary = R1ExtractionSummary(
        run_id=run_id,
        extractor_version=EXTRACTOR_VERSION,
        input_event_count=len(event_batch),
        evidence_count=len(evidences),
        status="completed",
        telemetry_completeness="not_provided",
        lineage_inputs=lineage_provenance,
        warnings=(),
        diagnostics=pipeline_result.diagnostics,
        error_type=None,
        error_message=None,
        evidence_artifact_sha256=_sha256(evidence_content),
    )
    _publish_files(
        (
            (evidence_path, evidence_content),
            (summary_path, _serialize_summary(completed_summary)),
        )
    )

    return R1EvidenceArtifactRun(
        evidences=evidences,
        summary=completed_summary,
        evidence_path=evidence_path,
        summary_path=summary_path,
    )


def load_r1_evidence_artifacts(output_directory: Path) -> R1EvidenceArtifactRun:
    """검증을 통과한 completed R1 Evidence artifact를 읽는다."""
    evidence_path, summary_path = _artifact_paths(output_directory)
    summary = _read_summary(summary_path)
    if summary.status != "completed":
        raise ValueError("failed R1 extraction artifact cannot be loaded as Evidence")

    evidence_content = _read_evidence_content(evidence_path)
    if _sha256(evidence_content) != summary.evidence_artifact_sha256:
        raise ValueError("R1 Evidence JSONL SHA-256 does not match the extraction summary")

    evidences = _read_evidences(evidence_content)
    _validate_completed_artifacts(evidences, summary)
    return R1EvidenceArtifactRun(
        evidences=evidences,
        summary=summary,
        evidence_path=evidence_path,
        summary_path=summary_path,
    )


def load_r1_extraction_summary(output_directory: Path) -> R1ExtractionSummary:
    """Evidence 소비 여부와 무관하게 R1 extraction summary를 검증해 읽는다."""
    _, summary_path = _artifact_paths(output_directory)
    return _read_summary(summary_path)


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str):
        raise TypeError("run_id must be a string")
    RunMetadata.validate_required_identifier(run_id)
    RunMetadata.validate_run_id(run_id)


def _prepare_output_paths(output_directory: Path) -> tuple[Path, Path]:
    evidence_path, summary_path = _artifact_paths(output_directory)
    existing_paths = [path for path in (evidence_path, summary_path) if path.exists()]
    if existing_paths:
        names = ", ".join(path.name for path in existing_paths)
        raise FileExistsError(f"R1 artifact files must not already exist: {names}")

    return evidence_path, summary_path


def _artifact_paths(output_directory: Path) -> tuple[Path, Path]:
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a Path")
    if not output_directory.is_dir():
        raise ValueError(f"output_directory must be an existing directory: {output_directory}")

    evidence_path = output_directory / R1_EVIDENCE_FILENAME
    summary_path = output_directory / R1_EXTRACTION_SUMMARY_FILENAME
    return evidence_path, summary_path


def _validate_event_run_scope(
    events: tuple[NormalizedEvent, ...],
    *,
    run_id: str,
) -> None:
    for event in events:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("events must contain NormalizedEvent items")
        if event.run_id != run_id:
            raise ValueError(
                "all events must belong to the requested run_id: "
                f"{event.event_id} belongs to {event.run_id}"
            )


def _lineage_input_provenance(
    lineage_inputs: tuple[R1LineageInput, ...],
) -> tuple[R1LineageInputProvenance, ...]:
    provenance: list[R1LineageInputProvenance] = []
    for lineage_input in lineage_inputs:
        if not isinstance(lineage_input, R1LineageInput):
            raise TypeError("lineage_inputs must contain R1LineageInput items")
        policy = lineage_input.approved_policy
        provenance.append(
            R1LineageInputProvenance(
                anchor_event_id=lineage_input.anchor_event_id,
                terminal_event_id=lineage_input.terminal_event_id,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                policy_config_hash=policy.config_hash,
            )
        )

    return tuple(
        sorted(
            provenance,
            key=_lineage_provenance_key,
        )
    )


def _serialize_evidences(evidences: tuple[Evidence, ...]) -> bytes:
    return "".join(f"{evidence.model_dump_json()}\n" for evidence in evidences).encode("utf-8")


def _serialize_summary(summary: R1ExtractionSummary) -> bytes:
    lineage_inputs = (
        None
        if summary.lineage_inputs is None
        else [
            {
                "anchor_event_id": item.anchor_event_id,
                "terminal_event_id": item.terminal_event_id,
                "policy_id": item.policy_id,
                "policy_version": item.policy_version,
                "policy_config_hash": item.policy_config_hash,
            }
            for item in summary.lineage_inputs
        ]
    )
    payload = {
        "run_id": summary.run_id,
        "extractor_version": summary.extractor_version,
        "input_event_count": summary.input_event_count,
        "evidence_count": summary.evidence_count,
        "status": summary.status,
        "telemetry_completeness": summary.telemetry_completeness,
        "lineage_inputs": lineage_inputs,
        "warnings": list(summary.warnings),
        "diagnostics": list(summary.diagnostics),
        "error_type": summary.error_type,
        "error_message": summary.error_message,
        "evidence_artifact_sha256": summary.evidence_artifact_sha256,
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _read_summary(path: Path) -> R1ExtractionSummary:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"R1 extraction summary is not valid JSON: {path}") from error

    try:
        _validate_summary_payload(payload)
        summary = _SUMMARY_TYPE_ADAPTER.validate_python(payload)
        _validate_summary_contract(summary)
    except (TypeError, ValueError) as error:
        raise ValueError("R1 extraction summary does not match the writer contract") from error
    return summary


def _validate_summary_payload(payload: object) -> None:
    if not isinstance(payload, dict):
        raise TypeError("R1 extraction summary must be a JSON object")
    if set(payload) != _SUMMARY_FIELD_NAMES:
        raise ValueError("R1 extraction summary fields do not match the writer contract")

    for field_name in ("run_id", "extractor_version"):
        value = payload[field_name]
        if not isinstance(value, str) or not value.strip():
            raise TypeError(f"{field_name} must be a non-blank string")
    for field_name in ("input_event_count", "evidence_count"):
        value = payload[field_name]
        if value is not None and type(value) is not int:
            raise TypeError(f"{field_name} must be an integer or null")
    for field_name in ("warnings", "diagnostics"):
        value = payload[field_name]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise TypeError(f"{field_name} must be an array of strings")
    for field_name in ("error_type", "error_message", "evidence_artifact_sha256"):
        value = payload[field_name]
        if value is not None and not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string or null")

    lineage_inputs = payload["lineage_inputs"]
    if lineage_inputs is None:
        return
    if not isinstance(lineage_inputs, list):
        raise TypeError("lineage_inputs must be an array or null")
    for item in lineage_inputs:
        if not isinstance(item, dict) or set(item) != _LINEAGE_PROVENANCE_FIELD_NAMES:
            raise TypeError("lineage_inputs items must match the provenance contract")
        if any(not isinstance(value, str) or not value.strip() for value in item.values()):
            raise TypeError("lineage_inputs provenance values must be non-blank strings")


def _validate_summary_contract(summary: R1ExtractionSummary) -> None:
    _validate_run_id(summary.run_id)
    for field_name, value in (
        ("input_event_count", summary.input_event_count),
        ("evidence_count", summary.evidence_count),
    ):
        if value is not None and value < 0:
            raise ValueError(f"{field_name} must not be negative")

    if summary.lineage_inputs is not None and summary.lineage_inputs != tuple(
        sorted(summary.lineage_inputs, key=_lineage_provenance_key)
    ):
        raise ValueError("lineage_inputs must use the writer's canonical ordering")

    if summary.status == "completed":
        if summary.input_event_count is None or summary.evidence_count is None:
            raise ValueError("completed summary requires Event and Evidence counts")
        if summary.lineage_inputs is None:
            raise ValueError("completed summary requires lineage_inputs provenance")
        if summary.error_type is not None or summary.error_message is not None:
            raise ValueError("completed summary must not contain extraction errors")
        if not _is_sha256(summary.evidence_artifact_sha256):
            raise ValueError("completed summary requires a SHA-256 value")
        return

    if summary.evidence_count is not None or summary.evidence_artifact_sha256 is not None:
        raise ValueError("failed summary must not describe a completed Evidence artifact")
    if summary.diagnostics:
        raise ValueError("failed summary must not store extraction exceptions as diagnostics")
    if not summary.error_type or summary.error_message is None:
        raise ValueError("failed summary requires error_type and error_message")


def _read_evidence_content(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"R1 Evidence JSONL is not readable: {path}") from error


def _read_evidences(content: bytes) -> tuple[Evidence, ...]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("R1 Evidence JSONL is not valid UTF-8") from error

    evidences: list[Evidence] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValueError(f"R1 Evidence JSONL contains a blank line at {line_number}")
        try:
            evidences.append(Evidence.model_validate_json(line))
        except ValidationError as error:
            raise ValueError(f"invalid Evidence JSON at line {line_number}") from error
    return tuple(evidences)


def _validate_completed_artifacts(
    evidences: tuple[Evidence, ...],
    summary: R1ExtractionSummary,
) -> None:
    if summary.evidence_count != len(evidences):
        raise ValueError("R1 Evidence count does not match the extraction summary")

    seen_evidence_ids: set[str] = set()
    for evidence in evidences:
        if evidence.evidence_id in seen_evidence_ids:
            raise ValueError(
                f"R1 Evidence JSONL contains duplicate evidence_id: {evidence.evidence_id}"
            )
        seen_evidence_ids.add(evidence.evidence_id)
        if evidence.run_id != summary.run_id:
            raise ValueError("Evidence run_id does not match the extraction summary")
        if evidence.extractor_version != summary.extractor_version:
            raise ValueError("Evidence extractor_version does not match the extraction summary")


def _lineage_provenance_key(
    provenance: R1LineageInputProvenance,
) -> tuple[str, str, str, str, str]:
    return (
        provenance.anchor_event_id,
        provenance.terminal_event_id,
        provenance.policy_id,
        provenance.policy_version,
        provenance.policy_config_hash,
    )


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == _SHA256_LENGTH and set(value) <= _HEX_DIGITS


def _publish_files(files: tuple[tuple[Path, bytes], ...]) -> None:
    """기존 파일을 덮어쓰지 않고 summary를 마지막 완료 표식으로 게시한다."""
    staged: list[Path] = []
    published: list[tuple[Path, Path]] = []
    try:
        for target, content in files:
            with tempfile.NamedTemporaryFile(
                dir=target.parent,
                prefix=f".{target.name}.",
                delete=False,
            ) as temporary:
                temporary.write(content)
                staged.append(Path(temporary.name))

        for source, (target, _) in zip(staged, files, strict=True):
            os.link(source, target)
            published.append((source, target))
    except BaseException:
        for source, target in reversed(published):
            try:
                if os.path.samestat(source.stat(), target.lstat()):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for source in staged:
            source.unlink(missing_ok=True)


__all__ = [
    "R1_EVIDENCE_FILENAME",
    "R1_EXTRACTION_SUMMARY_FILENAME",
    "R1EvidenceArtifactRun",
    "R1ExtractionSummary",
    "R1LineageInputProvenance",
    "load_r1_evidence_artifacts",
    "load_r1_extraction_summary",
    "run_and_write_r1_evidence_artifacts",
]
