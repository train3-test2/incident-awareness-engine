"""R1 candidate Evidence와 추출 상태를 Run 단위 artifact로 저장한다."""

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evidence.r1_multi_event import EXTRACTOR_VERSION
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline_with_diagnostics,
)

R1_EVIDENCE_FILENAME = "r1_evidence.jsonl"
R1_EXTRACTION_SUMMARY_FILENAME = "r1_extraction_summary.json"

type R1ExtractionStatus = Literal["completed", "failed"]
type TelemetryCompleteness = Literal["not_provided"]


@dataclass(frozen=True, slots=True)
class R1ExtractionSummary:
    """한 Run의 R1 extraction 종료 상태를 나타내는 로컬 sidecar 값."""

    run_id: str
    extractor_version: str
    input_event_count: int
    evidence_count: int | None
    status: R1ExtractionStatus
    telemetry_completeness: TelemetryCompleteness
    warnings: tuple[str, ...]
    diagnostics: tuple[str, ...]
    evidence_artifact_sha256: str | None


@dataclass(frozen=True, slots=True)
class R1EvidenceArtifactRun:
    """완료된 R1 extraction 결과와 게시된 artifact 경로."""

    evidences: tuple[Evidence, ...]
    summary: R1ExtractionSummary
    evidence_path: Path
    summary_path: Path


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
    event_batch = tuple(events)
    lineage_input_batch = tuple(lineage_inputs)

    try:
        _validate_event_run_scope(event_batch, run_id=run_id)
        pipeline_result = run_r1_evidence_pipeline_with_diagnostics(
            event_batch,
            lineage_inputs=lineage_input_batch,
        )
    except Exception as error:
        failed_summary = R1ExtractionSummary(
            run_id=run_id,
            extractor_version=EXTRACTOR_VERSION,
            input_event_count=len(event_batch),
            evidence_count=None,
            status="failed",
            telemetry_completeness="not_provided",
            warnings=(),
            diagnostics=(f"{type(error).__name__}: {error}",),
            evidence_artifact_sha256=None,
        )
        _publish_files(
            ((summary_path, _serialize_summary(failed_summary)),),
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
        warnings=(),
        diagnostics=pipeline_result.diagnostics,
        evidence_artifact_sha256=hashlib.sha256(evidence_content).hexdigest(),
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


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str):
        raise TypeError("run_id must be a string")
    RunMetadata.validate_required_identifier(run_id)
    RunMetadata.validate_run_id(run_id)


def _prepare_output_paths(output_directory: Path) -> tuple[Path, Path]:
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a Path")
    if not output_directory.is_dir():
        raise ValueError(f"output_directory must be an existing directory: {output_directory}")

    evidence_path = output_directory / R1_EVIDENCE_FILENAME
    summary_path = output_directory / R1_EXTRACTION_SUMMARY_FILENAME
    existing_paths = [path for path in (evidence_path, summary_path) if path.exists()]
    if existing_paths:
        names = ", ".join(path.name for path in existing_paths)
        raise FileExistsError(f"R1 artifact files must not already exist: {names}")

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


def _serialize_evidences(evidences: tuple[Evidence, ...]) -> bytes:
    return "".join(f"{evidence.model_dump_json()}\n" for evidence in evidences).encode("utf-8")


def _serialize_summary(summary: R1ExtractionSummary) -> bytes:
    payload = {
        "run_id": summary.run_id,
        "extractor_version": summary.extractor_version,
        "input_event_count": summary.input_event_count,
        "evidence_count": summary.evidence_count,
        "status": summary.status,
        "telemetry_completeness": summary.telemetry_completeness,
        "warnings": list(summary.warnings),
        "diagnostics": list(summary.diagnostics),
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
    "run_and_write_r1_evidence_artifacts",
]
