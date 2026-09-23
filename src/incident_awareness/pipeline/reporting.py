"""Execution summary and error logging for the First Cycle pipeline."""

import logging
from dataclasses import dataclass

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PipelineExecutionSummary:
    """A concise, runtime-only summary of one completed First Cycle execution."""

    run_id: str
    entity_id: str
    normalized_event_count: int
    evidence_count: int
    fusion_status: str
    detector_status: str
    decision_path: str | None


def build_execution_summary(
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
) -> PipelineExecutionSummary:
    """Create a summary after all First Cycle outputs have been produced."""
    return PipelineExecutionSummary(
        run_id=artifacts.run_metadata.run_id,
        entity_id=decision_result.entity_id,
        normalized_event_count=len(normalized_artifacts.events),
        evidence_count=len(normalized_artifacts.evidences),
        fusion_status=fusion_result.fusion_status,
        detector_status=fast_result.detection_result.detector_status.value,
        decision_path=(
            decision_result.decision_path.value
            if decision_result.decision_path is not None
            else None
        ),
    )


def log_execution_summary(summary: PipelineExecutionSummary) -> None:
    """Write one stable, non-Ground-Truth completion record at INFO level."""
    _LOGGER.info(
        "First Cycle pipeline completed: run_id=%s entity_id=%s events=%d evidences=%d "
        "fusion_status=%s detector_status=%s decision_path=%s",
        summary.run_id,
        summary.entity_id,
        summary.normalized_event_count,
        summary.evidence_count,
        summary.fusion_status,
        summary.detector_status,
        summary.decision_path,
    )


def log_pipeline_error(stage: str, error: Exception) -> None:
    """Log an execution failure with the stage that raised it."""
    _LOGGER.error("First Cycle pipeline failed at stage=%s: %s", stage, error, exc_info=error)


__all__ = [
    "PipelineExecutionSummary",
    "build_execution_summary",
    "log_execution_summary",
    "log_pipeline_error",
]
