"""Orchestrate one First Cycle pipeline invocation through existing stages."""

import logging
from collections.abc import Callable

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.fast import load_s0_fast_detection
from incident_awareness.pipeline.fusion import run_s0_fusion
from incident_awareness.pipeline.hybrid import combine_parallel_decision
from incident_awareness.pipeline.persistence import (
    DatabaseConnection,
    persist_s0_results,
    resolve_expected_supersedes_decision_id,
)
from incident_awareness.pipeline.reporting import (
    PipelineExecutionSummary,
    build_execution_summary,
    log_execution_summary,
    log_pipeline_error,
)
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts

_LOGGER = logging.getLogger(__name__)


def run_first_cycle_pipeline(
    inputs: PipelineInputs,
    *,
    connection: DatabaseConnection | None = None,
) -> PipelineExecutionSummary:
    """Run the assembled First Cycle stages and report their terminal state."""
    artifacts = _run_stage("artifact_validation", lambda: load_s0_pipeline_artifacts(inputs))
    normalized_artifacts = _run_stage(
        "normalization",
        lambda: normalize_sysmon_and_extract_evidence(artifacts),
    )
    fusion_result = _run_stage(
        "fusion",
        lambda: run_s0_fusion(inputs, artifacts, normalized_artifacts),
    )
    fast_result = _run_stage(
        "fast_handoff",
        lambda: load_s0_fast_detection(inputs, artifacts),
    )
    decision_result = _run_stage(
        "hybrid",
        lambda: _combine_with_lifecycle_resolution(
            inputs,
            fast_result,
            fusion_result,
            run_id=artifacts.run_metadata.run_id,
            connection=connection,
        ),
    )
    _run_stage(
        "persistence",
        lambda: persist_s0_results(
            artifacts,
            normalized_artifacts,
            fusion_result,
            fast_result,
            decision_result,
            connection=connection,
        ),
    )
    summary = build_execution_summary(
        artifacts,
        normalized_artifacts,
        fusion_result,
        fast_result,
        decision_result,
    )
    log_execution_summary(summary)
    return summary


def _combine_with_lifecycle_resolution(
    inputs: PipelineInputs,
    fast_result: FastDetectionAdapterResult,
    fusion_result: FusionResult,
    *,
    run_id: str,
    connection: DatabaseConnection | None,
) -> DecisionResult:
    expected_supersedes_decision_id = resolve_expected_supersedes_decision_id(
        decision_id=inputs.decision_id,
        run_id=run_id,
        entity_id=inputs.entity_id,
        connection=connection,
    )
    try:
        return combine_parallel_decision(
            inputs,
            fast_result,
            fusion_result,
            supersedes_decision_id=expected_supersedes_decision_id,
        )
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                _LOGGER.exception("Hybrid Decision rollback failed")
        raise


def _run_stage[T](stage: str, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except Exception as error:
        log_pipeline_error(stage, error)
        raise


__all__ = ["run_first_cycle_pipeline"]
