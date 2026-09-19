"""Orchestrate one First Cycle pipeline invocation through existing stages."""

from collections.abc import Callable

from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.fast import load_s0_fast_detection
from incident_awareness.pipeline.fusion import run_s0_fusion
from incident_awareness.pipeline.hybrid import combine_parallel_decision
from incident_awareness.pipeline.persistence import DatabaseConnection, persist_s0_results
from incident_awareness.pipeline.reporting import (
    PipelineExecutionSummary,
    build_execution_summary,
    log_execution_summary,
    log_pipeline_error,
)
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts


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
        lambda: combine_parallel_decision(inputs, fast_result, fusion_result),
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


def _run_stage[T](stage: str, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except Exception as error:
        log_pipeline_error(stage, error)
        raise


__all__ = ["run_first_cycle_pipeline"]
