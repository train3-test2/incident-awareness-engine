"""Orchestrate one First Cycle pipeline invocation through existing stages."""

import logging
from collections.abc import Callable
from datetime import datetime

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.fast import load_s0_fast_detection
from incident_awareness.pipeline.fusion import run_s0_fusion_with_trace
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
from incident_awareness.pipeline.runtime_telemetry import (
    PipelineRuntimeObserver,
    PipelineRuntimeTracker,
    generate_execution_id,
    utc_now_milliseconds,
)
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts

_LOGGER = logging.getLogger(__name__)


def run_first_cycle_pipeline(
    inputs: PipelineInputs,
    *,
    connection: DatabaseConnection | None = None,
    runtime_observer: PipelineRuntimeObserver | None = None,
) -> PipelineExecutionSummary:
    """Run the assembled First Cycle stages and report their terminal state."""
    started_at = _capture_runtime_started_at()
    artifacts = _run_stage(
        PipelineStage.ARTIFACT_VALIDATION,
        lambda: load_s0_pipeline_artifacts(inputs),
    )
    runtime_tracker = _bootstrap_runtime_tracker(
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
        input_total=len(artifacts.sysmon_records),
        started_at=started_at,
        observer=runtime_observer,
    )
    normalized_artifacts = _run_stage(
        PipelineStage.NORMALIZATION,
        lambda: normalize_sysmon_and_extract_evidence(
            artifacts,
            progress_callback=(
                runtime_tracker.record_normalization_progress
                if runtime_tracker is not None
                else None
            ),
        ),
        runtime_tracker=runtime_tracker,
    )
    fusion_output = _run_stage(
        PipelineStage.FUSION,
        lambda: run_s0_fusion_with_trace(inputs, artifacts, normalized_artifacts),
        runtime_tracker=runtime_tracker,
    )
    fusion_result = fusion_output.fusion_result
    stopping_trace = fusion_output.stopping_trace
    runtime_config_snapshot = fusion_output.runtime_config_snapshot
    fast_result = _run_stage(
        PipelineStage.FAST_HANDOFF,
        lambda: load_s0_fast_detection(inputs, artifacts),
        runtime_tracker=runtime_tracker,
    )
    decision_result = _run_stage(
        PipelineStage.HYBRID,
        lambda: _combine_with_lifecycle_resolution(
            inputs,
            fast_result,
            fusion_result,
            run_id=artifacts.run_metadata.run_id,
            connection=connection,
        ),
        runtime_tracker=runtime_tracker,
    )
    _run_stage(
        PipelineStage.PERSISTENCE,
        lambda: persist_s0_results(
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            runtime_config_snapshot,
            fast_result,
            decision_result,
            connection=connection,
        ),
        runtime_tracker=runtime_tracker,
    )
    if runtime_tracker is not None:
        runtime_tracker.complete()
    summary = build_execution_summary(
        artifacts,
        normalized_artifacts,
        fusion_result,
        fast_result,
        decision_result,
    )
    log_execution_summary(summary)
    return summary


def _capture_runtime_started_at() -> datetime | None:
    try:
        return utc_now_milliseconds()
    except Exception:
        _LOGGER.exception(
            "Pipeline Runtime started_at capture failed; disabling telemetry for this invocation"
        )
        return None


def _bootstrap_runtime_tracker(
    *,
    run_id: str,
    entity_id: str,
    input_total: int,
    started_at: datetime | None,
    observer: PipelineRuntimeObserver | None,
) -> PipelineRuntimeTracker | None:
    if started_at is None:
        return None

    try:
        return PipelineRuntimeTracker(
            execution_id=generate_execution_id(),
            run_id=run_id,
            entity_id=entity_id,
            input_total=input_total,
            started_at=started_at,
            observer=observer,
            clock=utc_now_milliseconds,
        )
    except Exception:
        _LOGGER.exception(
            "Pipeline Runtime tracker bootstrap failed; disabling telemetry for this invocation"
        )
        return None


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


def _run_stage[T](
    stage: PipelineStage,
    operation: Callable[[], T],
    *,
    runtime_tracker: PipelineRuntimeTracker | None = None,
) -> T:
    if runtime_tracker is not None:
        runtime_tracker.start_stage(stage)
    try:
        return operation()
    except Exception as error:
        if runtime_tracker is not None:
            runtime_tracker.fail(stage)
        log_pipeline_error(stage.value, error)
        raise


__all__ = ["run_first_cycle_pipeline"]
