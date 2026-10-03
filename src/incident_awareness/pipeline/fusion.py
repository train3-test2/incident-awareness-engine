"""Run First Cycle Fusion through the official S0 Runtime path."""

from dataclasses import dataclass

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
    FusionRuntimeReplaySnapshot,
    FusionRuntimeScoringSnapshot,
    FusionRuntimeStoppingSnapshot,
    FusionRuntimeWindowSnapshot,
)
from incident_awareness.decision.fusion.config import FusionConfig, load_fusion_config
from incident_awareness.integration.s0_replay_window import run_s0_runtime_fusion
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


@dataclass(frozen=True, slots=True)
class S0FusionPipelineResult:
    fusion_result: FusionResult
    stopping_trace: FusionStoppingTrace
    runtime_config_snapshot: FusionRuntimeConfigSnapshot


def run_s0_fusion(
    inputs: PipelineInputs,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
) -> FusionResult:
    """Create the target host FusionResult using the S0 replay policy."""
    return run_s0_fusion_with_trace(inputs, artifacts, normalized_artifacts).fusion_result


def run_s0_fusion_with_trace(
    inputs: PipelineInputs,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
) -> S0FusionPipelineResult:
    """Create the target host FusionResult and its Runtime stopping trace."""
    measured_end_time = artifacts.run_metadata.end_time
    if measured_end_time is None:
        raise ValueError("Fusion requires a completed RunMetadata end_time")

    config = load_fusion_config(inputs.fusion_config_path)
    runtime_config_snapshot = build_fusion_runtime_config_snapshot(
        config=config,
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
    )
    runtime_result = run_s0_runtime_fusion(
        normalized_artifacts.events,
        config=config,
        run_id=artifacts.run_metadata.run_id,
        start_time=artifacts.run_metadata.start_time,
        end_time=measured_end_time,
        expected_entity_ids=(inputs.entity_id,),
    )
    (fusion_result,) = runtime_result.fusion_results
    (stopping_trace,) = runtime_result.stopping_traces
    return S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
    )


def build_fusion_runtime_config_snapshot(
    *,
    config: FusionConfig,
    run_id: str,
    entity_id: str,
) -> FusionRuntimeConfigSnapshot:
    """Copy one validated execution config into its scoped Runtime contract."""
    return FusionRuntimeConfigSnapshot(
        run_id=run_id,
        entity_id=entity_id,
        config_version=config.config_version,
        model_version=config.model_version,
        window=FusionRuntimeWindowSnapshot(
            window_size_sec=config.window.window_size_sec,
        ),
        replay=FusionRuntimeReplaySnapshot(
            step_size_sec=config.replay.step_size_sec,
        ),
        scoring=FusionRuntimeScoringSnapshot(
            method=config.scoring.method,
            scorer_version=config.scoring.scorer_version,
            profile_id=config.scoring.profile_id,
            evidence_types=config.scoring.evidence_types,
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=config.stopping.threshold_on,
            threshold_off=config.stopping.threshold_off,
            persistence_k=config.stopping.persistence_k,
        ),
    )


__all__ = [
    "S0FusionPipelineResult",
    "build_fusion_runtime_config_snapshot",
    "run_s0_fusion",
    "run_s0_fusion_with_trace",
]
