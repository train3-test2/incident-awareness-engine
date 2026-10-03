"""Run First Cycle Fusion through the official S0 Runtime path."""

from dataclasses import dataclass

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.decision.fusion.config import load_fusion_config
from incident_awareness.integration.s0_replay_window import run_s0_runtime_fusion
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


@dataclass(frozen=True, slots=True)
class S0FusionPipelineResult:
    fusion_result: FusionResult
    stopping_trace: FusionStoppingTrace


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
    )


__all__ = ["S0FusionPipelineResult", "run_s0_fusion", "run_s0_fusion_with_trace"]
