"""Run First Cycle Fusion through the official S0 Runtime path."""

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.decision.fusion.config import load_fusion_config
from incident_awareness.integration.s0_replay_window import run_s0_runtime_fusion
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


def run_s0_fusion(
    inputs: PipelineInputs,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
) -> FusionResult:
    """Create the target host FusionResult using the S0 replay policy."""
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
    return runtime_result.fusion_results[0]


__all__ = ["run_s0_fusion"]
