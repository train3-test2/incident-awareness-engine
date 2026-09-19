"""Run the existing Fusion pipeline for normalized First Cycle Evidence."""

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.decision.fusion.config import load_fusion_config
from incident_awareness.decision.fusion.pipeline import run_fusion_pipeline_from_config
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


def run_s0_fusion(
    inputs: PipelineInputs,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
) -> FusionResult:
    """Create one FusionResult from the current Run's extracted Evidence.

    Fusion is only evaluated after the Run has ended because the temporal
    replay requires a finite, cadence-aligned evaluation interval.
    """
    run_end = artifacts.run_metadata.end_time
    if run_end is None:
        raise ValueError("Fusion requires a completed RunMetadata end_time")

    config = load_fusion_config(inputs.fusion_config_path)
    result = run_fusion_pipeline_from_config(
        normalized_artifacts.evidences,
        config=config,
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
        run_start=artifacts.run_metadata.start_time,
        run_end=run_end,
    )
    return result.fusion_result


__all__ = ["run_s0_fusion"]
