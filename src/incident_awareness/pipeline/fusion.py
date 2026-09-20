"""Run the existing Fusion pipeline for normalized First Cycle Evidence."""

from datetime import datetime, timedelta

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
    measured_end_time = artifacts.run_metadata.end_time
    if measured_end_time is None:
        raise ValueError("Fusion requires a completed RunMetadata end_time")

    config = load_fusion_config(inputs.fusion_config_path)
    replay_end = _last_replay_tick(
        artifacts.run_metadata.start_time,
        measured_end_time,
        step_size=timedelta(seconds=config.replay.step_size_sec),
    )
    result = run_fusion_pipeline_from_config(
        normalized_artifacts.evidences,
        config=config,
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
        run_start=artifacts.run_metadata.start_time,
        run_end=replay_end,
    )
    return result.fusion_result


def _last_replay_tick(
    run_start: datetime,
    measured_end_time: datetime,
    *,
    step_size: timedelta,
) -> datetime:
    """Return the last fixed-cadence replay point that does not exceed Run end."""
    elapsed = measured_end_time - run_start
    return run_start + (elapsed // step_size) * step_size


__all__ = ["run_s0_fusion"]
