from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.decision.fusion.config import FusionConfig
from incident_awareness.decision.fusion.result_builder import (
    build_fusion_result,
)
from incident_awareness.decision.fusion.temporal_replay import (
    TemporalReplayResult,
    TemporalReplayRunner,
)


@dataclass(frozen=True, slots=True)
class FusionPipelineResult:
    replay_result: TemporalReplayResult
    fusion_result: FusionResult


def run_fusion_pipeline(
    evidences: Iterable[Evidence],
    *,
    runner: TemporalReplayRunner,
    run_id: str,
    entity_id: str,
    run_start: datetime,
    run_end: datetime,
    scoring_config_version: str,
    scoring_profile_id: str,
    scoring_method: str,
    scorer_version: str,
    model_version: str | None = None,
    replay_end: datetime | None = None,
) -> FusionPipelineResult:
    """Run Temporal Fusion for one run and entity pair.

    Preconditions:
    - All Evidence items must match the given run_id and entity_id.
    - Evidence timestamps must be UTC and non-decreasing.
    - Evidence timestamps must fall within the actual [run_start, run_end].
    - run_start and run_end must be UTC.
    - replay_end must align with the runner's fixed cadence. When omitted,
      replay_end is run_end.
    - Evidence after replay_end is excluded from score replay, while run_end
      remains the stopping-policy boundary for open episodes.
    - Ground Truth and reference_time must not be used as Fusion inputs.

    Replay-time validation is delegated to TemporalReplayRunner.
    """
    replay_result = runner.run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
        replay_end=replay_end,
    )

    fusion_result = build_fusion_result(
        replay_result,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=scoring_config_version,
        scoring_profile_id=scoring_profile_id,
        scoring_method=scoring_method,
        scorer_version=scorer_version,
        model_version=model_version,
    )

    return FusionPipelineResult(
        replay_result=replay_result,
        fusion_result=fusion_result,
    )


def run_fusion_pipeline_from_config(
    evidences: Iterable[Evidence],
    *,
    config: FusionConfig,
    run_id: str,
    entity_id: str,
    run_start: datetime,
    run_end: datetime,
    replay_end: datetime | None = None,
) -> FusionPipelineResult:
    """Run Temporal Fusion using one validated, versioned Fusion configuration."""
    runner = config.build_runner()

    return run_fusion_pipeline(
        evidences,
        runner=runner,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
        replay_end=replay_end,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
