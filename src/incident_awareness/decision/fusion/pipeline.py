from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.fusion import FusionResult
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
) -> FusionPipelineResult:
    """Run Temporal Fusion for one run and entity pair.

    Preconditions:
    - All Evidence items must match the given run_id and entity_id.
    - Evidence timestamps must be UTC and non-decreasing.
    - Evidence timestamps must fall within [run_start, run_end].
    - run_start and run_end must be UTC.
    - run_end must align with the runner's fixed cadence.
    - Ground Truth and reference_time must not be used as Fusion inputs.

    Replay-time validation is delegated to TemporalReplayRunner.
    """
    replay_result = runner.run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
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
