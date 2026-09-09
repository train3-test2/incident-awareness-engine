from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
    FusionResult,
)
from incident_awareness.decision.fusion.temporal_replay import (
    TemporalReplayResult,
)


def build_fusion_result(
    replay_result: TemporalReplayResult,
    *,
    run_id: str,
    entity_id: str,
    scoring_config_version: str,
    scoring_profile_id: str,
    scoring_method: str,
    scorer_version: str,
    model_version: str | None = None,
) -> FusionResult:
    stopping_result = replay_result.stopping_result

    evidence_ids_by_timestamp = {
        snapshot.timestamp: snapshot.contributing_evidence_ids
        for snapshot in replay_result.evidence_snapshots
    }

    fusion_episodes: list[FusionEpisodeResult] = []

    for episode in stopping_result.fusion_episodes:
        contributing_evidence_ids = evidence_ids_by_timestamp.get(episode.start_time)

        if contributing_evidence_ids is None:
            raise ValueError("Missing Evidence snapshot for FusionEpisode start_time")

        fusion_episodes.append(
            FusionEpisodeResult(
                episode_id=episode.episode_id,
                run_id=episode.run_id,
                entity_id=episode.entity_id,
                start_time=episode.start_time,
                end_time=episode.end_time,
                end_reason=episode.end_reason,
                score_at_start=episode.score_at_start,
                peak_score=episode.peak_score,
                contributing_evidence_ids=list(contributing_evidence_ids),
            )
        )

    if stopping_result.fusion_status == "detected":
        if stopping_result.fusion_time is None:
            raise ValueError("Detected StoppingResult must include fusion_time")

        contributing_evidence_ids = evidence_ids_by_timestamp.get(stopping_result.fusion_time)

        if contributing_evidence_ids is None:
            raise ValueError("Missing Evidence snapshot for fusion_time")

        result_contributing_evidence_ids = list(contributing_evidence_ids)
    else:
        result_contributing_evidence_ids = []

    return FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=stopping_result.fusion_time,
        fusion_status=stopping_result.fusion_status,
        score_at_decision=stopping_result.score_at_decision,
        contributing_evidence_ids=result_contributing_evidence_ids,
        scoring_config_version=scoring_config_version,
        scoring_profile_id=scoring_profile_id,
        model_version=model_version,
        scoring_method=scoring_method,
        scorer_version=scorer_version,
        fusion_episodes=fusion_episodes,
    )
