from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.decision.fusion.result_builder import (
    build_fusion_result,
    build_not_evaluated_fusion_result,
)
from incident_awareness.decision.fusion.stopping_policy import (
    FusionEpisode,
    StoppingResult,
)
from incident_awareness.decision.fusion.temporal_replay import (
    ReplayEvidenceSnapshot,
    TemporalReplayResult,
)


def test_builds_detected_fusion_result_from_replay_result() -> None:
    # Given
    run_start = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)
    fusion_time = run_start + timedelta(seconds=20)
    run_end = run_start + timedelta(seconds=40)

    replay_result = TemporalReplayResult(
        trajectory=(),
        evidence_snapshots=(
            ReplayEvidenceSnapshot(
                timestamp=fusion_time,
                contributing_evidence_ids=("EVD-001", "EVD-002"),
            ),
        ),
        stopping_result=StoppingResult(
            fusion_status="detected",
            fusion_time=fusion_time,
            score_at_decision=1.0,
            fusion_episodes=(
                FusionEpisode(
                    episode_id="FEP-001",
                    run_id="RUN-01",
                    entity_id="HOST-01",
                    start_time=fusion_time,
                    end_time=run_end,
                    end_reason="run_end",
                    score_at_start=1.0,
                    peak_score=1.0,
                ),
            ),
        ),
    )

    # When
    result = build_fusion_result(
        replay_result,
        run_id="RUN-01",
        entity_id="HOST-01",
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == fusion_time
    assert result.score_at_decision == 1.0
    assert result.contributing_evidence_ids == ["EVD-001", "EVD-002"]
    assert len(result.fusion_episodes) == 1
    assert result.fusion_episodes[0].contributing_evidence_ids == [
        "EVD-001",
        "EVD-002",
    ]


def test_builds_miss_fusion_result_without_contributing_evidence() -> None:
    # Given
    replay_result = TemporalReplayResult(
        trajectory=(),
        evidence_snapshots=(),
        stopping_result=StoppingResult(
            fusion_status="miss",
            fusion_time=None,
            score_at_decision=None,
            fusion_episodes=(),
        ),
    )

    # When
    result = build_fusion_result(
        replay_result,
        run_id="RUN-01",
        entity_id="HOST-01",
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        model_version="simple-score-v0.1",
    )

    # Then
    assert result.fusion_status == "miss"
    assert result.fusion_time is None
    assert result.score_at_decision is None
    assert result.contributing_evidence_ids == []
    assert result.fusion_episodes == []
    assert result.model_version == "simple-score-v0.1"


def test_preserves_contributing_evidence_for_each_reentry_episode() -> None:
    # Given
    first_start = datetime(2026, 9, 9, 1, 0, 10, tzinfo=UTC)
    first_end = first_start + timedelta(seconds=10)
    second_start = first_start + timedelta(seconds=20)
    run_end = second_start + timedelta(seconds=10)

    replay_result = TemporalReplayResult(
        trajectory=(),
        evidence_snapshots=(
            ReplayEvidenceSnapshot(
                timestamp=first_start,
                contributing_evidence_ids=("EVD-001",),
            ),
            ReplayEvidenceSnapshot(
                timestamp=second_start,
                contributing_evidence_ids=("EVD-002", "EVD-003"),
            ),
        ),
        stopping_result=StoppingResult(
            fusion_status="detected",
            fusion_time=first_start,
            score_at_decision=0.8,
            fusion_episodes=(
                FusionEpisode(
                    episode_id="FEP-001",
                    run_id="RUN-01",
                    entity_id="HOST-01",
                    start_time=first_start,
                    end_time=first_end,
                    end_reason="released",
                    score_at_start=0.8,
                    peak_score=0.9,
                ),
                FusionEpisode(
                    episode_id="FEP-002",
                    run_id="RUN-01",
                    entity_id="HOST-01",
                    start_time=second_start,
                    end_time=run_end,
                    end_reason="run_end",
                    score_at_start=0.9,
                    peak_score=1.0,
                ),
            ),
        ),
    )

    # When
    result = build_fusion_result(
        replay_result,
        run_id="RUN-01",
        entity_id="HOST-01",
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    # Then
    assert result.fusion_time == first_start
    assert result.contributing_evidence_ids == ["EVD-001"]
    assert result.fusion_episodes[0].contributing_evidence_ids == ["EVD-001"]
    assert result.fusion_episodes[1].contributing_evidence_ids == [
        "EVD-002",
        "EVD-003",
    ]


def test_rejects_missing_snapshot_for_episode_start() -> None:
    # Given
    first_start = datetime(2026, 9, 9, 1, 0, 10, tzinfo=UTC)
    second_start = first_start + timedelta(seconds=20)
    run_end = second_start + timedelta(seconds=10)

    replay_result = TemporalReplayResult(
        trajectory=(),
        evidence_snapshots=(
            ReplayEvidenceSnapshot(
                timestamp=first_start,
                contributing_evidence_ids=("EVD-001",),
            ),
        ),
        stopping_result=StoppingResult(
            fusion_status="detected",
            fusion_time=first_start,
            score_at_decision=0.8,
            fusion_episodes=(
                FusionEpisode(
                    episode_id="FEP-001",
                    run_id="RUN-01",
                    entity_id="HOST-01",
                    start_time=first_start,
                    end_time=first_start + timedelta(seconds=10),
                    end_reason="released",
                    score_at_start=0.8,
                    peak_score=0.9,
                ),
                FusionEpisode(
                    episode_id="FEP-002",
                    run_id="RUN-01",
                    entity_id="HOST-01",
                    start_time=second_start,
                    end_time=run_end,
                    end_reason="run_end",
                    score_at_start=0.9,
                    peak_score=1.0,
                ),
            ),
        ),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        build_fusion_result(
            replay_result,
            run_id="RUN-01",
            entity_id="HOST-01",
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
        )

    # Then
    assert "Missing Evidence snapshot for FusionEpisode start_time" in str(exc_info.value)


def test_builds_not_evaluated_fusion_result_without_replay() -> None:
    # Given
    run_id = "RUN-01"
    entity_id = "HOST-01"

    # When
    result = build_not_evaluated_fusion_result(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        model_version=None,
    )

    # Then
    assert result.run_id == run_id
    assert result.entity_id == entity_id
    assert result.fusion_status == "not_evaluated"
    assert result.fusion_time is None
    assert result.score_at_decision is None
    assert result.contributing_evidence_ids == []
    assert result.fusion_episodes == []
    assert result.scoring_config_version == "fusion-config-v0.1"
    assert result.scoring_profile_id == "s0-profile"
    assert result.scoring_method == "simple_score"
    assert result.scorer_version == "simple-score-v0.1"
    assert result.model_version is None
