from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
    FusionResult,
)


def test_accepts_detected_fusion_result() -> None:
    # Given
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001", "EVD-002"],
    )

    # When
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=fusion_time,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=["EVD-001", "EVD-002"],
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[episode],
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_time == fusion_time
    assert result.score_at_decision == 0.8
    assert result.entity_id == "HOST-01"
    assert len(result.fusion_episodes) == 1


def test_accepts_miss_fusion_result() -> None:
    # Given
    expected_status = "miss"

    # When
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=None,
        fusion_status=expected_status,
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[],
    )

    # Then
    assert result.fusion_status == expected_status
    assert result.fusion_time is None
    assert result.score_at_decision is None
    assert result.contributing_evidence_ids == []
    assert result.fusion_episodes == []


def test_accepts_not_evaluated_fusion_result() -> None:
    # Given
    expected_status = "not_evaluated"

    # When
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=None,
        fusion_status=expected_status,
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[],
    )

    # Then
    assert result.fusion_status == expected_status
    assert result.fusion_time is None
    assert result.score_at_decision is None
    assert result.contributing_evidence_ids == []
    assert result.fusion_episodes == []


def test_rejects_detected_result_without_fusion_time() -> None:
    # Given
    expected_message = "detected FusionResult must include fusion_time"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=None,
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_detected_result_without_score_at_decision() -> None:
    # Given
    expected_message = "detected FusionResult must include score_at_decision"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="detected",
            score_at_decision=None,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_detected_result_without_contributing_evidence() -> None:
    # Given
    expected_message = "detected FusionResult must include contributing_evidence_ids"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_miss_result_with_fusion_time() -> None:
    # Given
    expected_message = "miss FusionResult must not include fusion_time"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="miss",
            score_at_decision=None,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_not_evaluated_result_with_fusion_time() -> None:
    # Given
    expected_message = "not_evaluated FusionResult must not include fusion_time"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="not_evaluated",
            score_at_decision=None,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_not_evaluated_result_with_score_at_decision() -> None:
    # Given
    expected_message = "not_evaluated FusionResult must not include score_at_decision"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=None,
            fusion_status="not_evaluated",
            score_at_decision=0.8,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[],
        )

    # Then
    assert expected_message in str(exc_info.value)
