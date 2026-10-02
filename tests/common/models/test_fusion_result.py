import json
from datetime import UTC, datetime, timedelta, timezone
from math import inf, nan

import pytest

from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
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


def test_accepts_replay_end_episode_reason() -> None:
    # Given
    start_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    replay_end = datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC)

    # When
    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=start_time,
        end_time=replay_end,
        end_reason="replay_end",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # Then
    assert episode.end_time == replay_end
    assert episode.end_reason == "replay_end"


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
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = "detected FusionResult must include score_at_decision"

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=fusion_time,
            fusion_status="detected",
            score_at_decision=None,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_detected_result_without_contributing_evidence() -> None:
    # Given
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = "detected FusionResult must include contributing_evidence_ids"

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=fusion_time,
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
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


def test_rejects_episode_end_reason_without_end_time() -> None:
    # Given
    expected_message = "FusionEpisodeResult without end_time must not include end_reason"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionEpisodeResult(
            episode_id="FEP-001",
            run_id="RUN-01",
            entity_id="HOST-01",
            start_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            end_time=None,
            end_reason="released",
            score_at_start=0.8,
            peak_score=0.9,
            contributing_evidence_ids=["EVD-001"],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_episode_end_time_without_end_reason() -> None:
    # Given
    expected_message = "FusionEpisodeResult with end_time must include end_reason"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionEpisodeResult(
            episode_id="FEP-001",
            run_id="RUN-01",
            entity_id="HOST-01",
            start_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
            end_reason=None,
            score_at_start=0.8,
            peak_score=0.9,
            contributing_evidence_ids=["EVD-001"],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_episode_end_time_before_start_time() -> None:
    # Given
    expected_message = "FusionEpisodeResult end_time must not be earlier than start_time"

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionEpisodeResult(
            episode_id="FEP-001",
            run_id="RUN-01",
            entity_id="HOST-01",
            start_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            end_time=datetime(2026, 9, 9, 1, 0, 10, tzinfo=UTC),
            end_reason="released",
            score_at_start=0.8,
            peak_score=0.9,
            contributing_evidence_ids=["EVD-001"],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_episode_with_mismatched_run_id() -> None:
    # Given
    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-OTHER",
        entity_id="HOST-01",
        start_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert "FusionEpisodeResult run_id must match FusionResult run_id" in str(exc_info.value)


def test_rejects_episode_with_mismatched_entity_id() -> None:
    # Given
    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-OTHER",
        start_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert "FusionEpisodeResult entity_id must match FusionResult entity_id" in str(exc_info.value)


def test_serializes_detected_timestamps_as_utc_milliseconds() -> None:
    # Given
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, 123456, tzinfo=UTC)
    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, 987654, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=fusion_time,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=["EVD-001"],
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[episode],
    )

    # When
    payload = json.loads(result.model_dump_json())

    # Then
    assert payload["fusion_time"] == "2026-09-09T01:00:20.123Z"
    assert payload["fusion_episodes"][0]["start_time"] == "2026-09-09T01:00:20.123Z"
    assert payload["fusion_episodes"][0]["end_time"] == "2026-09-09T01:00:40.987Z"


def test_serializes_null_fusion_time_as_null() -> None:
    # Given
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=None,
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

    # When
    payload = json.loads(result.model_dump_json())

    # Then
    assert payload["fusion_time"] is None


def test_rejects_blank_required_string_fields() -> None:
    # Given
    base_payload = {
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "fusion_time": None,
        "fusion_status": "miss",
        "score_at_decision": None,
        "contributing_evidence_ids": [],
        "scoring_config_version": "fusion-config-v0.1",
        "scoring_profile_id": "s0-profile",
        "model_version": None,
        "scoring_method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "fusion_episodes": [],
    }

    required_fields = [
        "run_id",
        "entity_id",
        "scoring_config_version",
        "scoring_profile_id",
        "scoring_method",
        "scorer_version",
    ]

    # When / Then
    for field_name in required_fields:
        payload = {**base_payload, field_name: ""}

        with pytest.raises(ValueError):
            FusionResult(**payload)


def test_rejects_extra_fusion_result_fields() -> None:
    # Given
    payload = {
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "fusion_time": None,
        "fusion_status": "miss",
        "score_at_decision": None,
        "contributing_evidence_ids": [],
        "scoring_config_version": "fusion-config-v0.1",
        "scoring_profile_id": "s0-profile",
        "model_version": None,
        "scoring_method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "fusion_episodes": [],
        "unexpected_field": "unexpected",
    }

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(**payload)

    # Then
    assert "Extra inputs are not permitted" in str(exc_info.value)


def test_rejects_extra_fusion_episode_fields() -> None:
    # Given
    payload = {
        "episode_id": "FEP-001",
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "start_time": datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC),
        "end_time": datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        "end_reason": "released",
        "score_at_start": 0.8,
        "peak_score": 0.9,
        "contributing_evidence_ids": ["EVD-001"],
        "unexpected_field": "unexpected",
    }

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionEpisodeResult(**payload)

    # Then
    assert "Extra inputs are not permitted" in str(exc_info.value)


def test_rejects_detected_result_when_score_differs_from_first_episode() -> None:
    # Given
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = (
        "detected FusionResult score_at_decision must match the first FusionEpisode score_at_start"
    )

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=fusion_time,
            fusion_status="detected",
            score_at_decision=0.9,
            contributing_evidence_ids=["EVD-001"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_detected_result_when_contributing_evidence_differs_from_first_episode() -> None:
    # Given
    fusion_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = (
        "detected FusionResult contributing_evidence_ids "
        "must match the first FusionEpisode contributing_evidence_ids"
    )

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=fusion_time,
            fusion_status="detected",
            score_at_decision=0.8,
            contributing_evidence_ids=["EVD-002"],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_allows_detected_result_when_first_episode_contributing_evidence_is_none() -> None:
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
        contributing_evidence_ids=None,
    )

    # When
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=fusion_time,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=["EVD-001"],
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[episode],
    )

    # Then
    assert result.fusion_status == "detected"
    assert result.fusion_episodes[0].contributing_evidence_ids is None


def test_rejects_miss_result_with_fusion_episodes() -> None:
    # Given
    start_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = "miss FusionResult must not include fusion_episodes"

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=start_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=None,
            fusion_status="miss",
            score_at_decision=None,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_not_evaluated_result_with_fusion_episodes() -> None:
    # Given
    start_time = datetime(2026, 9, 9, 1, 0, 20, tzinfo=UTC)
    expected_message = "not_evaluated FusionResult must not include fusion_episodes"

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=start_time,
        end_time=datetime(2026, 9, 9, 1, 0, 40, tzinfo=UTC),
        end_reason="released",
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=None,
            fusion_status="not_evaluated",
            score_at_decision=None,
            contributing_evidence_ids=[],
            scoring_config_version="fusion-config-v0.1",
            scoring_profile_id="s0-profile",
            model_version=None,
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            fusion_episodes=[episode],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_numeric_fusion_time() -> None:
    # Given
    expected_message = (
        "FusionResult fusion_time must be an ISO 8601 datetime, not a numeric timestamp"
    )

    # When
    with pytest.raises(TypeError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time=1234567890,
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


def test_rejects_numeric_string_fusion_time() -> None:
    # Given
    expected_message = (
        "FusionResult fusion_time must be an ISO 8601 datetime, not a numeric timestamp"
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionResult(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_time="1234567890",
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


def test_rejects_numeric_episode_start_time() -> None:
    # Given
    expected_message = (
        "FusionEpisode timestamp must be an ISO 8601 datetime, not a numeric timestamp"
    )

    # When
    with pytest.raises(TypeError) as exc_info:
        FusionEpisodeResult(
            episode_id="FEP-001",
            run_id="RUN-01",
            entity_id="HOST-01",
            start_time=1234567890,
            end_time=None,
            end_reason=None,
            score_at_start=0.8,
            peak_score=0.9,
            contributing_evidence_ids=["EVD-001"],
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_accepts_iso_8601_string_timestamp() -> None:
    # Given
    fusion_time = "2026-09-09T01:00:20.123Z"

    # When
    result = FusionResult(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_time=None,
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

    episode = FusionEpisodeResult(
        episode_id="FEP-001",
        run_id="RUN-01",
        entity_id="HOST-01",
        start_time=fusion_time,
        end_time=None,
        end_reason=None,
        score_at_start=0.8,
        peak_score=0.9,
        contributing_evidence_ids=["EVD-001"],
    )

    # Then
    assert result.fusion_status == "miss"
    assert episode.start_time == datetime(
        2026,
        9,
        9,
        1,
        0,
        20,
        123000,
        tzinfo=UTC,
    )


@pytest.mark.parametrize(
    ("policy_state", "persistence_count"),
    [
        ("off", 1),
        ("on", 2),
        ("on", None),
        ("off", None),
    ],
)
def test_accepts_stopping_trace_point_state_and_persistence_combinations(
    policy_state: str,
    persistence_count: int | None,
) -> None:
    # Given
    timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)

    # When
    point = FusionStoppingTracePoint(
        timestamp=timestamp,
        score=0.8,
        persistence_count=persistence_count,
        policy_state=policy_state,
    )

    # Then
    assert point.timestamp == timestamp
    assert point.persistence_count == persistence_count
    assert point.policy_state == policy_state


@pytest.mark.parametrize("score", [-0.1, 1.1, nan, inf, -inf])
def test_rejects_invalid_stopping_trace_point_score(score: float) -> None:
    # Given
    timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=score,
            persistence_count=None,
            policy_state="off",
        )

    # Then
    assert "score" in str(exc_info.value)


@pytest.mark.parametrize("persistence_count", [0, -1])
def test_rejects_invalid_stopping_trace_point_persistence_count(
    persistence_count: int,
) -> None:
    # Given
    timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=0.8,
            persistence_count=persistence_count,
            policy_state="off",
        )

    # Then
    assert "persistence_count" in str(exc_info.value)


def test_rejects_invalid_stopping_trace_point_policy_state() -> None:
    # Given
    timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=0.8,
            persistence_count=None,
            policy_state="active",
        )

    # Then
    assert "policy_state" in str(exc_info.value)


@pytest.mark.parametrize(
    ("timestamp", "expected_message"),
    [
        (
            datetime(2026, 9, 9, 1, 0, tzinfo=UTC).replace(tzinfo=None),
            "FusionStoppingTracePoint timestamp must include timezone information",
        ),
        (
            datetime(2026, 9, 9, 10, 0, tzinfo=timezone(timedelta(hours=9))),
            "FusionStoppingTracePoint timestamp must be UTC",
        ),
    ],
)
def test_rejects_invalid_stopping_trace_point_datetime(
    timestamp: datetime,
    expected_message: str,
) -> None:
    # Given
    expected_error = expected_message

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=0.8,
            persistence_count=None,
            policy_state="off",
        )

    # Then
    assert expected_error in str(exc_info.value)


@pytest.mark.parametrize("timestamp", [1234567890, 1234567890.0, True])
def test_rejects_numeric_stopping_trace_point_timestamp(timestamp: object) -> None:
    # Given
    expected_message = (
        "FusionStoppingTracePoint timestamp must be an ISO 8601 datetime, not a numeric timestamp"
    )

    # When
    with pytest.raises(TypeError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=0.8,
            persistence_count=None,
            policy_state="off",
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_numeric_string_stopping_trace_point_timestamp() -> None:
    # Given
    expected_message = (
        "FusionStoppingTracePoint timestamp must be an ISO 8601 datetime, not a numeric timestamp"
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp="1234567890",
            score=0.8,
            persistence_count=None,
            policy_state="off",
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_accepts_and_serializes_iso_8601_stopping_trace_point_timestamp() -> None:
    # Given
    timestamp = "2026-09-09T01:00:20.123456Z"

    # When
    point = FusionStoppingTracePoint(
        timestamp=timestamp,
        score=0.8,
        persistence_count=1,
        policy_state="off",
    )
    payload = json.loads(point.model_dump_json())

    # Then
    assert point.timestamp == datetime(2026, 9, 9, 1, 0, 20, 123456, tzinfo=UTC)
    assert payload["timestamp"] == "2026-09-09T01:00:20.123Z"


def test_accepts_ordered_stopping_trace_points() -> None:
    # Given
    first_timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)
    points = [
        FusionStoppingTracePoint(
            timestamp=first_timestamp,
            score=0.8,
            persistence_count=1,
            policy_state="off",
        ),
        FusionStoppingTracePoint(
            timestamp=first_timestamp + timedelta(seconds=10),
            score=0.9,
            persistence_count=2,
            policy_state="on",
        ),
    ]

    # When
    trace = FusionStoppingTrace(
        run_id="RUN-01",
        entity_id="HOST-01",
        scoring_config_version="fusion-config-v0.1",
        points=points,
    )

    # Then
    assert trace.points == points


def test_accepts_empty_stopping_trace_points() -> None:
    # Given
    points: list[FusionStoppingTracePoint] = []

    # When
    trace = FusionStoppingTrace(
        run_id="RUN-01",
        entity_id="HOST-01",
        scoring_config_version="fusion-config-v0.1",
        points=points,
    )

    # Then
    assert trace.points == []


@pytest.mark.parametrize("timestamp_offsets", [(0, 0), (10, 0)])
def test_rejects_non_increasing_stopping_trace_timestamps(
    timestamp_offsets: tuple[int, int],
) -> None:
    # Given
    start = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)
    points = [
        FusionStoppingTracePoint(
            timestamp=start + timedelta(seconds=offset),
            score=0.8,
            persistence_count=None,
            policy_state="off",
        )
        for offset in timestamp_offsets
    ]

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTrace(
            run_id="RUN-01",
            entity_id="HOST-01",
            scoring_config_version="fusion-config-v0.1",
            points=points,
        )

    # Then
    assert "point timestamps must be strictly increasing" in str(exc_info.value)


@pytest.mark.parametrize("field_name", ["run_id", "entity_id", "scoring_config_version"])
def test_rejects_empty_stopping_trace_identifiers(field_name: str) -> None:
    # Given
    values = {
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "scoring_config_version": "fusion-config-v0.1",
        "points": [],
    }
    values[field_name] = ""

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTrace(**values)

    # Then
    assert field_name in str(exc_info.value)


def test_rejects_extra_stopping_trace_point_fields() -> None:
    # Given
    timestamp = datetime(2026, 9, 9, 1, 0, tzinfo=UTC)

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTracePoint(
            timestamp=timestamp,
            score=0.8,
            persistence_count=None,
            policy_state="off",
            unexpected="value",
        )

    # Then
    assert "unexpected" in str(exc_info.value)


def test_rejects_extra_stopping_trace_fields() -> None:
    # Given
    points: list[FusionStoppingTracePoint] = []

    # When
    with pytest.raises(ValueError) as exc_info:
        FusionStoppingTrace(
            run_id="RUN-01",
            entity_id="HOST-01",
            scoring_config_version="fusion-config-v0.1",
            points=points,
            unexpected="value",
        )

    # Then
    assert "unexpected" in str(exc_info.value)
