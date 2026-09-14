from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.fusion import FusionEpisodeResult, FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.decision.hybrid import combine_results


def inputs(fast_status, fusion_status, fast_seconds=10, fusion_seconds=20):
    start = datetime(2026, 9, 13, tzinfo=UTC)
    fast_time = start + timedelta(seconds=fast_seconds) if fast_status == "detected" else None
    fusion_time = start + timedelta(seconds=fusion_seconds) if fusion_status == "detected" else None
    detection = DetectionResult(
        run_id="RUN-20260913-001",
        entity_id="WIN-01",
        detector_status=fast_status,
        detector_time=fast_time,
        detector_id="mock" if fast_time else None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )
    episodes = []
    if fusion_time:
        episodes.append(
            FusionEpisodeResult(
                episode_id="FEP-001",
                run_id=detection.run_id,
                entity_id=detection.entity_id,
                start_time=fusion_time,
                score_at_start=1,
                peak_score=1,
                contributing_evidence_ids=["E-1"],
            )
        )
    fusion = FusionResult(
        run_id=detection.run_id,
        entity_id=detection.entity_id,
        fusion_time=fusion_time,
        fusion_status=fusion_status,
        score_at_decision=1 if fusion_time else None,
        contributing_evidence_ids=["E-1"] if fusion_time else [],
        fusion_episodes=episodes,
        scoring_config_version="mock-v1",
        scoring_profile_id="mock",
        scoring_method="simple_score",
        scorer_version="v1",
    )
    return detection, fusion


def combine(detection, fusion, **overrides):
    kwargs = {
        "decision_id": "D-001",
        "config_version": "mock-parallel-v1",
        "parallel_required": True,
    }
    kwargs.update(overrides)
    return combine_results(detection, fusion, **kwargs)


@pytest.mark.parametrize("fast", ["detected", "miss", "not_evaluated"])
@pytest.mark.parametrize("fusion", ["detected", "miss", "not_evaluated"])
def test_status_matrix(fast, fusion):
    # Given / When
    d, f = inputs(fast, fusion)
    result = combine(d, f)
    # Then
    assert result.fast_status == fast
    assert result.fusion_status == fusion
    assert result.detector_time == d.detector_time
    assert result.fusion_time == f.fusion_time
    if "not_evaluated" in (fast, fusion):
        assert (result.t_e, result.decision_path, result.winning_path) == (None, None, None)
    elif fast == fusion == "detected":
        assert (result.t_e, result.decision_path, result.winning_path) == (
            d.detector_time,
            "fast_and_fusion",
            "fast",
        )
    elif fast == "detected":
        assert (result.t_e, result.decision_path, result.winning_path) == (
            d.detector_time,
            "fast",
            "fast",
        )
    elif fusion == "detected":
        assert (result.t_e, result.decision_path, result.winning_path) == (
            f.fusion_time,
            "fusion",
            "fusion",
        )
    else:
        assert (result.t_e, result.decision_path, result.winning_path) == (None, "none", "none")
    assert result.contributing_evidence_ids == f.contributing_evidence_ids


@pytest.mark.parametrize("seconds,winner", [(5, "fusion"), (10, "tie"), (10.0001, "tie")])
def test_comparison_at_canonical_precision(seconds, winner):
    # Given / When / Then
    result = combine(*inputs("detected", "detected", fusion_seconds=seconds))
    assert result.winning_path == winner
    assert result.decision_path == "fast_and_fusion"
    assert result.t_e.microsecond % 1000 == 0


@pytest.mark.parametrize("field,value", [("run_id", "RUN-20260913-002"), ("entity_id", "WIN-02")])
def test_rejects_mixed_scope(field, value):
    # Given
    d, f = inputs("miss", "miss")
    setattr(f, field, value)
    # When / Then
    with pytest.raises(ValueError, match="same run_id and entity_id"):
        combine(d, f)


def test_optional_policy_is_not_invented():
    # Given / When / Then
    with pytest.raises(ValueError, match="parallel_required"):
        combine(*inputs("miss", "not_evaluated"), parallel_required=False)


@pytest.mark.parametrize("field", ["decision_id", "config_version"])
def test_rejects_blank_context(field):
    # Given / When / Then
    with pytest.raises(ValueError):
        combine(*inputs("miss", "miss"), **{field: " "})
