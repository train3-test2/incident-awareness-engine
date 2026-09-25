"""Evaluation-boundary regression cases using canonical stored result models."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from incident_awareness.common.models.fusion import FusionEpisodeResult, FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.evaluation.result_inputs import (
    EvaluationPlan,
    EvaluationSnapshot,
    FastEpisodeStarts,
    StoredRunResults,
    build_evaluation_inputs,
    evaluate_snapshot,
    load_evaluation_snapshot,
)

START = datetime(2026, 9, 20, tzinfo=UTC)


def at(seconds):
    return START + timedelta(seconds=seconds)


def bundle(
    number=1,
    *,
    normal=False,
    fast=(20, 100),
    fusion=((30, 80), (130, 250)),
    fast_status="detected",
    fusion_status="detected",
):
    payload = json.loads(Path("tests/fixtures/pipeline/first_cycle/run_metadata.json").read_text())
    payload.update(
        run_id=f"RUN-20260920-{number:03d}",
        run_type="normal" if normal else "attack",
        reference_time=None if normal else at(60),
        end_time=at(300),
        detector_set_version="set-v1",
    )
    run = RunMetadata.model_validate(payload)
    detection = DetectionResult(
        run_id=run.run_id,
        entity_id=run.target_host,
        detector_status=fast_status,
        detector_time=at(fast[0]) if fast_status == "detected" else None,
        detector_id="hayabusa" if fast_status == "detected" else None,
        rule_id="rule-1",
        rule_version="rule-v1",
        severity=None,
    )
    episodes = (
        [
            FusionEpisodeResult(
                episode_id=f"FEP-{index}",
                run_id=run.run_id,
                entity_id=run.target_host,
                start_time=at(start),
                end_time=at(end),
                end_reason="released",
                score_at_start=1,
                peak_score=1,
                contributing_evidence_ids=["ev-1"],
            )
            for index, (start, end) in enumerate(fusion)
        ]
        if fusion_status == "detected"
        else []
    )
    fused = FusionResult(
        run_id=run.run_id,
        entity_id=run.target_host,
        fusion_status=fusion_status,
        fusion_time=episodes[0].start_time if episodes else None,
        score_at_decision=1 if episodes else None,
        contributing_evidence_ids=["ev-1"] if episodes else [],
        scoring_config_version="fusion-v1",
        scoring_profile_id="profile-v1",
        scoring_method="simple_score",
        scorer_version="score-v1",
        fusion_episodes=episodes,
    )
    decision = combine_results(
        detection,
        fused,
        decision_id=f"D-{number}",
        config_version="parallel-v1",
        parallel_required=True,
    )
    history = (
        FastEpisodeStarts(
            run_id=run.run_id,
            entity_id=run.target_host,
            policy_version="episodes-v1",
            detector_set_version="set-v1",
            observation_start=run.start_time,
            observation_end=run.end_time,
            start_times=[at(t) for t in fast],
        )
        if fast_status == "detected"
        else None
    )
    return StoredRunResults(
        run_metadata=run,
        detection=detection,
        fusion=fused,
        decision=decision,
        fast_episodes=history,
    )


def snapshot(*runs):
    return EvaluationSnapshot(
        snapshot_id="snapshot-1",
        runs=list(runs),
        plan=EvaluationPlan(
            scenario_id="S0",
            purpose="smoke",
            decision_ids={run.run_metadata.run_id: run.decision.decision_id for run in runs},
            decision_config_version="parallel-v1",
            scoring_config_version="fusion-v1",
            detector_set_version="set-v1",
            fast_episode_policy_version="episodes-v1",
            evaluation_horizon_sec=120,
        ),
    )


def test_eligible_times_use_new_episodes_not_runtime_candidates():
    value = snapshot(bundle())
    frames, excluded = build_evaluation_inputs(value)
    assert value.runs[0].decision.t_e == at(20)
    assert frames["Fast"].iloc[0].timestamp == at(100)
    assert frames["Fusion"].iloc[0].timestamp == at(130)
    assert frames["Hybrid"].iloc[0].timestamp == at(100)
    assert excluded == []
    report = evaluate_snapshot(value)
    assert report["metrics"]["Hybrid"]["median_ttsd_sec"] == 40
    assert report["metrics"]["Fusion"]["median_ttsd_sec"] == 70
    assert report["comparison_ready"] is True


def test_pre_reference_episode_continuing_after_reference_is_not_credit():
    value = snapshot(bundle(fast=(20,), fusion=((30, 250),)))
    frames, _ = build_evaluation_inputs(value)
    assert all(pd.isna(frame.iloc[0].timestamp) for frame in frames.values())
    assert evaluate_snapshot(value)["metrics"]["Hybrid"]["run_recall"] == 0.0


@pytest.mark.parametrize("time,expected", [(60, 0), (180, 120), (181, None)])
def test_attack_horizon_boundaries(time, expected):
    value = snapshot(bundle(fast=(time,), fusion_status="miss"))
    report = evaluate_snapshot(value)
    assert report["metrics"]["Fast"]["median_ttsd_sec"] == expected


def test_measured_end_clips_horizon():
    value = snapshot(bundle(fast=(300,), fusion_status="miss"))
    value.plan.evaluation_horizon_sec = 600
    assert evaluate_snapshot(value)["metrics"]["Fast"]["median_ttsd_sec"] == 240


def test_normal_observation_is_not_clipped_by_attack_horizon():
    value = snapshot(
        bundle(normal=True, fast=(290,), fusion_status="miss"),
        bundle(2, normal=True, fast_status="miss", fusion_status="miss"),
    )
    frames, _ = build_evaluation_inputs(value)
    assert frames["Fast"].iloc[0].timestamp == at(290)
    assert pd.isna(frames["Fast"].iloc[1].timestamp)
    assert frames["Fast"]["reference_time"].isna().all()
    assert len(frames["Fast"]) == 2


@pytest.mark.parametrize("fast", ["detected", "miss", "not_evaluated"])
@pytest.mark.parametrize("fusion", ["detected", "miss", "not_evaluated"])
def test_execution_status_matrix(fast, fusion):
    value = snapshot(bundle(fast_status=fast, fusion_status=fusion))
    frames, excluded = build_evaluation_inputs(value)
    assert len(frames["Fast"]) == (fast != "not_evaluated")
    assert len(frames["Fusion"]) == (fusion != "not_evaluated")
    complete = "not_evaluated" not in (fast, fusion)
    assert len(frames["Hybrid"]) == complete
    report = evaluate_snapshot(value)
    assert report["comparison_ready"] == complete
    assert len(excluded) == (fast == "not_evaluated") + (fusion == "not_evaluated") + (not complete)
    if not complete:
        assert report["metrics"]["Hybrid"] is None


@pytest.mark.parametrize("field", ["detection", "fusion", "decision"])
def test_missing_result_is_an_error_not_miss(field):
    value = snapshot(bundle())
    setattr(value.runs[0], field, None)
    with pytest.raises(ValueError, match="missing"):
        evaluate_snapshot(value)


@pytest.mark.parametrize("field", ["reference_time", "end_time"])
def test_missing_ground_truth_is_error(field):
    value = snapshot(bundle())
    setattr(value.runs[0].run_metadata, field, None)
    with pytest.raises(ValueError, match=field):
        evaluate_snapshot(value)


def test_incomplete_or_duplicate_inventory_rejected():
    value = snapshot(bundle(), bundle(2))
    value.runs.pop()
    with pytest.raises(ValueError, match="inventory"):
        evaluate_snapshot(value)
    value.runs.append(value.runs[0])
    with pytest.raises(ValueError, match="unique"):
        evaluate_snapshot(value)


@pytest.mark.parametrize(
    "field",
    [
        "decision_config_version",
        "scoring_config_version",
        "detector_set_version",
        "fast_episode_policy_version",
    ],
)
def test_wrong_expected_version_rejected(field):
    value = snapshot(bundle())
    setattr(value.plan, field, "different-version")
    with pytest.raises(ValueError, match="version"):
        evaluate_snapshot(value)


def test_wrong_entity_and_execution_id_rejected():
    value = snapshot(bundle())
    value.runs[0].run_metadata.target_host = "OTHER-HOST"
    with pytest.raises(ValueError, match="entity_id"):
        evaluate_snapshot(value)
    value = snapshot(bundle())
    value.plan.decision_ids[value.runs[0].run_metadata.run_id] = "old-decision"
    with pytest.raises(ValueError, match="decision_id"):
        evaluate_snapshot(value)


def test_changed_path_result_does_not_match_saved_decision():
    value = snapshot(bundle())
    value.runs[0].detection.detector_time = at(25)
    with pytest.raises(ValueError, match="disagree"):
        evaluate_snapshot(value)


def test_fast_history_required_and_observation_coverage_checked():
    value = snapshot(bundle())
    value.runs[0].fast_episodes.observation_end = at(299)
    with pytest.raises(ValueError, match="entire measured Run"):
        evaluate_snapshot(value)
    value.runs[0].fast_episodes = None
    with pytest.raises(ValueError, match="complete versioned episode"):
        evaluate_snapshot(value)


def test_outside_normal_observation_rejected():
    value = snapshot(bundle(normal=True, fast=(20, 301)))
    with pytest.raises(ValueError, match="outside measured Run"):
        evaluate_snapshot(value)


def test_s0_performance_and_optional_parallel_are_not_silently_supported():
    value = snapshot(bundle())
    value.plan.purpose = "performance"
    with pytest.raises(ValueError, match="S0"):
        evaluate_snapshot(value)
    value.plan.purpose = "smoke"
    value.plan.parallel_required = False
    with pytest.raises(ValueError):
        evaluate_snapshot(value)


def test_snapshot_roundtrip_and_report_do_not_mutate_source(tmp_path):
    value = snapshot(bundle(), bundle(2, fast_status="miss", fusion_status="miss"))
    before = value.model_dump_json()
    path = tmp_path / "snapshot.json"
    path.write_text(before)
    restored = load_evaluation_snapshot(path)
    report = evaluate_snapshot(restored)
    assert report["metrics"]["Fast"]["run_recall"] == 0.5
    assert restored.model_dump_json() == before
    json.dumps(report, allow_nan=False)


def test_submillisecond_episode_time_is_rejected_before_serialization():
    value = snapshot(bundle())
    value.runs[0].fusion.fusion_episodes[1].start_time += timedelta(microseconds=1)
    with pytest.raises(ValueError, match="millisecond"):
        evaluate_snapshot(value)
