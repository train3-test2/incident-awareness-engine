from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.fusion import FusionEpisodeResult, FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.hybrid import combine_parallel_decision

RUN_ID = "RUN-20260920-001"
ENTITY_ID = "WIN-01"


def test_combines_fast_and_fusion_results_into_validated_decision() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)

    decision = combine_parallel_decision(
        _inputs(),
        _fast_result(start_time + timedelta(seconds=10)),
        _fusion_result(start_time + timedelta(seconds=20)),
    )

    assert decision.fast_status == "detected"
    assert decision.fusion_status == "detected"
    assert decision.t_e == start_time + timedelta(seconds=10)
    assert decision.decision_path == "fast_and_fusion"
    assert decision.winning_path == "fast"
    assert decision.source_hit_ids == ["RUN-20260920-001-hit-1"]
    assert decision.selected_source_hit_id == "RUN-20260920-001-hit-1"


def test_rejects_hybrid_inputs_with_different_entity_scope() -> None:
    with pytest.raises(ValueError, match="same run_id and entity_id"):
        combine_parallel_decision(
            _inputs(),
            _fast_result(datetime(2026, 9, 20, tzinfo=UTC)),
            _fusion_result(datetime(2026, 9, 20, tzinfo=UTC), entity_id="WIN-02"),
        )


def _inputs() -> PipelineInputs:
    unused_path = Path("unused")
    return PipelineInputs(
        run_metadata_path=unused_path,
        manifest_path=unused_path,
        sysmon_jsonl_path=unused_path,
        fast_hits_path=unused_path,
        fast_trace_path=unused_path,
        fast_selection_path=unused_path,
        fusion_config_path=unused_path,
        entity_id=ENTITY_ID,
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )


def _fast_result(timestamp: datetime) -> FastDetectionAdapterResult:
    return FastDetectionAdapterResult(
        detection_result=DetectionResult(
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            detector_time=timestamp,
            detector_status="detected",
            detector_id="hayabusa",
            rule_id="mock-rule",
            rule_version="mock-v1",
            severity="high",
        ),
        source_hit_ids=("RUN-20260920-001-hit-1",),
        selected_source_hit_id="RUN-20260920-001-hit-1",
    )


def _fusion_result(timestamp: datetime, *, entity_id: str = ENTITY_ID) -> FusionResult:
    return FusionResult(
        run_id=RUN_ID,
        entity_id=entity_id,
        fusion_time=timestamp,
        fusion_status="detected",
        score_at_decision=1.0,
        contributing_evidence_ids=["E-001"],
        scoring_config_version="fusion-config-s0-pair-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[
            FusionEpisodeResult(
                episode_id="FEP-001",
                run_id=RUN_ID,
                entity_id=entity_id,
                start_time=timestamp,
                score_at_start=1.0,
                peak_score=1.0,
                contributing_evidence_ids=["E-001"],
            )
        ],
    )
