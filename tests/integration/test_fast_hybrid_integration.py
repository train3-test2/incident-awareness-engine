from datetime import UTC, datetime
from pathlib import Path

from incident_awareness.common.models.fusion import FusionEpisodeResult, FusionResult
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionSelection,
    adapt_fast_hit_handoff,
    read_fast_hit_handoff,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"
RUN_ID = "RUN-20260913-001"
ENTITY_ID = "WIN-01"


def _read_handoff(tmp_path: Path, *, empty: bool = False):
    csv_path = FIXTURES / "handoff.csv"
    if empty:
        csv_path = tmp_path / "empty.csv"
        csv_path.write_text("Timestamp,RuleID\n", encoding="utf-8")
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=csv_path,
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=jsonl_path,
        trace_path=trace_path,
    )
    return read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def _detected_fusion_result() -> FusionResult:
    fusion_time = datetime(2026, 9, 13, 0, 0, 2, tzinfo=UTC)
    return FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=fusion_time,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=["E-001"],
        scoring_config_version="integration-v1",
        scoring_profile_id="integration-profile",
        scoring_method="temporal_fusion",
        scorer_version="integration-v1",
        fusion_episodes=[
            FusionEpisodeResult(
                episode_id="FEP-001",
                run_id=RUN_ID,
                entity_id=ENTITY_ID,
                start_time=fusion_time,
                score_at_start=0.8,
                peak_score=0.8,
                contributing_evidence_ids=["E-001"],
            )
        ],
    )


def test_fast_handoff_adapter_output_flows_into_hybrid_decision(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)
    fast = adapt_fast_hit_handoff(
        handoff,
        entity_id=ENTITY_ID,
        selection=FastDetectionSelection(
            detector_status="detected",
            selected_hit_id=f"{RUN_ID}-hit-2",
            severity="high",
        ),
    )

    decision = combine_results(
        fast.detection_result,
        _detected_fusion_result(),
        decision_id="D-FAST-HYBRID-001",
        config_version="parallel-integration-v1",
        parallel_required=True,
    )

    assert fast.source_hit_ids == (f"{RUN_ID}-hit-2",)
    assert fast.selected_source_hit_id == f"{RUN_ID}-hit-2"
    assert decision.fast_status == "detected"
    assert decision.fusion_status == "detected"
    assert decision.detector_time == datetime(2026, 9, 13, 0, 0, 1, 123000, tzinfo=UTC)
    assert decision.fusion_time == datetime(2026, 9, 13, 0, 0, 2, tzinfo=UTC)
    assert decision.t_e == decision.detector_time
    assert decision.decision_path == "fast_and_fusion"
    assert decision.winning_path == "fast"
    assert decision.rule_version == "mock-v1"


def test_fast_miss_from_completed_handoff_flows_into_hybrid_decision(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path, empty=True)
    fast = adapt_fast_hit_handoff(
        handoff,
        entity_id=ENTITY_ID,
        selection=FastDetectionSelection(detector_status="miss"),
    )

    decision = combine_results(
        fast.detection_result,
        _detected_fusion_result(),
        decision_id="D-FAST-HYBRID-002",
        config_version="parallel-integration-v1",
        parallel_required=True,
    )

    assert decision.fast_status == "miss"
    assert decision.detector_time is None
    assert decision.t_e == decision.fusion_time
    assert decision.decision_path == "fusion"
    assert decision.winning_path == "fusion"
