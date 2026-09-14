from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import ThresholdStoppingPolicy
from incident_awareness.decision.fusion.temporal_replay import TemporalReplayRunner
from incident_awareness.decision.fusion.window_engine import WindowEngine
from incident_awareness.decision.hybrid import combine_results


@pytest.mark.parametrize(
    "fast_status,fast_seconds,with_evidence,expected_seconds,path,winner",
    [
        ("detected", 5, True, 5, "fast_and_fusion", "fast"),
        ("detected", 25, True, 20, "fast_and_fusion", "fusion"),
        ("detected", 20, True, 20, "fast_and_fusion", "tie"),
        ("miss", None, True, 20, "fusion", "fusion"),
        ("detected", 5, False, 5, "fast", "fast"),
        ("miss", None, False, None, "none", "none"),
        ("not_evaluated", None, True, None, None, None),
    ],
)
def test_real_fusion_runner_combines_with_mock_fast(
    fast_status, fast_seconds, with_evidence, expected_seconds, path, winner
):
    # Given: synthetic Evidence and mock Fast output, with real Fusion implementation.
    start = datetime(2026, 9, 14, tzinfo=UTC)
    run_id, entity_id = "RUN-20260914-001", "WIN-01"
    evidence = Evidence(
        evidence_id="E-SYNTHETIC-1",
        run_id=run_id,
        entity_id=entity_id,
        timestamp=start + timedelta(seconds=5),
        evidence_type="mock-type",
        event_ids=["EVT-SYNTHETIC-1"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="mock-v1",
    )
    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(["mock-type"]),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8, threshold_off=0.4, persistence_k=2
        ),
        step_size=timedelta(seconds=10),
    )
    replay = runner.run(
        [evidence] if with_evidence else [],
        run_id=run_id,
        entity_id=entity_id,
        run_start=start,
        run_end=start + timedelta(seconds=30),
    )
    fusion = build_fusion_result(
        replay,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="synthetic-v1",
        scoring_profile_id="mock-profile",
        scoring_method="simple_score",
        scorer_version="mock-v1",
    )
    fast = DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_status=fast_status,
        detector_time=start + timedelta(seconds=fast_seconds) if fast_seconds is not None else None,
        detector_id="mock-fast" if fast_status == "detected" else None,
        rule_id="mock-rule",
        rule_version="mock-v1",
        severity=None,
    )
    original = fusion.model_dump_json()
    # When
    result = combine_results(
        fast,
        fusion,
        decision_id="D-SYNTHETIC-1",
        config_version="synthetic-parallel-v1",
        parallel_required=True,
    )
    # Then: persistence confirms at 20s, not at Evidence time 5s or first tick 10s.
    assert fusion.fusion_time == (start + timedelta(seconds=20) if with_evidence else None)
    assert result.t_e == (
        start + timedelta(seconds=expected_seconds) if expected_seconds is not None else None
    )
    assert result.decision_path == path
    assert result.winning_path == winner
    assert result.contributing_evidence_ids == ([evidence.evidence_id] if with_evidence else [])
    assert result.rule_version == "mock-v1"
    assert result.run_id == run_id and result.entity_id == entity_id
    assert result.fast_status == fast_status
    assert result.fusion_status == ("detected" if with_evidence else "miss")
    assert fusion.model_dump_json() == original
    payload = result.model_dump(mode="json")
    assert payload["t_e"] == (
        result.t_e.isoformat(timespec="milliseconds").replace("+00:00", "Z") if result.t_e else None
    )
