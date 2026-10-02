from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import ThresholdStoppingPolicy
from incident_awareness.decision.fusion.temporal_replay import TemporalReplayRunner
from incident_awareness.decision.fusion.window_engine import WindowEngine
from incident_awareness.evaluation.baselines.weighted_rule import WeightedRuleScorer

START = datetime(2026, 9, 7, tzinfo=UTC)


def evidence(name="a", identifier="EVD-001", seconds=0, group="fusion_feature"):
    return Evidence(
        evidence_id=identifier,
        run_id="RUN-20260907-001",
        entity_id="HOST-01",
        timestamp=START + timedelta(seconds=seconds),
        evidence_type=name,
        event_ids=[f"EVENT-{identifier}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group=group,
        extractor_version="test",
    )


def test_weighted_presence_and_provenance():
    scorer = WeightedRuleScorer({"a": 1, "b": 3})
    rows = [
        evidence(),
        evidence(identifier="EVD-002"),
        evidence(),
        evidence("b", "DIAGNOSTIC", group="diagnostic_only"),
        evidence("other", "OTHER"),
    ]
    assert scorer.score(iter(rows)) == 0.25
    assert scorer.contributing_evidence_ids(rows) == ("EVD-001", "EVD-002")
    assert scorer.score([]) == 0
    assert scorer.score([*rows, evidence("b", "EVD-003")]) == 1


@pytest.mark.parametrize("names", [[], ["a"], ["b"], ["a", "b"], ["a", "a", "other"]])
def test_uniform_weights_match_existing_scorer(names):
    rows = [evidence(name, f"EVD-{index}") for index, name in enumerate(names)]
    weighted = WeightedRuleScorer({"a": 2, "b": 2})
    simple = SimpleScorer(["a", "b"])
    assert weighted.score(rows) == simple.score(rows)
    assert weighted.contributing_evidence_ids(rows) == simple.contributing_evidence_ids(rows)


@pytest.mark.parametrize(
    "weights",
    [
        {},
        {"": 1},
        {" a": 1},
        {1: 1},
        {"a": True},
        {"a": "1"},
        {"a": 0},
        {"a": -1},
        {"a": float("nan")},
        {"a": float("inf")},
        {"a": 1e308, "b": 1e308},
        {"a": 10**1000},
    ],
)
def test_rejects_invalid_weights(weights):
    with pytest.raises((TypeError, ValueError)):
        WeightedRuleScorer(weights)


def test_weights_are_copied_and_order_independent():
    weights = {"a": 1, "b": 3, "c": 0.1}
    scorer = WeightedRuleScorer(weights)
    equivalent = WeightedRuleScorer(dict(reversed(list(weights.items()))))
    weights["a"] = 100
    rows = [evidence("a"), evidence("c", "EVD-002")]
    assert scorer.total_weight == 4.1
    assert scorer.score(rows) == equivalent.score(reversed(rows))


def test_replay_and_fusion_result_use_existing_window_and_stopping_contract():
    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=20)),
        scorer=WeightedRuleScorer({"a": 1, "b": 3}),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
        step_size=timedelta(seconds=10),
    )
    replay = runner.run(
        [evidence(), evidence("b", "EVD-002", seconds=15)],
        run_id="RUN-20260907-001",
        entity_id="HOST-01",
        run_start=START,
        run_end=START + timedelta(seconds=40),
    )
    assert [point.score for point in replay.trajectory] == [0.25, 0.25, 1, 0.75, 0]
    result = build_fusion_result(
        replay,
        run_id="RUN-20260907-001",
        entity_id="HOST-01",
        scoring_config_version="test-weights-v1",
        scoring_profile_id="test-profile",
        scoring_method="weighted_rule",
        scorer_version="weighted-rule-v0.1",
    )
    assert result.fusion_status == "detected"
    assert result.fusion_time == START + timedelta(seconds=20)
    assert set(result.contributing_evidence_ids) == {"EVD-001", "EVD-002"}
    assert result.scoring_method == "weighted_rule"
