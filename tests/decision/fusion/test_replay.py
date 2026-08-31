from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.replay import replay_fusion
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)


def make_evidence(
    evidence_id: str,
    timestamp: datetime,
    evidence_type: str,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-01",
        timestamp=timestamp,
        entity_id="HOST-01",
        evidence_type=evidence_type,
        source_event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="fixture-v0.1",
    )


def make_scorer() -> SimpleScorer:
    return SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )


def make_policy() -> ThresholdStoppingPolicy:
    return ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=3,
    )


def test_replay_produces_fixed_cadence_and_fusion_time() -> None:
    run_start = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=50)

    evidence = [
        make_evidence("001", run_start, "type_a"),
        make_evidence(
            "002",
            run_start + timedelta(seconds=10),
            "type_b",
        ),
        make_evidence(
            "003",
            run_start + timedelta(seconds=20),
            "type_c",
        ),
    ]

    result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_end,
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=make_scorer(),
        stopping_policy=make_policy(),
    )

    assert [point.timestamp for point in result.trajectory] == [
        run_start,
        run_start + timedelta(seconds=10),
        run_start + timedelta(seconds=20),
        run_start + timedelta(seconds=30),
        run_start + timedelta(seconds=40),
        run_start + timedelta(seconds=50),
    ]

    assert [point.score for point in result.trajectory] == [
        0.25,
        0.5,
        0.75,
        0.75,
        0.75,
        0.75,
    ]

    assert result.stopping_result.fusion_status == "detected"
    assert result.stopping_result.fusion_time == (run_start + timedelta(seconds=40))
    assert result.stopping_result.score_at_decision == 0.75


def test_future_evidence_does_not_change_past_scores() -> None:
    run_start = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    initial_evidence = [
        make_evidence("001", run_start, "type_a"),
        make_evidence(
            "002",
            run_start + timedelta(seconds=10),
            "type_b",
        ),
    ]

    initial = replay_fusion(
        evidence=initial_evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=20),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=make_scorer(),
        stopping_policy=make_policy(),
    )

    extended_evidence = [
        *initial_evidence,
        make_evidence(
            "003",
            run_start + timedelta(seconds=30),
            "type_c",
        ),
    ]

    extended = replay_fusion(
        evidence=extended_evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=40),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=make_scorer(),
        stopping_policy=make_policy(),
    )

    assert extended.trajectory[:3] == initial.trajectory


def test_evidence_is_not_used_before_its_timestamp() -> None:
    run_start = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence = [
        make_evidence(
            "001",
            run_start + timedelta(seconds=5),
            "type_a",
        ),
    ]

    result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=20),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=make_scorer(),
        stopping_policy=make_policy(),
    )

    assert result.trajectory[0].score == 0.0
    assert result.trajectory[1].score == 0.25


def test_returns_miss_for_insufficient_evidence() -> None:
    run_start = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence = [
        make_evidence("001", run_start, "type_a"),
    ]

    result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=40),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=make_scorer(),
        stopping_policy=make_policy(),
    )

    assert result.stopping_result.fusion_status == "miss"
    assert result.stopping_result.fusion_time is None
    assert result.stopping_result.score_at_decision is None


def test_rejects_run_interval_not_aligned_to_step_size() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    scorer = SimpleScorer(
        [
            "type_a",
        ]
    )

    stopping_policy = ThresholdStoppingPolicy(
        threshold_on=0.7,
        persistence_k=1,
    )

    with pytest.raises(
        ValueError,
        match="run interval must align with step_size",
    ):
        replay_fusion(
            evidence=[],
            run_id="RUN-01",
            entity_id="HOST-01",
            run_start=run_start,
            run_end=run_start + timedelta(seconds=25),
            window_size=timedelta(minutes=5),
            step_size=timedelta(seconds=10),
            scorer=scorer,
            stopping_policy=stopping_policy,
        )


def test_includes_evidence_at_aligned_run_end() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    run_end = run_start + timedelta(seconds=20)

    evidence = [
        make_evidence(
            "E-END",
            run_end,
            "type_a",
        )
    ]

    scorer = SimpleScorer(
        [
            "type_a",
        ]
    )

    result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_end,
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=1.0,
            persistence_k=1,
        ),
    )

    assert result.trajectory[-1].timestamp == run_end
    assert result.trajectory[-1].score == 1.0
    assert result.stopping_result.fusion_status == "detected"
    assert result.stopping_result.fusion_time == run_end
