from datetime import UTC, datetime, timedelta

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.output_builder import (
    FusionOutputMetadata,
    build_fusion_output,
    serialize_fusion_output,
)
from incident_awareness.decision.fusion.replay import replay_fusion
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)


def make_evidence(
    evidence_id: str,
    timestamp: datetime,
    evidence_type: str,
    *,
    feature_channel_group: str = "fusion_feature",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-01",
        timestamp=timestamp,
        entity_id="HOST-01",
        evidence_type=evidence_type,
        source_event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group=feature_channel_group,
        extractor_version="fixture-v0.1",
    )


def make_scorer() -> SimpleScorer:
    return SimpleScorer(
        [
            "type_a",
            "type_b",
            "type_c",
            "type_d",
        ]
    )


def make_metadata() -> FusionOutputMetadata:
    return FusionOutputMetadata(
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        evidence_schema_version="v0.1",
        scoring_config_version="v0.1",
        scoring_profile_id="fixture-v0.1",
        git_commit="abc1234",
    )


def test_builds_detected_fusion_output() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    evidence = [
        make_evidence(
            "E-002",
            run_start,
            "type_a",
        ),
        make_evidence(
            "E-001",
            run_start,
            "type_b",
        ),
        make_evidence(
            "E-003",
            run_start + timedelta(seconds=10),
            "type_c",
        ),
    ]

    scorer = make_scorer()

    replay_result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=20),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=1,
        ),
    )

    output = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    assert output.fusion_status == "detected"
    assert output.fusion_time == (run_start + timedelta(seconds=10))
    assert output.score_at_decision == 0.75

    assert output.contributing_evidence_ids == [
        "E-001",
        "E-002",
        "E-003",
    ]


def test_excludes_non_scoring_evidence_from_provenance() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    evidence = [
        make_evidence(
            "E-001",
            run_start,
            "type_a",
        ),
        make_evidence(
            "E-002",
            run_start,
            "type_b",
        ),
        make_evidence(
            "E-003",
            run_start,
            "type_c",
        ),
        make_evidence(
            "E-DIAG",
            run_start,
            "type_d",
            feature_channel_group="diagnostic_only",
        ),
        make_evidence(
            "E-OUTSIDE",
            run_start,
            "type_outside_profile",
        ),
    ]

    scorer = make_scorer()

    replay_result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start,
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=1,
        ),
    )

    output = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    assert output.contributing_evidence_ids == [
        "E-001",
        "E-002",
        "E-003",
    ]


def test_future_evidence_is_not_in_decision_provenance() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    evidence = [
        make_evidence(
            "E-001",
            run_start,
            "type_a",
        ),
        make_evidence(
            "E-002",
            run_start,
            "type_b",
        ),
        make_evidence(
            "E-003",
            run_start,
            "type_c",
        ),
        make_evidence(
            "E-FUTURE",
            run_start + timedelta(seconds=20),
            "type_d",
        ),
    ]

    scorer = make_scorer()

    replay_result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=30),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=1,
        ),
    )

    output = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    assert "E-FUTURE" not in (output.contributing_evidence_ids)


def test_miss_has_no_contributing_evidence_ids() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    evidence = [
        make_evidence(
            "E-001",
            run_start,
            "type_a",
        ),
    ]

    scorer = make_scorer()

    replay_result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=20),
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=1,
        ),
    )

    output = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    assert output.fusion_status == "miss"
    assert output.fusion_time is None
    assert output.score_at_decision is None
    assert output.contributing_evidence_ids == []


def test_serialization_is_deterministic() -> None:
    run_start = datetime(
        2026,
        8,
        31,
        1,
        0,
        tzinfo=UTC,
    )

    evidence = [
        make_evidence(
            "E-001",
            run_start,
            "type_a",
        ),
        make_evidence(
            "E-002",
            run_start,
            "type_b",
        ),
        make_evidence(
            "E-003",
            run_start,
            "type_c",
        ),
    ]

    scorer = make_scorer()

    replay_result = replay_fusion(
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start,
        window_size=timedelta(minutes=5),
        step_size=timedelta(seconds=10),
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=1,
        ),
    )

    first = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    second = build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id="RUN-01",
        entity_id="HOST-01",
        window_size=timedelta(minutes=5),
        scorer=scorer,
        metadata=make_metadata(),
    )

    assert serialize_fusion_output(first) == serialize_fusion_output(second)
