from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.window_engine import WindowEngine


def make_evidence(
    evidence_id: str,
    evidence_type: str,
    *,
    feature_channel_group: str = "fusion_feature",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-01",
        timestamp=datetime(2026, 8, 30, 1, 0, tzinfo=UTC),
        entity_id="HOST-01",
        evidence_type=evidence_type,
        source_event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group=feature_channel_group,
        extractor_version="fixture-v0.1",
    )


def test_uses_fixed_profile_denominator() -> None:
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_b"),
    ]

    assert scorer.score(evidence) == 0.5


def test_counts_duplicate_evidence_type_once() -> None:
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_a"),
        make_evidence("003", "type_a"),
    ]

    assert scorer.score(evidence) == 0.25


def test_excludes_diagnostic_only_evidence() -> None:
    scorer = SimpleScorer(["type_a", "type_b"])

    evidence = [
        make_evidence(
            "001",
            "type_a",
            feature_channel_group="diagnostic_only",
        ),
    ]

    assert scorer.score(evidence) == 0.0


def test_excludes_evidence_type_outside_profile() -> None:
    scorer = SimpleScorer(["type_a", "type_b"])

    evidence = [
        make_evidence("001", "type_outside_profile"),
    ]

    assert scorer.score(evidence) == 0.0


def test_returns_zero_when_no_evidence_is_active() -> None:
    scorer = SimpleScorer(["type_a", "type_b"])

    assert scorer.score([]) == 0.0


def test_same_input_produces_same_score() -> None:
    scorer = SimpleScorer(["type_a", "type_b", "type_c"])

    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_b"),
    ]

    first = scorer.score(evidence)
    second = scorer.score(evidence)

    assert first == second


def test_rejects_empty_profile() -> None:
    with pytest.raises(
        ValueError,
        match="evidence_types must not be empty",
    ):
        SimpleScorer([])


def test_rejects_duplicate_profile_types() -> None:
    with pytest.raises(
        ValueError,
        match="evidence_types must not contain duplicates",
    ):
        SimpleScorer(["type_a", "type_a"])


def test_score_decreases_when_evidence_expires_from_window() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    t0 = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence_a = Evidence(
        evidence_id="001",
        run_id="RUN-01",
        timestamp=t0,
        entity_id="HOST-01",
        evidence_type="type_a",
        source_event_ids=["EVT-001"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="fixture-v0.1",
    )
    evidence_b = Evidence(
        evidence_id="002",
        run_id="RUN-01",
        timestamp=t0 + timedelta(minutes=3),
        entity_id="HOST-01",
        evidence_type="type_b",
        source_event_ids=["EVT-002"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="fixture-v0.1",
    )
    evidence_c = Evidence(
        evidence_id="003",
        run_id="RUN-01",
        timestamp=t0 + timedelta(minutes=5),
        entity_id="HOST-01",
        evidence_type="type_c",
        source_event_ids=["EVT-003"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="fixture-v0.1",
    )

    engine.ingest(evidence_a)
    engine.ingest(evidence_b)
    engine.ingest(evidence_c)

    engine.advance_to(
        run_id="RUN-01",
        entity_id="HOST-01",
        timestamp=t0 + timedelta(minutes=5),
    )

    score_at_5m = scorer.score(
        engine.get_active_evidence(
            run_id="RUN-01",
            entity_id="HOST-01",
        )
    )

    assert score_at_5m == 0.75

    engine.advance_to(
        run_id="RUN-01",
        entity_id="HOST-01",
        timestamp=t0 + timedelta(minutes=7),
    )

    score_at_7m = scorer.score(
        engine.get_active_evidence(
            run_id="RUN-01",
            entity_id="HOST-01",
        )
    )

    assert score_at_7m == 0.5
