from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.window_engine import WindowEngine


def make_evidence(
    evidence_id: str,
    evidence_type: str,
    *,
    timestamp: datetime | None = None,
    feature_channel_group: str = "fusion_feature",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-01",
        timestamp=timestamp or datetime(2026, 8, 30, 1, 0, tzinfo=UTC),
        entity_id="HOST-01",
        evidence_type=evidence_type,
        event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group=feature_channel_group,
        extractor_version="fixture-v0.1",
    )


def test_uses_fixed_profile_denominator() -> None:
    # Given
    scorer = SimpleScorer(
        ["type_a", "type_b", "type_c", "type_d"],
    )

    # When
    denominator = scorer.denominator

    # Then
    assert denominator == 4


def test_rejects_empty_profile() -> None:
    # Given
    evidence_types: list[str] = []

    # When
    with pytest.raises(ValueError) as exc_info:
        SimpleScorer(evidence_types)

    # Then
    assert str(exc_info.value) == "evidence_types must not be empty"


def test_rejects_duplicate_profile_types() -> None:
    # Given
    evidence_types = ["type_a", "type_a"]

    # When
    with pytest.raises(ValueError) as exc_info:
        SimpleScorer(evidence_types)

    # Then
    assert str(exc_info.value) == "evidence_types must not contain duplicates"


def test_scores_active_profile_types() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b", "type_c", "type_d"])
    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_b"),
    ]

    # When
    score = scorer.score(evidence)

    # Then
    assert score == 0.5


def test_returns_zero_when_no_evidence_is_active() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b"])

    # When
    score = scorer.score([])

    # Then
    assert score == 0.0


def test_returns_one_when_all_profile_types_are_active() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b", "type_c", "type_d"])
    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_b"),
        make_evidence("003", "type_c"),
        make_evidence("004", "type_d"),
    ]

    # When
    score = scorer.score(evidence)

    # Then
    assert score == 1.0


def test_counts_duplicate_evidence_type_once() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b", "type_c", "type_d"])
    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_a"),
        make_evidence("003", "type_a"),
    ]

    # When
    score = scorer.score(evidence)

    # Then
    assert score == 0.25


def test_excludes_evidence_type_outside_profile() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b"])
    evidence = [
        make_evidence("001", "type_outside_profile"),
    ]

    # When
    score = scorer.score(evidence)

    # Then
    assert score == 0.0


def test_excludes_diagnostic_only_evidence() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b"])
    evidence = [
        make_evidence(
            "001",
            "type_a",
            feature_channel_group="diagnostic_only",
        ),
    ]

    # When
    score = scorer.score(evidence)

    # Then
    assert score == 0.0


def test_same_input_produces_same_score() -> None:
    # Given
    scorer = SimpleScorer(["type_a", "type_b", "type_c"])
    evidence = [
        make_evidence("001", "type_a"),
        make_evidence("002", "type_b"),
    ]

    # When
    first_score = scorer.score(evidence)
    second_score = scorer.score(evidence)

    # Then
    assert first_score == second_score


def test_score_decreases_when_evidence_expires_from_window() -> None:
    # Given
    engine = WindowEngine(window_size=timedelta(minutes=5))
    scorer = SimpleScorer(["type_a", "type_b", "type_c", "type_d"])

    t0 = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence_a = make_evidence("001", "type_a", timestamp=t0)
    evidence_b = make_evidence(
        "002",
        "type_b",
        timestamp=t0 + timedelta(minutes=3),
    )
    evidence_c = make_evidence(
        "003",
        "type_c",
        timestamp=t0 + timedelta(minutes=5),
    )

    engine.ingest(evidence_a)
    engine.ingest(evidence_b)
    engine.ingest(evidence_c)

    # When
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

    # Then
    assert score_at_5m == 0.75
    assert score_at_7m == 0.5
