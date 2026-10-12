from datetime import UTC, datetime, timedelta

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import ThresholdStoppingPolicy
from incident_awareness.decision.fusion.temporal_replay import (
    ScheduledEvidence,
    TemporalReplayRunner,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine

_START = datetime(2026, 10, 12, 0, 0, tzinfo=UTC)


def _evidence(
    evidence_id: str,
    *,
    timestamp: datetime,
    evidence_type: str = "remote_session_process_lineage_deviation",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-20261012-001",
        timestamp=timestamp,
        entity_id="TARGET-A",
        evidence_type=evidence_type,
        event_ids=[f"event-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="r1-multi-event-v0.1",
    )


def _runner(
    *,
    window_seconds: int = 30,
    step_seconds: int = 10,
    persistence_k: int = 1,
) -> TemporalReplayRunner:
    return TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=window_seconds)),
        scorer=SimpleScorer(evidence_types=["remote_session_process_lineage_deviation"]),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=persistence_k,
        ),
        step_size=timedelta(seconds=step_seconds),
    )


def test_causal_gate_activates_only_at_or_after_available_at() -> None:
    # Given
    scheduled = ScheduledEvidence(
        evidence=_evidence("E-001", timestamp=_START + timedelta(seconds=40)),
        available_at=_START + timedelta(seconds=50),
    )

    # When
    result = _runner(window_seconds=60).run_causal(
        [scheduled],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=_START + timedelta(seconds=60),
    )

    # Then
    assert [point.score for point in result.trajectory] == [0, 0, 0, 0, 0, 1, 1]
    assert result.stopping_result.fusion_time == _START + timedelta(seconds=50)


def test_late_evidence_does_not_contribute_after_semantic_window_expiry() -> None:
    # Given
    scheduled = ScheduledEvidence(
        evidence=_evidence("E-001", timestamp=_START + timedelta(seconds=10)),
        available_at=_START + timedelta(seconds=100),
    )

    # When
    result = _runner(window_seconds=30).run_causal(
        [scheduled],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=_START + timedelta(seconds=100),
    )

    # Then
    assert all(point.score == 0 for point in result.trajectory)
    assert result.stopping_result.fusion_status == "miss"


def test_timestamp_reverse_activation_order_is_supported() -> None:
    # Given
    later_semantic_first = ScheduledEvidence(
        evidence=_evidence("E-B", timestamp=_START + timedelta(seconds=20)),
        available_at=_START + timedelta(seconds=50),
    )
    earlier_semantic_later = ScheduledEvidence(
        evidence=_evidence("E-A", timestamp=_START + timedelta(seconds=10)),
        available_at=_START + timedelta(seconds=60),
    )

    # When
    result = _runner(window_seconds=60).run_causal(
        [earlier_semantic_later, later_semantic_first],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=_START + timedelta(seconds=60),
    )

    # Then
    assert result.trajectory[-2].score == 1
    assert result.trajectory[-1].score == 1


def test_adds_terminal_partial_tick_and_scores_it() -> None:
    # Given
    run_end = _START + timedelta(seconds=35)
    scheduled = ScheduledEvidence(
        evidence=_evidence("E-001", timestamp=run_end),
        available_at=run_end,
    )

    # When
    result = _runner().run_causal(
        [scheduled],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=run_end,
    )

    # Then
    assert [point.timestamp for point in result.trajectory] == [
        _START,
        _START + timedelta(seconds=10),
        _START + timedelta(seconds=20),
        _START + timedelta(seconds=30),
        run_end,
    ]
    assert result.trajectory[-1].score == 1
    assert result.stopping_result.fusion_time == run_end


def test_aligned_run_end_does_not_duplicate_terminal_tick() -> None:
    # When
    result = _runner().run_causal(
        [],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=_START + timedelta(seconds=30),
    )

    # Then
    assert [point.timestamp for point in result.trajectory] == [
        _START,
        _START + timedelta(seconds=10),
        _START + timedelta(seconds=20),
        _START + timedelta(seconds=30),
    ]


def test_terminal_partial_tick_is_a_persistence_observation() -> None:
    # Given
    run_end = _START + timedelta(seconds=35)
    scheduled = ScheduledEvidence(
        evidence=_evidence("E-001", timestamp=_START + timedelta(seconds=30)),
        available_at=_START + timedelta(seconds=30),
    )

    # When
    result = _runner(persistence_k=2).run_causal(
        [scheduled],
        run_id="RUN-20261012-001",
        entity_id="TARGET-A",
        run_start=_START,
        run_end=run_end,
    )

    # Then
    assert result.stopping_result.fusion_status == "detected"
    assert result.stopping_result.fusion_time == run_end
    assert result.stopping_trace[-1].persistence_count == 2
