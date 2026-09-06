from datetime import UTC, datetime, timedelta

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import ThresholdStoppingPolicy
from incident_awareness.decision.fusion.temporal_replay import TemporalReplayRunner
from incident_awareness.decision.fusion.window_engine import WindowEngine


def make_evidence(
    *,
    evidence_id: str,
    seconds: int,
    evidence_type: str,
) -> Evidence:
    start = datetime(2026, 9, 7, 1, 0, tzinfo=UTC)

    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-01",
        timestamp=start + timedelta(seconds=seconds),
        entity_id="HOST-01",
        evidence_type=evidence_type,
        event_ids=[f"EVENT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="test",
    )


def test_replays_scores_at_fixed_cadence() -> None:
    # Given
    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=20)),
        scorer=SimpleScorer(
            evidence_types=[
                "encoded_powershell_command",
                "suspicious_process",
            ]
        ),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
        step_size=timedelta(seconds=10),
    )
    evidences = [
        make_evidence(
            evidence_id="EVD-001",
            seconds=0,
            evidence_type="encoded_powershell_command",
        ),
        make_evidence(
            evidence_id="EVD-002",
            seconds=15,
            evidence_type="suspicious_process",
        ),
    ]
    run_start = datetime(2026, 9, 7, 1, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    # When
    result = runner.run(
        evidences,
        run_id="RUN-01",
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_end,
    )

    # Then
    assert [point.timestamp for point in result.trajectory] == [
        run_start,
        run_start + timedelta(seconds=10),
        run_start + timedelta(seconds=20),
        run_start + timedelta(seconds=30),
    ]
    assert [point.score for point in result.trajectory] == [
        0.5,
        0.5,
        1.0,
        0.5,
    ]

    assert result.stopping_result.fusion_status == "detected"
    assert result.stopping_result.fusion_time == run_start + timedelta(seconds=20)
