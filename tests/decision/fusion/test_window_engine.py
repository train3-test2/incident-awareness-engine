from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.window_engine import WindowEngine


def make_evidence(
    evidence_id: str,
    timestamp: datetime,
    *,
    run_id: str = "RUN-01",
    entity_id: str = "HOST-01",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=run_id,
        timestamp=timestamp,
        entity_id=entity_id,
        evidence_type="test_evidence",
        source_event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="fixture-v0.1",
    )


def test_expires_evidence_outside_window() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    t0 = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    engine.ingest(make_evidence("001", t0))
    engine.advance_to(
        run_id="RUN-01",
        entity_id="HOST-01",
        timestamp=t0 + timedelta(minutes=6),
    )

    active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-01",
    )

    assert active == []


def test_keeps_evidence_on_exact_window_boundary() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    t0 = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence = make_evidence("001", t0)
    engine.ingest(evidence)

    engine.advance_to(
        run_id="RUN-01",
        entity_id="HOST-01",
        timestamp=t0 + timedelta(minutes=5),
    )

    active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-01",
    )

    assert active == [evidence]


def test_separates_run_state() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    timestamp = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    run_1_evidence = make_evidence(
        "001",
        timestamp,
        run_id="RUN-01",
    )
    run_2_evidence = make_evidence(
        "002",
        timestamp,
        run_id="RUN-02",
    )

    engine.ingest(run_1_evidence)
    engine.ingest(run_2_evidence)

    run_1_active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-01",
    )
    run_2_active = engine.get_active_evidence(
        run_id="RUN-02",
        entity_id="HOST-01",
    )

    assert run_1_active == [run_1_evidence]
    assert run_2_active == [run_2_evidence]


def test_separates_entity_state() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    timestamp = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    host_1_evidence = make_evidence(
        "001",
        timestamp,
        entity_id="HOST-01",
    )
    host_2_evidence = make_evidence(
        "002",
        timestamp,
        entity_id="HOST-02",
    )

    engine.ingest(host_1_evidence)
    engine.ingest(host_2_evidence)

    host_1_active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-01",
    )
    host_2_active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-02",
    )

    assert host_1_active == [host_1_evidence]
    assert host_2_active == [host_2_evidence]


def test_reset_clears_state() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    timestamp = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    evidence = make_evidence("001", timestamp)

    engine.ingest(evidence)

    engine.reset(
        run_id="RUN-01",
        entity_id="HOST-01",
    )

    active = engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-01",
    )

    assert active == []


def test_rejects_out_of_order_evidence() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    later = datetime(2026, 8, 30, 1, 5, tzinfo=UTC)
    earlier = datetime(2026, 8, 30, 1, 4, tzinfo=UTC)

    engine.ingest(make_evidence("001", later))

    with pytest.raises(
        ValueError,
        match="Evidence timestamps must be non-decreasing",
    ):
        engine.ingest(make_evidence("002", earlier))


def test_reset_does_not_clear_other_state() -> None:
    engine = WindowEngine(window_size=timedelta(minutes=5))

    timestamp = datetime(2026, 8, 30, 1, 0, tzinfo=UTC)

    target = make_evidence(
        "001",
        timestamp,
        run_id="RUN-01",
        entity_id="HOST-01",
    )
    other_run = make_evidence(
        "002",
        timestamp,
        run_id="RUN-02",
        entity_id="HOST-01",
    )
    other_entity = make_evidence(
        "003",
        timestamp,
        run_id="RUN-01",
        entity_id="HOST-02",
    )

    engine.ingest(target)
    engine.ingest(other_run)
    engine.ingest(other_entity)

    engine.reset(
        run_id="RUN-01",
        entity_id="HOST-01",
    )

    assert (
        engine.get_active_evidence(
            run_id="RUN-01",
            entity_id="HOST-01",
        )
        == []
    )
    assert engine.get_active_evidence(
        run_id="RUN-02",
        entity_id="HOST-01",
    ) == [other_run]
    assert engine.get_active_evidence(
        run_id="RUN-01",
        entity_id="HOST-02",
    ) == [other_entity]
