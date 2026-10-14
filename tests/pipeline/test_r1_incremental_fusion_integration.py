"""Development integration of finalized Role2 Evidence with Role1 causal replay."""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
import test_r1_incremental_evidence as incremental_fixture
from test_r1_causal_availability import _run_metadata

from incident_awareness.common.models.r1_stream import R1RunClosed, R1SourceWatermark
from incident_awareness.decision.fusion.config import (
    FusionConfig,
    ReplayConfig,
    ScoringConfig,
    StoppingConfig,
    WindowConfig,
)
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.decision.fusion.temporal_replay import ScheduledEvidence
from incident_awareness.pipeline.r1_artifacts import (
    R1SelectorProvenance,
    load_r1_evidence_artifacts,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_causal_availability import (
    build_r1_causal_availability_envelope_from_artifacts,
)
from incident_awareness.pipeline.r1_causal_replay import run_r1_causal_replay
from incident_awareness.pipeline.r1_evidence import run_r1_evidence_pipeline_with_selector
from incident_awareness.pipeline.r1_incremental_evidence import (
    R1IncrementalEvidenceSnapshot,
    R1IncrementalEvidenceState,
)
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamDeliveryDisposition,
    R1StreamIngress,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedWatermark,
)

_RUN_ID = incremental_fixture._RUN_ID
_HOST_ID = incremental_fixture._HOST_ID
_RUN_START = incremental_fixture._RUN_START
_RUN_END = incremental_fixture._RUN_END


class _CloseLedger(incremental_fixture._Ledger):
    """Reuse chunk storage and verify final watermark binding for the real ingress."""

    def __init__(self) -> None:
        super().__init__()
        self.closes: dict[tuple[str, str], str] = {}

    def assert_final_watermarks_match(self, final_watermarks) -> None:
        for final in final_watermarks:
            expected = R1AcceptedWatermark(
                final.watermark_id,
                final.watermark_sequence,
                final.watermark_at,
                final.allowed_lateness_ms,
                final.covered_through_chunk_sequence,
            )
            if self.watermarks.get(final.partition) != expected:
                raise ValueError("run_closed must match an accepted final watermark")

    def save_run_close(self, *, run_id: str, close_id: str, content_sha256: str) -> bool:
        key = (run_id, close_id)
        if key in self.closes:
            if self.closes[key] != content_sha256:
                raise ValueError("run_closed identity conflict")
            return False
        self.closes[key] = content_sha256
        return True


@dataclass(frozen=True)
class _Stream:
    state: R1IncrementalEvidenceState
    ingress: R1StreamIngress
    ledger: _CloseLedger


def _stream() -> _Stream:
    ledger = _CloseLedger()
    ingress = incremental_fixture._ingress(ledger)
    return _Stream(incremental_fixture._state(ingress), ingress, ledger)


def _accept_close(stream: _Stream, close: R1RunClosed) -> R1IncrementalEvidenceSnapshot:
    for final in close.final_watermarks:
        stream.ingress.accept_watermark(
            R1SourceWatermark(
                schema="r1-incremental-stream",
                contract_version="v0.1",
                message_type="source_watermark",
                emitted_at=close.emitted_at,
                **final.model_dump(),
            )
        )
    admission = stream.ingress.accept_run_closed(close)
    assert admission.disposition is R1StreamDeliveryDisposition.ACCEPTED
    return stream.state.accept_run_closed(close)


def _scheduled(snapshot: R1IncrementalEvidenceSnapshot) -> tuple[ScheduledEvidence, ...]:
    """Test-local ID join; no production adapter or availability inference."""
    by_id = {evidence.evidence_id: evidence for evidence in snapshot.evidences}
    availability_by_id = {item.evidence_id: item for item in snapshot.availability}
    assert len(by_id) == len(snapshot.evidences)
    assert len(availability_by_id) == len(snapshot.availability)
    assert by_id.keys() == availability_by_id.keys()
    return tuple(
        ScheduledEvidence(evidence=by_id[item.evidence_id], available_at=item.available_at)
        for item in reversed(snapshot.availability)
    )


def _config(*, window_seconds: int = 900, persistence_k: int = 1) -> FusionConfig:
    return FusionConfig(
        config_version="r1-incremental-fusion-integration-test-v0.1",
        model_version=None,
        window=WindowConfig(window_size_sec=window_seconds),
        replay=ReplayConfig(step_size_sec=10),
        scoring=ScoringConfig(
            method="simple_score",
            scorer_version="simple-score-v0.1",
            profile_id="r1-incremental-fusion-integration-test-v0.1",
            evidence_types=(
                "remote_session_process_lineage_deviation",
                "remote_process_network_follow_on",
            ),
        ),
        stopping=StoppingConfig(threshold_on=0.8, threshold_off=0.4, persistence_k=persistence_k),
    )


def test_provisional_and_accepted_close_publish_no_fusion_input() -> None:
    # Given
    stream = _stream()
    initial = stream.state.snapshot
    config = _config()

    # When
    incremental_fixture._accept_all_events(stream.state)
    provisional = stream.state.snapshot
    closed = _accept_close(stream, incremental_fixture._run_closed())
    replay = config.build_runner().run_causal(
        _scheduled(closed),
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        run_end=_RUN_END,
    )

    # Then
    assert initial.status == "accumulating"
    assert provisional.status == closed.status == "provisional"
    assert provisional.selector_result.selection is not None
    for snapshot in (initial, provisional, closed):
        assert snapshot.evidences == snapshot.availability == ()
        assert snapshot.available_at is None
    assert len(stream.ledger.closes) == 1
    assert all(point.score == 0 for point in replay.trajectory)
    assert all(item.contributing_evidence_ids == () for item in replay.evidence_snapshots)
    assert replay.stopping_result.fusion_status == "miss"


def test_finalized_evidence_join_preserves_event_and_context_provenance() -> None:
    # Given
    stream = _stream()
    events_by_id = {event.event_id: event for event in incremental_fixture._events()}
    incremental_fixture._accept_all_events(stream.state)
    _accept_close(stream, incremental_fixture._run_closed())

    # When
    finalized = stream.state.finalize_at_run_end(_RUN_END)
    scheduled = _scheduled(finalized)

    # Then
    assert finalized.status == "finalized"
    assert finalized.close_mode == "authoritative_run_end_fallback"
    assert finalized.candidate_boundary_at == finalized.available_at == _RUN_END
    assert finalized.extraction_diagnostics == ()
    assert finalized.lineage_input is not None
    assert finalized.lineage_input.context_event_ids == ("evt-context-root",)
    assert len(finalized.evidences) == len(finalized.availability) == len(scheduled) == 2
    by_id = {evidence.evidence_id: evidence for evidence in finalized.evidences}
    for item in finalized.availability:
        evidence = by_id[item.evidence_id]
        assert item.timestamp == evidence.timestamp
        assert item.event_ids == tuple(evidence.event_ids)
        assert item.context_event_ids == finalized.lineage_input.context_event_ids
        assert item.available_at == _RUN_END
        assert item.timestamp == max(
            events_by_id[event_id].timestamp for event_id in item.event_ids
        )
        assert set(item.event_ids).isdisjoint(item.context_event_ids)
        assert all(
            events_by_id[event_id].timestamp < _RUN_START for event_id in item.context_event_ids
        )
    for item in scheduled:
        assert item.evidence is by_id[item.evidence.evidence_id]
        assert item.available_at == _RUN_END


@pytest.mark.parametrize(
    ("window_seconds", "persistence_k", "terminal_score", "fusion_status"),
    [
        (900, 1, 1.0, "detected"),
        (900, 2, 1.0, "miss"),
        (300, 1, 0.5, "miss"),
        (299, 1, 0.0, "miss"),
    ],
)
def test_causal_gate_and_semantic_window_match_whole_episode_fusion(
    tmp_path: Path,
    window_seconds: int,
    persistence_k: int,
    terminal_score: float,
    fusion_status: str,
) -> None:
    # Given
    stream = _stream()
    incremental_fixture._accept_all_events(stream.state)
    _accept_close(stream, incremental_fixture._run_closed())
    finalized = stream.state.finalize_at_run_end(_RUN_END)
    config = _config(window_seconds=window_seconds, persistence_k=persistence_k)
    selector_policy = incremental_fixture._selector_policy()
    approved_policy = incremental_fixture._approved_policy()
    whole = run_r1_evidence_pipeline_with_selector(
        incremental_fixture._events(),
        selector_policy=selector_policy,
        approved_policy=approved_policy,
        run_start=_RUN_START,
    )
    assert whole.lineage_input is not None
    run_and_write_r1_evidence_artifacts(
        incremental_fixture._events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=(whole.lineage_input,),
        selector_provenance=R1SelectorProvenance(
            policy_id=selector_policy.policy_id,
            version=selector_policy.version,
            config_hash=selector_policy.config_hash,
            status="selected",
            diagnostics=(),
        ),
    )
    artifact_run = load_r1_evidence_artifacts(tmp_path)
    metadata = _run_metadata(
        run_id=_RUN_ID,
        target_host=_HOST_ID,
        start_time=_RUN_START,
        end_time=_RUN_END,
        family_id=approved_policy.family_id,
    )
    envelope = build_r1_causal_availability_envelope_from_artifacts(
        artifact_run,
        run_metadata=metadata,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
    )
    scheduled = _scheduled(finalized)

    # When
    runner = config.build_runner()
    replay = runner.run_causal(
        scheduled,
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        run_end=_RUN_END,
    )
    repeated = runner.run_causal(
        scheduled,
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        run_end=_RUN_END,
    )
    fusion = build_fusion_result(
        replay,
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
    whole_replay = run_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=metadata,
        approved_policy=approved_policy,
        config=config,
        execution_commit="a" * 40,
    )

    # Then
    assert finalized.evidences == whole.evidences == artifact_run.evidences
    assert finalized.lineage_input == whole.lineage_input
    assert finalized.availability == envelope.evidences
    assert replay == repeated == whole_replay.replay_result
    assert fusion == whole_replay.fusion_result
    assert fusion.fusion_status == fusion_status
    assert replay.trajectory[:-1]
    assert all(point.timestamp < _RUN_END and point.score == 0 for point in replay.trajectory[:-1])
    assert all(item.contributing_evidence_ids == () for item in replay.evidence_snapshots[:-1])
    assert replay.trajectory[-1].timestamp == _RUN_END
    assert replay.trajectory[-1].score == terminal_score
    cutoff = _RUN_END - timedelta(seconds=window_seconds)
    expected_ids = tuple(
        sorted(item.evidence_id for item in finalized.evidences if item.timestamp >= cutoff)
    )
    assert replay.evidence_snapshots[-1].contributing_evidence_ids == expected_ids
    assert fusion.fusion_time == (_RUN_END if fusion_status == "detected" else None)


def test_reordered_and_replayed_chunks_produce_identical_finalized_fusion() -> None:
    # Given
    ordered = _stream()
    reordered = _stream()
    events = incremental_fixture._events()
    first = incremental_fixture._chunk(events[:2], chunk_id="CHK-001", sequence=1)
    second = incremental_fixture._chunk(events[2:], chunk_id="CHK-002", sequence=2)
    config = _config()

    # When
    for stream, chunks in ((ordered, (first, second)), (reordered, (second, first, second))):
        for chunk in chunks:
            stream.state.accept_chunk(chunk)
        _accept_close(stream, incremental_fixture._run_closed())
        stream.state.finalize_at_run_end(_RUN_END)
    replays = tuple(
        config.build_runner().run_causal(
            _scheduled(stream.state.snapshot),
            run_id=_RUN_ID,
            entity_id=_HOST_ID,
            run_start=_RUN_START,
            run_end=_RUN_END,
        )
        for stream in (ordered, reordered)
    )
    repeated_finalization = reordered.state.finalize_at_run_end(_RUN_END)

    # Then
    assert ordered.state.snapshot.status == "finalized"
    assert ordered.state.snapshot == reordered.state.snapshot == repeated_finalization
    assert replays[0] == replays[1]
    assert len(ordered.ledger.events) == len(reordered.ledger.events) == len(events)


@pytest.mark.parametrize("failure", ["missing_chunk", "truncated_lineage"])
def test_failed_closed_snapshot_has_no_scheduled_evidence_or_fusion_contribution(
    failure: str,
) -> None:
    # Given
    stream = _stream()
    events = incremental_fixture._events()
    if failure == "missing_chunk":
        stream.state.accept_chunk(
            incremental_fixture._chunk(events[:2], chunk_id="CHK-001", sequence=1)
        )
        close = incremental_fixture._run_closed(covered_through_chunk_sequence=2)
        expected_diagnostic = "covered chunk sequence is missing"
    else:
        stream.state.accept_chunk(
            incremental_fixture._chunk(events[2:], chunk_id="CHK-001", sequence=1)
        )
        close = incremental_fixture._run_closed(covered_through_chunk_sequence=1)
        expected_diagnostic = "truncated_lineage"
    _accept_close(stream, close)

    # When
    failed = stream.state.finalize_at_run_end(_RUN_END)
    scheduled = _scheduled(failed)
    replay = (
        _config()
        .build_runner()
        .run_causal(
            scheduled,
            run_id=_RUN_ID,
            entity_id=_HOST_ID,
            run_start=_RUN_START,
            run_end=_RUN_END,
        )
    )

    # Then
    assert failed.status == "failed_closed"
    assert any(expected_diagnostic in diagnostic for diagnostic in failed.diagnostics)
    assert failed.evidences == failed.availability == scheduled == ()
    assert failed.available_at == _RUN_END
    assert all(point.score == 0 for point in replay.trajectory)
    assert all(item.contributing_evidence_ids == () for item in replay.evidence_snapshots)
    assert replay.stopping_result.fusion_status == "miss"


@pytest.mark.parametrize("failure", ["missing_close", "insufficient_watermark"])
def test_incomplete_close_rejects_finalization_and_keeps_fusion_input_empty(failure: str) -> None:
    # Given
    stream = _stream()
    incremental_fixture._accept_all_events(stream.state)
    expected_message = "accepted run_closed is required"
    if failure == "insufficient_watermark":
        close = incremental_fixture._run_closed(watermark_at=_RUN_END - timedelta(seconds=1))
        _accept_close(stream, close)
        expected_message = "final watermark must cover the candidate boundary"
    before = stream.state.snapshot

    # When
    with pytest.raises(ValueError) as exc_info:
        stream.state.finalize_at_run_end(_RUN_END)

    # Then
    assert exc_info.match(expected_message)
    assert stream.state.snapshot is before
    assert before.status == "provisional"
    assert before.evidences == before.availability == _scheduled(before) == ()


def test_ingress_rejects_unbound_close_before_it_reaches_incremental_state() -> None:
    # Given
    stream = _stream()
    incremental_fixture._accept_all_events(stream.state)
    close = incremental_fixture._run_closed()
    before = stream.state.snapshot

    # When
    with pytest.raises(ValueError) as exc_info:
        stream.ingress.accept_run_closed(close)

    # Then
    assert exc_info.match("run_closed must match an accepted final watermark")
    assert stream.ledger.closes == {}
    assert stream.state.snapshot is before
    assert before.evidences == before.availability == _scheduled(before) == ()
