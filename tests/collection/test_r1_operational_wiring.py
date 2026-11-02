"""Role3 spool -> Role2 consumer -> Role1 handoff, with synthetic v0.2 inputs only."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import test_r1_candidate_generation_seal as seal_fixture
import test_r1_incremental_availability_v02 as fixture
import test_r1_role2_verified_close_proof as proof_fixture

from incident_awareness.collection.r1_role2_verified_close_proof import (
    role2_safe_source_seal_projection_sha256,
    write_r1_role2_verified_close_proof,
)
from incident_awareness.common.models.r1_stream import R1SourceWatermark
from incident_awareness.common.models.result import DecisionResult, DetectorStatus
from incident_awareness.decision.fusion.temporal_replay import TemporalReplayRunner
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionAdapterResult,
    build_not_evaluated_detection_result,
)
from incident_awareness.pipeline import r1_incremental_consumer as consumer_module
from incident_awareness.pipeline import r1_incremental_evidence as incremental_evidence_module
from incident_awareness.pipeline import r1_stream_wiring as wiring
from incident_awareness.pipeline.r1_artifact_io import utc_now
from incident_awareness.pipeline.r1_fusion_handoff import (
    R1_DECISION_RESULT_FILENAME,
    R1_FUSION_RESULT_FILENAME,
    R1_FUSION_STOPPING_TRACE_FILENAME,
    R1FusionHandoffIdentityConflict,
    R1FusionHandoffRejected,
    R1FusionHandoffTrust,
    consume_published_r1_evidence,
)
from incident_awareness.pipeline.r1_incremental_consumer import (
    R1_INCREMENTAL_CHECKPOINT_FILENAME,
    R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME,
    R1_ROLE2_TRACE_FILENAME,
    R1CommittedChunkIngress,
    R1FinalizationBlockedError,
    R1FinalizationTrust,
    R1IncrementalChunkConsumer,
    R1IncrementalConsumerConfig,
    R1IncrementalConsumerError,
)
from incident_awareness.pipeline.r1_operational_trace import R1OperationalTrace
from incident_awareness.pipeline.r1_process_lock import R1DirectoryLockTimeout, r1_directory_lock
from incident_awareness.pipeline.r1_stream_ingress import r1_stream_message_sha256
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
    R1AcceptedWatermark,
    R1StreamDeliveryRepository,
)

_RUN_ID = fixture._RUN_ID
_HOST_ID = fixture._HOST_ID


class _Ledger(fixture._Ledger):
    """In-memory Role3 double used only because these tests have no PostgreSQL."""

    def __init__(self) -> None:
        super().__init__()
        self.watermarks: dict[object, R1AcceptedWatermark] = {}
        self.close: R1AcceptedRunCloseReceipt | None = None

    def save_watermark(self, watermark: R1SourceWatermark, *, content_sha256: str) -> bool:
        self.watermarks[watermark.partition] = R1AcceptedWatermark(
            watermark.watermark_id,
            watermark.watermark_sequence,
            watermark.watermark_at,
            watermark.allowed_lateness_ms,
            watermark.covered_through_chunk_sequence,
        )
        return True

    def assert_final_watermarks_match(self, final_watermarks) -> None:
        for final in final_watermarks:
            assert final.partition in self.watermarks

    def save_run_close(self, *, run_id: str, close_id: str, content_sha256: str) -> bool:
        self.close = R1AcceptedRunCloseReceipt(run_id, close_id, content_sha256)
        return True

    def load_accepted_run_close_receipt(self, run_id: str) -> R1AcceptedRunCloseReceipt | None:
        return self.close


class _Transaction:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _Sink:
    def write(self, message) -> None:
        raise AssertionError(f"unexpected dead letter: {message!r}")


class _Clock:
    """Contract clock inside the fixed synthetic Run bounds."""

    def __init__(self) -> None:
        self._times: Iterator[datetime] = (
            fixture._PROOF_VALIDATED_AT + timedelta(seconds=index) for index in range(10_000)
        )

    def __call__(self) -> datetime:
        return next(self._times)


class _Harness:
    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        connection=None,
    ) -> None:
        self.ledger = _Ledger() if connection is None else R1StreamDeliveryRepository(connection)
        self.connection = _Transaction() if connection is None else connection
        self.spool = tmp_path / "spool"
        self.control = tmp_path / "control"
        self.state_root = tmp_path / "state"
        self.fusion_output = tmp_path / "fusion"
        self.contract_path = tmp_path / "contract.json"
        wiring.render_required_partition_contract(path=self.contract_path, target_host=_HOST_ID)
        self.contract = fixture._required_contract()
        self.clock = _Clock()
        self.chunks = tuple(
            fixture._chunk(event, index) for index, event in enumerate(fixture._events(), start=1)
        ) + (fixture._chunk(fixture._events()[0], 5),)
        self.ordinal = 0
        if connection is None:
            monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda _conn: self.ledger)
        # Restored state reads this module clock. Fixture proofs fix the Run in the past,
        # so the contract clock stays inside it while trace clocks keep real wall time.
        monkeypatch.setattr(incremental_evidence_module, "utc_now", lambda: self.clock())

    def write_run_started(self) -> None:
        path = self.control / _RUN_ID / "run-started.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema": "r1-incremental-run-control",
                    "contract_version": "v0.1",
                    "message_type": "run_started",
                    "run_id": _RUN_ID,
                    "target_host": _HOST_ID,
                    "run_start": fixture._RUN_START.isoformat().replace("+00:00", "Z"),
                }
            ),
            encoding="utf-8",
        )

    def _publish(self, name: str, message) -> Path:
        self.ordinal += 1
        path = self.spool / "outbox" / f"{self.ordinal:012d}-{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(wiring._canonical_bytes(message.model_dump(mode="json", by_alias=True)))
        return path

    def publish_chunk(self, chunk) -> Path:
        return self._publish("event_chunk", chunk)

    def write_ack(self, path: Path) -> None:
        wiring._publish_immutable(
            self.spool / "acks" / f"{path.name}.ack.json",
            wiring._canonical_bytes(
                {
                    "message_path": str(path.resolve()),
                    "message_sha256": wiring._sha256(path.read_bytes()),
                    "disposition": "accepted",
                    "accepted_at": "2026-10-13T01:06:00Z",
                }
            ),
        )

    def role3_consume(self) -> None:
        """The real Role3 consume_spool_once path, committing to the ledger double."""
        wiring.consume_spool_once(
            spool_root=self.spool,
            contract=self.contract,
            connection=self.connection,
        )

    def publish_close_through_role3(self) -> Path:
        close = seal_fixture._run_closed()
        for final in close.final_watermarks:
            self._publish(
                "source_watermark",
                R1SourceWatermark(
                    schema="r1-incremental-stream",
                    contract_version="v0.1",
                    message_type="source_watermark",
                    emitted_at=close.emitted_at,
                    **final.model_dump(),
                ),
            )
        close_path = self._publish("run_closed", close)
        self.role3_consume()
        return wiring.export_accepted_close(
            spool_root=self.spool,
            accepted_run_closed_path=close_path,
            connection=self.connection,
            contract_path=self.contract_path,
        )

    def ingress(self) -> R1CommittedChunkIngress:
        return R1CommittedChunkIngress(
            self.ledger, dead_letter_sink=_Sink(), clock=lambda: fixture._RUN_END
        )

    def trust(self, export_path: Path) -> R1FinalizationTrust:
        seal = seal_fixture._seal()
        return R1FinalizationTrust(
            candidate_policy=seal_fixture._policy(),
            close_export_path=export_path,
            source_seal_id=seal.seal_id,
            source_seal_projection_sha256=role2_safe_source_seal_projection_sha256(
                seal, host_id=_HOST_ID
            ),
        )

    def consumer(
        self,
        *,
        trust: R1FinalizationTrust | None = None,
        lock_timeout_sec: float = 30.0,
    ) -> R1IncrementalChunkConsumer:
        return R1IncrementalChunkConsumer(
            R1IncrementalConsumerConfig(
                run_id=_RUN_ID,
                target_host=_HOST_ID,
                scenario_family_id="wmi_management",
                spool_root=self.spool,
                control_root=self.control,
                state_root=self.state_root,
                contract=self.contract,
                selector_policy=fixture._selector_policy(),
                approved_policy=fixture._approved_policy(),
            ),
            ingress=self.ingress(),
            transaction=self.connection,
            finalization_trust=trust,
            clock=self.clock,
            lock_timeout_sec=lock_timeout_sec,
        )

    def handoff_trust(self, export_path: Path) -> R1FusionHandoffTrust:
        trust = self.trust(export_path)
        return R1FusionHandoffTrust(
            selector_policy=fixture._selector_policy(),
            approved_policy=fixture._approved_policy(),
            candidate_policy=trust.candidate_policy,
            close_export_path=export_path,
            source_seal_id=trust.source_seal_id,
            source_seal_projection_sha256=trust.source_seal_projection_sha256,
            ingress=self.ingress(),
        )

    def consume_all_chunks(self) -> None:
        self.write_run_started()
        for chunk in self.chunks:
            self.publish_chunk(chunk)
        self.role3_consume()
        self.consumer().consume_available()

    def finalize(self, tmp_path: Path, export_path: Path):
        proof_path = tmp_path / "verified-close-proof.json"
        if not proof_path.exists():
            write_r1_role2_verified_close_proof(proof_path, proof_fixture._proof())
        consumer = self.consumer(trust=self.trust(export_path))
        return consumer, consumer.finalize_and_publish(
            proof_path, run_metadata=fixture._run_metadata()
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Harness:
    return _Harness(tmp_path, monkeypatch)


def _stages(trace: R1OperationalTrace) -> list[str]:
    return [record.stage for record in trace.records()]


def test_acked_chunks_reach_incremental_state_without_issuing_evidence(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    for chunk in harness.chunks:
        harness.publish_chunk(chunk)
    harness.role3_consume()
    consumer = harness.consumer()

    # When
    result = consumer.consume_available()

    # Then
    assert result.status == "up_to_date"
    assert result.state_status == "provisional"
    assert result.applied_chunk_ids == tuple(chunk.chunk_id for chunk in harness.chunks)
    assert result.finalization_blocked_reason == "accepted_run_closed_missing"
    assert consumer.snapshot is not None
    assert consumer.snapshot.evidences == consumer.snapshot.availability == ()
    assert consumer.snapshot.available_at is None
    stages = _stages(consumer.trace)
    for stage in (
        "chunk_received",
        "chunk_accepted",
        "incremental_state_updated",
        "provisional_candidate",
        "finalization_blocked",
    ):
        assert stage in stages
    assert "evidence_finalized" not in stages
    assert "evidence_published" not in stages
    candidates = [r for r in consumer.trace.records() if r.stage == "provisional_candidate"]
    assert all(record.details["is_finalized_evidence"] is False for record in candidates)
    accepted = [r for r in consumer.trace.records() if r.stage == "chunk_accepted"]
    assert all(record.details["ack_disposition"] == "accepted" for record in accepted)
    assert all(record.details["ack_accepted_at"] for record in accepted)
    assert not (harness.state_root / "r1_evidence.jsonl").exists()


def test_consumer_waits_for_authoritative_run_start_instead_of_inventing_it(
    harness: _Harness,
) -> None:
    # Given
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()

    # When
    result = harness.consumer().consume_available()

    # Then
    assert result.status == "waiting_run_start"
    assert not (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).exists()
    assert not (harness.state_root / R1_ROLE2_TRACE_FILENAME).exists()


def test_restart_restores_state_and_duplicate_chunks_do_not_reapply(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.publish_chunk(harness.chunks[1])
    harness.role3_consume()
    first = harness.consumer().consume_available()
    before = harness.consumer()._read_checkpoint()

    # When
    restarted = harness.consumer()
    replay = restarted.consume_available()
    harness.publish_chunk(harness.chunks[2])
    harness.role3_consume()
    next_result = restarted.consume_available()

    # Then
    assert first.applied_chunk_ids == ("CHK-001", "CHK-002")
    assert replay.applied_chunk_ids == ()
    assert replay.already_consumed_chunks == 2
    assert harness.consumer()._read_checkpoint().generation == before.generation + 1
    assert next_result.applied_chunk_ids == ("CHK-003",)
    assert next_result.already_consumed_chunks == 2


def test_missing_ack_stops_consumption_without_advancing_state(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    harness.publish_chunk(harness.chunks[1])
    consumer = harness.consumer()

    # When
    result = consumer.consume_available()

    # Then
    assert result.status == "waiting_ack"
    assert result.applied_chunk_ids == ("CHK-001",)
    assert consumer._read_checkpoint().accepted_chunks[-1].chunk_id == "CHK-001"
    pending = [r for r in consumer.trace.records() if r.stage == "chunk_received"][-1]
    assert pending.details["ack_present"] is False


def test_tampered_chunk_bytes_are_rejected_and_state_does_not_advance(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    path = harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    path.write_bytes(path.read_bytes() + b" ")
    consumer = harness.consumer()

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="does not match the spool message bytes"):
        consumer.consume_available()
    assert not consumer.checkpoint_path.exists()
    assert _stages(consumer.trace)[-1] == "chunk_rejected"


def test_wrong_host_chunk_is_rejected_before_state_update(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    chunk = harness.chunks[0]
    wrong = chunk.model_copy(
        update={
            "partition": chunk.partition.model_copy(update={"host_id": "R1-OTHER"}),
            "events": tuple(e.model_copy(update={"host_id": "R1-OTHER"}) for e in chunk.events),
        }
    )
    harness.write_ack(harness.publish_chunk(wrong))
    consumer = harness.consumer()

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="Run or host"):
        consumer.consume_available()
    assert not consumer.checkpoint_path.exists()


def test_partition_outside_contract_is_rejected_before_state_update(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    chunk = harness.chunks[0]
    wrong = chunk.model_copy(
        update={"partition": chunk.partition.model_copy(update={"source_channel": "Security"})}
    )
    harness.write_ack(harness.publish_chunk(wrong))
    consumer = harness.consumer()

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="required-partition contract"):
        consumer.consume_available()
    assert not consumer.checkpoint_path.exists()


def test_sequence_gap_is_rejected_without_state_update(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    consumer = harness.consumer()
    consumer.consume_available()
    harness.ledger.chunks[next(iter(harness.ledger.chunks))[0], harness.chunks[2].chunk_id] = (
        harness.chunks[2].chunk_sequence,
        r1_stream_message_sha256(harness.chunks[2]),
    )
    harness.write_ack(harness.publish_chunk(harness.chunks[2]))

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="not the next expected"):
        consumer.consume_available()
    assert consumer._read_checkpoint().accepted_chunks[-1].chunk_id == "CHK-001"


def test_acked_chunk_without_ledger_row_is_rejected_and_rolled_back(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    path = harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    harness.ledger.chunks.clear()
    harness.ledger.events.clear()
    consumer = harness.consumer()
    rollbacks = harness.connection.rollbacks

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="no committed Role3 ledger entry"):
        consumer.consume_available()
    assert harness.connection.rollbacks == rollbacks + 1
    assert not consumer.checkpoint_path.exists()
    assert path.exists()


def test_finalize_blocks_without_event_time_close_or_proof(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given
    harness.consume_all_chunks()
    consumer = harness.consumer(trust=harness.trust(tmp_path / "missing-close-export.json"))

    # When / Then
    with pytest.raises(R1FinalizationBlockedError, match="event_time_close_or_proof_rejected"):
        consumer.finalize_and_publish(
            tmp_path / "missing-proof.json", run_metadata=fixture._run_metadata()
        )
    assert _stages(consumer.trace)[-1] == "finalization_blocked"
    assert consumer.snapshot.status == "provisional"
    assert consumer.snapshot.evidences == ()
    assert not (harness.state_root / "r1_evidence.jsonl").exists()


def test_position_proof_payload_is_not_accepted_as_event_time_proof(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    position_proof = tmp_path / "position-proof.json"
    position_proof.write_text(
        json.dumps({"schema": "r1-role2-verified-position-close-proof"}), encoding="utf-8"
    )
    consumer = harness.consumer(trust=harness.trust(export))

    # When / Then
    with pytest.raises(R1FinalizationBlockedError, match="event_time_close_or_proof_rejected"):
        consumer.finalize_and_publish(position_proof, run_metadata=fixture._run_metadata())
    assert consumer.snapshot.evidences == ()


def test_mismatched_seal_binding_fails_closed(harness: _Harness, tmp_path: Path) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    proof_path = tmp_path / "proof.json"
    write_r1_role2_verified_close_proof(proof_path, proof_fixture._proof())
    trust = harness.trust(export)
    bad = R1FinalizationTrust(
        candidate_policy=trust.candidate_policy,
        close_export_path=export,
        source_seal_id=trust.source_seal_id,
        source_seal_projection_sha256="0" * 64,
    )
    consumer = harness.consumer(trust=bad)

    # When / Then
    with pytest.raises(R1FinalizationBlockedError, match="verified close rejected"):
        consumer.finalize_and_publish(proof_path, run_metadata=fixture._run_metadata())
    assert _stages(consumer.trace)[-1] == "finalization_failed_closed"
    assert consumer.snapshot.status == "failed_closed"
    assert consumer.snapshot.evidences == ()
    assert not (harness.state_root / "r1_evidence.jsonl").exists()


def test_tampered_close_export_receipt_is_blocked(harness: _Harness, tmp_path: Path) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    payload = json.loads(export.read_text(encoding="utf-8"))
    payload["acceptance_receipt"]["content_sha256"] = "0" * 64
    forged = tmp_path / "forged-close.json"
    forged.write_text(json.dumps(payload), encoding="utf-8")
    proof_path = tmp_path / "proof.json"
    write_r1_role2_verified_close_proof(proof_path, proof_fixture._proof())
    consumer = harness.consumer(trust=harness.trust(forged))

    # When / Then
    with pytest.raises(R1FinalizationBlockedError, match="does not match its ledger receipt"):
        consumer.finalize_and_publish(proof_path, run_metadata=fixture._run_metadata())


def test_provisional_state_never_reaches_role1_fusion(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    calls = []
    monkeypatch.setattr(TemporalReplayRunner, "run_causal", lambda *a, **k: calls.append(a))

    # When / Then
    with pytest.raises(R1FusionHandoffRejected, match="only finalized verified-proof"):
        consume_published_r1_evidence(
            harness.state_root,
            output_directory=harness.fusion_output,
            run_metadata=fixture._run_metadata(),
            trust=harness.handoff_trust(export),
            config=fixture._config(),
        )
    assert calls == []
    assert not (harness.fusion_output / R1_FUSION_RESULT_FILENAME).exists()
    trace = R1OperationalTrace(harness.fusion_output / "r1_fusion_execution_trace.jsonl")
    assert _stages(trace) == ["handoff_rejected"]


class _ScriptedDatabase:
    """Records the SQL the real repositories issue; results are never read back as PASS."""

    autocommit = False

    def __init__(self, registered_run=None) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self.registered_run = registered_run

    def execute(self, query: str, params: tuple[object, ...] = ()):
        self.statements.append((query, params))

        class _Result:
            def __init__(self, row, rows):
                self._row, self._rows = row, rows

            def fetchone(self):
                return self._row

            def fetchall(self):
                return self._rows

        if "FROM runs WHERE run_id" in query and self.registered_run is not None:
            return _Result((self.registered_run.model_dump(mode="json"),), [])
        if "transaction_isolation" in query:
            return _Result(("read committed",), [])
        if "current_head" in query or "scope_has_decisions" in query:
            return _Result(None, [(False, None)])
        return _Result(None, [])

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def test_synthetic_close_publishes_then_role1_consumes_and_records_wall_clock(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.consumer().consume_available()
    before = utc_now()
    consumer, published = harness.finalize(tmp_path, export)
    database = _ScriptedDatabase(registered_run=fixture._run_metadata())
    runs: list[int] = []
    real_run_causal = TemporalReplayRunner.run_causal

    def _spy(self, scheduled, **kwargs):
        runs.append(len(tuple(scheduled)))
        return real_run_causal(self, scheduled, **kwargs)

    monkeypatch.setattr(TemporalReplayRunner, "run_causal", _spy)

    # When
    result = consume_published_r1_evidence(
        harness.state_root,
        output_directory=harness.fusion_output,
        run_metadata=fixture._run_metadata(),
        trust=harness.handoff_trust(export),
        config=fixture._config(),
        connection=database,
        availability_clock=harness.clock,
    )
    after = utc_now()

    # Then: Role2 finalized and published through the existing v0.2 API.
    assert published.snapshot.status == "finalized"
    assert published.snapshot.availability_contract_version == "v0.2"
    assert len(published.snapshot.evidences) == 2
    assert published.receipt.publication_completed_at >= published.receipt.evidence_ready_at
    assert (harness.state_root / R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME).exists()
    role2_stages = _stages(consumer.trace)
    assert role2_stages.index("evidence_finalized") < role2_stages.index("evidence_published")

    # Then: Role1 really invoked causal Fusion with both published Evidence items.
    assert runs == [2]
    assert result.fusion_result.fusion_status == "detected"
    assert result.persisted_to_database is True
    assert database.commits == 1
    assert any("INSERT INTO fusion_results" in query for query, _ in database.statements)
    assert not any("INSERT INTO runs" in query for query, _ in database.statements)
    assert any("INSERT INTO decisions" in query for query, _ in database.statements)

    # Then: wall-clock stages are ordered, real, and separate from fusion_time.
    stages = [record.stage for record in result.trace]
    assert stages == [
        "handoff_accepted",
        "fusion_processing_started",
        "fusion_processing_completed",
        "decision_recorded",
    ]
    observed = [datetime.fromisoformat(record.observed_at) for record in result.trace]
    assert observed == sorted(observed)
    assert before <= observed[0] and observed[-1] <= after + timedelta(milliseconds=1)
    assert result.fusion_result.fusion_time < observed[0]
    accepted = result.trace[0].details
    assert accepted["input_validation"] == "passed"
    assert set(accepted["evidence_payload_sha256"]) == {
        item.evidence_id for item in published.snapshot.evidences
    }
    recorded = result.trace[-1].details
    assert recorded["fusion_result_sha256"] == result.trace[2].details["fusion_result_sha256"]
    assert recorded["input_envelope_sha256"] == accepted["envelope_sha256"]

    # Then: Fast was not run, so the Decision stays incomplete and is not a miss.
    assert recorded["decision_complete"] is False
    assert recorded["fast_status"] == "not_evaluated"
    assert result.decision_result.fast_status.value == "not_evaluated"
    assert result.decision_result.t_e is None
    assert result.decision_result.decision_path is None
    stored = DecisionResult.model_validate_json(
        (harness.fusion_output / R1_DECISION_RESULT_FILENAME).read_bytes()
    )
    assert stored == result.decision_result


def test_role1_retry_is_idempotent_and_keeps_first_observations(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.finalize(tmp_path, export)
    arguments = {
        "output_directory": harness.fusion_output,
        "run_metadata": fixture._run_metadata(),
        "trust": harness.handoff_trust(export),
        "config": fixture._config(),
        "availability_clock": harness.clock,
    }
    first = consume_published_r1_evidence(harness.state_root, **arguments)
    monkeypatch.setattr(
        TemporalReplayRunner,
        "run_causal",
        lambda *a, **k: pytest.fail("retry must not run Fusion again"),
    )

    # When
    second = consume_published_r1_evidence(harness.state_root, **arguments)

    # Then
    assert first.already_consumed is False
    assert second.already_consumed is True
    assert second.fusion_result == first.fusion_result
    assert second.decision_result == first.decision_result
    assert second.trace == first.trace


def test_tampered_published_evidence_is_rejected_before_fusion(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.finalize(tmp_path, export)
    (harness.state_root / "r1_evidence.jsonl").write_bytes(b"")
    monkeypatch.setattr(
        TemporalReplayRunner, "run_causal", lambda *a, **k: pytest.fail("Fusion must not run")
    )

    # When / Then
    with pytest.raises(R1FusionHandoffRejected):
        consume_published_r1_evidence(
            harness.state_root,
            output_directory=harness.fusion_output,
            run_metadata=fixture._run_metadata(),
            trust=harness.handoff_trust(export),
            config=fixture._config(),
            availability_clock=harness.clock,
        )


def test_finalized_state_survives_restart_and_republish_is_idempotent(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    _, first = harness.finalize(tmp_path, export)

    # When
    _, second = harness.finalize(tmp_path, export)
    restarted = harness.consumer(trust=harness.trust(export)).consume_available()

    # Then
    assert second.receipt == first.receipt
    assert second.snapshot.evidences == first.snapshot.evidences
    assert restarted.status == "terminal"


def test_evidence_ready_after_run_end_is_not_published_or_clipped(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.clock = lambda: fixture._RUN_END + timedelta(seconds=1)
    proof_path = tmp_path / "proof.json"
    write_r1_role2_verified_close_proof(proof_path, proof_fixture._proof())
    consumer = harness.consumer(trust=harness.trust(export))

    # When / Then
    with pytest.raises(R1FinalizationBlockedError, match="availability_envelope_rejected"):
        consumer.finalize_and_publish(proof_path, run_metadata=fixture._run_metadata())
    assert "evidence_published" not in _stages(consumer.trace)
    assert not (harness.state_root / "r1_incremental_availability_v0.2.json").exists()


def test_consume_cli_binds_real_repository_and_commits_through_connection(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    monkeypatch.setattr(consumer_module, "R1StreamDeliveryRepository", lambda _conn: harness.ledger)
    args = consumer_module.build_parser().parse_args(
        [
            "consume",
            "--run-id", _RUN_ID,
            "--target-host", _HOST_ID,
            "--spool-root", str(harness.spool),
            "--control-root", str(harness.control),
            "--state-root", str(harness.state_root),
            "--required-partition-contract", str(harness.contract_path),
        ]
    )  # fmt: skip

    # When
    built = consumer_module.build_consumer_from_args(args, harness.connection)
    result = built.consume_available()

    # Then
    assert result.applied_chunk_ids == ("CHK-001",)
    assert built.checkpoint_path.exists()


def test_consume_without_finalize_trust_reports_verified_finalized_state_as_terminal(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given: the finalize command already published verified-proof Evidence.
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.finalize(tmp_path, export)
    checkpoint = (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).read_bytes()

    # When: the consume sidecar restarts without the finalize trust bindings.
    result = harness.consumer().consume_available()

    # Then
    assert result.status == "terminal"
    assert result.state_status == "finalized"
    assert (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).read_bytes() == checkpoint


def test_stale_consume_sidecar_does_not_overwrite_a_finalized_checkpoint(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given: a long-running sidecar holds provisional state in memory.
    harness.consume_all_chunks()
    sidecar = harness.consumer()
    sidecar.consume_available()
    export = harness.publish_close_through_role3()

    # When: another process finalizes, then the sidecar polls again.
    harness.finalize(tmp_path, export)
    finalized = (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).read_bytes()
    result = sidecar.consume_available()

    # Then
    assert result.status == "terminal"
    assert (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).read_bytes() == finalized


def test_consumer_reloads_a_checkpoint_advanced_by_another_process(harness: _Harness) -> None:
    # Given: two consumer instances over one state root.
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    stale = harness.consumer()
    stale.consume_available()
    harness.publish_chunk(harness.chunks[1])
    harness.role3_consume()
    harness.consumer().consume_available()

    # When
    result = stale.consume_available()

    # Then: the stale instance sees CHK-002 as consumed instead of re-applying it.
    assert result.applied_chunk_ids == ()
    assert result.already_consumed_chunks == 2
    checkpoint = stale._read_checkpoint()
    assert [chunk.chunk_id for chunk in checkpoint.accepted_chunks] == ["CHK-001", "CHK-002"]
    assert R1OperationalTrace(harness.state_root / R1_ROLE2_TRACE_FILENAME).records()


def test_consume_waits_for_the_state_root_lock_and_writes_nothing(harness: _Harness) -> None:
    # Given
    harness.write_run_started()
    harness.publish_chunk(harness.chunks[0])
    harness.role3_consume()
    consumer = harness.consumer(lock_timeout_sec=0.2)

    # When / Then
    with r1_directory_lock(harness.state_root), pytest.raises(R1DirectoryLockTimeout):
        consumer.consume_available()
    assert not (harness.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME).exists()
    assert not (harness.state_root / R1_ROLE2_TRACE_FILENAME).exists()


def _published(harness: _Harness, tmp_path: Path) -> Path:
    harness.consume_all_chunks()
    export = harness.publish_close_through_role3()
    harness.finalize(tmp_path, export)
    return export


def _handoff(harness: _Harness, export: Path, **overrides):
    arguments = {
        "output_directory": harness.fusion_output,
        "run_metadata": fixture._run_metadata(),
        "trust": harness.handoff_trust(export),
        "config": fixture._config(),
        "availability_clock": harness.clock,
        **overrides,
    }
    return consume_published_r1_evidence(harness.state_root, **arguments)


def _miss_fast() -> FastDetectionAdapterResult:
    not_evaluated = build_not_evaluated_detection_result(run_id=_RUN_ID, entity_id=_HOST_ID)
    return FastDetectionAdapterResult(
        detection_result=not_evaluated.detection_result.model_copy(
            update={"detector_status": DetectorStatus.MISS}
        ),
        source_hit_ids=(),
        selected_source_hit_id=None,
    )


def _output_bytes(harness: _Harness) -> dict[str, bytes]:
    return {
        name: (harness.fusion_output / name).read_bytes()
        for name in (
            R1_FUSION_RESULT_FILENAME,
            R1_FUSION_STOPPING_TRACE_FILENAME,
            R1_DECISION_RESULT_FILENAME,
        )
    }


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"config": fixture._config().model_copy(update={"config_version": "other-config"})},
            id="fusion-config",
        ),
        pytest.param({"fast_result": _miss_fast()}, id="fast-input"),
        pytest.param({"decision_config_version": "parallel-v9"}, id="decision-config"),
    ],
)
def test_retry_with_a_different_execution_identity_is_refused_before_fusion(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict
) -> None:
    # Given
    export = _published(harness, tmp_path)
    first = _handoff(harness, export)
    outputs = _output_bytes(harness)
    monkeypatch.setattr(
        TemporalReplayRunner, "run_causal", lambda *a, **k: pytest.fail("Fusion must not run")
    )

    # When / Then
    with pytest.raises(R1FusionHandoffIdentityConflict, match="different execution identity"):
        _handoff(harness, export, **overrides)
    assert _output_bytes(harness) == outputs
    trace = R1OperationalTrace(harness.fusion_output / "r1_fusion_execution_trace.jsonl")
    records = trace.records()
    assert records[: len(first.trace)] == first.trace
    assert records[-1].stage == "handoff_rejected"
    assert records[-1].details["fusion_invoked"] is False


def test_unpersisted_handoff_is_stored_when_retried_with_a_connection(
    harness: _Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: the first run had no database connection.
    export = _published(harness, tmp_path)
    first = _handoff(harness, export)
    monkeypatch.setattr(
        TemporalReplayRunner, "run_causal", lambda *a, **k: pytest.fail("Fusion must not run")
    )
    database = _ScriptedDatabase(registered_run=fixture._run_metadata())

    # When
    second = _handoff(harness, export, connection=database)

    # Then
    assert first.persisted_to_database is False
    assert second.already_consumed is True
    assert second.persisted_to_database is True
    assert second.decision_result == first.decision_result
    assert database.commits == 1
    assert any("INSERT INTO fusion_results" in query for query, _ in database.statements)
    assert any("INSERT INTO decisions" in query for query, _ in database.statements)
    recorded = [record for record in second.trace if record.stage == "decision_recorded"]
    assert [record.details["persisted_to_database"] for record in recorded] == [False, True]


def test_recorded_persistence_flag_is_rechecked_against_the_database(
    harness: _Harness, tmp_path: Path
) -> None:
    # Given: the trace says persisted, but this database has no stored Decision.
    export = _published(harness, tmp_path)
    _handoff(harness, export, connection=_ScriptedDatabase(registered_run=fixture._run_metadata()))
    other_database = _ScriptedDatabase(registered_run=fixture._run_metadata())

    # When
    result = _handoff(harness, export, connection=other_database)

    # Then
    assert result.already_consumed is True
    assert any("INSERT INTO decisions" in query for query, _ in other_database.statements)


def test_tampered_stopping_trace_is_not_reused(harness: _Harness, tmp_path: Path) -> None:
    # Given
    export = _published(harness, tmp_path)
    _handoff(harness, export)
    stopping_trace = harness.fusion_output / R1_FUSION_STOPPING_TRACE_FILENAME
    stopping_trace.write_bytes(stopping_trace.read_bytes().replace(b"}", b" }", 1))

    # When / Then
    with pytest.raises(ValueError, match="recorded Fusion stopping trace differs"):
        _handoff(harness, export)
