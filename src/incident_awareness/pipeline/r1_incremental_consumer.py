"""Feed post-commit Role3 EventChunks into the Role2 incremental Evidence state.

Only messages bound by a post-commit ack are consumed. Provisional selector state
never becomes Evidence here. Finalization requires an accepted event-time close and
a verified close proof; a position proof, ack, RecordId, quiet period, or run_end
is not a substitute. The ack ``accepted_at`` is recorded verbatim and keeps its
existing meaning: an observation after commit, not the first DB commit time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol

import psycopg
from pydantic import ValidationError

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
    load_r1_candidate_generation_policy,
)
from incident_awareness.collection.r1_role2_verified_close_proof import (
    load_r1_role2_verified_close_proof,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifact_io import ceil_utc_clock_observation, utc_now
from incident_awareness.pipeline.r1_artifacts import (
    R1_EVIDENCE_FILENAME,
    R1SelectorProvenance,
    load_r1_evidence_artifacts,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_incremental_availability import (
    R1IncrementalAvailabilityPublicationReceipt,
    build_r1_incremental_causal_availability_envelope,
    write_r1_incremental_causal_availability_envelope,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    R1IncrementalEvidenceCheckpoint,
    incremental_checkpoint_sha256,
    incremental_evidence_sha256,
    load_r1_incremental_checkpoint,
    write_r1_incremental_checkpoint,
)
from incident_awareness.pipeline.r1_incremental_evidence import (
    R1IncrementalEvidenceSnapshot,
    R1IncrementalEvidenceState,
)
from incident_awareness.pipeline.r1_operational_trace import R1OperationalTrace
from incident_awareness.pipeline.r1_process_lock import (
    DEFAULT_R1_LOCK_TIMEOUT_SEC,
    r1_directory_lock,
)
from incident_awareness.pipeline.r1_production import (
    R1_SELECTOR_LINEAGE_EVENT_COUNT,
    R1_SELECTOR_POLICY_CONFIG_HASH,
    R1_SELECTOR_POLICY_ID,
    R1_SELECTOR_POLICY_VERSION,
)
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamDeliveryDisposition,
    R1StreamDeliveryResult,
    R1StreamIngress,
)
from incident_awareness.pipeline.r1_stream_wiring import (
    load_accepted_spool_message,
    load_close_export,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1StreamDeliveryRepository,
)

R1_INCREMENTAL_CHECKPOINT_FILENAME = "r1_incremental_checkpoint.json"
R1_INCREMENTAL_AVAILABILITY_FILENAME = "r1_incremental_availability_v0.2.json"
R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME = "r1_incremental_replay_input_validation.json"
R1_ROLE2_TRACE_FILENAME = "r1_role2_operational_trace.jsonl"
DEFAULT_R1_APPROVED_POLICY_ID = "r1-wmi-management-approved-lineage"
DEFAULT_R1_APPROVED_POLICY_VERSION = "v0.1"

type R1ConsumeStatus = Literal[
    "waiting_run_start", "waiting_ack", "up_to_date", "terminal", "failed_closed"
]
type R1AcceptedMessageLoader = Callable[[Path, Path], object]


class R1IncrementalConsumerError(ValueError):
    """An accepted-input check failed; the Role2 state was not advanced."""


class R1FinalizationBlockedError(ValueError):
    """Required event-time finality or publication conditions were not satisfied."""


class _Transaction(Protocol):
    def commit(self) -> None: ...

    def rollback(self) -> None: ...


class R1CommittedChunkIngress(R1StreamIngress):
    """Role2 boundary: an acked chunk must already be a committed exact ledger replay."""

    def accept_chunk(self, chunk: R1EventChunk) -> R1StreamDeliveryResult:
        result = super().accept_chunk(chunk)
        if result.disposition is not R1StreamDeliveryDisposition.DUPLICATE:
            raise R1IncrementalConsumerError(
                f"acked chunk {chunk.chunk_id!r} has no committed Role3 ledger entry"
            )
        return result


@dataclass(frozen=True, slots=True)
class R1FinalizationTrust:
    """Trusted bindings needed to finalize or restore a verified-proof state."""

    candidate_policy: R1CandidateGenerationPolicy
    close_export_path: Path
    source_seal_id: str
    source_seal_projection_sha256: str


@dataclass(frozen=True, slots=True)
class R1IncrementalConsumerConfig:
    run_id: str
    target_host: str
    scenario_family_id: str
    spool_root: Path
    control_root: Path
    state_root: Path
    contract: R1RequiredPartitionContract
    selector_policy: R1SelectorPolicy
    approved_policy: ApprovedLineagePolicy


@dataclass(frozen=True, slots=True)
class R1IncrementalConsumeResult:
    status: R1ConsumeStatus
    state_status: str | None = None
    applied_chunk_ids: tuple[str, ...] = ()
    already_consumed_chunks: int = 0
    finalization_blocked_reason: str | None = None


@dataclass(frozen=True, slots=True)
class R1PublishedEvidence:
    snapshot: R1IncrementalEvidenceSnapshot
    checkpoint_path: Path
    envelope_path: Path
    receipt: R1IncrementalAvailabilityPublicationReceipt


@dataclass(slots=True)
class _ConsumedChunks:
    by_id: dict[str, str] = field(default_factory=dict)
    next_sequence: int = 1


class R1IncrementalChunkConsumer:
    """Role2 consumer of one Run's Role3 spool.

    Every consume and finalize step holds the state-root lock, and in-memory state
    is reloaded whenever another process changed the checkpoint, so the consume
    sidecar and the finalize command can run as separate processes.
    """

    def __init__(
        self,
        config: R1IncrementalConsumerConfig,
        *,
        ingress: R1CommittedChunkIngress,
        transaction: _Transaction | None = None,
        message_loader: R1AcceptedMessageLoader = load_accepted_spool_message,
        finalization_trust: R1FinalizationTrust | None = None,
        clock: Callable[[], datetime] | None = None,
        trace_clock: Callable[[], datetime] | None = None,
        lock_timeout_sec: float = DEFAULT_R1_LOCK_TIMEOUT_SEC,
    ) -> None:
        if not isinstance(ingress, R1CommittedChunkIngress):
            raise TypeError("ingress must be an R1CommittedChunkIngress")
        self._config = config
        self._ingress = ingress
        self._transaction = transaction
        self._message_loader = message_loader
        self._finalization_trust = finalization_trust
        self._clock = clock or utc_now
        self._lock_timeout_sec = lock_timeout_sec
        self._trace = R1OperationalTrace(
            config.state_root / R1_ROLE2_TRACE_FILENAME,
            clock=trace_clock or utc_now,
        )
        self._state: R1IncrementalEvidenceState | None = None
        self._checkpoint_digest: str | None = None
        self._consumed = _ConsumedChunks()

    @property
    def checkpoint_path(self) -> Path:
        return self._config.state_root / R1_INCREMENTAL_CHECKPOINT_FILENAME

    @property
    def trace(self) -> R1OperationalTrace:
        return self._trace

    @property
    def snapshot(self) -> R1IncrementalEvidenceSnapshot | None:
        return None if self._state is None else self._state.snapshot

    def consume_available(self) -> R1IncrementalConsumeResult:
        """Apply newly acked chunks in sequence; stop at the first unacked chunk."""
        with r1_directory_lock(self._config.state_root, timeout_sec=self._lock_timeout_sec):
            return self._consume_available_locked()

    def finalize_and_publish(
        self,
        proof_path: Path,
        *,
        run_metadata: RunMetadata,
    ) -> R1PublishedEvidence:
        """Finalize with an event-time proof and publish the v0.2 artifact set."""
        with r1_directory_lock(self._config.state_root, timeout_sec=self._lock_timeout_sec):
            return self._finalize_and_publish_locked(proof_path, run_metadata=run_metadata)

    def _consume_available_locked(self) -> R1IncrementalConsumeResult:
        checkpoint = self._read_checkpoint()
        if checkpoint is not None and checkpoint.status in {"finalized", "failed_closed"}:
            # A terminal state accepts no chunk, so it is reported without a restore;
            # restoring a verified-proof checkpoint would need the finalize trust.
            return R1IncrementalConsumeResult(
                status="terminal" if checkpoint.status == "finalized" else "failed_closed",
                state_status=checkpoint.status,
            )
        state = self._load_state()
        if state is None:
            return R1IncrementalConsumeResult(status="waiting_run_start")
        status = state.snapshot.status
        if status in {"finalized", "failed_closed"}:
            return R1IncrementalConsumeResult(
                status="terminal" if status == "finalized" else "failed_closed",
                state_status=status,
            )

        applied: list[str] = []
        duplicates = 0
        waiting_ack = False
        outbox = self._config.spool_root / "outbox"
        received = {
            record.details.get("message_file")
            for record in self._trace.records()
            if record.stage == "chunk_received"
        }
        for path in sorted(outbox.glob("*-event_chunk.json")):
            ack_path = self._ack_path(path)
            if path.name not in received:
                self._trace.append(
                    "chunk_received",
                    run_id=self._config.run_id,
                    details={"message_file": path.name, "ack_present": ack_path.exists()},
                )
                received.add(path.name)
            if not ack_path.exists():
                waiting_ack = True
                break
            chunk = self._load_verified_chunk(path, ack_path)
            digest = self._consumed.by_id.get(chunk.chunk_id)
            if digest is not None:
                if digest != chunk.chunk_content_sha256:
                    self._reject(path, "chunk identity was reused with different content")
                duplicates += 1
                continue
            self._apply_chunk(state, chunk, path, ack_path)
            applied.append(chunk.chunk_id)

        if not waiting_ack:
            self._accept_available_run_closed(state)
        blocked = self._record_finalization_status(state)
        return R1IncrementalConsumeResult(
            status="waiting_ack" if waiting_ack else "up_to_date",
            state_status=state.snapshot.status,
            applied_chunk_ids=tuple(applied),
            already_consumed_chunks=duplicates,
            finalization_blocked_reason=blocked,
        )

    def _finalize_and_publish_locked(
        self,
        proof_path: Path,
        *,
        run_metadata: RunMetadata,
    ) -> R1PublishedEvidence:
        trust = self._finalization_trust
        if trust is None:
            raise self._blocked("verified_close_trust_not_supplied")
        state = self._load_state()
        if state is None:
            raise self._blocked("run_start_not_available")
        try:
            run_closed, receipt = load_close_export(trust.close_export_path)
            proof = load_r1_role2_verified_close_proof(proof_path)
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise self._blocked(f"event_time_close_or_proof_rejected: {error}") from error

        checkpoint = self._read_checkpoint()
        recorded_validation = None if checkpoint is None else checkpoint.proof_validated_at
        proof_validated_at = recorded_validation or ceil_utc_clock_observation(
            "proof_validated_at", self._clock()
        )
        try:
            state.accept_run_closed(run_closed)
            snapshot = state.accept_verified_close_proof(
                proof,
                accepted_run_closed=run_closed,
                accepted_close_receipt=receipt,
                candidate_policy=trust.candidate_policy,
                accepted_source_seal_id=trust.source_seal_id,
                accepted_source_seal_projection_sha256=trust.source_seal_projection_sha256,
                proof_validated_at=proof_validated_at,
            )
        except (TypeError, ValueError) as error:
            self._persist_failed_state(state, str(error))
            raise R1FinalizationBlockedError(f"verified close rejected: {error}") from error
        if snapshot.status != "finalized":
            self._persist_failed_state(state, "; ".join(snapshot.diagnostics))
            raise R1FinalizationBlockedError(
                f"verified close failed closed: {snapshot.diagnostics}"
            )

        checkpoint = state.export_checkpoint()
        self._write_checkpoint(checkpoint)
        self._trace.append(
            "evidence_finalized",
            run_id=self._config.run_id,
            details={
                "evidence_ids": [item.evidence_id for item in snapshot.evidences],
                "evidence_ready_at": _utc_text(snapshot.available_at),
                "proof_validated_at": _utc_text(checkpoint.proof_validated_at),
                "verified_close_proof_id": snapshot.verified_close_proof_id,
                "verified_close_proof_sha256": snapshot.verified_close_proof_sha256,
                "checkpoint_sha256": incremental_checkpoint_sha256(checkpoint),
            },
        )
        self._publish_evidence_artifacts(snapshot, checkpoint)
        envelope_path = self._config.state_root / R1_INCREMENTAL_AVAILABILITY_FILENAME
        try:
            envelope = build_r1_incremental_causal_availability_envelope(
                snapshot,
                checkpoint,
                run_metadata=run_metadata,
                selector_policy=self._config.selector_policy,
                approved_policy=self._config.approved_policy,
                candidate_policy=trust.candidate_policy,
            )
        except (TypeError, ValueError) as error:
            raise self._blocked(f"availability_envelope_rejected: {error}") from error
        receipt_out = write_r1_incremental_causal_availability_envelope(
            envelope_path,
            envelope,
            clock=self._clock,
        )
        self._trace.append(
            "evidence_published",
            run_id=self._config.run_id,
            details={
                "evidence_ids": [item.evidence_id for item in snapshot.evidences],
                "evidence_ready_at": _utc_text(receipt_out.evidence_ready_at),
                "publication_completed_at": _utc_text(receipt_out.publication_completed_at),
                "envelope_sha256": _file_sha256(envelope_path),
                "receipt_content_sha256": receipt_out.receipt_content_sha256,
            },
        )
        return R1PublishedEvidence(snapshot, self.checkpoint_path, envelope_path, receipt_out)

    def _load_state(self) -> R1IncrementalEvidenceState | None:
        digest = self._current_checkpoint_digest()
        if self._state is not None and digest == self._checkpoint_digest:
            return self._state
        # Another process changed the checkpoint since this one last saw it.
        self._state = None
        self._consumed = _ConsumedChunks()
        self._checkpoint_digest = digest
        checkpoint = self._read_checkpoint()
        if checkpoint is not None:
            self._state = self._restore(checkpoint)
            for chunk in checkpoint.accepted_chunks:
                self._consumed.by_id[chunk.chunk_id] = chunk.chunk_content_sha256
                self._consumed.next_sequence = max(
                    self._consumed.next_sequence, chunk.chunk_sequence + 1
                )
            return self._state
        run_start = self._read_run_start()
        if run_start is None:
            return None
        self._state = R1IncrementalEvidenceState(
            run_id=self._config.run_id,
            entity_id=self._config.target_host,
            run_start=run_start,
            scenario_family_id=self._config.scenario_family_id,
            selector_policy=self._config.selector_policy,
            approved_policy=self._config.approved_policy,
            ingress=self._ingress,
            required_partition_contract=self._config.contract,
            clock=self._clock,
        )
        return self._state

    def _read_checkpoint(self) -> R1IncrementalEvidenceCheckpoint | None:
        if not self.checkpoint_path.exists():
            return None
        return load_r1_incremental_checkpoint(self.checkpoint_path)

    def _current_checkpoint_digest(self) -> str | None:
        if not self.checkpoint_path.exists():
            return None
        return _file_sha256(self.checkpoint_path)

    def _write_checkpoint(self, checkpoint: R1IncrementalEvidenceCheckpoint) -> None:
        write_r1_incremental_checkpoint(self.checkpoint_path, checkpoint)
        self._checkpoint_digest = self._current_checkpoint_digest()

    def _restore(self, checkpoint: R1IncrementalEvidenceCheckpoint) -> R1IncrementalEvidenceState:
        trust = self._finalization_trust
        kwargs: dict[str, Any] = {}
        if checkpoint.verified_close_proof is not None:
            if trust is None:
                raise R1FinalizationBlockedError(
                    "verified proof checkpoint recovery requires its trusted bindings"
                )
            _, receipt = load_close_export(trust.close_export_path)
            kwargs = {
                "candidate_policy": trust.candidate_policy,
                "accepted_close_receipt": receipt,
                "accepted_source_seal_id": trust.source_seal_id,
                "accepted_source_seal_projection_sha256": trust.source_seal_projection_sha256,
            }
        try:
            restored = R1IncrementalEvidenceState.restore_from_checkpoint(
                checkpoint,
                selector_policy=self._config.selector_policy,
                approved_policy=self._config.approved_policy,
                ingress=self._ingress,
                **kwargs,
            )
        except BaseException:
            self._rollback()
            raise
        self._commit()
        return restored

    def _read_run_start(self) -> datetime | None:
        path = self._config.control_root / self._config.run_id / "run-started.json"
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        expected = {
            "message_type": "run_started",
            "run_id": self._config.run_id,
            "target_host": self._config.target_host,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise R1IncrementalConsumerError("run-started control does not match this consumer")
        return datetime.fromisoformat(str(payload["run_start"]))

    def _ack_path(self, message_path: Path) -> Path:
        return self._config.spool_root / "acks" / f"{message_path.name}.ack.json"

    def _load_verified_chunk(self, path: Path, ack_path: Path) -> R1EventChunk:
        try:
            message = self._message_loader(path, ack_path)
        except (OSError, TypeError, ValueError, ValidationError) as error:
            self._reject(path, f"accepted message verification failed: {error}")
        if not isinstance(message, R1EventChunk):
            self._reject(path, "outbox event_chunk file did not contain an EventChunk")
        partition = message.partition
        if (partition.run_id, partition.host_id) != (
            self._config.run_id,
            self._config.target_host,
        ):
            self._reject(path, "chunk Run or host does not match this consumer")
        required = {
            (item.source, item.source_channel) for item in self._config.contract.required_partitions
        }
        if (partition.source, partition.source_channel) not in required:
            self._reject(path, "chunk partition is outside the required-partition contract")
        return message

    def _apply_chunk(
        self,
        state: R1IncrementalEvidenceState,
        chunk: R1EventChunk,
        path: Path,
        ack_path: Path,
    ) -> None:
        if chunk.chunk_sequence != self._consumed.next_sequence:
            self._reject(
                path,
                f"chunk sequence {chunk.chunk_sequence} is not the next expected "
                f"sequence {self._consumed.next_sequence}",
            )
        ack = json.loads(ack_path.read_text(encoding="utf-8"))
        message_sha256 = _file_sha256(path)
        try:
            snapshot = state.accept_chunk(chunk)
        except (TypeError, ValueError) as error:
            self._rollback()
            self._reject(path, f"incremental state rejected chunk: {error}")
        except BaseException:
            self._rollback()
            raise
        self._trace.append(
            "chunk_accepted",
            run_id=self._config.run_id,
            details={
                "chunk_id": chunk.chunk_id,
                "chunk_sequence": chunk.chunk_sequence,
                "message_sha256": message_sha256,
                "chunk_content_sha256": chunk.chunk_content_sha256,
                "ack_disposition": ack.get("disposition"),
                "ack_accepted_at": ack.get("accepted_at"),
                "max_event_ingest_time": _utc_text(max(e.ingest_time for e in chunk.events)),
            },
        )
        checkpoint = state.export_checkpoint()
        self._write_checkpoint(checkpoint)
        self._commit()
        self._consumed.by_id[chunk.chunk_id] = chunk.chunk_content_sha256
        self._consumed.next_sequence = chunk.chunk_sequence + 1
        self._trace.append(
            "incremental_state_updated",
            run_id=self._config.run_id,
            details={
                "chunk_id": chunk.chunk_id,
                "state_status": snapshot.status,
                "checkpoint_generation": checkpoint.generation,
                "checkpoint_sha256": incremental_checkpoint_sha256(checkpoint),
                "selector_diagnostics": list(snapshot.selector_result.diagnostics),
            },
        )
        selection = snapshot.selector_result.selection
        if snapshot.status == "provisional" and selection is not None:
            self._trace.append(
                "provisional_candidate",
                run_id=self._config.run_id,
                details={
                    "chunk_id": chunk.chunk_id,
                    "is_finalized_evidence": False,
                    "anchor_event_id": selection.anchor_event_id,
                    "terminal_event_id": selection.terminal_event_id,
                    "context_event_ids": list(selection.context_event_ids),
                },
            )

    def _accept_available_run_closed(self, state: R1IncrementalEvidenceState) -> None:
        outbox = self._config.spool_root / "outbox"
        for path in sorted(outbox.glob("*-run_closed.json")):
            ack_path = self._ack_path(path)
            if not ack_path.exists():
                return
            try:
                message = self._message_loader(path, ack_path)
            except (OSError, TypeError, ValueError, ValidationError) as error:
                self._reject(path, f"accepted run_closed verification failed: {error}")
            if not isinstance(message, R1RunClosed):
                self._reject(path, "outbox run_closed file did not contain a run_closed")
            try:
                state.accept_run_closed(message)
            except (TypeError, ValueError) as error:
                self._reject(path, f"incremental state rejected run_closed: {error}")
            self._write_checkpoint(state.export_checkpoint())

    def _record_finalization_status(self, state: R1IncrementalEvidenceState) -> str | None:
        if state.snapshot.status in {"finalized", "failed_closed"}:
            return None
        has_close = state.export_checkpoint().accepted_run_closed is not None
        reason = "verified_close_proof_not_supplied" if has_close else "accepted_run_closed_missing"
        blocked = [r for r in self._trace.records() if r.stage == "finalization_blocked"]
        if not blocked or blocked[-1].details.get("reason") != reason:
            self._trace.append(
                "finalization_blocked",
                run_id=self._config.run_id,
                details={"reason": reason, "evidence_issued": False},
            )
        return reason

    def _publish_evidence_artifacts(
        self,
        snapshot: R1IncrementalEvidenceSnapshot,
        checkpoint: R1IncrementalEvidenceCheckpoint,
    ) -> None:
        state_root = self._config.state_root
        if not (state_root / R1_EVIDENCE_FILENAME).exists():
            lineage = snapshot.lineage_input
            selector = self._config.selector_policy
            run_and_write_r1_evidence_artifacts(
                unique_checkpoint_events(checkpoint),
                run_id=self._config.run_id,
                output_directory=state_root,
                lineage_inputs=() if lineage is None else (lineage,),
                selector_provenance=R1SelectorProvenance(
                    policy_id=selector.policy_id,
                    version=selector.version,
                    config_hash=selector.config_hash,
                    status="selected",
                    diagnostics=(),
                ),
            )
        published = load_r1_evidence_artifacts(state_root)
        if _evidence_digests(published.evidences) != _evidence_digests(snapshot.evidences):
            raise R1FinalizationBlockedError(
                "published Evidence differs from the finalized incremental state"
            )

    def _persist_failed_state(self, state: R1IncrementalEvidenceState, reason: str) -> None:
        self._trace.append(
            "finalization_failed_closed",
            run_id=self._config.run_id,
            details={"reason": reason, "evidence_issued": False},
        )
        if state.snapshot.status == "failed_closed":
            self._write_checkpoint(state.export_checkpoint())

    def _blocked(self, reason: str) -> R1FinalizationBlockedError:
        self._trace.append(
            "finalization_blocked",
            run_id=self._config.run_id,
            details={"reason": reason, "evidence_issued": False},
        )
        return R1FinalizationBlockedError(reason)

    def _reject(self, path: Path, reason: str) -> None:
        self._trace.append(
            "chunk_rejected",
            run_id=self._config.run_id,
            details={"message_file": path.name, "reason": reason},
        )
        raise R1IncrementalConsumerError(f"{path.name}: {reason}")

    def _commit(self) -> None:
        if self._transaction is not None:
            self._transaction.commit()

    def _rollback(self) -> None:
        if self._transaction is not None:
            self._transaction.rollback()


def unique_checkpoint_events(
    checkpoint: R1IncrementalEvidenceCheckpoint,
) -> tuple[NormalizedEvent, ...]:
    """Collapse only identical retransmitted Events recorded in the checkpoint."""
    by_id: dict[str, NormalizedEvent] = {}
    for chunk in checkpoint.accepted_chunks:
        for event in chunk.events:
            if by_id.setdefault(event.event_id, event) != event:
                raise ValueError("conflicting Event identity in checkpoint")
    return tuple(by_id.values())


def r1_selector_policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id=R1_SELECTOR_POLICY_ID,
        version=R1_SELECTOR_POLICY_VERSION,
        config_hash=R1_SELECTOR_POLICY_CONFIG_HASH,
        lineage_event_count=R1_SELECTOR_LINEAGE_EVENT_COUNT,
    )


def _evidence_digests(evidences) -> dict[str, str]:
    return {item.evidence_id: incremental_evidence_sha256(item) for item in evidences}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


class _DeadLetterSink:
    """A committed replay never admits new Events, so no dead letter is legitimate."""

    def write(self, dead_letter: object) -> None:
        raise R1IncrementalConsumerError(f"Role2 replay produced a dead letter: {dead_letter!r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--run-id", required=True)
    common.add_argument("--target-host", required=True)
    common.add_argument("--spool-root", required=True, help="Run spool holding outbox and acks")
    common.add_argument("--control-root", required=True)
    common.add_argument("--state-root", required=True)
    common.add_argument("--required-partition-contract", required=True)
    common.add_argument("--approved-policy-id", default=DEFAULT_R1_APPROVED_POLICY_ID)
    common.add_argument("--approved-policy-version", default=DEFAULT_R1_APPROVED_POLICY_VERSION)
    consume = commands.add_parser("consume", parents=[common])
    consume.add_argument("--follow-interval-sec", type=float, default=None)
    finalize = commands.add_parser("finalize", parents=[common])
    finalize.add_argument("--close-export", required=True)
    finalize.add_argument("--verified-close-proof", required=True)
    finalize.add_argument("--run-metadata", required=True)
    finalize.add_argument("--candidate-policy-id", required=True)
    finalize.add_argument("--candidate-policy-version", required=True)
    finalize.add_argument("--source-seal-id", required=True)
    finalize.add_argument("--source-seal-projection-sha256", required=True)
    return parser


def build_consumer_from_args(
    args: argparse.Namespace,
    connection: Any,
) -> R1IncrementalChunkConsumer:
    approved = load_r1_approved_lineage_policy(
        args.approved_policy_id,
        args.approved_policy_version,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )
    if approved.family_id is None:
        raise ValueError("Role2 consumer requires a family-bound approved policy")
    trust = None
    if args.command == "finalize":
        trust = R1FinalizationTrust(
            candidate_policy=load_r1_candidate_generation_policy(
                args.candidate_policy_id, args.candidate_policy_version
            ),
            close_export_path=Path(args.close_export),
            source_seal_id=args.source_seal_id,
            source_seal_projection_sha256=args.source_seal_projection_sha256,
        )
    return R1IncrementalChunkConsumer(
        R1IncrementalConsumerConfig(
            run_id=args.run_id,
            target_host=args.target_host,
            scenario_family_id=approved.family_id,
            spool_root=Path(args.spool_root),
            control_root=Path(args.control_root),
            state_root=Path(args.state_root),
            contract=load_r1_required_partition_contract(
                args.required_partition_contract, expected_target_host=args.target_host
            ),
            selector_policy=r1_selector_policy(),
            approved_policy=approved,
        ),
        ingress=R1CommittedChunkIngress(
            R1StreamDeliveryRepository(connection),
            dead_letter_sink=_DeadLetterSink(),
            clock=utc_now,
        ),
        transaction=connection,
        finalization_trust=trust,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = DatabaseConfig.from_environment()
    with psycopg.connect(config.url, autocommit=False) as connection:
        consumer = build_consumer_from_args(args, connection)
        if args.command == "finalize":
            published = consumer.finalize_and_publish(
                Path(args.verified_close_proof),
                run_metadata=RunMetadata.model_validate_json(
                    Path(args.run_metadata).read_text(encoding="utf-8-sig")
                ),
            )
            print(published.envelope_path)
            return 0
        while True:
            result = consumer.consume_available()
            print(result)
            if args.follow_interval_sec is None or result.status in {"terminal", "failed_closed"}:
                return 0
            time.sleep(args.follow_interval_sec)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "R1CommittedChunkIngress",
    "R1FinalizationBlockedError",
    "R1FinalizationTrust",
    "R1IncrementalChunkConsumer",
    "R1IncrementalConsumeResult",
    "R1IncrementalConsumerConfig",
    "R1IncrementalConsumerError",
    "R1PublishedEvidence",
    "r1_selector_policy",
    "unique_checkpoint_events",
]
