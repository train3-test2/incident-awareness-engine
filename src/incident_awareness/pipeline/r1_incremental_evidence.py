"""R1 Event chunk를 누적하고 검증된 close에서만 Evidence를 확정한다."""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
    R1VerifiedCandidateBoundary,
)
from incident_awareness.collection.r1_role2_verified_close_proof import (
    R1Role2VerifiedCloseProof,
    R1Role2VerifiedCloseProofValidation,
    role2_verified_close_proof_sha256,
    validate_r1_role2_verified_close_proof,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
)
from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
    R1FinalPartitionWatermark,
    R1RunClosed,
    R1StreamPartition,
)
from incident_awareness.evidence.r1_approved_lineage_policy import (
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import (
    ApprovedLineagePolicy,
    R1ExtractionDiagnostic,
)
from incident_awareness.evidence.r1_selector import (
    R1SelectorPolicy,
    R1SelectorResult,
    select_r1_lineage,
)
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalEvidenceAvailability,
    R1CausalPolicyIdentity,
)
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline_with_selector,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    R1IncrementalApprovedPolicyIdentity,
    R1IncrementalEvidenceCheckpoint,
    R1IncrementalEvidenceDigest,
    R1IncrementalSelectorIdentity,
    build_r1_incremental_checkpoint,
    incremental_evidence_sha256,
    validate_r1_incremental_finalized_evidence,
)
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamDeliveryDisposition,
    R1StreamIngress,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
)

_R1_SOURCE = "sysmon"
_R1_SOURCE_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

type R1IncrementalStatus = Literal["accumulating", "provisional", "finalized", "failed_closed"]
type R1IncrementalCloseMode = Literal[
    "authoritative_run_end_fallback",
    "verified_close_proof",
]
type _PartitionKey = tuple[str, str, str, str]
type _ChunkIdentity = tuple[str, str, str, str, str, str, str]
type _ChunkSequenceIdentity = tuple[str, str, str, str, str, str, int]
type _EventIdentity = tuple[str, str, str, str, str, str, str]


@dataclass(frozen=True, slots=True)
class R1IncrementalEvidenceSnapshot:
    """현재 상태와, 확정된 경우에만 노출하는 Evidence/availability."""

    status: R1IncrementalStatus
    selector_result: R1SelectorResult
    evidences: tuple[Evidence, ...] = ()
    availability: tuple[R1CausalEvidenceAvailability, ...] = ()
    lineage_input: R1LineageInput | None = None
    extraction_diagnostics: tuple[R1ExtractionDiagnostic, ...] = ()
    close_mode: R1IncrementalCloseMode | None = None
    candidate_boundary_at: datetime | None = None
    available_at: datetime | None = None
    availability_contract_version: Literal["v0.1", "v0.2"] | None = None
    verified_close_proof_id: str | None = None
    verified_close_proof_sha256: str | None = None
    diagnostics: tuple[str, ...] = ()


class R1IncrementalEvidenceState:
    """Append-only R1 selector state.

    chunk는 주입된 Role3 ingress가 수락한 뒤 승인한 새 Event만 누적한다.
    ``run_closed``는 Role3가 이미 수락한 control 입력이다. 현재 #269 v0.1 최소
    boundary 객체는 독립 검증 가능한 결속 정보가 없어 항상 거부한다.
    """

    def __init__(
        self,
        *,
        run_id: str,
        entity_id: str,
        run_start: datetime,
        scenario_family_id: str,
        selector_policy: R1SelectorPolicy,
        approved_policy: ApprovedLineagePolicy,
        ingress: R1StreamIngress,
        required_partition_contract: R1RequiredPartitionContract | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._run_id = _unpad("run_id", run_id)
        self._entity_id = _unpad("entity_id", entity_id)
        self._run_start = _utc("run_start", run_start)
        if not isinstance(selector_policy, R1SelectorPolicy):
            raise TypeError("selector_policy must be an R1SelectorPolicy")
        if not isinstance(approved_policy, ApprovedLineagePolicy):
            raise TypeError("approved_policy must be an ApprovedLineagePolicy")
        validate_r1_policy_family_binding(scenario_family_id, approved_policy)
        if selector_policy.lineage_event_count != len(approved_policy.approved_lineage):
            raise ValueError("selector lineage_event_count must match approved_lineage length")
        self._scenario_family_id = scenario_family_id
        self._selector_policy = selector_policy
        self._approved_policy = approved_policy
        if not isinstance(ingress, R1StreamIngress):
            raise TypeError("ingress must be an R1StreamIngress")
        self._ingress = ingress
        self._clock = clock or (lambda: datetime.now(UTC))

        if required_partition_contract is not None:
            if not isinstance(required_partition_contract, R1RequiredPartitionContract):
                raise TypeError(
                    "required_partition_contract must be an R1RequiredPartitionContract"
                )
            if required_partition_contract.target_host != self._entity_id:
                raise ValueError(
                    "required-partition contract target_host must match incremental entity_id"
                )
            self._required_partition_identities = frozenset(
                (partition.source, partition.source_channel)
                for partition in required_partition_contract.required_partitions
            )
        else:
            # Preserve the #277 v0.1 fallback.  Verified proof finalization is
            # unavailable until the caller supplies the versioned contract.
            self._required_partition_identities = frozenset({(_R1_SOURCE, _R1_SOURCE_CHANNEL)})
        self._required_partition_contract = required_partition_contract

        self._events_by_identity: dict[_EventIdentity, NormalizedEvent] = {}
        self._event_hashes: dict[_EventIdentity, str] = {}
        self._chunk_hashes: dict[_ChunkIdentity, str] = {}
        self._chunk_sequence_identities: dict[_ChunkSequenceIdentity, str] = {}
        self._chunks_by_identity: dict[_ChunkIdentity, R1EventChunk] = {}
        self._run_closed: R1RunClosed | None = None
        self._verified_proof: R1Role2VerifiedCloseProof | None = None
        self._proof_validation: R1Role2VerifiedCloseProofValidation | None = None
        self._accepted_close_receipt: R1AcceptedRunCloseReceipt | None = None
        self._candidate_policy: R1CandidateGenerationPolicy | None = None
        self._snapshot = self._provisional_snapshot()

    @property
    def snapshot(self) -> R1IncrementalEvidenceSnapshot:
        return self._snapshot

    def accept_chunk(self, chunk: R1EventChunk) -> R1IncrementalEvidenceSnapshot:
        """동일 호출의 Role3 ingress 수락 결과에 결속해 새 Event만 누적한다."""
        if not isinstance(chunk, R1EventChunk):
            raise TypeError("chunk must be an R1EventChunk")
        if chunk.partition.run_id != self._run_id:
            raise ValueError("chunk run_id does not match incremental state")
        if self._required_partition_contract is not None and not self._is_selector_partition(
            chunk.partition
        ):
            raise ValueError("chunk partition is outside the required-partition contract")

        chunk_hash = _chunk_sha256(chunk)
        if chunk_hash != chunk.chunk_content_sha256:
            raise ValueError("chunk_content_sha256 does not match the canonical chunk payload")
        partition_key = _partition_key(chunk.partition)
        chunk_identity = (
            chunk.schema_id,
            chunk.contract_version,
            *partition_key,
            chunk.chunk_id,
        )
        existing_chunk_hash = self._chunk_hashes.get(chunk_identity)
        if existing_chunk_hash is not None:
            if existing_chunk_hash != chunk_hash:
                raise ValueError("chunk identity was reused with different content")
            self._ingress.accept_chunk(chunk)
            return self._snapshot
        if self._snapshot.status in {"finalized", "failed_closed"}:
            raise ValueError("incremental state is already terminal")
        if self._run_closed is not None:
            self._validate_chunk_after_run_closed(chunk)

        sequence_key = (
            chunk.schema_id,
            chunk.contract_version,
            *partition_key,
            chunk.chunk_sequence,
        )
        existing_chunk_id = self._chunk_sequence_identities.get(sequence_key)
        if existing_chunk_id is not None and existing_chunk_id != chunk.chunk_id:
            raise ValueError("chunk sequence was reused by another identity")

        event_updates: list[tuple[NormalizedEvent, str, _EventIdentity]] = []
        for event in chunk.events:
            event_hash = _event_sha256(event)
            event_identity = (
                chunk.schema_id,
                chunk.contract_version,
                *partition_key,
                event.event_id,
            )
            existing_event_hash = self._event_hashes.get(event_identity)
            if existing_event_hash is not None:
                if existing_event_hash != event_hash:
                    raise ValueError("Event identity was reused with different content")
                continue
            event_updates.append((event, event_hash, event_identity))

        admission = self._ingress.accept_chunk(chunk)
        # If Role3 committed before Role2 persisted its checkpoint, the exact
        # immutable chunk is redelivered as DUPLICATE.  Re-applying that payload
        # repairs the crash gap without asking Role3 for a new replay contract.
        is_recovery_replay = admission.disposition is R1StreamDeliveryDisposition.DUPLICATE
        new_event_ids = (
            {event.event_id for event in chunk.events}
            if is_recovery_replay
            else set(admission.new_event_ids)
        )
        chunk_event_ids = {event.event_id for event in chunk.events}
        if not new_event_ids <= chunk_event_ids:
            raise ValueError("ingress approved Event IDs outside this chunk")
        if any(event.event_id not in new_event_ids for event, _, _ in event_updates):
            raise ValueError(
                "replayed Event is absent from local state; recover state before replay"
            )

        self._chunk_hashes[chunk_identity] = chunk_hash
        self._chunk_sequence_identities[sequence_key] = chunk.chunk_id
        self._chunks_by_identity[chunk_identity] = chunk
        for event, event_hash, event_identity in event_updates:
            self._event_hashes[event_identity] = event_hash
            if self._is_selector_partition(chunk.partition):
                self._events_by_identity[event_identity] = event
        self._snapshot = self._provisional_snapshot(diagnostics=self._chunk_coverage_diagnostics())
        return self._snapshot

    def accept_run_closed(self, run_closed: R1RunClosed) -> R1IncrementalEvidenceSnapshot:
        """Role3가 수락한 final watermark 집합을 기록한다."""
        if not isinstance(run_closed, R1RunClosed):
            raise TypeError("run_closed must be an R1RunClosed")
        if run_closed.run_id != self._run_id:
            raise ValueError("run_closed run_id does not match incremental state")
        if self._run_closed is not None:
            if self._run_closed != run_closed:
                raise ValueError("incremental state already has a different run_closed")
            return self._snapshot
        if self._required_partition_contract is None:
            self._require_entity_partition(run_closed)
        else:
            self._require_exact_target_partitions(run_closed.final_watermarks)
        self._run_closed = run_closed
        self._snapshot = self._provisional_snapshot(diagnostics=self._chunk_coverage_diagnostics())
        return self._snapshot

    def accept_verified_boundary(
        self,
        boundary: R1VerifiedCandidateBoundary,
    ) -> R1IncrementalEvidenceSnapshot:
        """v0.1에서는 독립 검증 가능한 proof가 없어 verified close를 거부한다."""
        if not isinstance(boundary, R1VerifiedCandidateBoundary):
            raise TypeError("boundary must be an R1VerifiedCandidateBoundary")
        if boundary.run_id != self._run_id:
            raise ValueError("verified boundary run_id does not match incremental state")
        raise ValueError("Role2-safe verified close proof is not available in v0.1")

    def accept_verified_close_proof(
        self,
        proof: R1Role2VerifiedCloseProof,
        *,
        accepted_run_closed: R1RunClosed,
        accepted_close_receipt: R1AcceptedRunCloseReceipt,
        candidate_policy: R1CandidateGenerationPolicy,
        accepted_source_seal_id: str,
        accepted_source_seal_projection_sha256: str,
        proof_validated_at: datetime,
    ) -> R1IncrementalEvidenceSnapshot:
        """Finalize after strict Role3/Role4 proof and partition validation."""

        if self._required_partition_contract is None:
            raise ValueError(
                "verified close proof requires an explicit required-partition contract"
            )
        if self._snapshot.status in {"finalized", "failed_closed"}:
            if self._verified_proof == proof:
                if (
                    self._run_closed != accepted_run_closed
                    or self._accepted_close_receipt != accepted_close_receipt
                    or self._candidate_policy != candidate_policy
                    or proof.source_seal_id != accepted_source_seal_id
                    or proof.source_seal_projection_sha256 != accepted_source_seal_projection_sha256
                    or self._proof_validation is None
                    or self._proof_validation.proof_validated_at
                    != _utc("proof_validated_at", proof_validated_at)
                ):
                    raise ValueError("verified proof replay trusted binding does not match")
                return self._snapshot
            raise ValueError("incremental state is already terminal")
        if self._run_closed is None:
            raise ValueError("accepted run_closed is required before verified proof finalization")
        if self._run_closed != accepted_run_closed:
            self._fail_closed("verified proof run_closed does not match incremental state")
            raise ValueError("verified proof run_closed does not match incremental state")

        coverage_diagnostics = self._chunk_coverage_diagnostics()
        if coverage_diagnostics:
            self._fail_closed(*coverage_diagnostics)
            return self._snapshot

        try:
            required_partitions = self._required_stream_partitions()
            self._require_exact_target_partitions(proof.sealed_partitions)
            validations = tuple(
                validate_r1_role2_verified_close_proof(
                    proof,
                    accepted_run_closed=accepted_run_closed,
                    accepted_close_receipt=accepted_close_receipt,
                    candidate_policy=candidate_policy,
                    expected_run_id=self._run_id,
                    expected_family_id=self._scenario_family_id,
                    expected_selector_partition=partition,
                    accepted_source_seal_id=accepted_source_seal_id,
                    accepted_source_seal_projection_sha256=(accepted_source_seal_projection_sha256),
                    proof_validated_at=proof_validated_at,
                )
                for partition in required_partitions
            )
            if not validations:
                raise ValueError("required-partition contract must not be empty")
            validated_at = validations[0].proof_validated_at
            if any(item.proof_validated_at != validated_at for item in validations):
                raise ValueError("proof validation time changed across required partitions")
            self._require_watermark_coverage(proof.candidate_boundary_at)
            latest_input_time = self._latest_verified_input_ingest_time()
            frontier_inputs = (
                accepted_run_closed.emitted_at,
                proof.candidate_boundary_at,
                proof.verified_seal_at,
                proof.proof_created_at,
                validated_at,
                latest_input_time,
            )
            available_at = max(frontier_inputs)
            if available_at != validated_at:
                raise ValueError(
                    "proof_validated_at must not precede any accepted finalization input"
                )
        except (TypeError, ValueError) as error:
            self._fail_closed(f"verified close proof validation failed: {error}")
            raise

        self._verified_proof = proof
        self._proof_validation = validations[0]
        self._accepted_close_receipt = accepted_close_receipt
        self._candidate_policy = candidate_policy
        return self._finalize(
            boundary_at=proof.candidate_boundary_at,
            available_at=available_at,
            close_mode="verified_close_proof",
            diagnostics=("Role2-safe verified close proof finalized incremental Evidence",),
            event_cutoff=None,
            availability_contract_version="v0.2",
            observe_evidence_ready_at=True,
        )

    def export_checkpoint(self) -> R1IncrementalEvidenceCheckpoint:
        """Return a canonical lossless checkpoint for durable Role2 recovery."""

        if self._required_partition_contract is None:
            raise ValueError("durable checkpoint requires a required-partition contract")
        if self._approved_policy.family_id is None or self._approved_policy.lifecycle is None:
            raise ValueError("durable checkpoint requires a family-bound approved policy")
        candidate_identity = None
        if self._candidate_policy is not None:
            candidate_identity = R1CausalPolicyIdentity(
                policy_id=self._candidate_policy.policy_id,
                version=self._candidate_policy.version,
                config_hash=self._candidate_policy.config_hash,
            )
        evidence_digests = tuple(
            R1IncrementalEvidenceDigest(
                evidence_id=evidence.evidence_id,
                content_sha256=incremental_evidence_sha256(evidence),
            )
            for evidence in sorted(self._snapshot.evidences, key=lambda item: item.evidence_id)
        )
        generation = len(self._chunks_by_identity)
        generation += int(self._run_closed is not None)
        generation += int(self._snapshot.status in {"finalized", "failed_closed"})
        return build_r1_incremental_checkpoint(
            {
                "generation": generation,
                "run_id": self._run_id,
                "entity_id": self._entity_id,
                "run_start": self._run_start,
                "scenario_family_id": self._scenario_family_id,
                "required_partition_contract": self._required_partition_contract,
                "selector_policy_identity": R1IncrementalSelectorIdentity(
                    policy_id=self._selector_policy.policy_id,
                    version=self._selector_policy.version,
                    config_hash=self._selector_policy.config_hash,
                    lineage_event_count=self._selector_policy.lineage_event_count,
                ),
                "approved_policy_identity": R1IncrementalApprovedPolicyIdentity(
                    policy_id=self._approved_policy.policy_id,
                    version=self._approved_policy.version,
                    config_hash=self._approved_policy.config_hash,
                    family_id=self._approved_policy.family_id,
                    lifecycle=self._approved_policy.lifecycle,
                ),
                "candidate_policy_identity": candidate_identity,
                "accepted_chunks": tuple(
                    chunk
                    for _, chunk in sorted(
                        self._chunks_by_identity.items(),
                        key=lambda item: (
                            item[1].partition.host_id,
                            item[1].partition.source,
                            item[1].partition.source_channel,
                            item[1].chunk_sequence,
                            item[1].chunk_id,
                        ),
                    )
                ),
                "accepted_run_closed": self._run_closed,
                "accepted_close_receipt": self._accepted_close_receipt,
                "verified_close_proof": self._verified_proof,
                "proof_validated_at": (
                    self._proof_validation.proof_validated_at
                    if self._proof_validation is not None
                    else None
                ),
                "status": self._snapshot.status,
                "close_mode": self._snapshot.close_mode,
                "candidate_boundary_at": self._snapshot.candidate_boundary_at,
                "available_at": self._snapshot.available_at,
                "evidence_digests": evidence_digests,
                "diagnostics": self._snapshot.diagnostics,
            }
        )

    @classmethod
    def restore_from_checkpoint(
        cls,
        checkpoint: R1IncrementalEvidenceCheckpoint,
        *,
        selector_policy: R1SelectorPolicy,
        approved_policy: ApprovedLineagePolicy,
        ingress: R1StreamIngress,
        candidate_policy: R1CandidateGenerationPolicy | None = None,
        accepted_close_receipt: R1AcceptedRunCloseReceipt | None = None,
        accepted_source_seal_id: str | None = None,
        accepted_source_seal_projection_sha256: str | None = None,
    ) -> "R1IncrementalEvidenceState":
        """Rebuild state and revalidate terminal inputs against trusted bindings."""

        if not isinstance(checkpoint, R1IncrementalEvidenceCheckpoint):
            raise TypeError("checkpoint must be an R1IncrementalEvidenceCheckpoint")
        _validate_checkpoint_policy_inputs(checkpoint, selector_policy, approved_policy)
        recovery_available_at = checkpoint.available_at
        state = cls(
            run_id=checkpoint.run_id,
            entity_id=checkpoint.entity_id,
            run_start=checkpoint.run_start,
            scenario_family_id=checkpoint.scenario_family_id,
            selector_policy=selector_policy,
            approved_policy=approved_policy,
            ingress=ingress,
            required_partition_contract=checkpoint.required_partition_contract,
            clock=(
                (lambda: recovery_available_at)
                if checkpoint.close_mode == "verified_close_proof"
                and recovery_available_at is not None
                else None
            ),
        )
        for chunk in checkpoint.accepted_chunks:
            state.accept_chunk(chunk)
        if checkpoint.accepted_run_closed is not None:
            state.accept_run_closed(checkpoint.accepted_run_closed)

        if checkpoint.close_mode == "authoritative_run_end_fallback":
            if checkpoint.candidate_boundary_at is None:
                raise ValueError("fallback checkpoint is missing authoritative run_end")
            state.finalize_at_run_end(checkpoint.candidate_boundary_at)
        elif checkpoint.close_mode == "verified_close_proof":
            if checkpoint.verified_close_proof is None:
                if checkpoint.status != "failed_closed":
                    raise ValueError("verified proof checkpoint is missing its proof")
                state._fail_closed(*checkpoint.diagnostics)
                _validate_restored_snapshot(checkpoint, state.snapshot)
                return state
            if (
                checkpoint.proof_validated_at is None
                or checkpoint.accepted_run_closed is None
                or candidate_policy is None
                or accepted_close_receipt is None
                or accepted_source_seal_id is None
                or accepted_source_seal_projection_sha256 is None
            ):
                raise ValueError("verified proof recovery requires every trusted binding")
            expected_candidate_identity = checkpoint.candidate_policy_identity
            actual_candidate_identity = R1CausalPolicyIdentity(
                policy_id=candidate_policy.policy_id,
                version=candidate_policy.version,
                config_hash=candidate_policy.config_hash,
            )
            if expected_candidate_identity != actual_candidate_identity:
                raise ValueError(
                    "checkpoint candidate policy identity does not match supplied policy"
                )
            if checkpoint.accepted_close_receipt != accepted_close_receipt:
                raise ValueError("checkpoint close receipt does not match trusted receipt")
            state.accept_verified_close_proof(
                checkpoint.verified_close_proof,
                accepted_run_closed=checkpoint.accepted_run_closed,
                accepted_close_receipt=accepted_close_receipt,
                candidate_policy=candidate_policy,
                accepted_source_seal_id=accepted_source_seal_id,
                accepted_source_seal_projection_sha256=(accepted_source_seal_projection_sha256),
                proof_validated_at=checkpoint.proof_validated_at,
            )
        _validate_restored_snapshot(checkpoint, state.snapshot)
        return state

    def finalize_at_run_end(self, authoritative_run_end: datetime) -> R1IncrementalEvidenceSnapshot:
        """검증 seal이 없을 때만 명시적 authoritative run_end로 fallback한다."""
        run_end = _utc("authoritative_run_end", authoritative_run_end)
        if run_end < self._run_start:
            raise ValueError("authoritative_run_end must not precede run_start")
        if self._snapshot.status in {"finalized", "failed_closed"}:
            if (
                self._snapshot.close_mode == "authoritative_run_end_fallback"
                and self._snapshot.candidate_boundary_at != run_end
            ):
                raise ValueError(
                    "incremental state already finalized at a different authoritative_run_end"
                )
            return self._snapshot
        if self._run_closed is None:
            raise ValueError("accepted run_closed is required before stream fallback finalization")
        coverage_diagnostics = self._chunk_coverage_diagnostics()
        if coverage_diagnostics:
            self._snapshot = R1IncrementalEvidenceSnapshot(
                status="failed_closed",
                selector_result=self._snapshot.selector_result,
                close_mode="authoritative_run_end_fallback",
                candidate_boundary_at=run_end,
                available_at=run_end,
                availability_contract_version="v0.1",
                diagnostics=coverage_diagnostics,
            )
            return self._snapshot
        self._require_watermark_coverage(run_end)
        return self._finalize(
            boundary_at=run_end,
            available_at=run_end,
            close_mode="authoritative_run_end_fallback",
            diagnostics=("Role2-safe verified close proof is unavailable; used run_end fallback",),
            event_cutoff=run_end,
            availability_contract_version="v0.1",
        )

    def _finalize(
        self,
        *,
        boundary_at: datetime,
        available_at: datetime,
        close_mode: R1IncrementalCloseMode,
        diagnostics: tuple[str, ...],
        event_cutoff: datetime | None,
        availability_contract_version: Literal["v0.1", "v0.2"],
        observe_evidence_ready_at: bool = False,
    ) -> R1IncrementalEvidenceSnapshot:
        eligible_events = (
            self._ordered_events() if event_cutoff is None else self._eligible_events(event_cutoff)
        )
        result = run_r1_evidence_pipeline_with_selector(
            eligible_events,
            selector_policy=self._selector_policy,
            approved_policy=self._approved_policy,
            run_start=self._run_start,
        )
        if result.selector_result.selection is None or result.extraction_diagnostics:
            failure_diagnostics = (
                diagnostics
                + tuple(result.selector_result.diagnostics)
                + tuple(result.extraction_diagnostics)
            )
            self._snapshot = R1IncrementalEvidenceSnapshot(
                status="failed_closed",
                selector_result=result.selector_result,
                lineage_input=result.lineage_input,
                extraction_diagnostics=result.extraction_diagnostics,
                close_mode=close_mode,
                candidate_boundary_at=boundary_at,
                available_at=available_at,
                availability_contract_version=availability_contract_version,
                diagnostics=failure_diagnostics,
            )
            return self._snapshot

        if observe_evidence_ready_at:
            # Complete canonical Evidence validation before observing the first
            # time at which the immutable output is ready for downstream publish.
            for evidence in result.evidences:
                incremental_evidence_sha256(evidence)
            try:
                evidence_ready_at = _utc("evidence_ready_at", self._clock())
            except (TypeError, ValueError) as error:
                self._fail_closed(f"Evidence publication readiness clock is invalid: {error}")
                raise
            if evidence_ready_at < available_at:
                self._fail_closed("evidence_ready_at precedes the verified proof frontier")
                raise ValueError("evidence_ready_at must not precede the verified proof frontier")
            available_at = evidence_ready_at

        context_event_ids = (
            result.lineage_input.context_event_ids if result.lineage_input is not None else ()
        )
        if any(evidence.timestamp > available_at for evidence in result.evidences):
            self._snapshot = R1IncrementalEvidenceSnapshot(
                status="failed_closed",
                selector_result=result.selector_result,
                lineage_input=result.lineage_input,
                close_mode=close_mode,
                candidate_boundary_at=boundary_at,
                available_at=available_at,
                availability_contract_version=availability_contract_version,
                diagnostics=diagnostics
                + ("Evidence timestamp must not exceed causal available_at",),
            )
            return self._snapshot
        availability = tuple(
            R1CausalEvidenceAvailability(
                evidence_id=evidence.evidence_id,
                timestamp=evidence.timestamp,
                available_at=available_at,
                event_ids=tuple(evidence.event_ids),
                context_event_ids=context_event_ids,
            )
            for evidence in result.evidences
        )
        self._snapshot = R1IncrementalEvidenceSnapshot(
            status="finalized",
            selector_result=result.selector_result,
            evidences=result.evidences,
            availability=availability,
            lineage_input=result.lineage_input,
            extraction_diagnostics=(),
            close_mode=close_mode,
            candidate_boundary_at=boundary_at,
            available_at=available_at,
            availability_contract_version=availability_contract_version,
            verified_close_proof_id=(
                self._verified_proof.proof_id if self._verified_proof is not None else None
            ),
            verified_close_proof_sha256=(
                role2_verified_close_proof_sha256(self._verified_proof)
                if self._verified_proof is not None
                else None
            ),
            diagnostics=diagnostics,
        )
        return self._snapshot

    def _provisional_snapshot(
        self,
        *,
        diagnostics: tuple[str, ...] = (),
    ) -> R1IncrementalEvidenceSnapshot:
        selector_result = select_r1_lineage(
            self._ordered_events(),
            policy=self._selector_policy,
            run_start=self._run_start,
        )
        status: R1IncrementalStatus = (
            "provisional" if selector_result.selection is not None else "accumulating"
        )
        return R1IncrementalEvidenceSnapshot(
            status=status,
            selector_result=selector_result,
            diagnostics=diagnostics,
        )

    def _ordered_events(self) -> tuple[NormalizedEvent, ...]:
        return tuple(
            event
            for _, event in sorted(
                self._events_by_identity.items(),
                key=lambda item: (item[1].timestamp, item[1].event_id, item[0]),
            )
        )

    def _eligible_events(self, boundary_at: datetime) -> tuple[NormalizedEvent, ...]:
        return tuple(event for event in self._ordered_events() if event.timestamp <= boundary_at)

    def _require_entity_partition(self, run_closed: R1RunClosed) -> None:
        if not any(
            self._is_selector_partition(item.partition) for item in run_closed.final_watermarks
        ):
            raise ValueError(
                "run_closed does not contain a final watermark for the R1 Sysmon partition"
            )

    def _is_selector_partition(self, partition: R1StreamPartition) -> bool:
        return (
            partition.run_id == self._run_id
            and partition.host_id == self._entity_id
            and (partition.source, partition.source_channel) in self._required_partition_identities
        )

    def _required_stream_partitions(self) -> tuple[R1StreamPartition, ...]:
        return tuple(
            R1StreamPartition(
                run_id=self._run_id,
                host_id=self._entity_id,
                source=source,
                source_channel=source_channel,
            )
            for source, source_channel in sorted(self._required_partition_identities)
        )

    def _require_exact_target_partitions(
        self,
        final_watermarks: tuple[R1FinalPartitionWatermark, ...],
    ) -> None:
        actual = frozenset(
            (item.partition.source, item.partition.source_channel)
            for item in final_watermarks
            if item.partition.run_id == self._run_id and item.partition.host_id == self._entity_id
        )
        if actual != self._required_partition_identities:
            raise ValueError(
                "verified proof target partitions must exactly match required-partition contract"
            )

    def _fail_closed(self, *diagnostics: str) -> None:
        self._snapshot = R1IncrementalEvidenceSnapshot(
            status="failed_closed",
            selector_result=self._snapshot.selector_result,
            close_mode=(
                "verified_close_proof"
                if self._required_partition_contract is not None
                else self._snapshot.close_mode
            ),
            availability_contract_version=(
                "v0.2" if self._required_partition_contract is not None else None
            ),
            diagnostics=tuple(diagnostics),
        )

    def _validate_chunk_after_run_closed(self, chunk: R1EventChunk) -> None:
        assert self._run_closed is not None
        matching = tuple(
            item
            for item in self._run_closed.final_watermarks
            if _partition_key(item.partition) == _partition_key(chunk.partition)
        )
        if not matching:
            raise ValueError("new chunk partition is not sealed by run_closed")
        if chunk.chunk_sequence > matching[0].covered_through_chunk_sequence:
            raise ValueError("new chunk sequence exceeds run_closed coverage")

    def _chunk_coverage_diagnostics(self) -> tuple[str, ...]:
        if self._run_closed is None:
            return ()

        accepted: dict[_PartitionKey, set[int]] = {}
        for sequence_key in self._chunk_sequence_identities:
            partition_key = sequence_key[2:6]
            if not self._is_required_partition_key(partition_key):
                continue
            accepted.setdefault(partition_key, set()).add(sequence_key[6])

        final_by_partition = {
            _partition_key(item.partition): item.covered_through_chunk_sequence
            for item in self._run_closed.final_watermarks
            if self._is_required_partition_key(_partition_key(item.partition))
        }
        diagnostics: list[str] = []
        for partition_key in sorted(accepted):
            if partition_key not in final_by_partition:
                diagnostics.append(
                    "accepted chunk partition is absent from run_closed: "
                    + _format_partition_key(partition_key)
                )

        for partition_key, covered_through in sorted(final_by_partition.items()):
            sequences = accepted.get(partition_key, set())
            excess = tuple(sorted(sequence for sequence in sequences if sequence > covered_through))
            if excess:
                diagnostics.append(
                    "accepted chunk sequence exceeds run_closed coverage for "
                    + _format_partition_key(partition_key)
                    + f": {excess}"
                )
            missing = tuple(sorted(set(range(1, covered_through + 1)) - sequences))
            if missing:
                diagnostics.append(
                    "run_closed covered chunk sequence is missing for "
                    + _format_partition_key(partition_key)
                    + f": {missing}"
                )
        return tuple(diagnostics)

    def _is_required_partition_key(self, partition_key: _PartitionKey) -> bool:
        if self._required_partition_contract is None:
            return True
        run_id, host_id, source, source_channel = partition_key
        return (
            run_id == self._run_id
            and host_id == self._entity_id
            and (source, source_channel) in self._required_partition_identities
        )

    def _require_watermark_coverage(self, boundary_at: datetime) -> None:
        assert self._run_closed is not None
        entity_watermarks = tuple(
            item
            for item in self._run_closed.final_watermarks
            if self._is_selector_partition(item.partition)
        )
        if not entity_watermarks:
            raise ValueError("run_closed does not contain a final watermark for entity_id")
        if any(item.watermark_at < boundary_at for item in entity_watermarks):
            raise ValueError("every entity final watermark must cover the candidate boundary")

    def _latest_verified_input_ingest_time(self) -> datetime:
        ingest_times: list[datetime] = []
        for event in self._ordered_events():
            try:
                ingest_times.append(_utc("Event ingest_time", event.ingest_time))
            except (TypeError, ValueError) as error:
                raise ValueError("missing_or_invalid_ingest_time") from error
        return max(ingest_times, default=self._run_start)


def _unpad(field_name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value.strip() or value != value.strip():
        raise ValueError(f"{field_name} must be non-blank and unpadded")
    return value


def _utc(field_name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")
    if value.microsecond % 1000 != 0:
        raise ValueError(f"{field_name} must use millisecond precision")
    return value.astimezone(UTC)


def _chunk_sha256(chunk: R1EventChunk) -> str:
    payload = chunk.model_dump(mode="json", by_alias=True)
    del payload["chunk_content_sha256"]
    return _canonical_sha256(payload)


def _event_sha256(event: NormalizedEvent) -> str:
    return _canonical_sha256(event.model_dump(mode="json", by_alias=True))


def _validate_checkpoint_policy_inputs(
    checkpoint: R1IncrementalEvidenceCheckpoint,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
) -> None:
    selector_identity = checkpoint.selector_policy_identity
    if (
        selector_identity.policy_id,
        selector_identity.version,
        selector_identity.config_hash,
        selector_identity.lineage_event_count,
    ) != (
        selector_policy.policy_id,
        selector_policy.version,
        selector_policy.config_hash,
        selector_policy.lineage_event_count,
    ):
        raise ValueError("checkpoint selector policy identity does not match supplied policy")
    approved_identity = checkpoint.approved_policy_identity
    if (
        approved_identity.policy_id,
        approved_identity.version,
        approved_identity.config_hash,
        approved_identity.family_id,
        approved_identity.lifecycle,
    ) != (
        approved_policy.policy_id,
        approved_policy.version,
        approved_policy.config_hash,
        approved_policy.family_id,
        approved_policy.lifecycle,
    ):
        raise ValueError("checkpoint approved policy identity does not match supplied policy")


def _validate_restored_snapshot(
    checkpoint: R1IncrementalEvidenceCheckpoint,
    snapshot: R1IncrementalEvidenceSnapshot,
) -> None:
    if snapshot.status != checkpoint.status:
        raise ValueError("restored incremental status does not match checkpoint")
    if snapshot.close_mode != checkpoint.close_mode:
        raise ValueError("restored close mode does not match checkpoint")
    if snapshot.candidate_boundary_at != checkpoint.candidate_boundary_at:
        raise ValueError("restored candidate boundary does not match checkpoint")
    if snapshot.available_at != checkpoint.available_at:
        raise ValueError("restored availability does not match checkpoint")
    if checkpoint.status == "finalized":
        validate_r1_incremental_finalized_evidence(
            checkpoint,
            snapshot.evidences,
            expected_close_mode=checkpoint.close_mode,
        )
    elif snapshot.evidences or checkpoint.evidence_digests:
        raise ValueError("non-finalized checkpoint must not contain Evidence output")


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _partition_key(partition: R1StreamPartition) -> _PartitionKey:
    return (
        partition.run_id,
        partition.host_id,
        partition.source,
        partition.source_channel,
    )


def _format_partition_key(partition_key: _PartitionKey) -> str:
    return "/".join(partition_key)


__all__ = [
    "R1IncrementalCloseMode",
    "R1IncrementalEvidenceSnapshot",
    "R1IncrementalEvidenceState",
    "R1IncrementalStatus",
]
