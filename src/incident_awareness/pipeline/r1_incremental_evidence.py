"""R1 Event chunk를 누적하고 검증된 close에서만 Evidence를 확정한다."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1VerifiedCandidateBoundary,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.r1_stream import (
    R1EventChunk,
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
)
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline_with_selector,
)

type R1IncrementalStatus = Literal["accumulating", "provisional", "finalized", "failed_closed"]
type R1IncrementalCloseMode = Literal["authoritative_run_end_fallback"]
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
    diagnostics: tuple[str, ...] = ()


class R1IncrementalEvidenceState:
    """Append-only R1 selector state.

    Role3가 이미 수락한 chunk와 ``run_closed``만 입력으로 받는다. Role4의
    Ground Truth 결속 검증 결과인 ``R1VerifiedCandidateBoundary``는 정답 필드를
    포함하지 않는다. 현재 #269 v0.1 최소 객체는 같은 신뢰 경계에서 검증 함수가 직접
    반환한 경우에만 내부 close 입력으로 쓴다. 외부 artifact 연동은 별도 Role2-safe
    verified-close proof가 등록될 때까지 활성화하지 않는다.
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

        self._events_by_identity: dict[_EventIdentity, NormalizedEvent] = {}
        self._event_hashes: dict[_EventIdentity, str] = {}
        self._chunk_hashes: dict[_ChunkIdentity, str] = {}
        self._chunk_sequence_identities: dict[_ChunkSequenceIdentity, str] = {}
        self._run_closed: R1RunClosed | None = None
        self._snapshot = self._provisional_snapshot()

    @property
    def snapshot(self) -> R1IncrementalEvidenceSnapshot:
        return self._snapshot

    def accept_chunk(self, chunk: R1EventChunk) -> R1IncrementalEvidenceSnapshot:
        """Role3가 수락한 chunk를 idempotent하게 누적한다."""
        if not isinstance(chunk, R1EventChunk):
            raise TypeError("chunk must be an R1EventChunk")
        if chunk.partition.run_id != self._run_id:
            raise ValueError("chunk run_id does not match incremental state")

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

        self._chunk_hashes[chunk_identity] = chunk_hash
        self._chunk_sequence_identities[sequence_key] = chunk.chunk_id
        for event, event_hash, event_identity in event_updates:
            self._event_hashes[event_identity] = event_hash
            if event.host_id == self._entity_id:
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
        self._require_entity_partition(run_closed)
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
                diagnostics=coverage_diagnostics,
            )
            return self._snapshot
        self._require_watermark_coverage(run_end)
        return self._finalize(
            boundary_at=run_end,
            available_at=run_end,
            close_mode="authoritative_run_end_fallback",
            diagnostics=("Role2-safe verified close proof is unavailable; used run_end fallback",),
        )

    def _finalize(
        self,
        *,
        boundary_at: datetime,
        available_at: datetime,
        close_mode: R1IncrementalCloseMode,
        diagnostics: tuple[str, ...],
    ) -> R1IncrementalEvidenceSnapshot:
        eligible_events = self._eligible_events(boundary_at)
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
                diagnostics=failure_diagnostics,
            )
            return self._snapshot

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
            item.partition.host_id == self._entity_id for item in run_closed.final_watermarks
        ):
            raise ValueError("run_closed does not contain a final watermark for entity_id")

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
            accepted.setdefault(partition_key, set()).add(sequence_key[6])

        final_by_partition = {
            _partition_key(item.partition): item.covered_through_chunk_sequence
            for item in self._run_closed.final_watermarks
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

    def _require_watermark_coverage(self, boundary_at: datetime) -> None:
        assert self._run_closed is not None
        entity_watermarks = tuple(
            item
            for item in self._run_closed.final_watermarks
            if item.partition.host_id == self._entity_id
        )
        if not entity_watermarks:
            raise ValueError("run_closed does not contain a final watermark for entity_id")
        if any(item.watermark_at < boundary_at for item in entity_watermarks):
            raise ValueError("every entity final watermark must cover the candidate boundary")


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
