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
from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed
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
type R1IncrementalCloseMode = Literal[
    "verified_candidate_generation_seal",
    "authoritative_run_end_fallback",
]


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
        if selector_policy.lineage_event_count != len(approved_policy.approved_lineage):
            raise ValueError("selector lineage_event_count must match approved_lineage length")
        self._selector_policy = selector_policy
        self._approved_policy = approved_policy

        self._events_by_id: dict[str, NormalizedEvent] = {}
        self._event_hashes: dict[str, str] = {}
        self._chunk_hashes: dict[str, str] = {}
        self._chunk_sequence_identities: dict[tuple[str, str, str, str, int], str] = {}
        self._run_closed: R1RunClosed | None = None
        self._verified_boundary: R1VerifiedCandidateBoundary | None = None
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
        existing_chunk_hash = self._chunk_hashes.get(chunk.chunk_id)
        if existing_chunk_hash is not None:
            if existing_chunk_hash != chunk_hash:
                raise ValueError("chunk identity was reused with different content")
            return self._snapshot
        if self._run_closed is not None:
            raise ValueError("new chunk cannot be accepted after run_closed")
        if self._snapshot.status in {"finalized", "failed_closed"}:
            raise ValueError("incremental state is already terminal")

        sequence_key = (
            chunk.partition.run_id,
            chunk.partition.host_id,
            chunk.partition.source,
            chunk.partition.source_channel,
            chunk.chunk_sequence,
        )
        existing_chunk_id = self._chunk_sequence_identities.get(sequence_key)
        if existing_chunk_id is not None and existing_chunk_id != chunk.chunk_id:
            raise ValueError("chunk sequence was reused by another identity")

        event_updates: list[tuple[NormalizedEvent, str]] = []
        for event in chunk.events:
            event_hash = _event_sha256(event)
            existing_event_hash = self._event_hashes.get(event.event_id)
            if existing_event_hash is not None:
                if existing_event_hash != event_hash:
                    raise ValueError("Event identity was reused with different content")
                continue
            event_updates.append((event, event_hash))

        self._chunk_hashes[chunk.chunk_id] = chunk_hash
        self._chunk_sequence_identities[sequence_key] = chunk.chunk_id
        for event, event_hash in event_updates:
            self._event_hashes[event.event_id] = event_hash
            if event.host_id == self._entity_id:
                self._events_by_id[event.event_id] = event
        self._snapshot = self._provisional_snapshot()
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
        return self._try_verified_close()

    def accept_verified_boundary(
        self,
        boundary: R1VerifiedCandidateBoundary,
    ) -> R1IncrementalEvidenceSnapshot:
        """같은 신뢰 경계에서 Role4가 검증한 candidate boundary를 기록한다."""
        if not isinstance(boundary, R1VerifiedCandidateBoundary):
            raise TypeError("boundary must be an R1VerifiedCandidateBoundary")
        if boundary.run_id != self._run_id:
            raise ValueError("verified boundary run_id does not match incremental state")
        if boundary.candidate_boundary_at < self._run_start:
            raise ValueError("verified candidate boundary must not precede run_start")
        if boundary.verified_seal_at < boundary.candidate_boundary_at:
            raise ValueError("verified seal time must not precede candidate boundary")
        if self._verified_boundary is not None:
            if self._verified_boundary != boundary:
                raise ValueError("incremental state already has a different verified boundary")
            return self._snapshot
        if self._snapshot.status in {"finalized", "failed_closed"}:
            raise ValueError("incremental state is already terminal")
        self._verified_boundary = boundary
        return self._try_verified_close()

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
        self._require_watermark_coverage(run_end)
        diagnostics = self._snapshot.diagnostics or (
            "verified candidate-generation boundary is absent or not bound to run_closed",
        )
        available_at = max(run_end, self._run_closed.emitted_at)
        return self._finalize(
            boundary_at=run_end,
            available_at=available_at,
            close_mode="authoritative_run_end_fallback",
            diagnostics=diagnostics,
        )

    def _try_verified_close(self) -> R1IncrementalEvidenceSnapshot:
        if self._run_closed is None or self._verified_boundary is None:
            return self._snapshot
        boundary = self._verified_boundary
        if boundary.input_close_id != self._run_closed.close_id:
            self._snapshot = self._provisional_snapshot(
                diagnostics=("verified boundary input_close_id does not match run_closed",)
            )
            return self._snapshot
        try:
            self._require_watermark_coverage(boundary.candidate_boundary_at)
        except ValueError as error:
            self._snapshot = self._provisional_snapshot(diagnostics=(str(error),))
            return self._snapshot
        available_at = max(self._run_closed.emitted_at, boundary.verified_seal_at)
        return self._finalize(
            boundary_at=boundary.candidate_boundary_at,
            available_at=available_at,
            close_mode="verified_candidate_generation_seal",
            diagnostics=(),
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
            sorted(self._events_by_id.values(), key=lambda event: (event.timestamp, event.event_id))
        )

    def _eligible_events(self, boundary_at: datetime) -> tuple[NormalizedEvent, ...]:
        return tuple(event for event in self._ordered_events() if event.timestamp <= boundary_at)

    def _require_entity_partition(self, run_closed: R1RunClosed) -> None:
        if not any(
            item.partition.host_id == self._entity_id for item in run_closed.final_watermarks
        ):
            raise ValueError("run_closed does not contain a final watermark for entity_id")

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


__all__ = [
    "R1IncrementalCloseMode",
    "R1IncrementalEvidenceSnapshot",
    "R1IncrementalEvidenceState",
    "R1IncrementalStatus",
]
