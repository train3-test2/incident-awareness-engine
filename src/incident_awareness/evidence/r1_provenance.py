"""R1 Evidence의 NormalizedEvent provenance 참조를 검증하고 해석한다."""

from collections.abc import Iterable
from dataclasses import dataclass

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence


@dataclass(frozen=True, slots=True)
class ResolvedR1EvidenceProvenance:
    """Evidence와 `event_ids` 의미 순서로 해석한 Event를 묶는다."""

    evidence: Evidence
    resolved_events: tuple[NormalizedEvent, ...]


def resolve_r1_evidence_provenance(
    evidences: Iterable[Evidence],
    events: Iterable[NormalizedEvent],
) -> tuple[ResolvedR1EvidenceProvenance, ...]:
    """R1 Evidence가 참조하는 host-local NormalizedEvent를 해석한다."""
    evidence_batch = tuple(evidences)
    event_batch = tuple(events)
    events_by_id = _index_events_by_id(event_batch)

    resolved: list[ResolvedR1EvidenceProvenance] = []
    for evidence in evidence_batch:
        if not isinstance(evidence, Evidence):
            raise TypeError("evidences must contain Evidence items")

        resolved_events = tuple(
            _resolve_referenced_event(
                evidence=evidence,
                event_id=event_id,
                events_by_id=events_by_id,
            )
            for event_id in evidence.event_ids
        )
        resolved.append(
            ResolvedR1EvidenceProvenance(
                evidence=evidence,
                resolved_events=resolved_events,
            )
        )

    return tuple(resolved)


def _index_events_by_id(
    events: tuple[NormalizedEvent, ...],
) -> dict[str, NormalizedEvent]:
    events_by_id: dict[str, NormalizedEvent] = {}
    for event in events:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("events must contain NormalizedEvent items")
        if event.event_id in events_by_id:
            raise ValueError(
                f"events must contain unique NormalizedEvent.event_id values: {event.event_id}"
            )
        events_by_id[event.event_id] = event

    return events_by_id


def _resolve_referenced_event(
    *,
    evidence: Evidence,
    event_id: str,
    events_by_id: dict[str, NormalizedEvent],
) -> NormalizedEvent:
    event = events_by_id.get(event_id)
    if event is None:
        raise ValueError(
            f"Evidence {evidence.evidence_id} references a missing NormalizedEvent: {event_id}"
        )
    if event.run_id != evidence.run_id:
        raise ValueError(
            f"Evidence {evidence.evidence_id} and NormalizedEvent {event_id} have different run_id"
        )
    if event.host_id != evidence.entity_id:
        raise ValueError(
            f"Evidence {evidence.evidence_id} entity_id does not match "
            f"NormalizedEvent {event_id} host_id"
        )

    return event


__all__ = [
    "ResolvedR1EvidenceProvenance",
    "resolve_r1_evidence_provenance",
]
