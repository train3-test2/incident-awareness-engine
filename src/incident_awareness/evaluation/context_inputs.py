"""Validate offline context provenance; this does not certify causal availability."""

from datetime import datetime, timedelta

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.pipeline.r1_artifacts import R1EvidenceArtifactRun


def validate_context_inputs(
    artifact: R1EvidenceArtifactRun,
    events: list[NormalizedEvent],
    *,
    run_id: str,
    entity_id: str,
    run_start: datetime,
    run_end: datetime,
) -> tuple[str, ...]:
    """Reject ambiguous/missing context and direct evidence outside the Run.

    Caller must filter post-Run events BEFORE extraction. Pre-Run events remain
    available for lineage reconstruction. Returned IDs are context, not features.
    Event count matching is a minimum check, not proof of identical Event content.
    """
    for value in (run_start, run_end):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Run boundaries must be UTC")
        if value.microsecond % 1000:
            raise ValueError("Run boundaries must have millisecond precision")
    if run_end <= run_start:
        raise ValueError("Run must have positive duration")
    if artifact.summary.run_id != run_id or artifact.summary.status != "completed":
        raise ValueError("completed artifact must match Run")
    if artifact.summary.selector is None or artifact.summary.selector.status != "selected":
        raise ValueError("context validation requires a selected lineage")
    if not artifact.summary.lineage_inputs:
        raise ValueError("context validation requires lineage provenance")
    if artifact.summary.input_event_count != len(events):
        raise ValueError("input Event count differs from extraction summary")
    by_id = {event.event_id: event for event in events}
    if len(by_id) != len(events):
        raise ValueError("duplicate Event ID")
    for event in events:
        if event.run_id != run_id or event.host_id != entity_id:
            raise ValueError("input Run/host mismatch")
        if event.timestamp > run_end:
            raise ValueError("post-Run input must be removed before extraction")
    context = set()
    for lineage in artifact.summary.lineage_inputs:
        for event_id in lineage.context_event_ids:
            event = by_id.get(event_id)
            if event is None:
                raise ValueError("missing context Event")
            if event.timestamp >= run_start:
                raise ValueError("context must precede Run start")
            context.add(event_id)
    for evidence in artifact.evidences:
        if evidence.run_id != run_id or evidence.entity_id != entity_id:
            raise ValueError("Evidence Run/host mismatch")
        if not run_start <= evidence.timestamp <= run_end:
            raise ValueError("Evidence outside Run")
        for event_id in evidence.event_ids:
            event = by_id.get(event_id)
            if event is None:
                raise ValueError("missing direct Event")
            if event_id in context or not run_start <= event.timestamp <= run_end:
                raise ValueError("direct Evidence includes context or out-of-Run Event")
    return tuple(sorted(context))
