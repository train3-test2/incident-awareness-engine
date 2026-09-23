"""Normalize validated Sysmon records and extract their S0 Evidence."""

from __future__ import annotations

from dataclasses import dataclass

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.extractor import extract_evidence
from incident_awareness.normalization.sysmon import (
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

_SYSMON_PROCESS_CREATE_EVENT_ID = 1
_SYSMON_NETWORK_CONNECTION_EVENT_ID = 3


@dataclass(frozen=True, slots=True)
class NormalizedEvidenceArtifacts:
    """Normalized S0 Events and Evidence derived from the supplied Sysmon JSONL."""

    events: tuple[NormalizedEvent, ...]
    evidences: tuple[Evidence, ...]


def normalize_sysmon_and_extract_evidence(
    artifacts: S0PipelineArtifacts,
) -> NormalizedEvidenceArtifacts:
    """Normalize S0 Sysmon Event IDs 1 and 3, then extract Evidence for each Event."""
    events: list[NormalizedEvent] = []
    evidences: list[Evidence] = []

    for record in artifacts.sysmon_records:
        event = _normalize_sysmon_record(
            record_event_id=record.data.get("EventId"),
            record=record,
            artifacts=artifacts,
        )
        events.append(event)
        evidences.extend(extract_evidence(event))

    return NormalizedEvidenceArtifacts(events=tuple(events), evidences=tuple(evidences))


def _normalize_sysmon_record(
    *,
    record_event_id: object,
    record: SysmonJsonlRecord,
    artifacts: S0PipelineArtifacts,
) -> NormalizedEvent:
    if isinstance(record_event_id, bool) or not isinstance(record_event_id, int):
        raise TypeError(f"Sysmon record {record.record_no} EventId must be an integer")

    if record_event_id == _SYSMON_PROCESS_CREATE_EVENT_ID:
        return normalize_sysmon_process_create(
            record,
            context=artifacts.normalization_context,
        )
    if record_event_id == _SYSMON_NETWORK_CONNECTION_EVENT_ID:
        return normalize_sysmon_network_connection(
            record,
            context=artifacts.normalization_context,
        )

    raise ValueError(
        f"Sysmon record {record.record_no} has unsupported EventId {record_event_id}; "
        "S0 supports only Event IDs 1 and 3"
    )


__all__ = ["NormalizedEvidenceArtifacts", "normalize_sysmon_and_extract_evidence"]
