"""Normalize validated Sysmon records and extract their S0 Evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.extractor import extract_evidence
from incident_awareness.normalization.sysmon import (
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.pipeline.timeseries_telemetry import RecordMeasurement, _log_failure

_SYSMON_PROCESS_CREATE_EVENT_ID = 1
_SYSMON_NETWORK_CONNECTION_EVENT_ID = 3


@dataclass(frozen=True, slots=True)
class NormalizedEvidenceArtifacts:
    """Normalized S0 Events and Evidence derived from the supplied Sysmon JSONL."""

    events: tuple[NormalizedEvent, ...]
    evidences: tuple[Evidence, ...]


class RecordTelemetry(Protocol):
    def begin_record(self, record_no: int) -> RecordMeasurement | None: ...

    def record_success(self, token: RecordMeasurement | None) -> None: ...

    def record_failure(self, token: RecordMeasurement | None) -> None: ...


def normalize_sysmon_and_extract_evidence(
    artifacts: S0PipelineArtifacts,
    *,
    progress_callback: Callable[[int], None] | None = None,
    telemetry_collector: RecordTelemetry | None = None,
) -> NormalizedEvidenceArtifacts:
    """Normalize S0 Sysmon Event IDs 1 and 3, then extract Evidence for each Event."""
    events: list[NormalizedEvent] = []
    evidences: list[Evidence] = []
    for processed_count, record in enumerate(artifacts.sysmon_records, start=1):
        token = (
            _observe(lambda count=processed_count: telemetry_collector.begin_record(count))
            if telemetry_collector is not None
            else None
        )
        try:
            event = _normalize_sysmon_record(
                record_event_id=record.data.get("EventId"),
                record=record,
                artifacts=artifacts,
            )
            events.append(event)
            evidences.extend(extract_evidence(event))
        except BaseException:
            if telemetry_collector is not None:
                _observe(lambda measurement=token: telemetry_collector.record_failure(measurement))
            raise
        else:
            if telemetry_collector is not None:
                _observe(lambda measurement=token: telemetry_collector.record_success(measurement))
        if progress_callback is not None:
            progress_callback(processed_count)

    return NormalizedEvidenceArtifacts(events=tuple(events), evidences=tuple(evidences))


def _observe[T](operation: Callable[[], T]) -> T | None:
    try:
        return operation()
    except Exception:  # noqa: BLE001 - measurement callbacks must preserve business outcomes.
        _log_failure("normalization measurement callback")
        return None


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
