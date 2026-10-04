"""NormalizedEvent batch에서 R1 multi-event Evidence 후보를 추출한다."""

from collections.abc import Iterable
from dataclasses import dataclass

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_multi_event import (
    ApprovedLineagePolicy,
    R1ExtractionDiagnostic,
    R1LineageExtractionResult,
    extract_remote_process_network_follow_on,
    extract_remote_session_process_lineage_deviation_with_diagnostics,
)

type _CorrelationKey = tuple[str, str, str]
type _ResolvedLineageInput = tuple[R1LineageInput, NormalizedEvent, NormalizedEvent]


@dataclass(frozen=True, slots=True)
class R1LineageInput:
    """명시적인 lineage 양 끝 Event와 비교에 사용할 동결 policy 입력."""

    anchor_event_id: str
    terminal_event_id: str
    approved_policy: ApprovedLineagePolicy

    def __post_init__(self) -> None:
        for field_name, value in (
            ("anchor_event_id", self.anchor_event_id),
            ("terminal_event_id", self.terminal_event_id),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")
            if not value.strip():
                raise ValueError(f"{field_name} must be a non-blank string")

        if not isinstance(self.approved_policy, ApprovedLineagePolicy):
            raise TypeError("approved_policy must be an ApprovedLineagePolicy")


@dataclass(frozen=True, slots=True)
class R1EvidencePipelineResult:
    """R1 candidate Evidence와 fail-closed 입력 진단을 함께 반환한다."""

    evidences: tuple[Evidence, ...]
    diagnostics: tuple[R1ExtractionDiagnostic, ...]


def run_r1_evidence_pipeline(
    events: Iterable[NormalizedEvent],
    *,
    lineage_inputs: Iterable[R1LineageInput] = (),
) -> tuple[Evidence, ...]:
    """S0 추출이나 Fusion 호출 없이 R1 candidate Evidence를 반환한다."""
    return run_r1_evidence_pipeline_with_diagnostics(
        events,
        lineage_inputs=lineage_inputs,
    ).evidences


def run_r1_evidence_pipeline_with_diagnostics(
    events: Iterable[NormalizedEvent],
    *,
    lineage_inputs: Iterable[R1LineageInput] = (),
) -> R1EvidencePipelineResult:
    """기존 Evidence 결과와 공격 판정이 아닌 fail-closed 진단을 반환한다."""
    event_batch = tuple(events)
    lineage_input_batch = tuple(lineage_inputs)
    events_by_id = _index_events_by_id(event_batch)
    resolved_lineage_inputs = _resolve_lineage_inputs(
        lineage_input_batch,
        events_by_id,
    )

    terminal_events = tuple(
        {
            terminal_event.event_id: terminal_event
            for _, _, terminal_event in resolved_lineage_inputs
        }.values()
    )
    evidences = _extract_network_follow_on_candidates(event_batch, terminal_events)
    diagnostics: set[R1ExtractionDiagnostic] = set()
    for lineage_input, anchor_event, terminal_event in resolved_lineage_inputs:
        lineage_result: R1LineageExtractionResult = (
            extract_remote_session_process_lineage_deviation_with_diagnostics(
                event_batch,
                anchor_event,
                terminal_event,
                lineage_input.approved_policy,
            )
        )
        evidences.extend(lineage_result.evidences)
        diagnostics.update(lineage_result.diagnostics)

    evidences_by_id: dict[str, Evidence] = {}
    for evidence in evidences:
        evidences_by_id.setdefault(evidence.evidence_id, evidence)

    return R1EvidencePipelineResult(
        evidences=tuple(
            sorted(
                evidences_by_id.values(),
                key=lambda evidence: (
                    evidence.timestamp,
                    evidence.evidence_type,
                    evidence.evidence_id,
                ),
            )
        ),
        diagnostics=tuple(sorted(diagnostics)),
    )


def _index_events_by_id(
    events: tuple[NormalizedEvent, ...],
) -> dict[str, NormalizedEvent]:
    events_by_id: dict[str, NormalizedEvent] = {}
    for event in events:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("events must contain NormalizedEvent items")
        if event.event_id in events_by_id:
            raise ValueError(f"events must contain unique event_id values: {event.event_id}")
        events_by_id[event.event_id] = event

    return events_by_id


def _resolve_lineage_inputs(
    lineage_inputs: tuple[R1LineageInput, ...],
    events_by_id: dict[str, NormalizedEvent],
) -> tuple[_ResolvedLineageInput, ...]:
    resolved_inputs: list[_ResolvedLineageInput] = []
    for lineage_input in lineage_inputs:
        if not isinstance(lineage_input, R1LineageInput):
            raise TypeError("lineage_inputs must contain R1LineageInput items")

        anchor_event = _required_event(
            events_by_id,
            event_id=lineage_input.anchor_event_id,
            field_name="anchor_event_id",
        )
        terminal_event = _required_event(
            events_by_id,
            event_id=lineage_input.terminal_event_id,
            field_name="terminal_event_id",
        )
        resolved_inputs.append((lineage_input, anchor_event, terminal_event))

    return tuple(resolved_inputs)


def _extract_network_follow_on_candidates(
    events: tuple[NormalizedEvent, ...],
    terminal_events: tuple[NormalizedEvent, ...],
) -> list[Evidence]:
    network_events_by_key: dict[_CorrelationKey, list[NormalizedEvent]] = {}

    for event in events:
        process_guid = event.process.process_guid if event.process is not None else None
        if process_guid is None:
            continue

        key = (event.run_id, event.host_id, process_guid)
        if event.event_type == "network_connection":
            network_events_by_key.setdefault(key, []).append(event)

    evidences: list[Evidence] = []
    for terminal_event in sorted(
        terminal_events,
        key=lambda event: (event.timestamp, event.event_id),
    ):
        process_guid = (
            terminal_event.process.process_guid if terminal_event.process is not None else None
        )
        if process_guid is None:
            continue

        key = (terminal_event.run_id, terminal_event.host_id, process_guid)
        network_events = sorted(
            network_events_by_key.get(key, ()),
            key=lambda event: (event.timestamp, event.event_id),
        )

        for network_event in network_events:
            evidences.extend(
                extract_remote_process_network_follow_on(
                    terminal_event,
                    network_event,
                )
            )

    return evidences


def _required_event(
    events_by_id: dict[str, NormalizedEvent],
    *,
    event_id: str,
    field_name: str,
) -> NormalizedEvent:
    event = events_by_id.get(event_id)
    if event is None:
        raise ValueError(f"{field_name} does not reference an Event in the batch: {event_id}")
    return event


__all__ = [
    "R1EvidencePipelineResult",
    "R1LineageInput",
    "run_r1_evidence_pipeline",
    "run_r1_evidence_pipeline_with_diagnostics",
]
