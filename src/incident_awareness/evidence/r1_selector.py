"""R1 반복 평가 대상을 구조 계약으로 결정적으로 선택한다."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from incident_awareness.common.models.event import NormalizedEvent

type R1SelectorDiagnostic = Literal[
    "empty_event_batch",
    "mixed_run_scope",
    "mixed_host_scope",
    "duplicate_event_id",
    "missing_process_guid",
    "duplicate_process_guid",
    "no_terminal_candidate",
    "ambiguous_terminal_candidate",
    "truncated_lineage",
    "lineage_cycle",
    "temporal_inversion",
]


@dataclass(frozen=True, slots=True)
class R1SelectorPolicy:
    """평가 전에 동결하는 R1 lineage 선택 범위와 provenance."""

    policy_id: str
    version: str
    config_hash: str
    lineage_event_count: int

    def __post_init__(self) -> None:
        for field_name, value in (
            ("policy_id", self.policy_id),
            ("version", self.version),
            ("config_hash", self.config_hash),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")
            if not value.strip():
                raise ValueError(f"{field_name} must be a non-blank string")

        if isinstance(self.lineage_event_count, bool) or not isinstance(
            self.lineage_event_count,
            int,
        ):
            raise TypeError("lineage_event_count must be an integer")
        if self.lineage_event_count < 1:
            raise ValueError("lineage_event_count must be at least 1")


@dataclass(frozen=True, slots=True)
class R1LineageSelection:
    """선택된 host-local lineage와 selector policy provenance."""

    run_id: str
    entity_id: str
    anchor_event_id: str
    terminal_event_id: str
    selector_policy_id: str
    selector_policy_version: str
    selector_policy_config_hash: str


@dataclass(frozen=True, slots=True)
class R1SelectorResult:
    """유일한 선택 또는 공격 판정이 아닌 fail-closed 진단."""

    selection: R1LineageSelection | None
    diagnostics: tuple[R1SelectorDiagnostic, ...]


def select_r1_lineage(
    events: Iterable[NormalizedEvent],
    *,
    policy: R1SelectorPolicy,
) -> R1SelectorResult:
    """이름이나 label 없이 유일한 R1 구조 lineage를 선택한다."""
    if not isinstance(policy, R1SelectorPolicy):
        raise TypeError("policy must be an R1SelectorPolicy")

    event_batch = tuple(events)
    if not event_batch:
        return _failed("empty_event_batch")
    if any(not isinstance(event, NormalizedEvent) for event in event_batch):
        raise TypeError("events must contain NormalizedEvent items")

    event_ids = [event.event_id for event in event_batch]
    if len(event_ids) != len(set(event_ids)):
        return _failed("duplicate_event_id")

    run_ids = {event.run_id for event in event_batch}
    if len(run_ids) != 1:
        return _failed("mixed_run_scope")

    host_ids = {event.host_id for event in event_batch}
    if len(host_ids) != 1:
        return _failed("mixed_host_scope")

    process_events = tuple(event for event in event_batch if _is_process_create(event))
    network_events = tuple(event for event in event_batch if _is_network_connection(event))
    scoped_events = (*process_events, *network_events)
    if any(_process_guid(event) is None for event in scoped_events):
        return _failed("missing_process_guid")

    process_events_by_guid: dict[str, NormalizedEvent] = {}
    for event in process_events:
        process_guid = _process_guid(event)
        if process_guid is None:
            continue
        if process_guid in process_events_by_guid:
            return _failed("duplicate_process_guid")
        process_events_by_guid[process_guid] = event

    terminal_candidates, has_temporal_inversion = _terminal_candidates(
        process_events,
        network_events,
    )
    if not terminal_candidates:
        return _failed("temporal_inversion" if has_temporal_inversion else "no_terminal_candidate")
    if len(terminal_candidates) != 1:
        return _failed("ambiguous_terminal_candidate")

    terminal_event = terminal_candidates[0]
    lineage, diagnostic = _lineage_to_policy_boundary(
        terminal_event,
        process_events_by_guid=process_events_by_guid,
        lineage_event_count=policy.lineage_event_count,
    )
    if diagnostic is not None:
        return _failed(diagnostic)

    anchor_event = lineage[-1]
    return R1SelectorResult(
        selection=R1LineageSelection(
            run_id=terminal_event.run_id,
            entity_id=terminal_event.host_id,
            anchor_event_id=anchor_event.event_id,
            terminal_event_id=terminal_event.event_id,
            selector_policy_id=policy.policy_id,
            selector_policy_version=policy.version,
            selector_policy_config_hash=policy.config_hash,
        ),
        diagnostics=(),
    )


def _terminal_candidates(
    process_events: tuple[NormalizedEvent, ...],
    network_events: tuple[NormalizedEvent, ...],
) -> tuple[tuple[NormalizedEvent, ...], bool]:
    networks_by_guid: dict[str, list[NormalizedEvent]] = {}
    for network_event in network_events:
        process_guid = _process_guid(network_event)
        if process_guid is not None:
            networks_by_guid.setdefault(process_guid, []).append(network_event)

    terminal_candidates: list[NormalizedEvent] = []
    has_temporal_inversion = False
    for process_event in process_events:
        process_guid = _process_guid(process_event)
        if process_guid is None:
            continue

        linked_network_events = networks_by_guid.get(process_guid, ())
        if any(event.timestamp >= process_event.timestamp for event in linked_network_events):
            terminal_candidates.append(process_event)
        elif linked_network_events:
            has_temporal_inversion = True

    return (
        tuple(sorted(terminal_candidates, key=lambda event: (event.timestamp, event.event_id))),
        has_temporal_inversion,
    )


def _lineage_to_policy_boundary(
    terminal_event: NormalizedEvent,
    *,
    process_events_by_guid: dict[str, NormalizedEvent],
    lineage_event_count: int,
) -> tuple[tuple[NormalizedEvent, ...], R1SelectorDiagnostic | None]:
    lineage = [terminal_event]
    terminal_guid = _process_guid(terminal_event)
    if terminal_guid is None:
        return (), "missing_process_guid"

    visited_guids = {terminal_guid}
    child_event = terminal_event
    while len(lineage) < lineage_event_count:
        parent_guid = (
            child_event.process.parent_process_guid if child_event.process is not None else None
        )
        if parent_guid is None:
            return (), "truncated_lineage"
        if parent_guid in visited_guids:
            return (), "lineage_cycle"

        parent_event = process_events_by_guid.get(parent_guid)
        if parent_event is None:
            return (), "truncated_lineage"
        if child_event.timestamp < parent_event.timestamp:
            return (), "temporal_inversion"

        lineage.append(parent_event)
        visited_guids.add(parent_guid)
        child_event = parent_event

    return tuple(lineage), None


def _is_process_create(event: NormalizedEvent) -> bool:
    return (
        event.source == "sysmon"
        and event.source_layer == "raw_telemetry"
        and event.event_type == "process_create"
    )


def _is_network_connection(event: NormalizedEvent) -> bool:
    return (
        event.source == "sysmon"
        and event.source_layer == "raw_telemetry"
        and event.event_type == "network_connection"
    )


def _process_guid(event: NormalizedEvent) -> str | None:
    return event.process.process_guid if event.process is not None else None


def _failed(diagnostic: R1SelectorDiagnostic) -> R1SelectorResult:
    return R1SelectorResult(selection=None, diagnostics=(diagnostic,))


__all__ = [
    "R1LineageSelection",
    "R1SelectorDiagnostic",
    "R1SelectorPolicy",
    "R1SelectorResult",
    "select_r1_lineage",
]
