import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence

EXTRACTOR_VERSION = "r1-v0.1"

_REMOTE_PROCESS_NETWORK_FOLLOW_ON = "remote_process_network_follow_on"
_REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION = "remote_session_process_lineage_deviation"

LineageStatus = Literal["complete", "truncated", "cycle"]
LineageFailureReason = Literal["missing_parent", "duplicate_process_guid"]


@dataclass(frozen=True, slots=True)
class ApprovedLineagePolicy:
    """평가 전에 동결한 root-to-terminal 프로세스 이름 계보 정책."""

    policy_id: str
    version: str
    config_hash: str
    approved_lineage: tuple[str, ...]

    def __post_init__(self) -> None:
        provenance = {
            "policy_id": self.policy_id,
            "version": self.version,
            "config_hash": self.config_hash,
        }
        for field_name, value in provenance.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-blank string")

        if not isinstance(self.approved_lineage, tuple) or not self.approved_lineage:
            raise ValueError("approved_lineage must be a non-empty tuple")
        if any(
            not isinstance(process_name, str) or not process_name.strip()
            for process_name in self.approved_lineage
        ):
            raise ValueError("approved_lineage must contain only non-blank strings")


@dataclass(frozen=True, slots=True)
class _LineageCorrelation:
    status: LineageStatus
    events: tuple[NormalizedEvent, ...]
    failure_reason: LineageFailureReason | None = None
    missing_parent_process_guid: str | None = None
    duplicate_process_guid: str | None = None


def extract_remote_process_network_follow_on(
    process_event: NormalizedEvent,
    network_event: NormalizedEvent,
) -> list[Evidence]:
    """R1 프로세스-네트워크 후속 연결 Evidence 후보를 추출한다."""
    if not isinstance(process_event, NormalizedEvent) or not isinstance(
        network_event,
        NormalizedEvent,
    ):
        return []

    if not _has_expected_event_contract(process_event, network_event):
        return []

    process_guid = _process_guid(process_event)
    network_process_guid = _process_guid(network_event)

    # GUID가 없는 Event끼리 None 비교로 연결하지 않는다.
    if process_guid is None or network_process_guid is None:
        return []

    if process_event.run_id != network_event.run_id:
        return []
    if process_event.host_id != network_event.host_id:
        return []
    if process_guid != network_process_guid:
        return []
    if network_event.timestamp < process_event.timestamp:
        return []

    event_ids = [process_event.event_id, network_event.event_id]

    return [
        Evidence.model_validate(
            {
                "evidence_id": _deterministic_evidence_id(
                    run_id=process_event.run_id,
                    event_ids=event_ids,
                ),
                "run_id": process_event.run_id,
                "timestamp": max(process_event.timestamp, network_event.timestamp),
                "entity_id": process_event.host_id,
                "evidence_type": _REMOTE_PROCESS_NETWORK_FOLLOW_ON,
                "event_ids": event_ids,
                "derived_from_source_layer": "raw_telemetry",
                "feature_channel_group": "fusion_feature",
                "extractor_version": EXTRACTOR_VERSION,
            }
        )
    ]


def extract_remote_session_process_lineage_deviation(
    events: Iterable[NormalizedEvent],
    anchor_event: NormalizedEvent,
    terminal_event: NormalizedEvent,
    approved_policy: ApprovedLineagePolicy,
) -> list[Evidence]:
    """동결된 정책과 다른 complete 프로세스 계보 Evidence를 추출한다."""
    if not isinstance(anchor_event, NormalizedEvent) or not isinstance(
        terminal_event,
        NormalizedEvent,
    ):
        return []
    if not isinstance(approved_policy, ApprovedLineagePolicy):
        raise TypeError("approved_policy must be an ApprovedLineagePolicy")

    event_list = tuple(events)
    if not all(isinstance(event, NormalizedEvent) for event in event_list):
        return []
    if not _is_eligible_process_event(anchor_event) or not _is_eligible_process_event(
        terminal_event
    ):
        return []
    if anchor_event.run_id != terminal_event.run_id:
        return []
    if anchor_event.host_id != terminal_event.host_id:
        return []

    correlation = _reconstruct_process_lineage(event_list, anchor_event, terminal_event)
    if correlation.status != "complete":
        return []

    observed_lineage = tuple(_canonical_process_name(event) for event in correlation.events)
    approved_lineage = tuple(name.casefold() for name in approved_policy.approved_lineage)
    if observed_lineage == approved_lineage:
        return []

    event_ids = [event.event_id for event in correlation.events]
    timestamp = max(event.timestamp for event in correlation.events)

    return [
        Evidence.model_validate(
            {
                "evidence_id": _deterministic_lineage_deviation_id(
                    run_id=terminal_event.run_id,
                    event_ids=event_ids,
                    approved_policy=approved_policy,
                ),
                "run_id": terminal_event.run_id,
                "timestamp": timestamp,
                "entity_id": terminal_event.host_id,
                "evidence_type": _REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION,
                "event_ids": event_ids,
                "derived_from_source_layer": "raw_telemetry",
                "feature_channel_group": "fusion_feature",
                "extractor_version": EXTRACTOR_VERSION,
                "features": {
                    "policy_id": approved_policy.policy_id,
                    "version": approved_policy.version,
                    "config_hash": approved_policy.config_hash,
                },
            }
        )
    ]


def _has_expected_event_contract(
    process_event: NormalizedEvent,
    network_event: NormalizedEvent,
) -> bool:
    return (
        process_event.source == "sysmon"
        and network_event.source == "sysmon"
        and process_event.source_layer == "raw_telemetry"
        and network_event.source_layer == "raw_telemetry"
        and process_event.event_type == "process_create"
        and network_event.event_type == "network_connection"
    )


def _reconstruct_process_lineage(
    events: tuple[NormalizedEvent, ...],
    anchor_event: NormalizedEvent,
    terminal_event: NormalizedEvent,
) -> _LineageCorrelation:
    process_events_by_guid = _index_process_events(
        events,
        anchor_event=anchor_event,
        terminal_event=terminal_event,
    )
    observed_from_terminal = [terminal_event]
    anchor_guid = _process_guid(anchor_event)
    terminal_guid = _process_guid(terminal_event)
    if anchor_guid is None or terminal_guid is None:
        return _LineageCorrelation(
            status="truncated",
            events=(terminal_event,),
            failure_reason="missing_parent",
        )

    seen_process_guids = {terminal_guid}
    current = terminal_event

    while True:
        current_guid = _process_guid(current)
        if current_guid is None:
            return _LineageCorrelation(
                status="truncated",
                events=tuple(reversed(observed_from_terminal)),
                failure_reason="missing_parent",
            )

        events_for_current_guid = process_events_by_guid.get(current_guid, ())
        if len(events_for_current_guid) > 1:
            return _LineageCorrelation(
                status="truncated",
                events=tuple(reversed(observed_from_terminal)),
                failure_reason="duplicate_process_guid",
                duplicate_process_guid=current_guid,
            )

        if current_guid == anchor_guid:
            return _LineageCorrelation(
                status="complete",
                events=tuple(reversed(observed_from_terminal)),
            )

        parent_process_guid = _parent_process_guid(current)
        if parent_process_guid is None:
            return _LineageCorrelation(
                status="truncated",
                events=tuple(reversed(observed_from_terminal)),
                failure_reason="missing_parent",
                missing_parent_process_guid=anchor_guid,
            )

        if parent_process_guid in seen_process_guids:
            return _LineageCorrelation(
                status="cycle",
                events=tuple(reversed(observed_from_terminal)),
            )

        parent_candidates = process_events_by_guid.get(parent_process_guid, ())
        if len(parent_candidates) > 1:
            return _LineageCorrelation(
                status="truncated",
                events=tuple(reversed(observed_from_terminal)),
                failure_reason="duplicate_process_guid",
                duplicate_process_guid=parent_process_guid,
            )

        if not parent_candidates or not _is_parent_edge(
            child=current,
            parent=parent_candidates[0],
        ):
            return _LineageCorrelation(
                status="truncated",
                events=tuple(reversed(observed_from_terminal)),
                failure_reason="missing_parent",
                missing_parent_process_guid=parent_process_guid,
            )

        current = parent_candidates[0]
        seen_process_guids.add(parent_process_guid)
        observed_from_terminal.append(current)


def _index_process_events(
    events: tuple[NormalizedEvent, ...],
    *,
    anchor_event: NormalizedEvent,
    terminal_event: NormalizedEvent,
) -> dict[str, tuple[NormalizedEvent, ...]]:
    events_by_id: dict[str, NormalizedEvent] = {}
    for event in (*events, anchor_event, terminal_event):
        if event.event_id in events_by_id:
            continue
        if not _is_eligible_process_event(event):
            continue
        if event.run_id != terminal_event.run_id or event.host_id != terminal_event.host_id:
            continue
        events_by_id[event.event_id] = event

    grouped_events: dict[str, list[NormalizedEvent]] = {}
    for event in events_by_id.values():
        process_guid = _process_guid(event)
        if process_guid is not None:
            grouped_events.setdefault(process_guid, []).append(event)

    return {process_guid: tuple(group) for process_guid, group in grouped_events.items()}


def _is_parent_edge(*, child: NormalizedEvent, parent: NormalizedEvent) -> bool:
    if not _is_eligible_process_event(child) or not _is_eligible_process_event(parent):
        return False

    child_parent_guid = _parent_process_guid(child)
    parent_guid = _process_guid(parent)
    return (
        child_parent_guid is not None
        and parent_guid is not None
        and child.run_id == parent.run_id
        and child.host_id == parent.host_id
        and child_parent_guid == parent_guid
        and child.timestamp >= parent.timestamp
    )


def _is_eligible_process_event(event: NormalizedEvent) -> bool:
    return (
        event.source == "sysmon"
        and event.source_layer == "raw_telemetry"
        and event.event_type == "process_create"
        and _process_guid(event) is not None
    )


def _process_guid(event: NormalizedEvent) -> str | None:
    if event.process is None:
        return None
    return event.process.process_guid


def _parent_process_guid(event: NormalizedEvent) -> str | None:
    if event.process is None:
        return None
    return event.process.parent_process_guid


def _process_name(event: NormalizedEvent) -> str | None:
    if event.process is None:
        return None
    return event.process.name


def _canonical_process_name(event: NormalizedEvent) -> str | None:
    process_name = _process_name(event)
    return process_name.casefold() if process_name is not None else None


def _deterministic_evidence_id(*, run_id: str, event_ids: list[str]) -> str:
    # Provenance 표시 순서와 무관하게 같은 Event 집합은 같은 ID를 사용한다.
    canonical_event_ids = sorted(event_ids)
    identity = json.dumps(
        [run_id, canonical_event_ids, _REMOTE_PROCESS_NETWORK_FOLLOW_ON, EXTRACTOR_VERSION],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"E-{uuid5(NAMESPACE_URL, identity)}"


def _deterministic_lineage_deviation_id(
    *,
    run_id: str,
    event_ids: list[str],
    approved_policy: ApprovedLineagePolicy,
) -> str:
    # Policy provenance까지 identity에 포함해 다른 승인 기준의 판단을 구분한다.
    canonical_event_ids = sorted(event_ids)
    identity = json.dumps(
        [
            run_id,
            canonical_event_ids,
            _REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION,
            EXTRACTOR_VERSION,
            approved_policy.policy_id,
            approved_policy.version,
            approved_policy.config_hash,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"E-{uuid5(NAMESPACE_URL, identity)}"
