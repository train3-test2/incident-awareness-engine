import json
from uuid import NAMESPACE_URL, uuid5

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence

EXTRACTOR_VERSION = "r1-v0.1"

_REMOTE_PROCESS_NETWORK_FOLLOW_ON = "remote_process_network_follow_on"


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


def _process_guid(event: NormalizedEvent) -> str | None:
    if event.process is None:
        return None
    return event.process.process_guid


def _deterministic_evidence_id(*, run_id: str, event_ids: list[str]) -> str:
    # Provenance 표시 순서와 무관하게 같은 Event 집합은 같은 ID를 사용한다.
    canonical_event_ids = sorted(event_ids)
    identity = json.dumps(
        [run_id, canonical_event_ids, _REMOTE_PROCESS_NETWORK_FOLLOW_ON, EXTRACTOR_VERSION],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"E-{uuid5(NAMESPACE_URL, identity)}"
