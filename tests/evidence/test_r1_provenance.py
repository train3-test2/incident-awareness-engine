from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_provenance import resolve_r1_evidence_provenance

_BASE_TIME = datetime(2026, 10, 6, 2, 0, tzinfo=UTC)
_RUN_ID = "RUN-20261006-001"
_HOST_ID = "TARGET-A"


def _event(
    event_id: str,
    *,
    offset_seconds: int,
    run_id: str = _RUN_ID,
    host_id: str = _HOST_ID,
    event_type: str = "process_create",
) -> NormalizedEvent:
    timestamp = _BASE_TIME + timedelta(seconds=offset_seconds)
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": run_id,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": timestamp,
            "ingest_time": timestamp,
            "host_id": host_id,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"source-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": f"raw-{run_id}",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": offset_seconds + 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
        }
    )


def _evidence(
    evidence_id: str,
    event_ids: list[str],
    *,
    run_id: str = _RUN_ID,
    entity_id: str = _HOST_ID,
    evidence_type: str = "remote_process_network_follow_on",
) -> Evidence:
    return Evidence.model_validate(
        {
            "evidence_id": evidence_id,
            "run_id": run_id,
            "timestamp": _BASE_TIME + timedelta(seconds=10),
            "entity_id": entity_id,
            "evidence_type": evidence_type,
            "event_ids": event_ids,
            "derived_from_source_layer": "raw_telemetry",
            "feature_channel_group": "fusion_feature",
            "extractor_version": "r1-v0.1",
        }
    )


def test_resolves_multiple_evidences_and_preserves_semantic_event_order() -> None:
    # Given
    anchor = _event("evt-anchor", offset_seconds=0)
    middle = _event("evt-middle", offset_seconds=1)
    terminal = _event("evt-terminal", offset_seconds=2)
    network = _event(
        "evt-network",
        offset_seconds=3,
        event_type="network_connection",
    )
    lineage_evidence = _evidence(
        "E-lineage",
        [anchor.event_id, middle.event_id, terminal.event_id],
        evidence_type="remote_session_process_lineage_deviation",
    )
    network_evidence = _evidence(
        "E-network",
        [terminal.event_id, network.event_id],
    )

    # When
    result = resolve_r1_evidence_provenance(
        [lineage_evidence, network_evidence],
        [network, terminal, anchor, middle],
    )

    # Then
    assert [item.evidence for item in result] == [lineage_evidence, network_evidence]
    assert [event.event_id for event in result[0].resolved_events] == lineage_evidence.event_ids
    assert [event.event_id for event in result[1].resolved_events] == network_evidence.event_ids


def test_rejects_missing_referenced_event_without_returning_partial_result() -> None:
    # Given
    process_event = _event("evt-process", offset_seconds=0)
    evidence = _evidence(
        "E-missing",
        [process_event.event_id, "evt-missing"],
    )

    # When
    with pytest.raises(ValueError, match="missing NormalizedEvent") as error_info:
        resolve_r1_evidence_provenance([evidence], [process_event])

    # Then
    assert "evt-missing" in str(error_info.value)


def test_rejects_referenced_event_run_id_mismatch() -> None:
    # Given
    event = _event(
        "evt-other-run",
        offset_seconds=0,
        run_id="RUN-20261006-002",
    )
    evidence = _evidence("E-run-mismatch", [event.event_id])

    # When
    with pytest.raises(ValueError, match="different run_id") as error_info:
        resolve_r1_evidence_provenance([evidence], [event])

    # Then
    assert event.event_id in str(error_info.value)


def test_rejects_referenced_event_host_id_mismatch() -> None:
    # Given
    event = _event(
        "evt-other-host",
        offset_seconds=0,
        host_id="TARGET-B",
    )
    evidence = _evidence("E-host-mismatch", [event.event_id])

    # When
    with pytest.raises(ValueError, match="entity_id") as error_info:
        resolve_r1_evidence_provenance([evidence], [event])

    # Then
    assert "host_id" in str(error_info.value)


def test_rejects_duplicate_normalized_event_id_even_when_events_are_identical() -> None:
    # Given
    event = _event("evt-duplicate", offset_seconds=0)
    evidence = _evidence("E-duplicate-event", [event.event_id])

    # When
    with pytest.raises(ValueError, match="unique NormalizedEvent.event_id") as error_info:
        resolve_r1_evidence_provenance([evidence], [event, event])

    # Then
    assert event.event_id in str(error_info.value)


def test_allows_unreferenced_events_in_event_batch() -> None:
    # Given
    process_event = _event("evt-process", offset_seconds=0)
    network_event = _event(
        "evt-network",
        offset_seconds=1,
        event_type="network_connection",
    )
    unrelated_event = _event("evt-unrelated", offset_seconds=2)
    evidence = _evidence(
        "E-with-unrelated-input",
        [process_event.event_id, network_event.event_id],
    )

    # When
    result = resolve_r1_evidence_provenance(
        [evidence],
        [unrelated_event, process_event, network_event],
    )

    # Then
    assert [event.event_id for event in result[0].resolved_events] == evidence.event_ids
    assert unrelated_event not in result[0].resolved_events


def test_exposes_raw_provenance_only_through_resolved_normalized_event() -> None:
    # Given
    event = _event("evt-provenance", offset_seconds=0)
    evidence = _evidence("E-provenance", [event.event_id])

    # When
    result = resolve_r1_evidence_provenance([evidence], [event])
    resolved_event = result[0].resolved_events[0]

    # Then
    assert resolved_event.source_event_id == "source-evt-provenance"
    assert resolved_event.raw_ref.source_record_id == "record-evt-provenance"
    assert "source_event_id" not in result[0].evidence.model_dump()
    assert "raw_ref" not in result[0].evidence.model_dump()


def test_allows_multiple_runs_when_each_evidence_matches_its_events() -> None:
    # Given
    first_event = _event("evt-run-1", offset_seconds=0)
    second_event = _event(
        "evt-run-2",
        offset_seconds=1,
        run_id="RUN-20261006-002",
    )
    first_evidence = _evidence("E-run-1", [first_event.event_id])
    second_evidence = _evidence(
        "E-run-2",
        [second_event.event_id],
        run_id=second_event.run_id,
    )

    # When
    result = resolve_r1_evidence_provenance(
        [first_evidence, second_evidence],
        [second_event, first_event],
    )

    # Then
    assert [item.evidence.run_id for item in result] == [first_event.run_id, second_event.run_id]
    assert [item.resolved_events[0].run_id for item in result] == [
        first_event.run_id,
        second_event.run_id,
    ]
