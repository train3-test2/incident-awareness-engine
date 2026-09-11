import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence import extract_evidence

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "evidence_extractor" / "s0_cases.json"
VOCABULARY_PATH = Path(__file__).parents[2] / "configs" / "evidence_types_v0.2.yaml"
CASES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _case_event(case: dict[str, object]) -> NormalizedEvent:
    event = case["event"]
    assert isinstance(event, dict)
    return NormalizedEvent.model_validate(event)


def _normalized_event(
    *,
    event_id: str,
    event_type: str,
    process: ProcessInfo,
    network: NetworkInfo | None = None,
) -> NormalizedEvent:
    timestamp = datetime(2026, 9, 11, 1, 2, 3, 456000, tzinfo=UTC)
    return NormalizedEvent(
        event_id=event_id,
        run_id="RUN-20260911-001",
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        record_time=None,
        ingest_time=timestamp,
        host_id="HOST-INTEGRATION-001",
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=f"SOURCE-{event_id}",
        event_type=event_type,
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-001",
            segment_no=1,
            record_no=1,
        ),
        process=process,
        network=network,
    )


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_extract_evidence_matches_s0_cases(case: dict[str, object]) -> None:
    # Given
    event = _case_event(case)
    expected = case["expected"]

    assert isinstance(expected, list)

    # When
    evidences = extract_evidence(event)

    # Then
    assert isinstance(evidences, list)
    actual = [
        {
            "evidence_type": evidence.evidence_type,
            "features": evidence.features,
        }
        for evidence in evidences
    ]
    assert actual == expected


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case["expected"]],
    ids=[case["name"] for case in CASES if case["expected"]],
)
def test_evidence_preserves_event_provenance(case: dict[str, object]) -> None:
    # Given
    event = _case_event(case)

    # When
    (evidence,) = extract_evidence(event)

    # Then
    assert isinstance(evidence, Evidence)
    assert evidence.run_id == event.run_id
    assert isinstance(evidence.timestamp, datetime)
    assert evidence.timestamp == event.timestamp
    assert evidence.entity_id == event.host_id
    assert evidence.event_ids == [event.event_id]
    assert evidence.event_ids != [event.source_event_id]
    assert evidence.derived_from_source_layer == event.source_layer
    assert evidence.feature_channel_group == "fusion_feature"
    assert evidence.attack_technique_ids == []


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case["expected"]],
    ids=[case["name"] for case in CASES if case["expected"]],
)
def test_extraction_is_deterministic_and_does_not_mutate_input(
    case: dict[str, object],
) -> None:
    # Given
    event = _case_event(case)
    original = event.model_copy(deep=True)

    # When
    first = extract_evidence(event)
    second = extract_evidence(event)

    # Then
    assert first == second
    assert first[0].evidence_id == second[0].evidence_id
    assert first[0].evidence_id.startswith("E-")
    assert event == original


def test_output_uses_required_common_evidence_contract() -> None:
    # Given
    case = next(case for case in CASES if case["expected"])
    event = _case_event(case)

    # When
    (evidence,) = extract_evidence(event)

    # Then
    required_fields = {
        "evidence_id",
        "run_id",
        "timestamp",
        "entity_id",
        "evidence_type",
        "event_ids",
        "derived_from_source_layer",
        "feature_channel_group",
        "extractor_version",
        "attack_technique_ids",
        "features",
    }
    assert required_fields <= set(evidence.model_dump())


def test_different_event_ids_produce_different_evidence_ids() -> None:
    # Given
    case = next(case for case in CASES if case["expected"])
    first_event_payload = copy.deepcopy(case["event"])
    second_event_payload = copy.deepcopy(case["event"])
    assert isinstance(first_event_payload, dict)
    assert isinstance(second_event_payload, dict)
    second_event_payload["event_id"] = "evt-process-different"
    first_event = NormalizedEvent.model_validate(first_event_payload)
    second_event = NormalizedEvent.model_validate(second_event_payload)

    # When
    (first_evidence,) = extract_evidence(first_event)
    (second_evidence,) = extract_evidence(second_event)

    # Then
    assert first_evidence.evidence_type == second_evidence.evidence_type
    assert first_evidence.evidence_id != second_evidence.evidence_id


def test_generated_evidence_types_are_in_shared_vocabulary() -> None:
    # Given
    vocabulary = yaml.safe_load(VOCABULARY_PATH.read_text(encoding="utf-8"))

    # When
    generated_types = {
        evidence.evidence_type for case in CASES for evidence in extract_evidence(_case_event(case))
    }
    allowed_evidence_types = set(vocabulary["evidence_types"])
    s0_generated_types = {
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    }

    # Then
    assert generated_types == s0_generated_types
    assert s0_generated_types <= allowed_evidence_types


def test_extract_evidence_rejects_mapping_input() -> None:
    # Given
    event_mapping = _case_event(CASES[0]).model_dump()

    # When
    with pytest.raises(TypeError) as exc_info:
        extract_evidence(event_mapping)  # type: ignore[arg-type]

    # Then
    assert str(exc_info.value) == "event must be a NormalizedEvent"


def test_extracts_encoded_powershell_from_normalized_event() -> None:
    # Given
    event = _normalized_event(
        event_id="EVT-INTEGRATION-PROCESS-001",
        event_type="process_create",
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
    )

    # When
    evidences = extract_evidence(event)

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "encoded_powershell_command"
    assert evidence.event_ids == [event.event_id]
    assert evidence.entity_id == event.host_id
    assert evidence.run_id == event.run_id
    assert evidence.derived_from_source_layer == event.source_layer
    assert event.source_event_id not in evidence.event_ids


def test_extracts_external_connection_from_normalized_event() -> None:
    # Given
    event = _normalized_event(
        event_id="EVT-INTEGRATION-NETWORK-001",
        event_type="network_connection",
        process=ProcessInfo(
            pid=5252,
            name="cmd.exe",
            path=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            parent_pid=4242,
            parent_name="powershell.exe",
        ),
        network=NetworkInfo(
            protocol="tcp",
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="1.1.1.1",
            dst_port=8443,
        ),
    )

    # When
    evidences = extract_evidence(event)

    # Then
    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "script_interpreter_external_connection"
    assert evidence.event_ids == [event.event_id]
    assert evidence.entity_id == event.host_id
    assert evidence.run_id == event.run_id
    assert evidence.derived_from_source_layer == event.source_layer
    assert event.source_event_id not in evidence.event_ids


@pytest.mark.parametrize(
    ("destination_ip", "is_external"),
    [
        ("1.1.1.1", True),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("fe80::1", False),
        ("224.0.0.251", False),
        ("224.0.0.252", False),
        ("239.255.255.250", False),
        ("ff02::fb", False),
        ("2001:4860:4860::8888", True),
    ],
)
def test_external_ip_boundary(destination_ip: str, is_external: bool) -> None:
    # Given
    event = _normalized_event(
        event_id=f"EVT-IP-{destination_ip}",
        event_type="network_connection",
        process=ProcessInfo(name="pwsh.exe"),
        network=NetworkInfo(dst_ip=destination_ip),
    )

    # When
    evidences = extract_evidence(event)

    # Then
    assert bool(evidences) is is_external
