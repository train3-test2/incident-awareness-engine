import copy
import json
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence import extract_evidence

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "evidence_extractor" / "s0_cases.json"
VOCABULARY_PATH = Path(__file__).parents[2] / "configs" / "evidence_types_v0.2.yaml"
CASES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_extract_evidence_matches_s0_cases(case: dict[str, object]) -> None:
    # Given
    event = case["event"]
    expected = case["expected"]

    assert isinstance(event, dict)
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
    event = case["event"]
    assert isinstance(event, dict)
    timestamp = event["timestamp"]
    assert isinstance(timestamp, str)

    # When
    (evidence,) = extract_evidence(event)

    # Then
    assert isinstance(evidence, Evidence)
    assert evidence.run_id == event["run_id"]
    assert isinstance(evidence.timestamp, datetime)
    assert evidence.timestamp == datetime.fromisoformat(timestamp)
    assert evidence.entity_id == event["host_id"]
    assert evidence.event_ids == [event["event_id"]]
    assert evidence.event_ids != [event["source_event_id"]]
    assert evidence.derived_from_source_layer == event["source_layer"]
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
    event = case["event"]
    assert isinstance(event, dict)
    original = copy.deepcopy(event)

    # When
    first = extract_evidence(event)
    second = extract_evidence(event)

    # Then
    assert first == second
    assert first[0].evidence_id == second[0].evidence_id
    assert event == original


def test_output_uses_common_evidence_contract() -> None:
    # Given
    case = next(case for case in CASES if case["expected"])
    event = case["event"]
    assert isinstance(event, dict)

    # When
    (evidence,) = extract_evidence(event)

    # Then
    assert set(evidence.model_dump()) == {
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


def test_different_event_ids_produce_different_evidence_ids() -> None:
    # Given
    case = next(case for case in CASES if case["expected"])
    first_event = copy.deepcopy(case["event"])
    second_event = copy.deepcopy(case["event"])
    assert isinstance(first_event, dict)
    assert isinstance(second_event, dict)
    second_event["event_id"] = "evt-process-different"

    # When
    (first_evidence,) = extract_evidence(first_event)
    (second_evidence,) = extract_evidence(second_event)

    # Then
    assert first_evidence.evidence_type == second_evidence.evidence_type
    assert first_evidence.evidence_id != second_evidence.evidence_id


def test_generated_evidence_types_match_vocabulary() -> None:
    # Given
    vocabulary = yaml.safe_load(VOCABULARY_PATH.read_text(encoding="utf-8"))

    # When
    generated_types = {
        evidence.evidence_type for case in CASES for evidence in extract_evidence(case["event"])
    }

    # Then
    assert vocabulary == {
        "version": "v0.2",
        "evidence_types": [
            "encoded_powershell_command",
            "script_interpreter_external_connection",
        ],
    }
    assert generated_types == set(vocabulary["evidence_types"])
