import copy
import json
from dataclasses import fields
from pathlib import Path

import pytest

from incident_awareness.evidence import EvidenceCandidate, extract_evidence

FIXTURE_PATH = Path(__file__).parents[1] / "fixtures" / "evidence_extractor" / "s0_cases.json"
CASES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_extract_evidence_matches_s0_cases(case: dict[str, object]) -> None:
    event = case["event"]
    expected = case["expected"]

    assert isinstance(event, dict)
    assert isinstance(expected, list)

    candidates = extract_evidence(event)

    actual = [
        {
            "evidence_type": candidate.evidence_type,
            "features": candidate.features,
        }
        for candidate in candidates
    ]
    assert actual == expected


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case["expected"]],
    ids=[case["name"] for case in CASES if case["expected"]],
)
def test_candidate_preserves_event_identity(case: dict[str, object]) -> None:
    event = case["event"]
    assert isinstance(event, dict)

    (candidate,) = extract_evidence(event)

    assert candidate.run_id == event["run_id"]
    assert candidate.timestamp == event["timestamp"]
    assert candidate.entity_id == event["host_id"]
    assert candidate.source_event_ids == [event["event_id"]]
    assert candidate.source_event_ids != [event["source_event_id"]]


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case["expected"]],
    ids=[case["name"] for case in CASES if case["expected"]],
)
def test_extraction_is_deterministic_and_does_not_mutate_input(
    case: dict[str, object],
) -> None:
    event = case["event"]
    assert isinstance(event, dict)
    original = copy.deepcopy(event)

    first = extract_evidence(event)
    second = extract_evidence(event)

    assert first == second
    assert first[0].evidence_id == second[0].evidence_id
    assert event == original


def test_evidence_candidate_has_only_s0_fields() -> None:
    assert {field.name for field in fields(EvidenceCandidate)} == {
        "evidence_id",
        "run_id",
        "timestamp",
        "entity_id",
        "evidence_type",
        "source_event_ids",
        "extractor_version",
        "features",
    }
