from pathlib import Path

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionSelection,
    adapt_fast_hit_handoff,
    build_not_evaluated_detection_result,
    read_fast_hit_handoff,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"
RUN_ID = "RUN-20260913-001"


def _read_handoff(tmp_path: Path, *, empty: bool = False):
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    csv_path = FIXTURES / "handoff.csv"
    if empty:
        csv_path = tmp_path / "empty.csv"
        csv_path.write_text("Timestamp,RuleID\n", encoding="utf-8")
    run_fast_handoff(
        csv_path=csv_path,
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=jsonl_path,
        trace_path=trace_path,
    )
    return read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_maps_detected_selection_to_detection_result(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    result = adapt_fast_hit_handoff(
        handoff,
        entity_id="WIN-01",
        selection=FastDetectionSelection(
            detector_status="detected",
            selected_hit_id=f"{RUN_ID}-hit-2",
            severity="high",
        ),
    )

    assert result.detection_result.model_dump(mode="json") == {
        "run_id": RUN_ID,
        "entity_id": "WIN-01",
        "detector_time": "2026-09-13T00:00:01.123Z",
        "detector_status": "detected",
        "detector_id": "hayabusa",
        "rule_id": "mock-rule",
        "rule_version": "mock-v1",
        "severity": "high",
    }
    assert result.source_hit_ids == (f"{RUN_ID}-hit-2",)


def test_rejects_selection_that_is_not_in_the_handoff(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="selected_hit_id"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-999",
            ),
        )


@pytest.mark.parametrize("entity_id", ["", "   ", " WIN-01", "WIN-01 "])
def test_rejects_invalid_entity_id(tmp_path: Path, entity_id: str) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="entity_id"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id=entity_id,
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-2",
            ),
        )


def test_maps_completed_empty_handoff_to_explicit_miss(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path, empty=True)

    result = adapt_fast_hit_handoff(
        handoff,
        entity_id="WIN-01",
        selection=FastDetectionSelection(detector_status="miss"),
    )

    assert result.detection_result.model_dump(mode="json") == {
        "run_id": RUN_ID,
        "entity_id": "WIN-01",
        "detector_time": None,
        "detector_status": "miss",
        "detector_id": None,
        "rule_id": None,
        "rule_version": None,
        "severity": None,
    }
    assert result.source_hit_ids == ()


def test_builds_not_evaluated_without_a_handoff() -> None:
    result = build_not_evaluated_detection_result(run_id=RUN_ID, entity_id="WIN-01")

    assert result.detection_result.model_dump(mode="json") == {
        "run_id": RUN_ID,
        "entity_id": "WIN-01",
        "detector_time": None,
        "detector_status": "not_evaluated",
        "detector_id": None,
        "rule_id": None,
        "rule_version": None,
        "severity": None,
    }
    assert result.source_hit_ids == ()


@pytest.mark.parametrize(
    "selection",
    [
        {"detector_status": "detected"},
        {"detector_status": "miss", "selected_hit_id": f"{RUN_ID}-hit-2"},
        {"detector_status": "not_evaluated", "severity": "high"},
    ],
)
def test_selection_rejects_invalid_status_metadata(selection: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        FastDetectionSelection.model_validate(selection)


def test_rejects_not_evaluated_from_completed_handoff(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="not_evaluated"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(detector_status="not_evaluated"),
        )
