from pathlib import Path

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.integration.fast_hit_handoff import (
    DetectedFastHitSelection,
    adapt_detected_fast_hit,
    read_fast_hit_handoff,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"
RUN_ID = "RUN-20260913-001"


def _read_handoff(tmp_path: Path):
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=FIXTURES / "handoff.csv",
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=jsonl_path,
        trace_path=trace_path,
    )
    return read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_adapts_role5_selected_hit_to_detection_result(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    result = adapt_detected_fast_hit(
        handoff,
        entity_id="WIN-01",
        selection=DetectedFastHitSelection(
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
        adapt_detected_fast_hit(
            handoff,
            entity_id="WIN-01",
            selection=DetectedFastHitSelection(
                selected_hit_id=f"{RUN_ID}-hit-999",
            ),
        )


@pytest.mark.parametrize("entity_id", ["", "   ", " WIN-01", "WIN-01 "])
def test_rejects_invalid_entity_id(tmp_path: Path, entity_id: str) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="entity_id"):
        adapt_detected_fast_hit(
            handoff,
            entity_id=entity_id,
            selection=DetectedFastHitSelection(selected_hit_id=f"{RUN_ID}-hit-2"),
        )


def test_selection_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError):
        DetectedFastHitSelection.model_validate(
            {
                "selected_hit_id": f"{RUN_ID}-hit-2",
                "severity": "high",
                "detector_time": "2026-09-13T00:00:01.123Z",
            }
        )
