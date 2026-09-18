import json
from dataclasses import replace
from pathlib import Path

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionSelection,
    FastHitHandoff,
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


def _read_multi_hit_handoff(tmp_path: Path):
    csv_path = tmp_path / "multi.csv"
    csv_path.write_text(
        "Timestamp,RuleID,Computer,RecordID\n"
        "2026-09-13T00:00:00.000Z,mock-ignored,WIN-01,10\n"
        "2026-09-13T00:00:01.123Z,mock-rule,WIN-01,11\n"
        "2026-09-13T00:00:02.123Z,mock-rule-2,WIN-01,12\n",
        encoding="utf-8",
    )
    config = json.loads((FIXTURES / "handoff_config.json").read_text(encoding="utf-8"))
    config["qualifying_rule_ids"].append("mock-rule-2")
    config["rule_metadata"]["mock-rule-2"] = {
        "rule_version": "mock-v2",
        "alert_key": "mock-alert-2",
    }
    config_path = tmp_path / "multi_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=csv_path,
        config_path=config_path,
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
    assert result.selected_source_hit_id == f"{RUN_ID}-hit-2"


def test_maps_native_host_to_distinct_canonical_entity_id(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    result = adapt_fast_hit_handoff(
        handoff,
        entity_id="endpoint-01",
        selection=FastDetectionSelection(
            detector_status="detected",
            selected_hit_id=f"{RUN_ID}-hit-2",
        ),
        entity_mapper=lambda native_host_id: {"WIN-01": "endpoint-01"}.get(native_host_id),
    )

    assert result.detection_result.entity_id == "endpoint-01"


def test_retains_all_input_hit_ids_and_selected_hit_provenance(tmp_path: Path) -> None:
    handoff = _read_multi_hit_handoff(tmp_path)

    result = adapt_fast_hit_handoff(
        handoff,
        entity_id="WIN-01",
        selection=FastDetectionSelection(
            detector_status="detected",
            selected_hit_id=f"{RUN_ID}-hit-3",
        ),
    )

    assert result.source_hit_ids == (f"{RUN_ID}-hit-2", f"{RUN_ID}-hit-3")
    assert result.selected_source_hit_id == f"{RUN_ID}-hit-3"
    assert result.detection_result.rule_id == "mock-rule-2"


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


def test_rejects_selected_hit_from_a_different_entity(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="native_host_id"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id="WIN-02",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-2",
            ),
        )


def test_rejects_handoff_with_record_run_id_mismatch(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)
    mismatched_record = handoff.records[0].model_copy(update={"run_id": "RUN-20260914-001"})
    mismatched_handoff = replace(handoff, records=(mismatched_record,))

    with pytest.raises(ValueError, match="run_id"):
        adapt_fast_hit_handoff(
            mismatched_handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-2",
            ),
        )


def test_rejects_handoff_with_rule_provenance_mismatch(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)
    mismatched_record = handoff.records[0].model_copy(update={"rule_id": "different-rule"})
    mismatched_handoff = FastHitHandoff(records=(mismatched_record,), trace=handoff.trace)

    with pytest.raises(ValueError, match="rule_id"):
        adapt_fast_hit_handoff(
            mismatched_handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-2",
            ),
        )


def test_adapter_rejects_hit_id_with_source_row_outside_input_range(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)
    mismatched_record = handoff.records[0].model_copy(update={"hit_id": f"{RUN_ID}-hit-3"})
    mismatched_trace_entry = handoff.trace.hits[0].model_copy(
        update={"hit_id": mismatched_record.hit_id, "source_row_index": 3}
    )
    mismatched_trace = handoff.trace.model_copy(update={"hits": [mismatched_trace_entry]})
    mismatched_handoff = FastHitHandoff(records=(mismatched_record,), trace=mismatched_trace)

    with pytest.raises(ValueError, match="input_row_count"):
        adapt_fast_hit_handoff(
            mismatched_handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=mismatched_record.hit_id,
            ),
        )


@pytest.mark.parametrize(
    ("trace_field", "error_message"),
    [
        ("input_sha256", "input CSV SHA-256"),
        ("config_sha256", "config SHA-256"),
    ],
)
def test_adapter_rechecks_input_and_config_provenance(
    tmp_path: Path,
    trace_field: str,
    error_message: str,
) -> None:
    handoff = _read_handoff(tmp_path)
    tampered_trace = handoff.trace.model_copy(update={trace_field: "0" * 64})
    tampered_handoff = replace(handoff, trace=tampered_trace)

    with pytest.raises(ValueError, match=error_message):
        adapt_fast_hit_handoff(
            tampered_handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(
                detector_status="detected",
                selected_hit_id=f"{RUN_ID}-hit-2",
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
    assert result.selected_source_hit_id is None


def test_rejects_miss_when_handoff_has_qualifying_hit_for_entity(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="miss selection contradicts"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id="WIN-01",
            selection=FastDetectionSelection(detector_status="miss"),
        )


def test_allows_miss_when_handoff_hits_belong_to_other_entities(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    result = adapt_fast_hit_handoff(
        handoff,
        entity_id="WIN-02",
        selection=FastDetectionSelection(detector_status="miss"),
    )

    assert result.detection_result.detector_status == "miss"


def test_rejects_miss_when_mapper_resolves_hit_to_entity(tmp_path: Path) -> None:
    handoff = _read_handoff(tmp_path)

    with pytest.raises(ValueError, match="miss selection contradicts"):
        adapt_fast_hit_handoff(
            handoff,
            entity_id="endpoint-01",
            selection=FastDetectionSelection(detector_status="miss"),
            entity_mapper=lambda native_host_id: {"WIN-01": "endpoint-01"}.get(native_host_id),
        )


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
    assert result.selected_source_hit_id is None


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
