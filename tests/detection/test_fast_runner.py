import hashlib
import json
from pathlib import Path

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"


def run(tmp_path, **overrides):
    args = {
        "csv_path": FIXTURES / "handoff.csv",
        "config_path": FIXTURES / "handoff_config.json",
        "run_id": "RUN-20260913-001",
        "output_path": tmp_path / "hits.jsonl",
        "trace_path": tmp_path / "trace.json",
    }
    args.update(overrides)
    return run_fast_handoff(**args)


def test_handoff_fields_and_provenance(tmp_path):
    # Given / When: a mock raw row precedes the qualifying row.
    assert run(tmp_path) == 1
    hit = json.loads((tmp_path / "hits.jsonl").read_text())
    # Then: original row position and every handoff field are preserved.
    assert hit == {
        "hit_id": "RUN-20260913-001-hit-2",
        "run_id": "RUN-20260913-001",
        "timestamp": "2026-09-13T00:00:01.123Z",
        "detector_engine": "hayabusa",
        "detector_engine_version": "4.0.0",
        "rule_id": "mock-rule",
        "rule_version": "mock-v1",
        "alert_key": "mock-alert",
        "native_host_id": "WIN-01",
        "native_record_ref": "11",
        "detector_config_version": "mock-handoff-v1",
    }
    trace = json.loads((tmp_path / "trace.json").read_text())
    assert trace["hits"][0]["source_row_index"] == 2
    assert (
        trace["input_sha256"] == hashlib.sha256((FIXTURES / "handoff.csv").read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    "run_id", ["", "   ", " RUN-20260913-001", "RUN-20260913-001 ", "RUN-20260230-001"]
)
def test_rejects_invalid_run_id(tmp_path, run_id):
    # Given / When / Then
    with pytest.raises(ValueError):
        run(tmp_path, run_id=run_id)
    assert not (tmp_path / "hits.jsonl").exists()


def test_missing_metadata_fails_before_output(tmp_path):
    # Given
    config = json.loads((FIXTURES / "handoff_config.json").read_text())
    config["rule_metadata"] = {}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    # When / Then
    with pytest.raises(KeyError):
        run(tmp_path, config_path=path)
    assert not (tmp_path / "hits.jsonl").exists()


def test_preserves_existing_output(tmp_path):
    # Given
    (tmp_path / "hits.jsonl").write_text("keep")
    # When / Then
    with pytest.raises(FileExistsError):
        run(tmp_path)
    assert (tmp_path / "hits.jsonl").read_text() == "keep"


def test_zero_hit_is_empty_handoff_not_detection_miss(tmp_path):
    # Given
    path = tmp_path / "empty.csv"
    path.write_text("Timestamp,RuleID\n")
    # When / Then
    assert run(tmp_path, csv_path=path) == 0
    assert (tmp_path / "hits.jsonl").read_text() == ""
    assert json.loads((tmp_path / "trace.json").read_text())["hit_count"] == 0
