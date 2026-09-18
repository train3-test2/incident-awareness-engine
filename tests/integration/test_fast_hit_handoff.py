import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.integration.fast_hit_handoff import read_fast_hit_handoff

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"
RUN_ID = "RUN-20260913-001"


def _create_handoff(tmp_path: Path) -> tuple[Path, Path]:
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=FIXTURES / "handoff.csv",
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=jsonl_path,
        trace_path=trace_path,
    )
    return jsonl_path, trace_path


def _rewrite_trace(trace_path: Path, payload: dict) -> None:
    trace_path.write_text(json.dumps(payload), encoding="utf-8")


def test_reads_valid_fast_hit_handoff(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)

    handoff = read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)

    assert len(handoff.records) == 1
    assert handoff.records[0].hit_id == f"{RUN_ID}-hit-2"
    assert handoff.records[0].timestamp == datetime(2026, 9, 13, 0, 0, 1, 123000, tzinfo=UTC)
    assert handoff.records[0].native_host_id == "WIN-01"
    assert handoff.trace.run_id == RUN_ID
    assert handoff.trace.config_path == str((FIXTURES / "handoff_config.json").resolve())


def test_reads_valid_empty_handoff(tmp_path: Path) -> None:
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("Timestamp,RuleID\n", encoding="utf-8")
    jsonl_path = tmp_path / "hits.jsonl"
    trace_path = tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=csv_path,
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=jsonl_path,
        trace_path=trace_path,
    )

    handoff = read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)

    assert handoff.records == ()
    assert handoff.trace.hit_count == 0


def test_rejects_mismatched_expected_run_id(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)

    with pytest.raises(ValueError, match="trace run_id"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id="RUN-20260914-001")


def test_rejects_tampered_jsonl_bytes(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    record = json.loads(jsonl_path.read_text(encoding="utf-8"))
    record["rule_id"] = "tampered-rule"
    jsonl_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_missing_input_csv_referenced_by_trace(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["input_csv"] = str(tmp_path / "missing.csv")
    trace["input_sha256"] = "0" * 64
    trace["config_sha256"] = "1" * 64
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="cannot read FastHit input CSV"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_input_csv_sha256_mismatch(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["input_sha256"] = "0" * 64
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="input CSV SHA-256"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_config_sha256_mismatch(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["config_sha256"] = "0" * 64
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="config SHA-256"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_trace_hit_count_mismatch(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["hit_count"] = 2
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="hit_count"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_record_with_non_contract_timestamp(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    record = json.loads(jsonl_path.read_text(encoding="utf-8"))
    record["timestamp"] = 0
    jsonl_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["output_sha256"] = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="invalid FastHitRecord"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_trace_record_provenance_mismatch(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["hits"][0]["rule_id"] = "different-rule"
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="rule_id"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_hit_id_with_mismatched_source_row_index(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    record = json.loads(jsonl_path.read_text(encoding="utf-8"))
    record["hit_id"] = f"{RUN_ID}-hit-1"
    jsonl_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["hits"][0]["hit_id"] = record["hit_id"]
    trace["output_sha256"] = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="source_row_index"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)


def test_rejects_hit_id_with_source_row_outside_input_range(tmp_path: Path) -> None:
    jsonl_path, trace_path = _create_handoff(tmp_path)
    record = json.loads(jsonl_path.read_text(encoding="utf-8"))
    record["hit_id"] = f"{RUN_ID}-hit-3"
    jsonl_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["hits"][0]["hit_id"] = record["hit_id"]
    trace["hits"][0]["source_row_index"] = 3
    trace["output_sha256"] = hashlib.sha256(jsonl_path.read_bytes()).hexdigest()
    _rewrite_trace(trace_path, trace)

    with pytest.raises(ValueError, match="input_row_count"):
        read_fast_hit_handoff(jsonl_path, trace_path, run_id=RUN_ID)
