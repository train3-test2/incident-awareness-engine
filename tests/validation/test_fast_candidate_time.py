import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "fast_audit", Path(__file__).parents[2] / "tools/validation/check_fast_candidate_time.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.fixture
def inputs():
    hit = {
        "Computer": "HOST",
        "Channel": "Sysmon",
        "RecordID": "1327",
        "EventID": "1",
        "Timestamp": "2026-10-05T19:38:26.260315Z",
        "RuleID": "candidate",
    }
    raw = {
        "Computer": "HOST",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "RecordId": 1327,
        "EventId": 1,
        "TimeCreated": "2026-10-05T19:38:26.260315Z",
        "EventData": {"UtcTime": "2026-10-05 19:38:26.253"},
    }
    return hit, raw


def test_join_preserves_policy_clock(inputs):
    # Given
    hit, raw = inputs

    # When
    result = audit.resolve_hits([hit], [raw])[0]

    # Then
    assert result["hayabusa_minus_event_time_us"] == 7315
    assert result["final_detector_time"] is None
    assert result["event_data_utc_time"] == "2026-10-05T19:38:26.253Z"


@pytest.mark.parametrize(
    "field,value", [("Computer", "OTHER"), ("Channel", "Security"), ("RecordId", 999)]
)
def test_full_key_must_match(inputs, field, value):
    # Given
    hit, raw = inputs
    raw[field] = value

    # When
    with pytest.raises(ValueError) as error:
        audit.resolve_hits([hit], [raw])

    # Then
    assert "got 0" in str(error.value)


def test_duplicate_raw_is_rejected(inputs):
    # Given
    hit, raw = inputs

    # When
    with pytest.raises(ValueError) as error:
        audit.resolve_hits([hit], [raw, raw])

    # Then
    assert "got 2" in str(error.value)


@pytest.mark.parametrize("value", [None, "", "invalid"])
def test_no_timecreated_fallback(inputs, value):
    # Given
    hit, raw = inputs
    raw["EventData"]["UtcTime"] = value

    # When
    with pytest.raises(ValueError) as error:
        audit.resolve_hits([hit], [raw])

    # Then
    assert str(error.value)


def test_event_type_mismatch(inputs):
    # Given
    hit, raw = inputs
    raw["EventId"] = 3

    # When
    with pytest.raises(ValueError) as error:
        audit.resolve_hits([hit], [raw])

    # Then
    assert "EventID mismatch" in str(error.value)


def test_zero_candidates_is_empty_not_miss(inputs):
    # Given
    _, raw = inputs

    # When
    result = audit.resolve_hits([], [raw])

    # Then
    assert result == []


def test_cli_reads_and_writes_utf8_with_non_ascii_values(inputs, tmp_path, monkeypatch):
    # Given
    hit, raw = inputs
    hit["Computer"] = raw["Computer"] = "검증호스트-漢字"
    hit["RuleID"] = "후보-규칙-🙂"
    raw["EventData"]["CommandLine"] = "한글 경로/실행🙂"
    csv_path = tmp_path / "hits.csv"
    raw_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "result.json"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(hit))
        writer.writeheader()
        writer.writerow(hit)
    raw_path.write_text(json.dumps(raw, ensure_ascii=False) + "\n", encoding="utf-8")
    original_open = Path.open

    def cp949_default_open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        # Simulate Windows legacy locale even on a UTF-8 development machine.
        if "b" not in mode and encoding is None:
            encoding = "cp949"
        return original_open(self, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", cp949_default_open)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_fast_candidate_time.py",
            "--run-id",
            "RUN-20261005-912",
            "--csv",
            str(csv_path),
            "--raw-jsonl",
            str(raw_path),
            "--output",
            str(output_path),
        ],
    )

    # When
    audit.main()
    output_bytes = output_path.read_bytes()
    result = json.loads(output_bytes.decode("utf-8"))

    # Then
    assert result["candidate_count"] == 1
    assert result["matches"][0]["host"] == hit["Computer"]
    assert result["matches"][0]["rule_id"] == hit["RuleID"]
    assert hit["RuleID"].encode("utf-8") in output_bytes
    assert result["raw_sha256"] == hashlib.sha256(raw_path.read_bytes()).hexdigest()
