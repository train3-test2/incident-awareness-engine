import json

import pytest

from incident_awareness.detection.fast_hit_adapter import (
    get_rule_metadata,
    hayabusa_row_to_fast_hit,
    hayabusa_rows_to_fast_hits,
    is_qualifying_hit,
    read_hayabusa_csv,
    write_fast_hits_jsonl,
)


def test_hayabusa_row_to_fast_hit():
    row = {
        "Timestamp": "2019-05-27 10:28:42.711 +09:00",
        "RuleID": "40d8f009-02f9-7db7-6504-25193624ab0a",
        "Computer": "IEWIN7",
        "RecordID": "5875",
    }

    result = hayabusa_row_to_fast_hit(
        row,
        run_id="run-s0-attack-001",
        hit_id="hit-001",
        detector_engine_version="4.0.0",
        rule_version="test",
        alert_key="encoded-powershell",
        detector_config_version="draft-v0.1",
    )

    assert result == {
        "hit_id": "hit-001",
        "run_id": "run-s0-attack-001",
        "timestamp": "2019-05-27T01:28:42.711Z",
        "detector_engine": "hayabusa",
        "detector_engine_version": "4.0.0",
        "rule_id": "40d8f009-02f9-7db7-6504-25193624ab0a",
        "rule_version": "test",
        "alert_key": "encoded-powershell",
        "native_host_id": "IEWIN7",
        "native_record_ref": "5875",
        "detector_config_version": "draft-v0.1",
    }


def test_timestamp_hayabusa_o_option_format():
    row = {
        "Timestamp": "2019-03-19T23:35:07.524202Z",
        "RuleID": "c2f690ac-53f8-4745-8cfe-7127dda28c74",
        "Computer": "PC01.example.corp",
        "RecordID": "452811",
    }

    result = hayabusa_row_to_fast_hit(
        row,
        run_id="run-s0-attack-003",
        hit_id="hit-003",
        detector_engine_version="4.0.0",
        rule_version="stable",
        alert_key="audit-log-clear",
        detector_config_version="draft-v0.1",
    )

    assert result["timestamp"] == "2019-03-19T23:35:07.524Z"


def test_read_hayabusa_csv(tmp_path):
    csv_path = tmp_path / "hayabusa.csv"

    csv_path.write_text(
        "Timestamp,RuleID,Computer,RecordID\n"
        "2019-05-27 10:28:42.711 +09:00,"
        "40d8f009-02f9-7db7-6504-25193624ab0a,"
        "IEWIN7,"
        "5875\n",
        encoding="utf-8",
    )

    rows = read_hayabusa_csv(csv_path)

    assert rows == [
        {
            "Timestamp": "2019-05-27 10:28:42.711 +09:00",
            "RuleID": "40d8f009-02f9-7db7-6504-25193624ab0a",
            "Computer": "IEWIN7",
            "RecordID": "5875",
        }
    ]


def test_hayabusa_rows_to_fast_hits():
    rows = [
        {
            "Timestamp": "2019-05-27 10:28:42.711 +09:00",
            "RuleID": "rule-1",
            "Computer": "HOST-A",
            "RecordID": "100",
        },
        {
            "Timestamp": "2019-05-27 10:29:42.711 +09:00",
            "RuleID": "rule-2",
            "Computer": "HOST-B",
            "RecordID": "101",
        },
    ]

    results = hayabusa_rows_to_fast_hits(
        rows,
        run_id="run-001",
        detector_engine_version="4.0.0",
        detector_config_version="draft-v0.1",
        qualifying_rule_ids={"rule-1", "rule-2"},
        rule_metadata={
            "rule-1": {
                "rule_version": "test",
                "alert_key": "encoded-powershell",
            },
            "rule-2": {
                "rule_version": "stable",
                "alert_key": "audit-log-clear",
            },
        },
    )

    assert len(results) == 2
    assert results[0]["hit_id"] == "run-001-hit-1"
    assert results[1]["hit_id"] == "run-001-hit-2"
    assert results[0]["rule_id"] == "rule-1"
    assert results[1]["rule_id"] == "rule-2"
    assert results[0]["rule_version"] == "test"
    assert results[0]["alert_key"] == "encoded-powershell"
    assert results[1]["rule_version"] == "stable"
    assert results[1]["alert_key"] == "audit-log-clear"


def test_write_fast_hits_jsonl(tmp_path):
    output_path = tmp_path / "fast_hits.jsonl"

    hits = [
        {
            "hit_id": "hit-001",
            "run_id": "run-001",
            "timestamp": "2019-05-27T01:28:42.711Z",
            "detector_engine": "hayabusa",
            "detector_engine_version": "4.0.0",
            "rule_id": "rule-1",
            "rule_version": "test",
            "alert_key": "test-alert",
            "native_host_id": "HOST-A",
            "native_record_ref": "100",
            "detector_config_version": "draft-v0.1",
        },
        {
            "hit_id": "hit-002",
            "run_id": "run-001",
            "timestamp": "2019-05-27T01:29:42.711Z",
            "detector_engine": "hayabusa",
            "detector_engine_version": "4.0.0",
            "rule_id": "rule-2",
            "rule_version": "test",
            "alert_key": "test-alert",
            "native_host_id": "HOST-B",
            "native_record_ref": "101",
            "detector_config_version": "draft-v0.1",
        },
    ]

    write_fast_hits_jsonl(hits, output_path)

    lines = output_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0]) == hits[0]
    assert json.loads(lines[1]) == hits[1]


def test_optional_native_fields_can_be_empty():
    row = {
        "Timestamp": "2019-05-27 10:28:42.711 +09:00",
        "RuleID": "rule-1",
        "Computer": "",
        "RecordID": "",
    }

    result = hayabusa_row_to_fast_hit(
        row,
        run_id="run-001",
        hit_id="hit-001",
        detector_engine_version="4.0.0",
        rule_version="test",
        alert_key="test-alert",
        detector_config_version="draft-v0.1",
    )

    assert result["native_host_id"] is None
    assert result["native_record_ref"] is None


def test_missing_rule_id_raises_error():
    row = {
        "Timestamp": "2019-05-27 10:28:42.711 +09:00",
        "Computer": "HOST-A",
        "RecordID": "100",
    }

    with pytest.raises(KeyError):
        hayabusa_row_to_fast_hit(
            row,
            run_id="run-001",
            hit_id="hit-001",
            detector_engine_version="4.0.0",
            rule_version="test",
            alert_key="test-alert",
            detector_config_version="draft-v0.1",
        )


def test_invalid_timestamp_raises_error():
    row = {
        "Timestamp": "not-a-timestamp",
        "RuleID": "rule-1",
        "Computer": "HOST-A",
        "RecordID": "100",
    }

    with pytest.raises(ValueError):
        hayabusa_row_to_fast_hit(
            row,
            run_id="run-001",
            hit_id="hit-001",
            detector_engine_version="4.0.0",
            rule_version="test",
            alert_key="test-alert",
            detector_config_version="draft-v0.1",
        )


def test_is_qualifying_hit_returns_true_for_matching_rule():
    row = {
        "RuleID": "rule-1",
    }

    qualifying_rule_ids = {"rule-1", "rule-2"}

    assert is_qualifying_hit(row, qualifying_rule_ids) is True


def test_is_qualifying_hit_returns_false_for_non_matching_rule():
    row = {
        "RuleID": "rule-3",
    }

    qualifying_rule_ids = {"rule-1", "rule-2"}

    assert is_qualifying_hit(row, qualifying_rule_ids) is False


def test_hayabusa_rows_to_fast_hits_filters_non_qualifying_rows():
    rows = [
        {
            "Timestamp": "2019-05-27 10:28:42.711 +09:00",
            "RuleID": "rule-1",
            "Computer": "HOST-A",
            "RecordID": "100",
        },
        {
            "Timestamp": "2019-05-27 10:29:42.711 +09:00",
            "RuleID": "rule-3",
            "Computer": "HOST-B",
            "RecordID": "101",
        },
        {
            "Timestamp": "2019-05-27 10:30:42.711 +09:00",
            "RuleID": "rule-2",
            "Computer": "HOST-C",
            "RecordID": "102",
        },
    ]

    results = hayabusa_rows_to_fast_hits(
        rows,
        run_id="run-001",
        detector_engine_version="4.0.0",
        detector_config_version="draft-v0.1",
        qualifying_rule_ids={"rule-1"},
        rule_metadata={
            "rule-1": {
                "rule_version": "test",
                "alert_key": "encoded-powershell",
            },
        },
    )

    assert len(results) == 1
    assert results[0]["rule_id"] == "rule-1"


def test_missing_timestamp_raises_error():
    row = {
        "RuleID": "rule-1",
        "Computer": "HOST-A",
        "RecordID": "100",
    }

    with pytest.raises(KeyError):
        hayabusa_row_to_fast_hit(
            row,
            run_id="run-001",
            hit_id="hit-001",
            detector_engine_version="4.0.0",
            rule_version="test",
            alert_key="test-alert",
            detector_config_version="draft-v0.1",
        )


def test_get_rule_metadata():
    rule_metadata = {
        "rule-1": {
            "rule_version": "test",
            "alert_key": "encoded-powershell",
        },
        "rule-2": {
            "rule_version": "stable",
            "alert_key": "audit-log-clear",
        },
    }

    result = get_rule_metadata("rule-1", rule_metadata)

    assert result == {
        "rule_version": "test",
        "alert_key": "encoded-powershell",
    }


def test_qualifying_rule_without_metadata_raises_key_error():
    rows = [{"Timestamp": "2022-02-22T10:10:10.123Z", "RuleID": "rule-missing"}]

    with pytest.raises(KeyError) as exc_info:
        hayabusa_rows_to_fast_hits(
            rows,
            run_id="run-001",
            detector_engine_version="4.0.0",
            detector_config_version="draft-v0.1",
            qualifying_rule_ids={"rule-missing"},
            rule_metadata={},
        )

    assert exc_info.value.args == ("rule-missing",)


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("2022-02-22T10:10:10.1234567Z", "2022-02-22T10:10:10.123Z"),
        ("2022-02-22T10:10:10.9999999+09:00", "2022-02-22T01:10:10.999Z"),
        ("2022-02-22 10:10:10.1234567 -05:00", "2022-02-22T15:10:10.123Z"),
    ],
)
def test_timestamp_excess_fractional_precision(timestamp, expected):
    result = hayabusa_row_to_fast_hit(
        {"Timestamp": timestamp, "RuleID": "rule-1"},
        run_id="run-001",
        hit_id="hit-001",
        detector_engine_version="4.0.0",
        rule_version="test",
        alert_key="test-alert",
        detector_config_version="draft-v0.1",
    )

    assert result["timestamp"] == expected
