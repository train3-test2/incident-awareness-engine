import importlib.util
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
    hit, raw = inputs
    result = audit.resolve_hits([hit], [raw])[0]
    assert result["hayabusa_minus_event_time_us"] == 7315
    assert result["final_detector_time"] is None
    assert result["event_data_utc_time"] == "2026-10-05T19:38:26.253000Z"


@pytest.mark.parametrize(
    "field,value", [("Computer", "OTHER"), ("Channel", "Security"), ("RecordId", 999)]
)
def test_full_key_must_match(inputs, field, value):
    hit, raw = inputs
    raw[field] = value
    with pytest.raises(ValueError, match="got 0"):
        audit.resolve_hits([hit], [raw])


def test_duplicate_raw_is_rejected(inputs):
    hit, raw = inputs
    with pytest.raises(ValueError, match="got 2"):
        audit.resolve_hits([hit], [raw, raw])


@pytest.mark.parametrize("value", [None, "", "invalid"])
def test_no_timecreated_fallback(inputs, value):
    hit, raw = inputs
    raw["EventData"]["UtcTime"] = value
    with pytest.raises(ValueError):
        audit.resolve_hits([hit], [raw])


def test_event_type_mismatch(inputs):
    hit, raw = inputs
    raw["EventId"] = 3
    with pytest.raises(ValueError, match="EventID mismatch"):
        audit.resolve_hits([hit], [raw])


def test_zero_candidates_is_empty_not_miss(inputs):
    _, raw = inputs
    assert audit.resolve_hits([], [raw]) == []
