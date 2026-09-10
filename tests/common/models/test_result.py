from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.result import (
    DetectionResult,
    DetectorStatus,
    Severity,
)


def _valid_detection_payload() -> dict[str, object]:
    return {
        "run_id": "RUN-20260901-001",
        "entity_id": "WIN-01",
        "detector_time": datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
        "detector_status": "detected",
        "detector_id": "hayabusa",
        "rule_id": "RULE-001",
        "rule_version": "v0.1",
        "severity": "high",
    }


def test_detection_result_preserves_v02_contract_fields() -> None:
    result = DetectionResult(**_valid_detection_payload())

    assert result.detector_status is DetectorStatus.DETECTED
    assert result.severity is Severity.HIGH
    assert result.detector_time == datetime(2026, 9, 1, 1, 8, tzinfo=UTC)


def test_detection_result_allows_nullable_detector_metadata() -> None:
    result = DetectionResult(
        **{
            **_valid_detection_payload(),
            "detector_time": None,
            "detector_id": None,
            "rule_id": None,
            "rule_version": None,
            "severity": None,
        }
    )

    assert result.detector_time is None
    assert result.severity is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "RUN-20260230-001"),
        ("entity_id", ""),
        ("detector_status", "alert"),
        ("severity", "urgent"),
    ],
)
def test_detection_result_rejects_invalid_contract_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        DetectionResult(**{**_valid_detection_payload(), field: value})


@pytest.mark.parametrize(
    "detector_time",
    [
        datetime.fromisoformat("2026-09-01T01:08:00"),
        datetime(2026, 9, 1, 10, 8, tzinfo=timezone(timedelta(hours=9))),
        datetime(2026, 9, 1, 1, 8, 0, 1, tzinfo=UTC),
    ],
)
def test_detection_result_rejects_invalid_detector_time(detector_time: datetime) -> None:
    with pytest.raises(ValidationError):
        DetectionResult(**{**_valid_detection_payload(), "detector_time": detector_time})


def test_detection_result_rejects_undefined_field() -> None:
    with pytest.raises(ValidationError):
        DetectionResult(**{**_valid_detection_payload(), "unknown": "value"})
