from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectionResult,
    DetectorStatus,
    Severity,
    WinningPath,
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


def _valid_decision_payload() -> dict[str, object]:
    return {
        "run_id": "RUN-20260901-001",
        "decision_id": "D-001",
        "entity_id": "WIN-01",
        "fast_status": "detected",
        "fusion_status": "detected",
        "fusion_time": datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        "detector_time": datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
        "t_e": datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        "decision_path": "fast_and_fusion",
        "winning_path": "fusion",
        "decision_reason": "두 경로가 모두 탐지했습니다.",
        "config_version": "v0.2",
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
            "detector_status": "miss",
            "detector_id": None,
            "rule_id": None,
            "rule_version": None,
            "severity": None,
        }
    )

    assert result.detector_time is None
    assert result.severity is None


@pytest.mark.parametrize(
    ("detector_status", "detector_time"),
    [
        ("detected", None),
        ("miss", datetime(2026, 9, 1, 1, 8, tzinfo=UTC)),
        ("not_evaluated", datetime(2026, 9, 1, 1, 8, tzinfo=UTC)),
    ],
)
def test_detection_result_rejects_inconsistent_detector_status_and_time(
    detector_status: str,
    detector_time: datetime | None,
) -> None:
    with pytest.raises(ValidationError):
        DetectionResult(
            **{
                **_valid_detection_payload(),
                "detector_status": detector_status,
                "detector_time": detector_time,
            }
        )


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


def test_decision_result_preserves_v02_contract_fields() -> None:
    result = DecisionResult(**_valid_decision_payload())

    assert result.decision_path is DecisionPath.FAST_AND_FUSION
    assert result.winning_path is WinningPath.FUSION
    assert result.t_e == datetime(2026, 9, 1, 1, 5, tzinfo=UTC)


def test_decision_result_allows_nullable_optional_fields() -> None:
    result = DecisionResult(
        **{
            **_valid_decision_payload(),
            "contributing_evidence_ids": None,
            "model_version": None,
            "rule_version": None,
            "detector_set_version": None,
            "supersedes_decision_id": None,
        }
    )

    assert result.contributing_evidence_ids is None
    assert result.supersedes_decision_id is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fast_status", "unknown"),
        ("fusion_status", "unknown"),
        ("decision_path", "hybrid"),
        ("winning_path", "hybrid"),
    ],
)
def test_decision_result_rejects_invalid_enum_value(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        DecisionResult(**{**_valid_decision_payload(), field: value})


def test_decision_result_rejects_invalid_timestamp() -> None:
    with pytest.raises(ValidationError):
        DecisionResult(
            **{
                **_valid_decision_payload(),
                "fusion_time": datetime.fromisoformat("2026-09-01T01:05:00"),
            }
        )


@pytest.mark.parametrize(
    ("fast_status", "fusion_status", "detector_time", "fusion_time"),
    [
        ("detected", "detected", None, datetime(2026, 9, 1, 1, 5, tzinfo=UTC)),
        (
            "miss",
            "detected",
            datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
            datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        ),
        (
            "not_evaluated",
            "detected",
            datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
            datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        ),
        ("detected", "detected", datetime(2026, 9, 1, 1, 8, tzinfo=UTC), None),
        (
            "detected",
            "miss",
            datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
            datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        ),
        (
            "detected",
            "not_evaluated",
            datetime(2026, 9, 1, 1, 8, tzinfo=UTC),
            datetime(2026, 9, 1, 1, 5, tzinfo=UTC),
        ),
    ],
)
def test_decision_result_rejects_inconsistent_status_times(
    fast_status: str,
    fusion_status: str,
    detector_time: datetime | None,
    fusion_time: datetime | None,
) -> None:
    with pytest.raises(ValidationError):
        DecisionResult(
            **{
                **_valid_decision_payload(),
                "fast_status": fast_status,
                "fusion_status": fusion_status,
                "detector_time": detector_time,
                "fusion_time": fusion_time,
            }
        )


def test_decision_result_rejects_undefined_field() -> None:
    with pytest.raises(ValidationError):
        DecisionResult(**{**_valid_decision_payload(), "decision_source": "fast"})
