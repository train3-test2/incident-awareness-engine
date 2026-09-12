import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.execution_record import ExecutionRecordRow


def test_execution_record_serializes_to_json() -> None:
    # given: 공격 Run 의 행위 한 건
    row = ExecutionRecordRow(
        run_id="RUN-20260903-001",
        action_id="A01",
        timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        action_type="execution",
        description="난독화 PowerShell 실행",
    )

    # when: JSON으로 직렬화
    payload = json.loads(row.model_dump_json())

    # then: 다섯 필드가 그대로 담긴다
    assert payload["run_id"] == "RUN-20260903-001"
    assert payload["action_id"] == "A01"
    assert payload["action_type"] == "execution"
    assert payload["description"] == "난독화 PowerShell 실행"
    assert payload["timestamp"].startswith("2026-09-03T01:00:00")


def test_normal_run_action_uses_same_contract() -> None:
    # given: 정상 Run 의 행위 한 건
    row = ExecutionRecordRow(
        run_id="RUN-20260903-002",
        action_id="N01",
        timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        action_type="admin_action",
        description="관리 스크립트 실행",
    )

    # when: 행위 유형을 확인하면
    # then: 공격 Run 과 같은 계약을 쓴다
    assert row.action_id == "N01"
    assert row.action_type == "admin_action"


def test_rejects_non_utc_timestamp() -> None:
    # given: KST 로 표기한 시각
    korea_timezone = timezone(timedelta(hours=9))

    # when / then: 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="UTC"):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 10, 0, tzinfo=korea_timezone),
            action_type="execution",
            description="난독화 PowerShell 실행",
        )


def test_rejects_naive_timestamp() -> None:
    # given: 시간대 정보가 없는 시각
    invalid_payload = {
        "run_id": "RUN-20260903-001",
        "action_id": "A01",
        "timestamp": "2026-09-03T01:00:00",
        "action_type": "execution",
        "description": "난독화 PowerShell 실행",
    }

    # when / then: 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="시간대 정보"):
        ExecutionRecordRow(**invalid_payload)


def test_rejects_empty_description() -> None:
    # given / when / then: description 이 비면 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="",
        )


def test_rejects_undefined_field() -> None:
    # given: Ground Truth 에 두지 않기로 한 필드를 넣은 입력
    # when / then: extra=forbid 로 거부된다
    with pytest.raises(ValidationError):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="난독화 PowerShell 실행",
            reference_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        )


def test_rejects_identifier_with_surrounding_space() -> None:
    # given / when / then: action_id 에 공백이 붙으면 거부된다
    with pytest.raises(ValidationError):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id=" A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="난독화 PowerShell 실행",
        )


def test_rejects_whitespace_only_description() -> None:
    # given: 공백만으로 채운 설명
    # when / then: 역추적에 쓸 수 없으므로 거부된다
    with pytest.raises(ValidationError, match="공백"):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="   ",
        )


@pytest.mark.parametrize("numeric_timestamp", [0, 1757376000, 1757376000.5])
def test_rejects_numeric_timestamp(numeric_timestamp: float) -> None:
    # given: Unix timestamp 로 넣은 시각
    # when / then: aware datetime 으로 변환되기 전에 거부된다
    with pytest.raises(ValidationError, match="Unix timestamp"):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=numeric_timestamp,
            action_type="execution",
            description="난독화 PowerShell 실행",
        )


@pytest.mark.parametrize("numeric_text", ["0", "1234567890", "1.5e9"])
def test_rejects_numeric_string_timestamp(numeric_text: str) -> None:
    # given: 숫자로만 이루어진 문자열 시각
    # when / then: 같은 이유로 거부된다
    with pytest.raises(ValidationError, match="Unix timestamp"):
        ExecutionRecordRow(
            run_id="RUN-20260903-001",
            action_id="A01",
            timestamp=numeric_text,
            action_type="execution",
            description="난독화 PowerShell 실행",
        )


def test_accepts_iso_8601_string_timestamp() -> None:
    # given: ISO 8601 문자열로 넣은 UTC 시각
    row = ExecutionRecordRow(
        run_id="RUN-20260903-001",
        action_id="A01",
        timestamp="2026-09-03T01:00:00Z",
        action_type="execution",
        description="난독화 PowerShell 실행",
    )

    # then: 숫자 차단이 정상 입력을 막지 않는다
    assert row.timestamp == datetime(2026, 9, 3, 1, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "run_id",
    [
        "RUN-01",
        "RUN-20260903-01",
        "RUN-20260230-001",
        "run-20260903-001",
        "RUN-20260903-１２３",
        "S0-ATK-001_R01",
    ],
)
def test_rejects_invalid_run_id(run_id: str) -> None:
    # given: 형식이나 날짜가 RUN-YYYYMMDD-NNN 규칙에 맞지 않는 run_id
    # when / then: RunMetadata 와 조인이 어긋나지 않도록 거부된다
    with pytest.raises(ValidationError, match="run_id"):
        ExecutionRecordRow(
            run_id=run_id,
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="난독화 PowerShell 실행",
        )


def test_rejects_run_id_with_trailing_space() -> None:
    # given: 뒤에 공백 하나가 붙은 run_id
    # when / then: 공백을 제거해 받아들이지 않고 거부된다
    with pytest.raises(ValidationError, match="공백"):
        ExecutionRecordRow(
            run_id="RUN-20260903-001 ",
            action_id="A01",
            timestamp=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
            action_type="execution",
            description="난독화 PowerShell 실행",
        )
