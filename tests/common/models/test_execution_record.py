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
