import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.run import RunMetadata, RunType


def test_run_metadata_serializes_to_json() -> None:
    # given: UTC 시간이 포함된 정상 데이터
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        end_time=datetime(2026, 9, 3, 1, 30, tzinfo=UTC),
    )

    # when: JSON으로 직렬화
    payload = json.loads(run_metadata.model_dump_json())

    # then: JSON으로 변환
    assert payload["run_id"] == "RUN-20260903-001"
    assert payload["scenario_id"] == "R1"
    assert payload["run_type"] == "attack"
    assert payload["target_host"] == "WIN-01"
    assert payload["start_time"] == "2026-09-03T01:00:00Z"
    assert payload["end_time"] == "2026-09-03T01:30:00Z"


def test_run_metadata_serializes_null_end_time() -> None:
    # given: 종료시간이 없는 데이터
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        end_time=None,
    )

    # when: JSON으로 직렬화
    payload = json.loads(run_metadata.model_dump_json())

    # then: JSON으로 변환
    assert payload["end_time"] is None


def test_run_metadata_rejects_end_time_before_start_time() -> None:
    # given: 종료 시각이 시작 시각보다 이른 실행 메타데이터 입력값
    invalid_payload = {
        "run_id": "RUN-20260903-001",
        "scenario_id": "R1",
        "run_type": RunType.ATTACK,
        "target_host": "WIN-01",
        "start_time": datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        "end_time": datetime(2026, 9, 3, 0, 59, tzinfo=UTC),
    }

    # when & then: 실행 메타데이터 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="종료 시각은 시작 시각보다 이를 수 없습니다."):
        RunMetadata(**invalid_payload)


@pytest.mark.parametrize(
    "run_id",
    [
        "ATTACK-20260903-001",
        "RUN-20260903-01",
        "RUN-20260230-001",
        "RUN-20260903-１２３",
    ],
)
def test_run_metadata_rejects_invalid_run_id(run_id: str) -> None:
    # given: 형식 또는 날짜가 잘못된 run_id
    invalid_payload = {
        "run_id": run_id,
        "scenario_id": "R1",
        "run_type": RunType.ATTACK,
        "target_host": "WIN-01",
        "start_time": datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
    }

    # when & then: 실행 메타데이터 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        RunMetadata(**invalid_payload)


def test_run_metadata_rejects_naive_start_time() -> None:
    # given: 시간대 정보가 없는 시작 시각
    invalid_payload = {
        "run_id": "RUN-20260903-001",
        "scenario_id": "R1",
        "run_type": RunType.ATTACK,
        "target_host": "WIN-01",
        "start_time": "2026-09-03T01:00:00",
    }

    # when & then: 실행 메타데이터 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="시간대 정보"):
        RunMetadata(**invalid_payload)


def test_run_metadata_rejects_non_utc_start_time() -> None:
    # given: UTC가 아닌 시간대의 시작 시각
    korea_timezone = timezone(timedelta(hours=9))
    invalid_payload = {
        "run_id": "RUN-20260903-001",
        "scenario_id": "R1",
        "run_type": RunType.ATTACK,
        "target_host": "WIN-01",
        "start_time": datetime(2026, 9, 3, 10, 0, tzinfo=korea_timezone),
    }

    # when & then: 실행 메타데이터 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="UTC 시간대"):
        RunMetadata(**invalid_payload)


def test_run_metadata_allows_equal_start_and_end_time() -> None:
    # given: 시작 시각과 종료 시각이 같은 실행 메타데이터
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        end_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
    )

    # then: 실행 메타데이터가 정상 생성된다
    assert run_metadata.end_time == run_metadata.start_time
