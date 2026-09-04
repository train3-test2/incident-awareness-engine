import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.run import RunMetadata, RunType

SCHEMA_VERSIONS = {
    "run_metadata": "v0.2",
    "event": "v0.2",
    "evidence": "v0.2",
    "fast_hit": "v0.2",
    "detection_result": "v0.2",
    "fusion_result": "v0.2",
    "decision_result": "v0.2",
    "execution_record": "v0.1",
    "evaluation_input": "v0.1",
}


def test_run_metadata_serializes_to_json() -> None:
    # given: UTC 시간이 포함된 정상 데이터
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        end_time=datetime(2026, 9, 3, 1, 30, tzinfo=UTC),
        schema_versions=SCHEMA_VERSIONS,
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
    assert payload["schema_versions"] == SCHEMA_VERSIONS


def test_run_metadata_serializes_null_end_time() -> None:
    # given: 종료시간이 없는 데이터
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        end_time=None,
        schema_versions=SCHEMA_VERSIONS,
    )

    # when: JSON으로 직렬화
    payload = json.loads(run_metadata.model_dump_json())

    # then: JSON으로 변환
    assert payload["end_time"] is None


@pytest.mark.parametrize(
    "run_id",
    [
        "ATTACK-20260903-001",
        "RUN-20260903-01",
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
        "schema_versions": SCHEMA_VERSIONS,
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
        "schema_versions": SCHEMA_VERSIONS,
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
        "schema_versions": SCHEMA_VERSIONS,
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
        schema_versions=SCHEMA_VERSIONS,
    )

    # then: 실행 메타데이터가 정상 생성된다
    assert run_metadata.end_time == run_metadata.start_time


def test_run_metadata_supports_v02_optional_fields() -> None:
    # given: v0.2에서 정의한 선택 메타데이터가 포함된 실행 정보
    run_metadata = RunMetadata(
        run_id="RUN-20260903-001",
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
        family_id="R",
        variation_id="R1-A",
        repetition=2,
        reference_time=datetime(2026, 9, 3, 1, 5, tzinfo=UTC),
        reference_action_id="action-001",
        reference_source_event_id="source-event-001",
        vm_snapshot="clean-snapshot-v1",
        sysmon_config_version="v1",
        detector_set_version="v2",
        scenario_version="v3",
        schema_versions=SCHEMA_VERSIONS,
        reference_policy_version="v1",
    )

    # then: 모든 v0.2 필드가 보존된다
    assert run_metadata.family_id == "R"
    assert run_metadata.repetition == 2
    assert run_metadata.reference_time == datetime(2026, 9, 3, 1, 5, tzinfo=UTC)
    assert run_metadata.reference_policy_version == "v1"


def test_run_metadata_requires_schema_versions() -> None:
    # given: Contract별 적용 버전이 빠진 실행 메타데이터
    invalid_payload = {
        "run_id": "RUN-20260903-001",
        "scenario_id": "R1",
        "run_type": RunType.ATTACK,
        "target_host": "WIN-01",
        "start_time": datetime(2026, 9, 3, 1, 0, tzinfo=UTC),
    }

    # when & then: v0.2 필수 필드 누락으로 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="schema_versions"):
        RunMetadata(**invalid_payload)
