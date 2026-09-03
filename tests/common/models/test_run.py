import json
from datetime import UTC, datetime

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
