import pytest
from pydantic import ValidationError

from incident_awareness.common.models.event import (
    NetworkInfo,
    ProcessInfo,
    RawLogReference,
)


def test_process_info_allows_omitted_fields() -> None:
    # given & when: 필드 없이 ProcessInfo를 생성
    process_info = ProcessInfo()

    # then: 모든 선택 필드는 None이다
    assert process_info.pid is None
    assert process_info.name is None
    assert process_info.path is None
    assert process_info.command_line is None
    assert process_info.parent_pid is None
    assert process_info.parent_name is None


def test_network_info_allows_omitted_fields() -> None:
    # given & when: 필드 없이 NetworkInfo를 생성
    network_info = NetworkInfo()

    # then: 모든 선택 필드는 None이다
    assert network_info.protocol is None
    assert network_info.src_ip is None
    assert network_info.src_port is None
    assert network_info.dst_ip is None
    assert network_info.dst_port is None


def test_raw_log_reference_accepts_valid_values() -> None:
    # given & when: 유효한 Raw Log 참조 정보를 생성
    raw_log_reference = RawLogReference(
        raw_log_id="RAW-001",
        segment_no=1,
        record_no=1,
    )

    # then: 정상적으로 생성된다
    assert raw_log_reference.raw_log_id == "RAW-001"
    assert raw_log_reference.segment_no == 1
    assert raw_log_reference.record_no == 1


@pytest.mark.parametrize(
    ("segment_no", "record_no"),
    [
        (0, 1),
        (-1, 1),
        (1, 0),
        (1, -1),
        (True, 1),
        (1, True),
    ],
)
def test_raw_log_reference_rejects_invalid_position(
    segment_no: int,
    record_no: int,
) -> None:
    # given: 1보다 작은 Segment 또는 Record 번호
    invalid_payload = {
        "raw_log_id": "RAW-001",
        "segment_no": segment_no,
        "record_no": record_no,
    }

    # when & then: 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        RawLogReference(**invalid_payload)


def test_raw_log_reference_rejects_empty_raw_log_id() -> None:
    # given: 빈 Raw Log 식별자
    invalid_payload = {
        "raw_log_id": "",
        "segment_no": 1,
        "record_no": 1,
    }

    # when & then: 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        RawLogReference(**invalid_payload)
