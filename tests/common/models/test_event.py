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


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (ProcessInfo, {"unexpected": "value"}),
        (NetworkInfo, {"unexpected": "value"}),
        (
            RawLogReference,
            {
                "raw_log_id": "RAW-001",
                "segment_no": 1,
                "record_no": 1,
                "unexpected": "value",
            },
        ),
    ],
)
def test_event_components_reject_undefined_fields(
    model: type[ProcessInfo] | type[NetworkInfo] | type[RawLogReference],
    payload: dict[str, str | int],
) -> None:
    # given: Contract에 정의되지 않은 필드가 포함된 입력
    # when & then: 입력 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model(**payload)


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


def test_raw_log_reference_supports_v02_provenance_fields() -> None:
    # given & when: v0.2 Provenance 필드가 포함된 Raw Log 참조 정보를 생성
    raw_log_reference = RawLogReference(
        raw_log_id="RAW-001",
        source_record_id="153",
        segment_no=1,
        record_no=153,
        parser_id="sysmon-normalizer",
        parser_version="v0.2",
    )

    # then: 원본 Record와 Parser 정보가 보존된다
    assert raw_log_reference.source_record_id == "153"
    assert raw_log_reference.parser_id == "sysmon-normalizer"
    assert raw_log_reference.parser_version == "v0.2"


@pytest.mark.parametrize(
    ("raw_log_id", "segment_no", "record_no"),
    [
        ("", 1, 1),
        ("RAW-001", 0, 1),
        ("RAW-001", 1, 0),
        ("RAW-001", -1, 1),
        ("RAW-001", 1, -1),
        ("RAW-001", True, 1),
        ("RAW-001", 1, True),
    ],
)
def test_raw_log_reference_rejects_invalid_identifier_or_position(
    raw_log_id: str,
    segment_no: int,
    record_no: int,
) -> None:
    # given: 비어 있는 식별자 또는 1 미만의 위치 번호
    invalid_payload = {
        "raw_log_id": raw_log_id,
        "segment_no": segment_no,
        "record_no": record_no,
    }

    # when & then: Raw Log 참조 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        RawLogReference(**invalid_payload)
