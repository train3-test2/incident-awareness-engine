from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
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


@pytest.mark.parametrize(("port",), [(0,), (65535,)])
def test_network_info_accepts_port_boundaries(port: int) -> None:
    # given & when: Contract에 정의된 포트 범위의 경계값을 입력
    network_info = NetworkInfo(src_port=port, dst_port=port)

    # then: 경계값이 보존된다
    assert network_info.src_port == port
    assert network_info.dst_port == port


@pytest.mark.parametrize(("port",), [(-1,), (65536,)])
def test_network_info_rejects_ports_outside_contract_range(port: int) -> None:
    # given: Contract 범위를 벗어난 포트 번호
    invalid_payload = {"src_port": port, "dst_port": port}

    # when & then: NetworkInfo 생성 시 검증 오류가 발생한다
    with pytest.raises(ValidationError):
        NetworkInfo.model_validate(invalid_payload)


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
        model.model_validate(payload)


def test_raw_log_reference_accepts_valid_values() -> None:
    # given & when: 1-based 위치를 포함한 유효한 Raw Log 참조 정보를 생성
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


def test_raw_log_reference_json_round_trip_preserves_provenance() -> None:
    # given: 모든 Provenance 필드가 포함된 Raw Log 참조 정보
    original = RawLogReference(
        raw_log_id="RAW-001",
        source_record_id="153",
        segment_no=1,
        record_no=153,
        parser_id="sysmon-normalizer",
        parser_version="v0.2",
    )

    # when: JSON 직렬화 후 역직렬화한다
    restored = RawLogReference.model_validate_json(original.model_dump_json())

    # then: 모든 Provenance 정보가 동일하게 보존된다
    assert restored == original


@pytest.mark.parametrize(
    ("raw_log_id", "segment_no", "record_no"),
    [
        ("", 1, 1),
        (" ", 1, 1),
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


def test_normalized_event_preserves_source_event_id_as_string() -> None:
    # given: 문자열로 표현한 원본 Event 식별자
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    # when: 정규화 Event를 생성
    event = NormalizedEvent(
        event_id="evt-001",
        run_id="RUN-20260906-001",
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id="WIN-01",
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="153",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            segment_no=1,
            record_no=153,
        ),
    )

    # then: 원본 Event 식별자가 문자열로 보존된다
    assert event.source_event_id == "153"


def test_normalized_event_rejects_non_string_source_event_id() -> None:
    # given: 문자열이 아닌 원본 Event 식별자
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    invalid_payload = {
        "event_id": "evt-001",
        "run_id": "RUN-20260906-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": 153,
        "event_type": "process_create",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "segment_no": 1,
            "record_no": 153,
        },
    }

    # when & then: 원본 Event 식별자는 문자열이어야 한다
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(invalid_payload)


@pytest.mark.parametrize(
    ("string_field", "binary_value"),
    [
        ("event_id", b"evt-001"),
        ("event_id", bytearray(b"evt-001")),
        ("run_id", b"RUN-20260906-001"),
        ("run_id", bytearray(b"RUN-20260906-001")),
        ("host_id", b"WIN-01"),
        ("host_id", bytearray(b"WIN-01")),
        ("source", b"sysmon"),
        ("source", bytearray(b"sysmon")),
        ("source_event_id", b"153"),
        ("source_event_id", bytearray(b"153")),
        ("event_type", b"process_create"),
        ("event_type", bytearray(b"process_create")),
        ("user", b"labuser"),
        ("user", bytearray(b"labuser")),
    ],
)
def test_normalized_event_rejects_binary_string_field(
    string_field: str, binary_value: bytes | bytearray
) -> None:
    # given: bytes 또는 bytearray로 표현한 Contract 문자열 필드
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload[string_field] = binary_value

    # when & then: Contract 문자열은 bytes 변환 없이 문자열이어야 한다
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(invalid_payload)


@pytest.mark.parametrize("identifier_field", ["event_id", "run_id", "host_id", "source_event_id"])
def test_normalized_event_rejects_empty_required_identifier(identifier_field: str) -> None:
    # given: 빈 문자열로 표현한 필수 Event 식별자
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload[identifier_field] = ""

    # when & then: 필수 Event 식별자는 비어 있을 수 없다
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_rejects_analysis_result_field() -> None:
    # given: Event Contract에 정의되지 않은 분석 결과 필드
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    invalid_payload = {
        "event_id": "evt-001",
        "run_id": "RUN-20260906-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": "153",
        "event_type": "process_create",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "segment_no": 1,
            "record_no": 153,
        },
        "risk_score": 0.9,
    }

    # when & then: 분석 결과 필드는 Event 입력으로 허용되지 않는다
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        NormalizedEvent.model_validate(invalid_payload)


@pytest.mark.parametrize(
    "required_field",
    [
        "event_id",
        "run_id",
        "timestamp",
        "timestamp_source",
        "host_id",
        "source",
        "source_layer",
        "source_event_id",
        "event_type",
        "raw_ref",
    ],
)
def test_normalized_event_requires_contract_fields(required_field: str) -> None:
    # given: 필수 Contract 필드 하나가 누락된 Event 입력
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    invalid_payload: dict[str, object] = {
        "event_id": "evt-001",
        "run_id": "RUN-20260906-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": "153",
        "event_type": "process_create",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "segment_no": 1,
            "record_no": 153,
        },
    }
    invalid_payload.pop(required_field)

    # when & then: 필수 필드 누락은 검증 오류로 거부된다
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_generates_json_schema() -> None:
    # when: Pydantic JSON Schema를 생성
    schema = NormalizedEvent.model_json_schema()

    # then: Contract 필드와 추가 필드 차단 설정이 Schema에 반영된다
    properties = schema["properties"]
    required_fields = set(schema["required"])

    assert {"event_id", "timestamp", "source_event_id", "raw_ref"} <= set(properties)
    assert {"user", "process", "network"} <= set(properties)
    assert {"event_id", "timestamp", "source_event_id", "raw_ref"} <= required_fields
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("timestamp_source", ["record_time", "ingest_time"])
def test_normalized_event_accepts_each_timestamp_source(timestamp_source: str) -> None:
    # given: timestamp_source가 가리키는 UTC 시간이 포함된 Event 입력
    valid_payload = _valid_normalized_event_payload()
    timestamp = valid_payload["timestamp"]
    valid_payload["timestamp_source"] = timestamp_source
    valid_payload["event_time"] = None
    valid_payload[timestamp_source] = timestamp

    # when: record_time 또는 ingest_time을 기준 시간으로 사용해 Event를 생성
    event = NormalizedEvent.model_validate(valid_payload)

    # then: 선택한 시간 필드가 timestamp와 동일하게 보존된다
    assert getattr(event, timestamp_source) == event.timestamp


def test_normalized_event_rejects_naive_timestamp() -> None:
    # given: 시간대 정보가 없는 timestamp
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload["timestamp"] = "2026-09-06T01:00:00"

    # when & then: UTC 시간대 정보가 없으면 거부된다
    with pytest.raises(ValidationError, match="시간대 정보"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_rejects_non_utc_timestamp() -> None:
    # given: UTC가 아닌 timestamp
    invalid_payload = _valid_normalized_event_payload()
    korea_timezone = timezone(timedelta(hours=9))
    invalid_payload["timestamp"] = datetime(2026, 9, 6, 10, 0, tzinfo=korea_timezone)

    # when & then: UTC가 아닌 시간대는 거부된다
    with pytest.raises(ValidationError, match="UTC 시간대"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_normalizes_zero_offset_timestamp_to_utc() -> None:
    # given: UTC와 offset은 같지만 tzinfo가 다른 timestamp
    zero_offset_timezone = timezone(timedelta(0), name="zero-offset")
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=zero_offset_timezone)
    valid_payload = _valid_normalized_event_payload()
    valid_payload["timestamp"] = timestamp
    valid_payload["event_time"] = timestamp

    # when: Event를 생성
    event = NormalizedEvent.model_validate(valid_payload)

    # then: UTC offset 0 timestamp는 UTC tzinfo로 정규화된다
    assert event.timestamp.tzinfo is UTC
    assert event.event_time is not None
    assert event.event_time.tzinfo is UTC


@pytest.mark.parametrize(
    ("time_field", "numeric_timestamp"),
    [
        ("timestamp", 1_788_588_800),
        ("timestamp", 1_788_588_800.0),
        ("timestamp", "1788588800"),
        ("timestamp", "1788588800.0"),
        ("event_time", 1_788_588_800),
        ("event_time", 1_788_588_800.0),
        ("event_time", "1788588800"),
        ("event_time", "1788588800.0"),
        ("record_time", 1_788_588_800),
        ("record_time", 1_788_588_800.0),
        ("record_time", "1788588800"),
        ("record_time", "1788588800.0"),
        ("ingest_time", 1_788_588_800),
        ("ingest_time", 1_788_588_800.0),
        ("ingest_time", "1788588800"),
        ("ingest_time", "1788588800.0"),
    ],
)
def test_normalized_event_rejects_numeric_timestamp(
    time_field: str, numeric_timestamp: float
) -> None:
    # given: 숫자형 또는 숫자 문자열로 표현한 Unix timestamp 시간 필드
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload[time_field] = numeric_timestamp

    # when & then: 숫자형 timestamp는 ISO 8601 시간 입력이 아니므로 거부된다
    with pytest.raises(ValidationError, match="숫자형 Unix timestamp"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_accepts_iso_8601_datetime_string() -> None:
    # given: UTC ISO 8601 밀리초 형식의 시간 문자열
    valid_payload = _valid_normalized_event_payload()
    timestamp = "2026-09-06T01:00:00.000Z"
    valid_payload["timestamp"] = timestamp
    valid_payload["event_time"] = timestamp

    # when: Event를 생성
    event = NormalizedEvent.model_validate(valid_payload)

    # then: 숫자가 아닌 유효한 ISO 8601 문자열은 허용된다
    assert event.timestamp == datetime(2026, 9, 6, 1, 0, tzinfo=UTC)


def test_normalized_event_accepts_millisecond_precision_timestamp() -> None:
    # given: 밀리초 단위의 UTC timestamp
    valid_payload = _valid_normalized_event_payload()
    timestamp = datetime(2026, 9, 6, 1, 0, 0, 123000, tzinfo=UTC)
    valid_payload["timestamp"] = timestamp
    valid_payload["event_time"] = timestamp

    # when: Event를 생성
    event = NormalizedEvent.model_validate(valid_payload)

    # then: 밀리초 단위 timestamp가 보존된다
    assert event.timestamp.microsecond == 123000


def test_normalized_event_rejects_sub_millisecond_precision_timestamp() -> None:
    # given: 밀리초보다 세밀한 UTC timestamp
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload["timestamp"] = datetime(2026, 9, 6, 1, 0, 0, 123456, tzinfo=UTC)

    # when & then: 밀리초 단위가 아니면 거부된다
    with pytest.raises(ValidationError, match="밀리초 단위"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_requires_timestamp_source_time() -> None:
    # given: timestamp_source가 가리키는 시간이 없는 Event 입력
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload["event_time"] = None

    # when & then: 선택한 시간 필드가 없으면 거부된다
    with pytest.raises(ValidationError, match="반드시 존재"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_rejects_mismatched_timestamp_source_time() -> None:
    # given: timestamp와 timestamp_source가 가리키는 시간이 서로 다른 Event 입력
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload["event_time"] = datetime(2026, 9, 6, 1, 0, 1, tzinfo=UTC)

    # when & then: 두 시간이 다르면 거부된다
    with pytest.raises(ValidationError, match="동일해야 합니다"):
        NormalizedEvent.model_validate(invalid_payload)


@pytest.mark.parametrize(
    "event_type",
    [
        "process_create",
        "network_connection",
        "script_block",
        "file_create",
        "registry_change",
    ],
)
def test_normalized_event_accepts_configured_event_types(event_type: str) -> None:
    # given: v0.2 관리 어휘에 정의된 Event type
    valid_payload = _valid_normalized_event_payload()
    valid_payload["event_type"] = event_type

    # when: Event를 생성
    event = NormalizedEvent.model_validate(valid_payload)

    # then: 관리 어휘의 Event type이 보존된다
    assert event.event_type == event_type


def test_normalized_event_rejects_unconfigured_event_type() -> None:
    # given: v0.2 관리 어휘에 없는 Event type
    invalid_payload = _valid_normalized_event_payload()
    invalid_payload["event_type"] = "unknown_event"

    # when & then: 관리 어휘 밖의 Event type은 거부된다
    with pytest.raises(ValidationError, match="관리 어휘"):
        NormalizedEvent.model_validate(invalid_payload)


def test_normalized_event_requires_event_types_config_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given: Event type 관리 어휘 경로 환경 변수가 없는 실행 환경
    monkeypatch.delenv("INCIDENT_AWARENESS_EVENT_TYPES_PATH")

    # when & then: Event type 검증은 설정 경로 없이 실행되지 않는다
    with pytest.raises(RuntimeError, match="INCIDENT_AWARENESS_EVENT_TYPES_PATH"):
        NormalizedEvent.model_validate(_valid_normalized_event_payload())


def test_normalized_event_rejects_missing_event_types_config_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # given: 존재하지 않는 Event type 관리 어휘 파일 경로
    monkeypatch.setenv("INCIDENT_AWARENESS_EVENT_TYPES_PATH", "configs/missing.yaml")

    # when & then: Event type 검증은 존재하지 않는 설정 파일을 거부한다
    with pytest.raises(RuntimeError, match="설정 파일을 찾을 수 없습니다"):
        NormalizedEvent.model_validate(_valid_normalized_event_payload())


def _valid_normalized_event_payload() -> dict[str, object]:
    timestamp = datetime(2026, 9, 6, 1, 0, tzinfo=UTC)

    return {
        "event_id": "evt-001",
        "run_id": "RUN-20260906-001",
        "timestamp": timestamp,
        "timestamp_source": "event_time",
        "event_time": timestamp,
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": "153",
        "event_type": "process_create",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "segment_no": 1,
            "record_no": 153,
        },
    }
