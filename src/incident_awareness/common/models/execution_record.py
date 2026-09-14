import re
from datetime import UTC, date, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")


class ExecutionRecordRow(BaseModel):
    """execution_record_v0 의 한 행.

    Run 안에서 실제로 실행한 행위 하나를 기록한다. 공격 Run 뿐 아니라
    **정상 Run 에도 반드시 작성한다.** 정상 Run 에서 오경보가 났을 때 어떤 정상 행위
    때문인지 역추적하려면 필요하다.

    Ground Truth 이므로 런타임 경로가 읽지 않는다. Normalizer, Evidence, Fusion,
    Fast runner 는 이 값을 입력으로 사용하지 않으며, 평가 단계에서만 결합한다
    (`docs/data-contract-v0.2.md` §5-3).

    `reference_time` 은 여기 담지 않는다. 실행 시각과 telemetry 를 정렬해 정하는 값이라
    `RunMetadata` 가 보유한다.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    timestamp: datetime
    action_type: str = Field(min_length=1)
    description: str = Field(min_length=1)

    @field_validator("run_id", "action_id", "action_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("식별자에는 앞뒤 공백을 포함할 수 없습니다.")

        return value

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        match = _RUN_ID_PATTERN.fullmatch(value)

        if match is None:
            raise ValueError("run_id는 RUN-YYYYMMDD-NNN의 형태를 가져야합니다.")

        try:
            date.fromisoformat(match.group("date"))
        except ValueError as error:
            raise ValueError("run_id는 유효한 날짜이어야 합니다.") from error

        return value

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("description은 공백만으로 구성될 수 없습니다.")

        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
            raise ValueError("datetime에 숫자형 Unix timestamp를 사용할 수 없습니다.")

        return value

    @field_validator("timestamp")
    @classmethod
    def validate_utc_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime에는 시간대 정보가 포함되어야 합니다.")

        if value.utcoffset() != timedelta(0):
            raise ValueError("datetime은 UTC 시간대여야 합니다.")

        return value.astimezone(UTC)


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False

    return True
