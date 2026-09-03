import re
from datetime import UTC, date, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>\d{8})-(?P<sequence>\d{3})$")


class RunType(str, Enum):
    NORMAL = "normal"
    ATTACK = "attack"


class RunMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    run_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    run_type: RunType
    target_host: str = Field(min_length=1)
    start_time: datetime
    end_time: datetime | None = None

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

    @field_validator("start_time", "end_time")
    @classmethod
    def validate_utc_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime에는 시간대 정보가 포함되어야 합니다.")

        if value.utcoffset() != timedelta(0):
            raise ValueError("datetime은 UTC 시간대여야 합니다.")

        return value.astimezone(UTC)
