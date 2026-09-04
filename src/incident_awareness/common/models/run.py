import re
from datetime import UTC, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, Field, field_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")


class RunType(str, Enum):
    NORMAL = "normal"
    ATTACK = "attack"


class RunMetadata(BaseModel):
    run_id: str
    scenario_id: str
    run_type: RunType
    target_host: str
    start_time: datetime
    end_time: datetime | None = None
    family_id: str | None = None
    variation_id: str | None = None
    repetition: int | None = None
    reference_time: datetime | None = None
    reference_action_id: str | None = None
    reference_source_event_id: str | None = None
    vm_snapshot: str | None = None
    sysmon_config_version: str | None = None
    detector_set_version: str | None = None
    scenario_version: str | None = None
    schema_versions: dict[str, str] = Field(min_length=1)
    reference_policy_version: str | None = None

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        match = _RUN_ID_PATTERN.fullmatch(value)

        if match is None:
            raise ValueError("run_id는 RUN-YYYYMMDD-NNN의 형태를 가져야합니다.")

        return value

    @field_validator("start_time", "end_time", "reference_time")
    @classmethod
    def validate_utc_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime에는 시간대 정보가 포함되어야 합니다.")

        if value.utcoffset() != timedelta(0):
            raise ValueError("datetime은 UTC 시간대여야 합니다.")

        return value.astimezone(UTC)
