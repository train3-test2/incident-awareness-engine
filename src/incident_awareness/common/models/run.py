import re
from datetime import UTC, date, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")


class RunType(str, Enum):
    NORMAL = "normal"
    ATTACK = "attack"


class SchemaVersions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_metadata: str = Field(min_length=1)
    event: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    fast_hit: str = Field(min_length=1)
    detection_result: str = Field(min_length=1)
    fusion_result: str = Field(min_length=1)
    decision_result: str = Field(min_length=1)
    execution_record: str = Field(min_length=1)
    evaluation_input: str = Field(min_length=1)


class RunMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    """실험 실행 메타데이터.

    Normalizer, Evidence, Fusion, Fast runtime은 `run_type` 및
    `reference_*` 평가 기준 필드를 런타임 판단 입력으로 사용하지 않는다.
    """

    run_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    run_type: RunType
    target_host: str = Field(min_length=1)
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
    schema_versions: SchemaVersions
    reference_policy_version: str | None = None

    @field_validator("run_id", "scenario_id", "target_host")
    @classmethod
    def validate_required_identifier(cls, value: str) -> str:
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

    @model_validator(mode="after")
    def validate_time_order(self) -> "RunMetadata":
        if self.run_type is RunType.NORMAL and self.reference_time is not None:
            raise ValueError("normal Run의 reference_time은 null이어야 합니다.")

        if self.end_time is not None and self.end_time < self.start_time:
            raise ValueError("종료 시각은 시작 시각보다 이를 수 없습니다.")

        return self
