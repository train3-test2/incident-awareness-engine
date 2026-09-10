import re
from datetime import UTC, date, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")


class DetectorStatus(str, Enum):
    DETECTED = "detected"
    MISS = "miss"
    NOT_EVALUATED = "not_evaluated"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DetectionResult(BaseModel):
    """Fast Adapter가 Fast runner 출력을 정규화한 결과 계약이다."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    detector_time: datetime | None
    detector_status: DetectorStatus
    detector_id: str | None
    rule_id: str | None
    rule_version: str | None
    severity: Severity | None

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

    @field_validator("detector_time")
    @classmethod
    def validate_detector_time(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("datetime에는 시간대 정보가 포함되어야 합니다.")

        if value.utcoffset() != timedelta(0):
            raise ValueError("datetime은 UTC 시간대여야 합니다.")

        if value.microsecond % 1000 != 0:
            raise ValueError("datetime은 밀리초 단위여야 합니다.")

        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_detector_status_time(self) -> "DetectionResult":
        if self.detector_status is DetectorStatus.DETECTED and self.detector_time is None:
            raise ValueError("detected 상태에서는 detector_time이 필요합니다.")

        if (
            self.detector_status
            in {
                DetectorStatus.MISS,
                DetectorStatus.NOT_EVALUATED,
            }
            and self.detector_time is not None
        ):
            raise ValueError(
                "miss 또는 not_evaluated 상태에서는 detector_time이 null이어야 합니다."
            )

        return self
