import re
from datetime import UTC, date, datetime, timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")


def _status_time_schema(status_field: str, time_field: str) -> list[dict[str, object]]:
    return [
        {
            "if": {
                "properties": {status_field: {"const": DetectorStatus.DETECTED.value}},
                "required": [status_field],
            },
            "then": {
                "properties": {time_field: {"type": "string", "format": "date-time"}},
                "required": [time_field],
            },
        },
        {
            "if": {
                "properties": {
                    status_field: {
                        "enum": [
                            DetectorStatus.MISS.value,
                            DetectorStatus.NOT_EVALUATED.value,
                        ]
                    }
                },
                "required": [status_field],
            },
            "then": {
                "properties": {time_field: {"type": "null"}},
                "required": [time_field],
            },
        },
    ]


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


class DecisionPath(str, Enum):
    FAST = "fast"
    FUSION = "fusion"
    FAST_AND_FUSION = "fast_and_fusion"
    NONE = "none"


class WinningPath(str, Enum):
    FAST = "fast"
    FUSION = "fusion"
    TIE = "tie"
    NONE = "none"


class DetectionResult(BaseModel):
    """Fast Adapter가 Fast runner 출력을 정규화한 결과 계약이다."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"allOf": _status_time_schema("detector_status", "detector_time")},
    )

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


class DecisionResult(BaseModel):
    """Fast와 Fusion 경로를 결합한 Hybrid Decision 결과 계약이다."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                *_status_time_schema("fast_status", "detector_time"),
                *_status_time_schema("fusion_status", "fusion_time"),
            ]
        },
    )

    run_id: str = Field(min_length=1)
    decision_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    fast_status: DetectorStatus
    fusion_status: DetectorStatus
    fusion_time: datetime | None
    detector_time: datetime | None
    t_e: datetime | None
    decision_path: DecisionPath | None
    winning_path: WinningPath | None
    decision_reason: str = Field(min_length=1)
    config_version: str = Field(min_length=1)
    contributing_evidence_ids: list[str] | None = None
    model_version: str | None = None
    rule_version: str | None = None
    detector_set_version: str | None = None
    supersedes_decision_id: str | None = None

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

    @field_validator("fusion_time", "detector_time", "t_e")
    @classmethod
    def validate_utc_datetime(cls, value: datetime | None) -> datetime | None:
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
    def validate_status_times(self) -> "DecisionResult":
        if self.fast_status is DetectorStatus.DETECTED and self.detector_time is None:
            raise ValueError("fast_status가 detected이면 detector_time이 필요합니다.")

        if (
            self.fast_status
            in {
                DetectorStatus.MISS,
                DetectorStatus.NOT_EVALUATED,
            }
            and self.detector_time is not None
        ):
            raise ValueError(
                "fast_status가 miss 또는 not_evaluated이면 detector_time은 null이어야 합니다."
            )

        if self.fusion_status is DetectorStatus.DETECTED and self.fusion_time is None:
            raise ValueError("fusion_status가 detected이면 fusion_time이 필요합니다.")

        if (
            self.fusion_status
            in {
                DetectorStatus.MISS,
                DetectorStatus.NOT_EVALUATED,
            }
            and self.fusion_time is not None
        ):
            raise ValueError(
                "fusion_status가 miss 또는 not_evaluated이면 fusion_time은 null이어야 합니다."
            )

        return self

    @model_validator(mode="after")
    def validate_decision_paths(self) -> "DecisionResult":
        if DetectorStatus.NOT_EVALUATED in {self.fast_status, self.fusion_status}:
            return self

        if (
            self.fast_status is DetectorStatus.DETECTED
            and self.fusion_status is DetectorStatus.DETECTED
        ):
            if self.detector_time is None or self.fusion_time is None:
                return self

            expected_time = min(self.detector_time, self.fusion_time)
            if self.t_e != expected_time:
                raise ValueError("두 경로가 detected이면 t_e는 더 이른 판단 시각이어야 합니다.")

            if self.decision_path is not DecisionPath.FAST_AND_FUSION:
                raise ValueError(
                    "두 경로가 detected이면 decision_path는 fast_and_fusion이어야 합니다."
                )

            expected_winning_path = (
                WinningPath.FAST
                if self.detector_time < self.fusion_time
                else WinningPath.FUSION
                if self.fusion_time < self.detector_time
                else WinningPath.TIE
            )
            if self.winning_path is not expected_winning_path:
                raise ValueError("winning_path는 더 이른 판단 시각의 경로와 일치해야 합니다.")

        elif self.fast_status is DetectorStatus.DETECTED:
            if self.detector_time is None:
                return self
            if (
                self.t_e != self.detector_time
                or self.decision_path is not DecisionPath.FAST
                or self.winning_path is not WinningPath.FAST
            ):
                raise ValueError(
                    "Fast 경로만 detected이면 t_e와 경로는 Fast 결과와 일치해야 합니다."
                )

        elif self.fusion_status is DetectorStatus.DETECTED:
            if self.fusion_time is None:
                return self
            if (
                self.t_e != self.fusion_time
                or self.decision_path is not DecisionPath.FUSION
                or self.winning_path is not WinningPath.FUSION
            ):
                raise ValueError(
                    "Fusion 경로만 detected이면 t_e와 경로는 Fusion 결과와 일치해야 합니다."
                )

        elif (
            self.t_e is not None
            or self.decision_path is not DecisionPath.NONE
            or self.winning_path is not WinningPath.NONE
        ):
            raise ValueError("두 경로가 miss이면 t_e는 null이고 경로는 none이어야 합니다.")

        return self
