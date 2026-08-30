from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    run_id: str
    timestamp: datetime
    entity_id: str
    evidence_type: str

    source_event_ids: list[str] = Field(min_length=1)

    derived_from_source_layer: Literal[
        "raw_telemetry",
        "detector_output",
        "mixed",
    ]

    feature_channel_group: Literal[
        "fusion_feature",
        "diagnostic_only",
    ]

    extractor_version: str

    attack_technique_ids: list[str] = Field(default_factory=list)
    features: dict[str, object] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")

        if value.utcoffset().total_seconds() != 0:
            raise ValueError("timestamp must be UTC")

        return value
