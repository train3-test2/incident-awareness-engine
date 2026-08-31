from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FusionOutput(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "fusion_status": {
                                "const": "detected",
                            }
                        },
                        "required": ["fusion_status"],
                    },
                    "then": {
                        "properties": {
                            "fusion_time": {
                                "type": "string",
                                "format": "date-time",
                            },
                            "score_at_decision": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0,
                            },
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "fusion_status": {
                                "enum": [
                                    "miss",
                                    "not_evaluated",
                                ]
                            }
                        },
                        "required": ["fusion_status"],
                    },
                    "then": {
                        "properties": {
                            "fusion_time": {
                                "type": "null",
                            },
                            "score_at_decision": {
                                "type": "null",
                            },
                        }
                    },
                },
            ]
        },
    )

    schema_version: Literal["fusion_output_v0.1"] = "fusion_output_v0.1"

    run_id: str
    entity_id: str

    fusion_status: Literal[
        "detected",
        "miss",
        "not_evaluated",
    ]

    fusion_time: datetime | None

    score_at_decision: float | None = Field(
        ge=0.0,
        le=1.0,
    )

    contributing_evidence_ids: list[str]

    decision_reason: str

    scoring_method: str
    scorer_version: str
    evidence_schema_version: str
    scoring_config_version: str
    scoring_profile_id: str
    git_commit: str

    @model_validator(mode="after")
    def validate_status_fields(self) -> "FusionOutput":
        if self.fusion_status == "detected":
            if self.fusion_time is None:
                raise ValueError("fusion_time is required when fusion_status is detected")

            if self.score_at_decision is None:
                raise ValueError("score_at_decision is required when fusion_status is detected")

        else:
            if self.fusion_time is not None:
                raise ValueError("fusion_time must be null unless fusion_status is detected")

            if self.score_at_decision is not None:
                raise ValueError("score_at_decision must be null unless fusion_status is detected")

        return self
