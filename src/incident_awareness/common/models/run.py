from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


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
