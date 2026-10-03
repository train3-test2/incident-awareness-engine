from datetime import datetime

from pydantic import BaseModel, ConfigDict

from incident_awareness.common.models.run import RunMetadata, RunType


class RunListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    scenario_id: str
    run_type: RunType
    target_host: str
    start_time: datetime
    end_time: datetime | None

    @classmethod
    def from_run_metadata(cls, run: RunMetadata) -> "RunListItem":
        return cls(
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            run_type=run.run_type,
            target_host=run.target_host,
            start_time=run.start_time,
            end_time=run.end_time,
        )


class RunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runs: list[RunListItem]
