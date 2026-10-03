from datetime import datetime

from pydantic import BaseModel, ConfigDict

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata, RunType
from incident_awareness.common.models.runtime_snapshot import DecisionRuntimeSnapshot
from incident_awareness.dashboard.decision_read_model import (
    CurrentDecisionReadModel,
    HistoricalDecisionReadModel,
)


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


class OverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_runs: int
    recent_runs: list[RunListItem]


class CurrentDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionResult
    latest_detection_result: DetectionResult | None
    latest_fusion_result: FusionResult | None
    latest_fusion_stopping_trace: FusionStoppingTrace | None

    @classmethod
    def from_read_model(cls, current: CurrentDecisionReadModel) -> "CurrentDecisionResponse":
        return cls(
            decision=current.decision,
            latest_detection_result=current.latest_detection_result,
            latest_fusion_result=current.latest_fusion_result,
            latest_fusion_stopping_trace=current.latest_fusion_stopping_trace,
        )


class RunDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run: RunMetadata
    current_decision: CurrentDecisionResponse | None
    decision_history: list[DecisionResult]


class HistoricalDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionResult
    runtime_snapshot: DecisionRuntimeSnapshot | None

    @classmethod
    def from_read_model(
        cls,
        historical: HistoricalDecisionReadModel,
    ) -> "HistoricalDecisionResponse":
        return cls(
            decision=historical.decision,
            runtime_snapshot=historical.runtime_snapshot,
        )
