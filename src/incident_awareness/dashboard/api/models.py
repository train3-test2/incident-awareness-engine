from datetime import datetime

from pydantic import BaseModel, ConfigDict

from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
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


class PipelineRuntimeItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str
    run_id: str
    entity_id: str
    status: PipelineRuntimeState
    current_stage: PipelineStage | None
    input_total: int
    normalization_processed_count: int
    remaining_count: int
    started_at: datetime
    stage_started_at: datetime | None
    updated_at: datetime
    completed_at: datetime | None
    failed_stage: PipelineStage | None
    has_error: bool
    is_stale: bool

    @classmethod
    def from_runtime_status(
        cls,
        runtime: PipelineRuntimeStatus,
        *,
        running_fresh_after: datetime,
    ) -> "PipelineRuntimeItem":
        return cls(
            execution_id=runtime.execution_id,
            run_id=runtime.run_id,
            entity_id=runtime.entity_id,
            status=runtime.status,
            current_stage=runtime.current_stage,
            input_total=runtime.input_total,
            normalization_processed_count=runtime.normalization_processed_count,
            remaining_count=runtime.remaining_count,
            started_at=runtime.started_at,
            stage_started_at=runtime.stage_started_at,
            updated_at=runtime.updated_at,
            completed_at=runtime.completed_at,
            failed_stage=runtime.failed_stage,
            has_error=runtime.has_error,
            is_stale=(
                runtime.status is PipelineRuntimeState.RUNNING
                and runtime.updated_at < running_fresh_after
            ),
        )


class PipelineRuntimeListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PipelineRuntimeItem]


class EventTimelineItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    host_id: str
    event_type: str

    @classmethod
    def from_normalized_event(cls, event: NormalizedEvent) -> "EventTimelineItem":
        return cls(
            event_id=event.event_id,
            timestamp=event.timestamp,
            host_id=event.host_id,
            event_type=event.event_type,
        )


class EventTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EventTimelineItem]
    total: int
    limit: int
    offset: int


class RawLogReferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_log_id: str
    source_record_id: str | None
    segment_no: int
    record_no: int
    parser_id: str | None
    parser_version: str | None

    @classmethod
    def from_raw_log_reference(cls, raw_ref: RawLogReference) -> "RawLogReferenceResponse":
        return cls(
            raw_log_id=raw_ref.raw_log_id,
            source_record_id=raw_ref.source_record_id,
            segment_no=raw_ref.segment_no,
            record_no=raw_ref.record_no,
            parser_id=raw_ref.parser_id,
            parser_version=raw_ref.parser_version,
        )


class EventDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    run_id: str
    timestamp: datetime
    host_id: str
    event_type: str
    source: str
    source_layer: str
    source_event_id: str
    timestamp_source: str
    raw_ref: RawLogReferenceResponse

    @classmethod
    def from_normalized_event(cls, event: NormalizedEvent) -> "EventDetailResponse":
        return cls(
            event_id=event.event_id,
            run_id=event.run_id,
            timestamp=event.timestamp,
            host_id=event.host_id,
            event_type=event.event_type,
            source=event.source,
            source_layer=event.source_layer,
            source_event_id=event.source_event_id,
            timestamp_source=event.timestamp_source,
            raw_ref=RawLogReferenceResponse.from_raw_log_reference(event.raw_ref),
        )


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
