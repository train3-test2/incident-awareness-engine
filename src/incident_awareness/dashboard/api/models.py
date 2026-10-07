from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.fusion_runtime_config import FusionRuntimeConfigSnapshot
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
from incident_awareness.dashboard.evaluation_read_model import EvaluationReadModel
from incident_awareness.evaluation.result_inputs import EvaluationPlan


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


class FusionEngineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run: RunMetadata
    current_decision: DecisionResult | None
    fusion_result: FusionResult | None
    stopping_trace: FusionStoppingTrace | None
    runtime_config_snapshot: FusionRuntimeConfigSnapshot | None


class EvaluationExclusionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    method: Literal["Fast", "Fusion", "Hybrid"]
    reason: Literal["not_evaluated"]


class EvaluationMethodMetricResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["Fast", "Fusion", "Hybrid"]
    total_attack_runs: int
    detected_runs: int
    run_recall: float | None
    median_ttsd_sec: float | None
    total_normal_runs: int
    false_positive_runs: int
    benign_run_fpr: float | None
    ttsd_iqr_sec: float | None


class EvaluationMethodMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fast: EvaluationMethodMetricResponse | None = Field(alias="Fast")
    fusion: EvaluationMethodMetricResponse | None = Field(alias="Fusion")
    hybrid: EvaluationMethodMetricResponse | None = Field(alias="Hybrid")


class EvaluationRunIdsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fast: list[str] = Field(alias="Fast")
    fusion: list[str] = Field(alias="Fusion")
    hybrid: list[str] = Field(alias="Hybrid")


class NormalAlertBurdenExclusionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    method: Literal["Fast", "Fusion"]
    reason: Literal["not_evaluated"]


class NormalAlertBurdenPerRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    entity_id: str
    family_id: str | None
    variation_id: str | None
    repetition: int | None
    false_alert_episodes: int
    observation_seconds: float


class NormalAlertBurdenMetricResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluated_run_ids: list[str]
    false_alert_episodes: int
    benign_run_hours: float
    false_alerts_per_benign_run_hour: float | None
    per_run: list[NormalAlertBurdenPerRunResponse]


class NormalAlertBurdenMetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fast: NormalAlertBurdenMetricResponse = Field(alias="Fast")
    fusion: NormalAlertBurdenMetricResponse = Field(alias="Fusion")


class NormalAlertBurdenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    plan: EvaluationPlan
    normal_run_ids: list[str]
    exclusions: list[NormalAlertBurdenExclusionResponse]
    comparison_ready: bool
    metrics: NormalAlertBurdenMetricsResponse


class PairedTimingPathResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    eligible_status: Literal["detected", "miss", "not_evaluated"]
    eligible_time: str | None
    ttsd_sec: float | None


class PairedTimingPathsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fast: PairedTimingPathResponse = Field(alias="Fast")
    fusion: PairedTimingPathResponse = Field(alias="Fusion")


class PairedTimingCountsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    both_detected: int
    fast_only: int
    fusion_only: int
    both_miss: int
    not_evaluated: int


class PairedTimingSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_count: int
    fast_earlier: int
    fusion_earlier: int
    ties: int
    median_fusion_minus_fast_sec: float | None


class PairedTimingRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    entity_id: str
    family_id: str | None
    variation_id: str | None
    repetition: int | None
    decision_id: str
    reference_time: str
    paths: PairedTimingPathsResponse
    outcome: Literal[
        "both_detected",
        "fast_only",
        "fusion_only",
        "both_miss",
        "not_evaluated",
    ]
    fusion_minus_fast_sec: float | None
    earlier_eligible_path: Literal["Fast", "Fusion", "tie"] | None


class PairedTimingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    snapshot_id: str
    plan: EvaluationPlan
    attack_run_ids: list[str]
    exclusions: list[NormalAlertBurdenExclusionResponse]
    paired_coverage_complete: bool
    counts: PairedTimingCountsResponse
    both_detected_summary: PairedTimingSummaryResponse
    per_run: list[PairedTimingRunResponse]


class DashboardEvaluationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: str
    plan: EvaluationPlan
    exclusions: list[EvaluationExclusionResponse]
    evaluated_run_ids: EvaluationRunIdsResponse
    comparison_ready: bool
    metrics: EvaluationMethodMetricsResponse
    normal_alert_burden: NormalAlertBurdenResponse
    paired_timing: PairedTimingResponse

    @classmethod
    def from_read_model(cls, read_model: EvaluationReadModel) -> "DashboardEvaluationResponse":
        return cls.model_validate(
            {
                **read_model.evaluation,
                "normal_alert_burden": read_model.normal_alert_burden,
                "paired_timing": read_model.paired_timing,
            }
        )


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
