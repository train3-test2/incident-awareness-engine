from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from incident_awareness.common.models.pipeline_runtime import PipelineRuntimeState
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_decision_reader,
    get_event_repository,
    get_pipeline_runtime_repository,
    get_run_repository,
)
from incident_awareness.dashboard.api.models import (
    CurrentDecisionResponse,
    EventDetailResponse,
    EventTimelineItem,
    EventTimelineResponse,
    HistoricalDecisionResponse,
    OverviewResponse,
    PipelineRuntimeItem,
    PipelineRuntimeListResponse,
    RunDetailResponse,
    RunListItem,
    RunListResponse,
)
from incident_awareness.dashboard.api.service import get_run_detail
from incident_awareness.dashboard.decision_read_model import DashboardDecisionReader
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

router = APIRouter()
_OVERVIEW_RECENT_RUN_LIMIT = 5
# Dashboard Runtime telemetry freshness window for displaying whether a persisted running
# snapshot has received recent telemetry. It is not a process-liveness, heartbeat,
# execution, or SLA timeout: an older running snapshot stays running and is marked stale.
_PIPELINE_RUNTIME_FRESHNESS_WINDOW = timedelta(minutes=5)


@router.get("/operations/runtime", response_model=PipelineRuntimeListResponse)
def list_pipeline_runtime(
    repository: Annotated[
        PipelineRuntimeStatusRepository,
        Depends(get_pipeline_runtime_repository),
    ],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    runtime_status: Annotated[
        PipelineRuntimeState | None,
        Query(alias="status"),
    ] = None,
) -> PipelineRuntimeListResponse:
    running_fresh_after = _runtime_utc_now() - _PIPELINE_RUNTIME_FRESHNESS_WINDOW
    runtime_statuses = repository.list_recent(
        limit=limit,
        status=runtime_status,
        running_fresh_after=running_fresh_after,
    )
    return PipelineRuntimeListResponse(
        items=[
            PipelineRuntimeItem.from_runtime_status(
                item,
                running_fresh_after=running_fresh_after,
            )
            for item in runtime_statuses
        ],
    )


@router.get("/overview", response_model=OverviewResponse)
def get_overview(
    repository: Annotated[RunRepository, Depends(get_run_repository)],
) -> OverviewResponse:
    total_runs, recent_runs = repository.list_recent_with_total_count(_OVERVIEW_RECENT_RUN_LIMIT)
    return OverviewResponse(
        total_runs=total_runs,
        recent_runs=[RunListItem.from_run_metadata(run) for run in recent_runs],
    )


@router.get("/runs", response_model=RunListResponse)
def list_runs(
    repository: Annotated[RunRepository, Depends(get_run_repository)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> RunListResponse:
    runs = repository.list_recent(limit)
    return RunListResponse(
        runs=[RunListItem.from_run_metadata(run) for run in runs],
    )


@router.get("/runs/{run_id}", response_model=RunDetailResponse)
def get_run(
    run_id: str,
    repository: Annotated[RunRepository, Depends(get_run_repository)],
    reader: Annotated[DashboardDecisionReader, Depends(get_dashboard_decision_reader)],
) -> RunDetailResponse:
    detail = get_run_detail(
        run_id=run_id,
        run_repository=repository,
        reader=reader,
    )
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Run not found",
        )

    current_response = (
        None
        if detail.current_decision is None
        else CurrentDecisionResponse.from_read_model(detail.current_decision)
    )
    return RunDetailResponse(
        run=detail.run,
        current_decision=current_response,
        decision_history=detail.decision_history,
    )


@router.get("/runs/{run_id}/timeline", response_model=EventTimelineResponse)
def get_event_timeline(
    run_id: str,
    repository: Annotated[EventRepository, Depends(get_event_repository)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventTimelineResponse:
    result = repository.list_by_run_with_total_count(
        run_id,
        limit=limit,
        offset=offset,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Run not found",
        )

    total, events = result
    return EventTimelineResponse(
        items=[EventTimelineItem.from_normalized_event(event) for event in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}/events/{event_id}", response_model=EventDetailResponse)
def get_event(
    run_id: str,
    event_id: str,
    repository: Annotated[EventRepository, Depends(get_event_repository)],
) -> EventDetailResponse:
    result = repository.get_by_run(run_id, event_id)
    if not result.run_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Run not found",
        )
    if result.event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return EventDetailResponse.from_normalized_event(result.event)


@router.get("/decisions/{decision_id}", response_model=HistoricalDecisionResponse)
def get_historical_decision(
    decision_id: str,
    reader: Annotated[DashboardDecisionReader, Depends(get_dashboard_decision_reader)],
) -> HistoricalDecisionResponse:
    historical = reader.get_historical(decision_id)
    if historical is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decision not found",
        )

    return HistoricalDecisionResponse.from_read_model(historical)


def _runtime_utc_now() -> datetime:
    return datetime.now(UTC)
