from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_decision_reader,
    get_run_repository,
)
from incident_awareness.dashboard.api.models import (
    CurrentDecisionResponse,
    HistoricalDecisionResponse,
    OverviewResponse,
    RunDetailResponse,
    RunListItem,
    RunListResponse,
)
from incident_awareness.dashboard.api.service import get_run_detail
from incident_awareness.dashboard.decision_read_model import DashboardDecisionReader
from incident_awareness.storage.repositories.run_repository import RunRepository

router = APIRouter()
_OVERVIEW_RECENT_RUN_LIMIT = 5


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
