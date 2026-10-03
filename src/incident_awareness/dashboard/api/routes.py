from typing import Annotated

from fastapi import APIRouter, Depends, Query

from incident_awareness.dashboard.api.dependencies import get_run_repository
from incident_awareness.dashboard.api.models import RunListItem, RunListResponse
from incident_awareness.storage.repositories.run_repository import RunRepository

router = APIRouter()


@router.get("/runs", response_model=RunListResponse)
def list_runs(
    repository: Annotated[RunRepository, Depends(get_run_repository)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> RunListResponse:
    runs = repository.list_recent(limit)
    return RunListResponse(
        runs=[RunListItem.from_run_metadata(run) for run in runs],
    )
