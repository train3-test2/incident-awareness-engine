"""Read-only latest Pipeline target and exact bounded Run/Entity progress scopes."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_awareness.common.models.pipeline_runtime import PipelineRuntimeState
from incident_awareness.dashboard.api.models import PipelineRuntimeItem
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)

router = APIRouter()


class RuntimeContextQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: list[str] = Field(default_factory=list, max_length=21)
    entity_id: list[str] = Field(default_factory=list, max_length=21)

    @model_validator(mode="after")
    def valid_scopes(self):
        if (
            len(self.run_id) != len(self.entity_id)
            or any(
                not 1 <= len(value) <= 512
                or value.strip() != value
                or any(ord(c) < 32 for c in value)
                for value in self.run_id + self.entity_id
            )
            or len(set(zip(self.run_id, self.entity_id, strict=True))) != len(self.run_id)
        ):
            raise ValueError("Distinct paired Run/Entity scopes required")
        return self


class RuntimeScope(BaseModel):
    run_id: str
    entity_id: str
    runtime: PipelineRuntimeItem | None


class RuntimeContextResponse(BaseModel):
    schema_version: Literal["dashboard_runtime_context_v1"] = "dashboard_runtime_context_v1"
    generated_at: datetime
    pipeline: PipelineRuntimeItem | None
    scopes: list[RuntimeScope]


def query_scopes(query: Annotated[RuntimeContextQuery, Query()]) -> RuntimeContextQuery:
    return query


def context_repository(_query: Annotated[RuntimeContextQuery, Depends(query_scopes)]):
    try:
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=5000 -c timezone=UTC",
        ) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield PipelineRuntimeStatusRepository(connection)
    except psycopg.Error:
        raise HTTPException(503, "Runtime context database unavailable") from None


def read_context(repository, scopes, *, now: datetime) -> RuntimeContextResponse:
    running = repository.list_recent(limit=1, status=PipelineRuntimeState.RUNNING)
    latest = running or repository.list_recent(limit=1)
    reports = repository.list_for_scopes(scopes)
    indexed = {(item.run_id, item.entity_id): item for item in reports}
    cutoff = now - timedelta(minutes=5)

    def public(item):
        return (
            PipelineRuntimeItem.from_runtime_status(item, running_fresh_after=cutoff)
            if item
            else None
        )

    return RuntimeContextResponse(
        generated_at=now,
        pipeline=public(latest[0]) if latest else None,
        scopes=[
            RuntimeScope(
                run_id=run_id, entity_id=entity_id, runtime=public(indexed.get((run_id, entity_id)))
            )
            for run_id, entity_id in scopes
        ],
    )


@router.get("/operations/runtime-context", response_model=RuntimeContextResponse)
def runtime_context(
    query: Annotated[RuntimeContextQuery, Depends(query_scopes)],
    repository: Annotated[PipelineRuntimeStatusRepository, Depends(context_repository)],
):
    try:
        return read_context(
            repository,
            tuple(zip(query.run_id, query.entity_id, strict=True)),
            now=datetime.now(UTC),
        )
    except (ValueError, TypeError):
        raise HTTPException(500, "Stored Runtime context invalid") from None
