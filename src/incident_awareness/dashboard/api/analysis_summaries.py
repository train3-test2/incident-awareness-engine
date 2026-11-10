"""Read-only analysis summaries for the Runs already shown in the Dashboard list.

One bounded snapshot replaces a detail request per row. Stored results are returned as they are;
nothing is classified, merged or repaired here.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.result_repository import (
    DecisionIntegrityError,
    DecisionRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

router = APIRouter()

# Matches the Dashboard Run list limit (/runs?limit=20).
MAX_SUMMARY_RUNS = 20


class AnalysisSummaryQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: list[str] = Field(min_length=1, max_length=MAX_SUMMARY_RUNS)

    @model_validator(mode="after")
    def distinct_identifiers(self):
        if len(set(self.run_id)) != len(self.run_id) or any(
            not 1 <= len(value) <= 512
            or value.strip() != value
            or any(ord(character) < 32 for character in value)
            for value in self.run_id
        ):
            raise ValueError("Distinct Run identifiers required")
        return self


class StoredObservationSummary(BaseModel):
    source: Literal["stored_events"] = "stored_events"
    entity_id: str
    event_count: int = Field(ge=0)
    event_type_counts: dict[str, int]


class AnalysisSummaryItem(BaseModel):
    run_id: str
    # run_not_found and integrity_error are facts about this Run, not an empty analysis.
    status: Literal["available", "run_not_found", "integrity_error"]
    entity_id: str | None = None
    decision: DecisionResult | None = None
    fusion_result: FusionResult | None = None
    observations: StoredObservationSummary | None = None


class AnalysisSummariesResponse(BaseModel):
    schema_version: Literal["dashboard_analysis_summaries_v1"] = "dashboard_analysis_summaries_v1"
    generated_at: datetime
    items: list[AnalysisSummaryItem]


class StoredObservationReader:
    """One grouped read for all requested Runs, scoped to each Run's declared target.

    These are stored normalized Event facts, not raw-verification results or attack claims.
    No command lines, IP relationships or technique mappings are inferred.
    """

    def __init__(self, connection):
        self.connection = connection

    def read(self, run_ids: tuple[str, ...]) -> dict[tuple[str, str], StoredObservationSummary]:
        with self.connection.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute(
                "SELECT r.run_id,r.target_host,e.event_type,COUNT(e.event_id) AS event_count"
                " FROM runs r LEFT JOIN events e ON e.run_id=r.run_id AND e.host_id=r.target_host"
                " WHERE r.run_id=ANY(%s) GROUP BY r.run_id,r.target_host,e.event_type"
                " ORDER BY r.run_id,e.event_type",
                (list(run_ids),),
            ).fetchall()
        grouped = {}
        for row in rows:
            key = (row["run_id"], row["target_host"])
            item = grouped.setdefault(
                key,
                StoredObservationSummary(
                    entity_id=row["target_host"], event_count=0, event_type_counts={}
                ),
            )
            count = row["event_count"]
            if row["event_type"] is not None:
                if not isinstance(count, int) or count < 1:
                    raise ValueError("Stored Event count invalid")
                item.event_type_counts[row["event_type"]] = count
                item.event_count += count
        return grouped


@dataclass(frozen=True, slots=True)
class SummaryRepositories:
    runs: RunRepository
    decisions: DecisionRepository
    fusion_results: FusionResultRepository
    observations: StoredObservationReader | None = None


def query_runs(query: Annotated[AnalysisSummaryQuery, Query()]) -> AnalysisSummaryQuery:
    return query


def summary_repositories(_query: Annotated[AnalysisSummaryQuery, Depends(query_runs)]):
    try:
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=5000 -c timezone=UTC",
        ) as connection:
            # One snapshot: every Run is summarized from the same committed state.
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield SummaryRepositories(
                runs=RunRepository(connection),
                decisions=DecisionRepository(connection),
                fusion_results=FusionResultRepository(connection),
                observations=StoredObservationReader(connection),
            )
    except psycopg.Error:
        raise HTTPException(503, "Analysis summary database unavailable") from None


def read_summaries(
    repositories: SummaryRepositories,
    run_ids: tuple[str, ...],
    *,
    now: datetime,
) -> AnalysisSummariesResponse:
    """Three reads per Run (metadata, current Decision head, Fusion result), at most 20 Runs."""
    observations = repositories.observations.read(run_ids) if repositories.observations else {}
    items = []
    for run_id in run_ids:
        run = repositories.runs.get(run_id)
        if run is None:
            items.append(AnalysisSummaryItem(run_id=run_id, status="run_not_found"))
            continue
        try:
            decision = repositories.decisions.get_current_head(run_id, run.target_host)
        except DecisionIntegrityError:
            items.append(
                AnalysisSummaryItem(
                    run_id=run_id, status="integrity_error", entity_id=run.target_host
                )
            )
            continue
        items.append(
            AnalysisSummaryItem(
                run_id=run_id,
                status="available",
                entity_id=run.target_host,
                decision=decision,
                fusion_result=repositories.fusion_results.get(run_id, run.target_host),
                observations=observations.get((run_id, run.target_host)),
            )
        )
    return AnalysisSummariesResponse(generated_at=now, items=items)


@router.get("/analysis-summaries", response_model=AnalysisSummariesResponse)
def analysis_summaries(
    query: Annotated[AnalysisSummaryQuery, Depends(query_runs)],
    repositories: Annotated[SummaryRepositories, Depends(summary_repositories)],
) -> AnalysisSummariesResponse:
    try:
        return read_summaries(repositories, tuple(query.run_id), now=datetime.now(UTC))
    except (ValueError, TypeError):
        raise HTTPException(500, "Stored analysis summary invalid") from None
