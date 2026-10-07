from collections.abc import Iterator
from typing import Annotated

import psycopg
from fastapi import Depends
from psycopg import Connection

from incident_awareness.dashboard.decision_read_model import DashboardDecisionReader
from incident_awareness.dashboard.fusion_engine_read_model import DashboardFusionEngineReader
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DecisionRuntimeSnapshotRepository,
    DetectionResultRepository,
    FusionResultRepository,
    FusionRuntimeConfigSnapshotRepository,
    FusionStoppingTraceRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository


def get_database_connection() -> Iterator[Connection[tuple[object, ...]]]:
    """Provide one PostgreSQL connection for the lifetime of an HTTP request."""
    connection = psycopg.connect(DatabaseConfig.from_environment().url)
    try:
        yield connection
    finally:
        connection.close()


def get_run_repository(
    connection: Annotated[Connection[tuple[object, ...]], Depends(get_database_connection)],
) -> RunRepository:
    return RunRepository(connection)


def get_event_repository(
    connection: Annotated[Connection[tuple[object, ...]], Depends(get_database_connection)],
) -> EventRepository:
    return EventRepository(connection)


def get_pipeline_runtime_repository(
    connection: Annotated[Connection[tuple[object, ...]], Depends(get_database_connection)],
) -> PipelineRuntimeStatusRepository:
    return PipelineRuntimeStatusRepository(connection)


def get_dashboard_decision_reader(
    connection: Annotated[Connection[tuple[object, ...]], Depends(get_database_connection)],
) -> DashboardDecisionReader:
    return DashboardDecisionReader(
        decision_repository=DecisionRepository(connection),
        detection_repository=DetectionResultRepository(connection),
        fusion_repository=FusionResultRepository(connection),
        stopping_trace_repository=FusionStoppingTraceRepository(connection),
        snapshot_repository=DecisionRuntimeSnapshotRepository(connection),
    )


def get_dashboard_fusion_engine_reader(
    connection: Annotated[Connection[tuple[object, ...]], Depends(get_database_connection)],
) -> DashboardFusionEngineReader:
    return DashboardFusionEngineReader(
        decision_repository=DecisionRepository(connection),
        fusion_repository=FusionResultRepository(connection),
        stopping_trace_repository=FusionStoppingTraceRepository(connection),
        runtime_config_repository=FusionRuntimeConfigSnapshotRepository(connection),
    )
