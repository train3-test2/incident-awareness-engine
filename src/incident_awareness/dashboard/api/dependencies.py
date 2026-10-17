from collections.abc import Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, Query
from psycopg import Connection

from incident_awareness.dashboard.decision_read_model import DashboardDecisionReader
from incident_awareness.dashboard.evaluation_read_model import (
    DashboardEvaluationReader,
    evaluation_snapshot_path_from_environment,
)
from incident_awareness.dashboard.fusion_engine_read_model import DashboardFusionEngineReader
from incident_awareness.dashboard.stage_timing_read_model import (
    DashboardStageTimingReader,
    StageTimingQuery,
    StageTimingReadError,
    stage_timing_database_error,
)
from incident_awareness.dashboard.telemetry_read_model import (
    DashboardTelemetryReader,
    TelemetryQuery,
    telemetry_configuration_error,
    translate_telemetry_database_error,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
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


def get_stage_timing_query(query: Annotated[StageTimingQuery, Query()]) -> StageTimingQuery:
    return query


def get_dashboard_stage_timing_reader(
    _query: Annotated[StageTimingQuery, Depends(get_stage_timing_query)],
) -> Iterator[DashboardStageTimingReader]:
    try:
        url = DatabaseConfig.from_environment().url
    except (RuntimeError, ValueError) as error:
        raise StageTimingReadError(500, "Stage timing read failed") from error
    try:
        connection = psycopg.connect(
            url,
            autocommit=False,
            connect_timeout=2,
            options="-c statement_timeout=5000 -c default_transaction_read_only=on -c timezone=UTC",
        )
    except psycopg.Error as error:
        raise stage_timing_database_error(error) from error
    try:
        yield DashboardStageTimingReader(PipelineStageTimingRepository(connection))
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


def get_dashboard_evaluation_reader() -> DashboardEvaluationReader:
    return DashboardEvaluationReader(
        snapshot_path=evaluation_snapshot_path_from_environment(),
    )


def get_telemetry_query(query: Annotated[TelemetryQuery, Query()]) -> TelemetryQuery:
    return query


def get_dashboard_telemetry_reader(
    _query: Annotated[TelemetryQuery, Depends(get_telemetry_query)],
) -> Iterator[DashboardTelemetryReader]:
    """Bound only the new telemetry read; do not change other API connections."""
    try:
        url = DatabaseConfig.from_environment().url
    except (RuntimeError, ValueError) as error:
        raise telemetry_configuration_error(error) from error
    try:
        connection = psycopg.connect(
            url,
            autocommit=False,
            connect_timeout=2,
            options="-c statement_timeout=5000 -c default_transaction_read_only=on",
        )
    except psycopg.Error as error:
        raise translate_telemetry_database_error(error) from error
    try:
        yield DashboardTelemetryReader(PipelineTelemetryRepository(connection))
    finally:
        connection.close()
