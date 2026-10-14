from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from incident_awareness.dashboard.api.routes import router
from incident_awareness.dashboard.decision_read_model import DashboardReadConsistencyError
from incident_awareness.dashboard.evaluation_read_model import (
    EvaluationSnapshotUnavailableError,
    StoredEvaluationSnapshotInvalidError,
)
from incident_awareness.dashboard.telemetry_read_model import (
    StoredTelemetryInvalidError,
    TelemetryReadDefectError,
    TelemetryUnavailableError,
)
from incident_awareness.dashboard.web import mount_dashboard_assets, operations_view_router
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryInputConflictError,
)
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


async def _handle_decision_integrity_error(
    _request: Request,
    _error: DecisionIntegrityError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Stored Decision lifecycle is inconsistent"},
    )


async def _handle_dashboard_read_consistency_error(
    _request: Request,
    _error: DashboardReadConsistencyError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Dashboard data is changing; retry the request"},
    )


async def _handle_evaluation_snapshot_unavailable_error(
    _request: Request,
    _error: EvaluationSnapshotUnavailableError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Evaluation snapshot is unavailable"},
    )


async def _handle_stored_evaluation_snapshot_invalid_error(
    _request: Request,
    _error: StoredEvaluationSnapshotInvalidError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Stored evaluation snapshot is invalid"},
    )


def create_app() -> FastAPI:
    """Create the Dashboard Read API and Operations View without opening external resources."""
    application = FastAPI(title="Incident Awareness Dashboard API")

    @application.exception_handler(PipelineTelemetryInputConflictError)
    async def handle_telemetry_input_conflict(
        _request: Request, _error: PipelineTelemetryInputConflictError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "detail": "Run telemetry input identity is conflicting or unknown across executions"
            },
        )

    @application.exception_handler(TelemetryUnavailableError)
    async def handle_telemetry_unavailable(
        _request: Request, _error: TelemetryUnavailableError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503, content={"detail": "Telemetry database is unavailable"}
        )

    @application.exception_handler(TelemetryReadDefectError)
    async def handle_telemetry_read_defect(
        _request: Request, _error: TelemetryReadDefectError
    ) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Telemetry read failed"})

    @application.exception_handler(StoredTelemetryInvalidError)
    async def handle_stored_telemetry_invalid(
        _request: Request, _error: StoredTelemetryInvalidError
    ) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Stored telemetry is invalid"})

    @application.get("/healthz")
    def get_health() -> dict[str, str]:
        """Report process health without requiring a database connection."""
        return {"status": "ok"}

    application.add_exception_handler(
        DecisionIntegrityError,
        _handle_decision_integrity_error,
    )
    application.add_exception_handler(
        DashboardReadConsistencyError,
        _handle_dashboard_read_consistency_error,
    )
    application.add_exception_handler(
        EvaluationSnapshotUnavailableError,
        _handle_evaluation_snapshot_unavailable_error,
    )
    application.add_exception_handler(
        StoredEvaluationSnapshotInvalidError,
        _handle_stored_evaluation_snapshot_invalid_error,
    )
    application.include_router(router)
    application.include_router(operations_view_router)
    mount_dashboard_assets(application)
    return application


app = create_app()
