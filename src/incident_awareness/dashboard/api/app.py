from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from incident_awareness.dashboard.api.routes import router
from incident_awareness.dashboard.decision_read_model import DashboardReadConsistencyError
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


def create_app() -> FastAPI:
    """Create the Dashboard Read API without opening external resources."""
    application = FastAPI(title="Incident Awareness Dashboard API")
    application.add_exception_handler(
        DecisionIntegrityError,
        _handle_decision_integrity_error,
    )
    application.add_exception_handler(
        DashboardReadConsistencyError,
        _handle_dashboard_read_consistency_error,
    )
    application.include_router(router)
    return application


app = create_app()
