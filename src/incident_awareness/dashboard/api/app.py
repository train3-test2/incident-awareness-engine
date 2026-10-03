from fastapi import FastAPI

from incident_awareness.dashboard.api.routes import router


def create_app() -> FastAPI:
    """Create the Dashboard Read API without opening external resources."""
    application = FastAPI(title="Incident Awareness Dashboard API")
    application.include_router(router)
    return application


app = create_app()
