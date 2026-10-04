"""Serve Dashboard UI shells and static assets without database access."""

import mimetypes
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_UI_DIRECTORY = Path(__file__).resolve().parent / "ui"
_ASSETS_DIRECTORY = _UI_DIRECTORY / "assets"
_DASHBOARD_ASSETS_PATH = "/dashboard-assets"

operations_view_router = APIRouter(include_in_schema=False)


@operations_view_router.get("/dashboard")
def get_dashboard_view() -> FileResponse:
    return FileResponse(_UI_DIRECTORY / "dashboard.html", media_type="text/html")


@operations_view_router.get("/operations")
def get_operations_view() -> FileResponse:
    return FileResponse(_UI_DIRECTORY / "operations.html", media_type="text/html")


def mount_dashboard_assets(application: FastAPI) -> None:
    """Serve CSS/JS assets, not the HTML shell, under a prefix that cannot shadow APIs."""
    # Browsers execute module scripts only with a JavaScript MIME type, and some Windows
    # registries map .mjs to text/plain, so register the standard type explicitly.
    mimetypes.add_type("text/javascript", ".mjs")
    application.mount(
        _DASHBOARD_ASSETS_PATH,
        StaticFiles(directory=_ASSETS_DIRECTORY),
        name="dashboard-assets",
    )


__all__ = ["mount_dashboard_assets", "operations_view_router"]
