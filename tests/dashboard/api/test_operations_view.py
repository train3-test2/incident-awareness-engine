from datetime import datetime
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_pipeline_runtime_repository

JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
OPERATIONS_VIEW_PATHS = (
    "/operations",
    "/dashboard-assets/operations.css",
    "/dashboard-assets/operations.js",
)


class _EmptyPipelineRuntimeRepository:
    def __init__(self) -> None:
        self.calls: list[tuple[int, PipelineRuntimeState | None]] = []

    def list_recent(
        self,
        *,
        limit: int,
        status: PipelineRuntimeState | None = None,
        running_fresh_after: datetime | None = None,
    ) -> list[PipelineRuntimeStatus]:
        self.calls.append((limit, status))
        return []


@pytest.fixture(autouse=True)
def database_connection_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        attempts.append("psycopg.connect")
        raise AssertionError("Operations View tests must not open a database connection")

    monkeypatch.setattr(psycopg, "connect", reject_connection)
    return attempts


def test_operations_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/operations")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Pipeline Runtime Operations" in html
    assert 'href="/dashboard-assets/operations.css"' in html
    assert 'src="/dashboard-assets/operations.js"' in html
    assert 'id="runtime-status"' in html
    assert 'id="runtime-list"' in html
    assert database_connection_attempts == []


def test_dashboard_assets_serve_operations_stylesheet() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/operations.css")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".runtime-status" in response.text


def test_dashboard_assets_serve_operations_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/operations.js")

    # Then
    assert response.status_code == 200
    media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
    assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert response.text.startswith('"use strict";')


def test_dashboard_assets_do_not_serve_operations_html_shell() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/operations.html")

    # Then
    assert response.status_code == 404
    assert "Pipeline Runtime Operations" not in response.text


def test_operations_runtime_api_is_not_shadowed_by_operations_view(
    database_connection_attempts: list[str],
) -> None:
    # Given
    repository = _EmptyPipelineRuntimeRepository()
    app = create_app()
    app.dependency_overrides[get_pipeline_runtime_repository] = lambda: repository
    client = TestClient(app)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"items": []}
    assert repository.calls == [(20, None)]
    assert database_connection_attempts == []


def test_api_docs_keep_runtime_api_and_hide_operations_view() -> None:
    # Given
    client = TestClient(create_app())

    # When
    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")

    # Then
    assert docs_response.status_code == 200
    assert openapi_response.status_code == 200
    paths = set(openapi_response.json()["paths"])
    assert "/operations/runtime" in paths
    assert "/operations" not in paths
    assert not any(path.startswith("/dashboard-assets") for path in paths)


def test_operations_view_html_has_no_inline_script_or_style() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/operations").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script src="/dashboard-assets/operations.js"') == 1
    assert "<style" not in html
    assert " style=" not in html


@pytest.mark.parametrize("path", OPERATIONS_VIEW_PATHS)
def test_operations_view_files_reference_no_external_resources_or_secrets(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200
    for forbidden_marker in ("://", "@import", "DATABASE_URL", "password"):
        assert forbidden_marker not in response.text


def test_operations_view_does_not_depend_on_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    # When
    responses = [client.get(path) for path in OPERATIONS_VIEW_PATHS]

    # Then
    assert [response.status_code for response in responses] == [200, 200, 200]
