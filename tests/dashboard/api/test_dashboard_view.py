from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_run_repository

JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
DASHBOARD_VIEW_PATHS = (
    "/dashboard",
    "/dashboard-assets/dashboard.css",
    "/dashboard-assets/dashboard.js",
)


class _EmptyRunRepository:
    def __init__(self) -> None:
        self.recent_limits: list[int] = []
        self.overview_limits: list[int] = []

    def list_recent(self, limit: int) -> list[object]:
        self.recent_limits.append(limit)
        return []

    def list_recent_with_total_count(self, limit: int) -> tuple[int, list[object]]:
        self.overview_limits.append(limit)
        return 0, []


@pytest.fixture(autouse=True)
def database_connection_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        attempts.append("psycopg.connect")
        raise AssertionError("Dashboard View tests must not open a database connection")

    monkeypatch.setattr(psycopg, "connect", reject_connection)
    return attempts


def test_dashboard_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Incident Awareness Dashboard" in html
    assert 'href="/dashboard-assets/dashboard.css"' in html
    assert 'src="/dashboard-assets/dashboard.js"' in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    for section in ("Overview", "Total Runs", "Recent Runs", "Runs"):
        assert section in html
    for status_id in ("overview-status", "recent-runs-status", "runs-status"):
        assert f'id="{status_id}"' in html
    assert database_connection_attempts == []


def test_operations_view_includes_dashboard_navigation() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/operations").text

    # Then
    assert 'href="/dashboard"' in html
    assert 'href="/operations" aria-current="page"' in html


def test_dashboard_assets_serve_stylesheet_and_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    stylesheet = client.get("/dashboard-assets/dashboard.css")
    script = client.get("/dashboard-assets/dashboard.js")

    # Then
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert ".dashboard-navigation" in stylesheet.text
    assert script.status_code == 200
    media_type = script.headers["content-type"].split(";", maxsplit=1)[0].strip()
    assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert script.text.startswith('"use strict";')


def test_dashboard_script_is_safe_bootstrap_without_api_fetching() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    assert 'document.getElementById("dashboard-view")' in script
    for forbidden_api in (
        "fetch(",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert forbidden_api not in script


def test_dashboard_assets_do_not_serve_dashboard_html_shell() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/dashboard.html")

    # Then
    assert response.status_code == 404
    assert "Incident Awareness Dashboard" not in response.text


def test_dashboard_view_does_not_shadow_overview_and_runs_apis(
    database_connection_attempts: list[str],
) -> None:
    # Given
    repository = _EmptyRunRepository()
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    client = TestClient(app)

    # When
    overview_response = client.get("/overview")
    runs_response = client.get("/runs")

    # Then
    assert overview_response.status_code == 200
    assert overview_response.headers["content-type"].startswith("application/json")
    assert overview_response.json() == {"total_runs": 0, "recent_runs": []}
    assert runs_response.status_code == 200
    assert runs_response.headers["content-type"].startswith("application/json")
    assert runs_response.json() == {"runs": []}
    assert repository.overview_limits == [5]
    assert repository.recent_limits == [20]
    assert database_connection_attempts == []


def test_api_docs_keep_json_apis_and_hide_dashboard_views() -> None:
    # Given
    client = TestClient(create_app())

    # When
    openapi_response = client.get("/openapi.json")

    # Then
    assert openapi_response.status_code == 200
    paths = set(openapi_response.json()["paths"])
    assert {"/overview", "/runs"} <= paths
    assert "/dashboard" not in paths
    assert "/operations" not in paths
    assert not any(path.startswith("/dashboard-assets") for path in paths)


def test_dashboard_view_has_no_inline_script_or_style() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script src="/dashboard-assets/dashboard.js" defer>') == 1
    assert "<style" not in html
    assert " style=" not in html


@pytest.mark.parametrize("path", DASHBOARD_VIEW_PATHS)
def test_dashboard_view_files_reference_no_external_resources_or_secrets(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200
    for forbidden_marker in ("://", "@import", "DATABASE_URL", "password"):
        assert forbidden_marker not in response.text


def test_dashboard_view_does_not_depend_on_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    # When
    responses = [client.get(path) for path in DASHBOARD_VIEW_PATHS]

    # Then
    assert [response.status_code for response in responses] == [200] * len(DASHBOARD_VIEW_PATHS)
