from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_decision_reader,
    get_run_repository,
)

RUN_ID = "RUN-20261005-001"
DECISION_ID = "D-TEST-001"
DETAIL_VIEW_PATHS = (
    f"/dashboard/runs/{RUN_ID}",
    f"/dashboard/decisions/{DECISION_ID}",
    "/dashboard-assets/detail.css",
)


class _MissingRunRepository:
    def __init__(self) -> None:
        self.get_calls: list[str] = []

    def get(self, run_id: str) -> None:
        self.get_calls.append(run_id)


class _MissingDecisionReader:
    def __init__(self) -> None:
        self.historical_calls: list[str] = []

    def get_current(self, *_args: object) -> None:
        raise AssertionError("Missing Run API must not query Current Decision")

    def list_history(self, *_args: object) -> None:
        raise AssertionError("Missing Run API must not query Decision History")

    def get_historical(self, decision_id: str) -> None:
        self.historical_calls.append(decision_id)


@pytest.fixture(autouse=True)
def database_connection_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        attempts.append("psycopg.connect")
        raise AssertionError("Detail View tests must not open a database connection")

    monkeypatch.setattr(psycopg, "connect", reject_connection)
    return attempts


def test_run_detail_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{RUN_ID}")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Run Detail" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    for section in ("Run Metadata", "Current Decision", "Decision History"):
        assert section in html
    assert database_connection_attempts == []


def test_historical_decision_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Historical Decision" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    for section in ("Decision", "Historical Runtime Snapshot"):
        assert section in html
    assert database_connection_attempts == []


def test_detail_stylesheet_is_served_with_css_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/detail.css")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".detail-page" in response.text


def test_detail_views_do_not_shadow_existing_json_apis(
    database_connection_attempts: list[str],
) -> None:
    # Given
    repository = _MissingRunRepository()
    reader = _MissingDecisionReader()
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    app.dependency_overrides[get_dashboard_decision_reader] = lambda: reader
    client = TestClient(app)

    # When
    run_response = client.get(f"/runs/{RUN_ID}")
    decision_response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert run_response.status_code == 404
    assert run_response.headers["content-type"].startswith("application/json")
    assert run_response.json() == {"detail": "Run not found"}
    assert decision_response.status_code == 404
    assert decision_response.headers["content-type"].startswith("application/json")
    assert decision_response.json() == {"detail": "Decision not found"}
    assert repository.get_calls == [RUN_ID]
    assert reader.historical_calls == [DECISION_ID]
    assert database_connection_attempts == []


def test_detail_view_routes_are_hidden_from_openapi() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/openapi.json")

    # Then
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert "/dashboard/runs/{run_id}" not in paths
    assert "/dashboard/decisions/{decision_id}" not in paths
    assert "/runs/{run_id}" in paths
    assert "/decisions/{decision_id}" in paths
    assert not any(path.startswith("/dashboard-assets") for path in paths)


@pytest.mark.parametrize("path", DETAIL_VIEW_PATHS)
def test_detail_views_and_assets_do_not_depend_on_working_directory(
    path: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200


@pytest.mark.parametrize("path", DETAIL_VIEW_PATHS)
def test_detail_view_files_reference_no_external_resources_or_secrets(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200
    for forbidden_marker in ("://", "@import", "DATABASE_URL", "password", "Traceback"):
        assert forbidden_marker not in response.text


@pytest.mark.parametrize(
    "path",
    (
        f"/dashboard/runs/{RUN_ID}",
        f"/dashboard/decisions/{DECISION_ID}",
    ),
)
def test_detail_views_have_no_inline_script_or_style(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(path).text

    # Then
    assert "<script" not in html
    assert "<style" not in html
    assert " style=" not in html
