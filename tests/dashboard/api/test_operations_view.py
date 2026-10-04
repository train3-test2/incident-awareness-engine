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


def test_operations_script_defines_runtime_polling_contract() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text

    # Then
    assert 'const RUNTIME_ENDPOINT = "/operations/runtime";' in script
    assert "const POLL_INTERVAL_MS = 5000;" in script
    assert "fetch(RUNTIME_ENDPOINT" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "setTimeout(pollRuntime, POLL_INTERVAL_MS);" in script
    assert "setInterval(" not in script


def test_operations_script_preserves_runtime_items_and_query_states() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text

    # Then
    assert "let latestRuntimeItems = [];" in script
    assert "latestRuntimeItems = items;" in script
    assert "!Array.isArray(payload.items)" in script
    assert "Runtime 정보를 불러오는 중입니다." in script
    assert "표시할 Runtime 정보가 없습니다." in script
    assert "Runtime 정보를 불러오지 못했습니다." in script
    assert "Runtime ${latestRuntimeItems.length}건을 불러왔습니다." in script
    assert 'document.getElementById("runtime-list")' not in script


def test_operations_script_uses_safe_status_dom_api() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text

    # Then
    assert "runtimeStatus.textContent = message;" in script
    for forbidden_api in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
    ):
        assert forbidden_api not in script


def test_operations_script_shows_loading_only_before_first_runtime_request() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    start_body = _block_body(script, "function startRuntimePolling() {")
    poll_body = _block_body(script, "async function pollRuntime() {")

    # Then
    assert 'const LOADING_MESSAGE = "Runtime 정보를 불러오는 중입니다.";' in script
    assert script.count("updateRuntimeStatus(LOADING_MESSAGE);") == 1
    assert start_body.index("updateRuntimeStatus(LOADING_MESSAGE);") < start_body.index(
        "void pollRuntime();"
    )
    assert "LOADING_MESSAGE" not in poll_body


def test_operations_script_skips_unchanged_runtime_status_updates() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    update_body = _block_body(script, "function updateRuntimeStatus(message) {")
    guarded_body = _block_body(update_body, "if (runtimeStatus.textContent !== message) {")

    # Then
    assert update_body.count("runtimeStatus.textContent = message;") == 1
    assert "runtimeStatus.textContent = message;" in guarded_body


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


def _block_body(source: str, opening: str) -> str:
    """Return the text inside the braces opened by ``opening`` (which ends with ``{``)."""
    start = source.index(opening) + len(opening)
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated block: {opening}")
