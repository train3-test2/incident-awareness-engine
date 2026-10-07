from datetime import datetime
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_pipeline_runtime_repository

JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
OPERATIONS_VIEW_PATHS = (
    "/operations",
    "/dashboard-assets/dashboard-shell.css",
    "/dashboard-assets/operations.css",
    "/dashboard-assets/operations.js",
    "/dashboard-assets/operations-contract.mjs",
)
OPERATIONS_CONTRACT_FUNCTIONS = (
    "getRuntimeProgressPresentation",
    "getRuntimeQueryMessage",
    "getRuntimeStatePresentation",
    "getStageLabel",
    "resolveRuntimeQueryState",
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
    assert 'href="/dashboard-assets/dashboard-shell.css"' in html
    assert 'href="/dashboard-assets/operations.css"' in html
    assert '<script type="module" src="/dashboard-assets/operations.js"></script>' in html
    assert 'id="runtime-status"' in html
    assert 'id="runtime-list"' in html
    assert "Detection Hub" in html
    assert "First Cycle 실행 단계와 마지막 보고 상태를 조회합니다." in html
    assert database_connection_attempts == []


def test_dashboard_assets_serve_operations_stylesheet() -> None:
    # Given
    client = TestClient(create_app())

    # When
    shell_response = client.get("/dashboard-assets/dashboard-shell.css")
    response = client.get("/dashboard-assets/operations.css")

    # Then
    assert shell_response.status_code == 200
    assert shell_response.headers["content-type"].startswith("text/css")
    assert ".status-badge" in shell_response.text
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".runtime-status" in response.text


def test_operations_view_uses_shared_shell_and_responsive_layout() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/operations").text
    shell = client.get("/dashboard-assets/dashboard-shell.css").text
    stylesheet = client.get("/dashboard-assets/operations.css").text

    # Then
    assert html.index("/dashboard-assets/dashboard-shell.css") < html.index(
        "/dashboard-assets/operations.css"
    )
    for semantic_element in ("<header", "<nav", "<main", "<section", "<h1", "<h2"):
        assert semantic_element in html
    assert 'class="app-header"' in html
    assert 'class="app-navigation"' in html
    assert 'class="app-page operations-page"' in html
    assert "@media (max-width: 48rem)" in shell
    assert "@media (max-width: 30rem)" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet


def test_dashboard_assets_serve_operations_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/operations.js")

    # Then
    assert response.status_code == 200
    media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
    assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert '} from "./operations-contract.mjs";' in response.text


def test_dashboard_assets_serve_operations_contract_module() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/operations-contract.mjs")

    # Then
    assert response.status_code == 200
    media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
    assert media_type in JAVASCRIPT_MEDIA_TYPES
    for contract_function in OPERATIONS_CONTRACT_FUNCTIONS:
        assert f"export function {contract_function}(" in response.text


def test_operations_contract_module_has_no_dom_network_or_timer_access() -> None:
    # Given
    client = TestClient(create_app())

    # When
    contract = client.get("/dashboard-assets/operations-contract.mjs").text

    # Then
    for browser_api in (
        "document",
        "window",
        "fetch(",
        "AbortController",
        "setTimeout(",
        "setInterval(",
    ):
        assert browser_api not in contract


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


def test_operations_script_keeps_latest_runtime_items_and_validates_payload() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text

    # Then
    assert "let latestRuntimeItems = [];" in script
    assert "latestRuntimeItems = next.items;" in script
    assert "!Array.isArray(payload.items)" in script


def test_operations_script_uses_runtime_query_state_contract() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    poll_body = _block_body(script, "async function pollRuntime() {")
    success_body = _block_body(poll_body, "try {")
    error_body = _block_body(poll_body, "} catch {")

    # Then
    assert 'resolveRuntimeQueryState(latestRuntimeItems, { kind: "error" })' in error_body
    assert "resolveRuntimeQueryState(" in success_body
    assert '{ kind: "success", items }' in success_body


def test_operations_scripts_use_safe_dom_api() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    contract = client.get("/dashboard-assets/operations-contract.mjs").text

    # Then
    assert "runtimeStatus.textContent = message;" in script
    for source in (script, contract):
        for forbidden_api in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ):
            assert forbidden_api not in source


def test_operations_script_shows_loading_only_before_first_runtime_request() -> None:
    # Given
    client = TestClient(create_app())
    loading_update = 'updateRuntimeStatus(getRuntimeQueryMessage("loading"));'

    # When
    script = client.get("/dashboard-assets/operations.js").text
    start_body = _block_body(script, "function startRuntimePolling() {")
    poll_body = _block_body(script, "async function pollRuntime() {")

    # Then
    assert script.count(loading_update) == 1
    assert start_body.index(loading_update) < start_body.index("void pollRuntime();")
    assert '"loading"' not in poll_body


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


def test_operations_contract_labels_every_runtime_stage() -> None:
    # Given
    client = TestClient(create_app())

    # When
    contract = client.get("/dashboard-assets/operations-contract.mjs").text
    stage_labels = _between(contract, "const STAGE_LABELS = new Map([", "]);")

    # Then
    for stage in PipelineStage:
        assert f'["{stage.value}", "' in stage_labels


def test_operations_script_renders_successful_runtime_items_into_list() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    success_body = _block_body(_block_body(script, "async function pollRuntime() {"), "try {")
    render_body = _block_body(script, "function renderRuntimeItems(items, telemetryAvailable) {")

    # Then
    assert 'document.getElementById("runtime-list")' in script
    assert success_body.index(
        "renderRuntimeItems(next.items, next.telemetryAvailable);"
    ) < success_body.index("latestRuntimeItems = next.items;")
    assert success_body.index("latestRuntimeItems = next.items;") < success_body.index(
        "updateRuntimeStatus(next.message);"
    )
    assert "createRuntimeCard(runtime, telemetryAvailable)" in render_body
    assert "runtimeList.replaceChildren(...cards);" in render_body


def test_operations_script_keeps_last_runtime_list_on_error() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    error_body = _block_body(_block_body(script, "async function pollRuntime() {"), "} catch {")

    # Then
    assert error_body.index("updateRuntimeStatus(next.message);") < error_body.index(
        "renderRuntimeItems(next.items, next.telemetryAvailable);"
    )
    assert "latestRuntimeItems =" not in error_body
    assert "replaceChildren" not in error_body


def test_operations_script_times_out_runtime_requests_and_keeps_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    fetch_body = _block_body(script, "async function fetchRuntimeItems() {")
    fetch_cleanup = _block_body(fetch_body, "} finally {")
    poll_cleanup = _block_body(_block_body(script, "async function pollRuntime() {"), "} finally {")

    # Then
    assert "const RUNTIME_REQUEST_TIMEOUT_MS = 10000;" in script
    assert "const POLL_INTERVAL_MS = 5000;" in script
    assert "const controller = new AbortController();" in fetch_body
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in fetch_body
    assert "signal: controller.signal" in fetch_body
    assert "POLL_INTERVAL_MS" not in fetch_body
    assert "clearTimeout(timeoutId);" in fetch_cleanup
    assert "setTimeout(pollRuntime, POLL_INTERVAL_MS);" in poll_cleanup
    assert "setInterval(" not in script


def test_operations_script_builds_runtime_cards_with_dom_api() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    field_body = _block_body(script, "function createField(label, value) {")
    card_body = _block_body(script, "function createRuntimeCard(runtime, telemetryAvailable) {")

    # Then
    assert "document.createElement(" in field_body
    assert "term.textContent = label;" in field_body
    assert "description.textContent = value;" in field_body
    assert 'document.createElement("article")' in card_body
    assert "heading.textContent = displayValue(runtime.run_id);" in card_body
    assert 'document.createElement("span")' in card_body
    assert 'badge.classList.add("status-badge")' in card_body
    assert "badge.textContent = presentation.statusLabel;" in card_body
    assert "header.append(heading, badge);" in card_body


def test_operations_script_renders_cards_from_presentation_contract() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    imported_names = _between(script, "import {", '} from "./operations-contract.mjs";')
    card_body = _block_body(script, "function createRuntimeCard(runtime, telemetryAvailable) {")

    # Then
    for contract_function in OPERATIONS_CONTRACT_FUNCTIONS:
        assert f"{contract_function}," in imported_names
        assert f"function {contract_function}(" not in script
    assert "const STAGE_LABELS" not in script
    assert "getRuntimeStatePresentation(runtime, telemetryAvailable)" in card_body
    assert "getRuntimeProgressPresentation(runtime)" in card_body
    for rendered_value in (
        "presentation.modifiers",
        "presentation.statusLabel",
        "presentation.telemetryLabel",
        "presentation.livenessLabel",
        "getStageLabel(runtime.current_stage)",
        "progress.processed",
        "progress.remaining",
        "getStageLabel(runtime.failed_stage)",
    ):
        assert rendered_value in card_body


def test_operations_scripts_keep_api_runtime_order() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    contract = client.get("/dashboard-assets/operations-contract.mjs").text

    # Then
    for source in (script, contract):
        for reordering_api in (".sort(", ".toSorted(", ".reverse(", ".toReversed("):
            assert reordering_api not in source


def test_operations_scripts_avoid_liveness_and_queue_wording() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/operations.js").text
    contract = client.get("/dashboard-assets/operations-contract.mjs").text

    # Then
    for source in (script, contract):
        for misleading_wording in ("현재 실행 중", "대기열", "backlog", "queue"):
            assert misleading_wording not in source


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
    assert html.count('<script type="module" src="/dashboard-assets/operations.js">') == 1
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
    assert [response.status_code for response in responses] == [200] * len(OPERATIONS_VIEW_PATHS)


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


def _between(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker) + len(start_marker)
    return source[start : source.index(end_marker, start)]
