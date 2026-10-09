from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_run_repository

JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
DASHBOARD_VIEW_PATHS = (
    "/dashboard",
    "/dashboard-assets/dashboard-shell.css",
    "/dashboard-assets/dashboard.css",
    "/dashboard-assets/dashboard.js",
    "/dashboard-assets/dashboard-contract.mjs",
)
DASHBOARD_CONTRACT_FUNCTIONS = (
    "displayValue",
    "formatRunTimestamp",
    "getOverviewQueryMessage",
    "getRunTypeLabel",
    "resolveOverviewQueryState",
    "resolveRunListQueryState",
    "resolveRuntimeSummaryQueryState",
)
DASHBOARD_SCRIPT_CONTRACT_FUNCTIONS = (
    "displayValue",
    "formatRunTimestamp",
    "getRunTypeLabel",
    "resolveOverviewQueryState",
    "resolveRunListQueryState",
    "resolveRuntimeSummaryQueryState",
)
OPERATIONS_SCRIPT_CONTRACT_FUNCTIONS = (
    "getRuntimeStatePresentation",
    "getStageLabel",
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
    assert 'href="/dashboard-assets/dashboard-shell.css"' in html
    assert 'href="/dashboard-assets/dashboard.css"' in html
    assert '<script type="module" src="/dashboard-assets/dashboard.js"></script>' in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert "Detection Hub" in html
    assert "운영 View" in html
    assert "침해사고 인지 시스템 실행 및 사건 조회" in html
    assert "Run의 Start와 End는 원본 데이터의 관측 구간입니다." in html
    assert "시스템 처리 시각과는 다릅니다." in html
    assert "Run ID나 Event timestamp로 추정하지 않습니다." in html
    for section in ("Overview", "Total Runs", "Recent Runs", "Pipeline Runtime Summary", "Runs"):
        assert section in html
    for status_id in (
        "total-runs-value",
        "overview-status",
        "recent-runs-status",
        "recent-runs-list",
        "runtime-summary-status",
        "runtime-summary-list",
        "runs-status",
        "runs-list",
    ):
        assert f'id="{status_id}"' in html
    assert (
        "페이지를 열 때 한 번 조회하며, 최근 보고된 Runtime 항목을 API 순서대로 "
        "최대 5건 표시합니다."
    ) in html
    assert '<a class="dashboard-section-link" href="/operations">Operations 보기</a>' in html
    assert '<details class="dashboard-runs-disclosure">' in html
    assert "<summary>Runs 목록 펼치기 — 관측 시작 최근순 최대 20건</summary>" in html
    assert '<details class="dashboard-runs-disclosure" open>' not in html
    assert "Run 목록은 다음 단계에서 표시됩니다." not in html
    assert database_connection_attempts == []


def test_dashboard_runs_status_remains_visible_while_run_list_is_collapsed() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text

    # Then
    runs_status_index = html.index('id="runs-status"')
    disclosure_start = html.index('<details class="dashboard-runs-disclosure">')
    disclosure_end = html.index("</details>", disclosure_start)
    runs_list_index = html.index('id="runs-list"')
    disclosure = html[disclosure_start:disclosure_end]
    assert runs_status_index < disclosure_start
    assert disclosure_start < runs_list_index < disclosure_end
    assert 'id="runs-status"' not in disclosure
    assert '<details class="dashboard-runs-disclosure" open>' not in html


def test_operations_view_includes_dashboard_navigation() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/operations").text

    # Then
    assert 'href="/dashboard"' in html
    assert 'href="/operations" aria-current="page"' in html


def test_dashboard_assets_serve_stylesheet_script_and_contract_module() -> None:
    # Given
    client = TestClient(create_app())

    # When
    shell_stylesheet = client.get("/dashboard-assets/dashboard-shell.css")
    stylesheet = client.get("/dashboard-assets/dashboard.css")
    script = client.get("/dashboard-assets/dashboard.js")
    contract = client.get("/dashboard-assets/dashboard-contract.mjs")

    # Then
    for response in (shell_stylesheet, stylesheet):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/css")
    assert ".app-navigation" in shell_stylesheet.text
    assert "--shell-color-primary" in shell_stylesheet.text
    assert ".run-card-list" in stylesheet.text
    assert script.status_code == 200
    assert contract.status_code == 200
    for response in (script, contract):
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert '} from "./dashboard-contract.mjs";' in script.text
    for contract_function in DASHBOARD_CONTRACT_FUNCTIONS:
        assert f"export function {contract_function}(" in contract.text


def test_dashboard_run_cards_link_to_encoded_run_detail_view_paths() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    contract = client.get("/dashboard-assets/run-detail-contract.mjs").text

    # Then
    assert 'import { buildRunDetailViewPath } from "./run-detail-contract.mjs";' in script
    assert 'const link = document.createElement("a");' in script
    assert "link.href = buildRunDetailViewPath(run.run_id);" in script
    assert "link.textContent = run.run_id;" in script
    assert "state.recentRuns.map((run) => createRecentRunCard(run))" in script
    assert "state.items.map((run) => createRunCard(run))" in script
    assert 'encodeURIComponent(requireIdentifier(runId, "runId"))' in contract
    assert "`/dashboard/runs/${run.run_id}`" not in script


def test_dashboard_script_fetches_three_independent_apis_once_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    assert 'document.getElementById("dashboard-view")' in script
    assert 'const OVERVIEW_ENDPOINT = "/overview";' in script
    assert 'const RUNS_ENDPOINT = "/runs";' in script
    assert 'const RUNTIME_ENDPOINT = "/operations/runtime?limit=5";' in script
    assert "const RUNTIME_REQUEST_TIMEOUT_MS = 10000;" in script
    assert "fetch(OVERVIEW_ENDPOINT" in script
    assert "fetch(RUNS_ENDPOINT" in script
    assert "fetch(RUNTIME_ENDPOINT" in script
    assert script.count('Accept: "application/json"') == 3
    assert script.count('cache: "no-store"') == 3
    assert script.count("void loadOverview();") == 1
    assert script.count("void loadRuns();") == 1
    assert script.count("void loadRuntimeSummary();") == 1
    assert 'document.getElementById("runs-status")' in script
    assert 'document.getElementById("runs-list")' in script
    assert 'document.getElementById("runtime-summary-status")' in script
    assert 'document.getElementById("runtime-summary-list")' in script
    assert "setInterval(" not in script
    assert script.count("setTimeout(") == 1
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "clearTimeout(timeoutId);" in script
    assert "signal: controller.signal" in script
    for repeated_request in (
        "setTimeout(loadRuntimeSummary",
        "setTimeout(fetchRuntimeSummary",
        "setInterval(loadRuntimeSummary",
        "setInterval(fetchRuntimeSummary",
    ):
        assert repeated_request not in script


def test_dashboard_view_uses_shared_shell_and_responsive_layout() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text
    shell = client.get("/dashboard-assets/dashboard-shell.css").text
    stylesheet = client.get("/dashboard-assets/dashboard.css").text

    # Then
    assert html.index("/dashboard-assets/dashboard-shell.css") < html.index(
        "/dashboard-assets/dashboard.css"
    )
    for semantic_element in ("<header", "<nav", "<main", "<section", "<h1", "<h2"):
        assert semantic_element in html
    assert 'class="app-header"' in html
    assert 'class="app-navigation"' in html
    assert 'class="app-page dashboard-page"' in html
    assert "@media (max-width: 48rem)" in shell
    assert "@media (max-width: 30rem)" in shell
    assert "@media (max-width: 40rem)" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet
    assert ".runtime-summary-card__header" in stylesheet
    assert "word-break: break-word" in stylesheet
    assert "width: min(100%, var(--shell-page-width))" in shell


def test_dashboard_script_uses_contract_and_safe_dom_rendering() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    for contract_function in DASHBOARD_SCRIPT_CONTRACT_FUNCTIONS:
        assert f"{contract_function}," in script
        assert f"function {contract_function}(" not in script
    for contract_function in OPERATIONS_SCRIPT_CONTRACT_FUNCTIONS:
        assert f"{contract_function}," in script
        assert f"function {contract_function}(" not in script
    for safe_api in (
        "document.createElement(",
        ".textContent =",
        ".append(",
        ".replaceChildren(",
        ".classList.add(",
    ):
        assert safe_api in script
    for forbidden_api in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert forbidden_api not in script
    assert 'createRunField("Scenario"' in script
    assert 'createRunField("Type"' in script
    assert 'createRunField("Target"' in script
    assert 'createRunField("Observed Start"' in script
    assert 'createRunField("Observed End"' in script
    assert 'document.createElement("a")' in script
    assert 'createRuntimeSummaryField("현재 단계"' in script
    assert 'createRuntimeSummaryField("Runtime 마지막 갱신"' in script
    assert 'createRuntimeSummaryField("Telemetry"' in script
    assert 'createRuntimeSummaryField("현재 실행 여부"' in script
    assert "getRuntimeStatePresentation(runtime, telemetryAvailable)" in script
    assert "getStageLabel(runtime.current_stage)" in script
    assert "formatRunTimestamp(runtime.updated_at)" in script


def test_dashboard_script_keeps_overview_runs_and_runtime_state_independent() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    assert "async function loadOverview()" in script
    assert "async function loadRuns()" in script
    assert "async function loadRuntimeSummary()" in script
    assert "renderOverviewState(state);" in script
    assert "renderRunListState(state);" in script
    assert "renderRuntimeSummaryState(state);" in script
    assert "overviewStatus.textContent = state.totalMessage;" in script
    assert "recentRunsStatus.textContent = state.message;" in script
    assert "runsStatus.textContent = state.message;" in script
    assert "runtimeSummaryStatus.textContent = state.message;" in script
    assert script.count("catch {") == 3


def test_dashboard_runtime_summary_preserves_order_and_operations_state_meaning() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    contract = client.get("/dashboard-assets/dashboard-contract.mjs").text

    # Then
    assert '} from "./operations-contract.mjs";' in script
    assert '} from "./operations-contract.mjs";' in contract
    assert "state.items.map(" in script
    assert "createRuntimeSummaryCard(runtime, state.telemetryAvailable)" in script
    assert "status-badge--${modifier}" in script
    assert "runtime-summary-card--${modifier}" in script
    assert "presentation.telemetryLabel" in script
    assert "presentation.livenessLabel" in script
    assert "현재 실행 중" not in script
    assert "setInterval(" not in script
    assert script.count("setTimeout(") == 1
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "clearTimeout(timeoutId);" in script


def test_dashboard_runtime_summary_requires_api_presentation_fields() -> None:
    # Given
    client = TestClient(create_app())

    # When
    contract = client.get("/dashboard-assets/dashboard-contract.mjs").text

    # Then
    assert (
        'const PIPELINE_RUNTIME_STATUSES = new Set(["running", "completed", "failed"]);' in contract
    )
    assert "const PIPELINE_RUNTIME_STAGES = new Set([" in contract
    assert '!Object.hasOwn(runtime, "current_stage")' in contract
    assert "runtime.current_stage !== null" in contract
    assert "!PIPELINE_RUNTIME_STAGES.has(runtime.current_stage)" in contract
    assert 'typeof runtime.updated_at !== "string"' in contract
    assert 'typeof runtime.is_stale !== "boolean"' in contract


def test_dashboard_runtime_summary_links_only_completed_runs_to_run_detail() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    card_source = script.split("function createRuntimeSummaryCard", maxsplit=1)[1].split(
        "function renderOverviewState",
        maxsplit=1,
    )[0]

    # Then
    assert 'if (runtime.status === "completed" && runtime.run_id.trim()) {' in card_source
    assert "link.href = buildRunDetailViewPath(runtime.run_id);" in card_source
    assert "heading.textContent = runtime.run_id;" in card_source
    assert card_source.count("buildRunDetailViewPath") == 1
    assert "if (runtime.run_id.trim()) {" not in card_source


def test_dashboard_contract_has_no_dom_network_or_timer_access() -> None:
    # Given
    client = TestClient(create_app())

    # When
    contract = client.get("/dashboard-assets/dashboard-contract.mjs").text

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
    assert "!Number.isInteger(payload.total_runs)" in contract
    assert "!Array.isArray(payload.recent_runs)" in contract
    assert "!Array.isArray(payload.runs)" in contract
    assert "payload.runs.some(" in contract


def test_dashboard_assets_do_not_reorder_api_results() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    contract = client.get("/dashboard-assets/dashboard-contract.mjs").text

    # Then
    for source in (script, contract):
        for reordering_api in (".sort(", ".toSorted(", ".reverse(", ".toReversed("):
            assert reordering_api not in source


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
    assert {"/overview", "/runs", "/operations/runtime"} <= paths
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
    assert html.count('<script type="module" src="/dashboard-assets/dashboard.js">') == 1
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
