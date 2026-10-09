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
    "/dashboard-assets/fusion-engine.css",
    "/dashboard-assets/dashboard.css",
    "/dashboard-assets/dashboard.js",
    "/dashboard-assets/dashboard-contract.mjs",
)
DASHBOARD_CONTRACT_FUNCTIONS = (
    "displayValue",
    "buildPipelineStagePresentation",
    "canRefreshSelectedAnalysis",
    "createSelectedRuntimeTracking",
    "findSelectedRuntime",
    "formatRunTimestamp",
    "getDecisionVersionConsistency",
    "getLatestRuntimeReport",
    "getOverviewQueryMessage",
    "getRunTypeLabel",
    "getSelectedAnalysisScope",
    "getSelectedAnalysisSource",
    "getSelectedAnalysisState",
    "getSelectedAnalysisTargetHost",
    "getSelectedRuntimeOutsideQueryLabel",
    "getSelectedRuntimeRecheckMessage",
    "getStoppingTraceAvailability",
    "isRunSelectionTarget",
    "recordSelectedRuntimeRecheck",
    "resolveInitialRunSelection",
    "resolveOverviewQueryState",
    "resolveRunSelectionFocus",
    "resolveRunListQueryState",
    "resolveRuntimeSummaryQueryState",
    "resolveSelectedRuntimeTracking",
    "shouldApplySelectedRunResponse",
    "shouldRecheckSelectedRuntimeAnalysis",
    "shouldRefreshSelectedRunAnalysis",
    "shouldUpdateSelectedRunFailureState",
)
DASHBOARD_SCRIPT_CONTRACT_FUNCTIONS = (
    "buildPipelineStagePresentation",
    "canRefreshSelectedAnalysis",
    "createSelectedRuntimeTracking",
    "displayValue",
    "findSelectedRuntime",
    "formatRunTimestamp",
    "getDecisionVersionConsistency",
    "getLatestRuntimeReport",
    "getSelectedAnalysisScope",
    "getSelectedAnalysisSource",
    "getSelectedAnalysisState",
    "getSelectedAnalysisTargetHost",
    "getSelectedRuntimeOutsideQueryLabel",
    "getSelectedRuntimeRecheckMessage",
    "getStoppingTraceAvailability",
    "isRunSelectionTarget",
    "recordSelectedRuntimeRecheck",
    "resolveInitialRunSelection",
    "resolveOverviewQueryState",
    "resolveRunSelectionFocus",
    "resolveRunListQueryState",
    "resolveRuntimeSummaryQueryState",
    "resolveSelectedRuntimeTracking",
    "shouldApplySelectedRunResponse",
    "shouldRecheckSelectedRuntimeAnalysis",
    "shouldRefreshSelectedRunAnalysis",
    "shouldUpdateSelectedRunFailureState",
)
OPERATIONS_SCRIPT_CONTRACT_FUNCTIONS = (
    "getRuntimeProgressPresentation",
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
    assert 'href="/dashboard-assets/fusion-engine.css"' in html
    assert 'href="/dashboard-assets/dashboard.css"' in html
    assert '<script type="module" src="/dashboard-assets/dashboard.js"></script>' in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert "Detection Hub" in html
    assert "운영 View" in html
    assert "저장된 Runtime 보고와 Run 분석 결과" in html
    assert "Run 시각은 원본 관측 구간" in html
    assert "Runtime updated_at은 마지막 저장 보고 시각" in html
    assert "최근 Runtime 조회 결과는" in html
    assert "전체 실행 통계가 아닙니다" in html
    for section in ("운영 상태", "Pipeline 실행 단계", "최근 Runtime 실행 현황", "최근 Run 목록"):
        assert section in html
    for status_id in (
        "total-runs-value",
        "overview-status",
        "latest-runtime-state",
        "latest-runtime-updated",
        "runtime-top-status",
        "pipeline-stage-list",
        "runtime-summary-status",
        "runtime-summary-list",
        "selected-run-id",
        "selected-run-scope",
        "selected-run-refresh",
        "selected-run-status",
        "selected-run-summary",
        "selected-run-chart-status",
        "selected-run-chart",
        "runs-status",
        "runs-list",
    ):
        assert f'id="{status_id}"' in html
    assert "조회 완료 후 약 5초 간격으로 Runtime 상태 갱신" in html
    assert "조회 범위 내 최신 Runtime 상태" in html
    assert "조회 범위 내 최신 Runtime 보고" in html
    assert '<table class="dashboard-table runtime-table">' in html
    assert '<table class="dashboard-table runs-table">' in html
    assert "Run Type" not in html
    assert database_connection_attempts == []


def test_dashboard_run_status_and_table_are_visible_without_disclosure() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text

    # Then
    runs_status_index = html.index('id="runs-status"')
    table_start = html.index('<table class="dashboard-table runs-table">')
    table_end = html.index("</table>", table_start)
    runs_list_index = html.index('id="runs-list"')
    table = html[table_start:table_end]
    assert runs_status_index < table_start
    assert table_start < runs_list_index < table_end
    assert 'id="runs-status"' not in table
    assert '<details class="dashboard-time-note">' in html
    assert "<summary>표시 기준 및 상태 안내</summary>" in html


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
    chart_stylesheet = client.get("/dashboard-assets/fusion-engine.css")
    stylesheet = client.get("/dashboard-assets/dashboard.css")
    script = client.get("/dashboard-assets/dashboard.js")
    contract = client.get("/dashboard-assets/dashboard-contract.mjs")
    chart = client.get("/dashboard-assets/fusion-score-chart.mjs")

    # Then
    for response in (shell_stylesheet, chart_stylesheet, stylesheet):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/css")
    assert ".app-navigation" in shell_stylesheet.text
    assert "--shell-color-primary" in shell_stylesheet.text
    assert ".dashboard-table" in stylesheet.text
    assert script.status_code == 200
    assert contract.status_code == 200
    assert chart.status_code == 200
    for response in (script, contract, chart):
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert '} from "./dashboard-contract.mjs";' in script.text
    assert 'from "./fusion-score-chart.mjs";' in script.text
    assert "export function createScoreTrajectoryChart(" in chart.text
    for contract_function in DASHBOARD_CONTRACT_FUNCTIONS:
        assert f"export function {contract_function}(" in contract.text


def test_dashboard_run_rows_link_to_encoded_run_detail_view_paths() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    contract = client.get("/dashboard-assets/run-detail-contract.mjs").text

    # Then
    assert "buildRunDetailViewPath," in script
    assert 'const detailLink = document.createElement("a");' in script
    assert "detailLink.href = buildRunDetailViewPath(run.run_id);" in script
    assert 'detailLink.textContent = "Run Detail";' in script
    assert "state.items.map((run) => createRunRow(run))" in script
    assert 'encodeURIComponent(requireIdentifier(runId, "runId"))' in contract
    assert "`/dashboard/runs/${run.run_id}`" not in script


def test_dashboard_script_fetches_independent_apis_and_polls_only_runtime() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    assert 'document.getElementById("dashboard-view")' in script
    assert 'const OVERVIEW_ENDPOINT = "/overview";' in script
    assert 'const RUNS_ENDPOINT = "/runs?limit=20";' in script
    assert 'const RUNTIME_ENDPOINT = "/operations/runtime?limit=5";' in script
    assert "const RUNTIME_POLL_INTERVAL_MS = 5000;" in script
    assert "const RUNTIME_REQUEST_TIMEOUT_MS = 10000;" in script
    assert "fetchJson(OVERVIEW_ENDPOINT" in script
    assert "fetchJson(RUNS_ENDPOINT" in script
    assert "fetch(RUNTIME_ENDPOINT" in script
    assert "fetch(buildRunDetailApiPath(runId)" in script
    assert "fetch(buildFusionEngineApiPath(runId)" in script
    assert script.count('Accept: "application/json"') == 4
    assert script.count('cache: "no-store"') == 4
    assert script.count("void loadOverview();") == 1
    assert script.count("void loadRuns();") == 1
    assert script.count("void pollRuntimeSummary();") == 1
    assert 'document.getElementById("runs-status")' in script
    assert 'document.getElementById("runs-list")' in script
    assert 'document.getElementById("runtime-summary-status")' in script
    assert 'document.getElementById("runtime-summary-list")' in script
    assert "setInterval(" not in script
    assert script.count("setTimeout(") == 2
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "runtimePollTimeoutId = setTimeout(" in script
    assert "() => void pollRuntimeSummary()" in script
    assert "clearTimeout(timeoutId);" in script
    assert "signal: controller.signal" in script
    assert script.index("const payload = await fetchRuntimeSummary();") < script.index(
        "runtimePollTimeoutId = setTimeout("
    )


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
    assert "@media (max-width: 70rem)" in stylesheet
    assert "@media (max-width: 48rem)" in stylesheet
    assert "@media (max-width: 30rem)" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet
    assert ".dashboard-workbench" in stylesheet
    assert ".dashboard-analysis-grid" in stylesheet
    assert "grid-template-columns: repeat(6, minmax(9rem, 1fr))" in stylesheet
    assert ".dashboard-table-wrapper" in stylesheet
    assert "overflow-x: auto" in stylesheet
    assert "width: min(100%, var(--shell-page-width))" in shell
    assert ".app-page.dashboard-page" in stylesheet
    assert "width: 100%" in stylesheet
    assert "max-width: 101rem" in stylesheet
    assert "@media (max-width: 82rem)" in stylesheet


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
    assert "displayValue(run.scenario_id)" in script
    assert "displayValue(run.target_host)" in script
    assert "formatRunTimestamp(run.start_time)" in script
    assert "run.run_type" not in script
    assert 'document.createElement("a")' in script
    assert 'document.createElement("button")' in script
    assert 'document.createElement("tr")' in script
    assert "getRuntimeProgressPresentation(runtime)" in script
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
    assert "async function pollRuntimeSummary()" in script
    assert "async function selectRun(runId, runtimeEntityId = null)" in script
    assert "renderOverviewState(overviewState);" in script
    assert "renderRunListState(runListState);" in script
    assert "renderRuntimeState(runtimeState);" in script
    assert "overviewStatus.textContent = state.totalMessage;" in script
    assert "runsStatus.textContent = state.message;" in script
    assert "runtimeSummaryStatus.textContent = state.message;" in script
    assert "async function loadRunDetailState(runId)" in script
    assert "async function loadFusionEngineState(runId)" in script
    assert 'resolveRunDetailQueryState(loading, { kind: "error" })' in script
    assert 'resolveFusionEngineQueryState(loading, { kind: "error" })' in script


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
    assert "createRuntimeRow(runtime, state.telemetryAvailable)" in script
    assert "status-badge--${modifier}" in script
    assert "presentation.telemetryLabel" in script
    assert "buildPipelineStagePresentation(" in script
    assert "현재 실행 중" not in script
    assert "setInterval(" not in script
    assert script.count("setTimeout(") == 2
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "() => void pollRuntimeSummary()" in script
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
    assert "export const PIPELINE_STAGE_ORDER = Object.freeze([" in contract
    assert "const PIPELINE_RUNTIME_STAGES = new Set(PIPELINE_STAGE_ORDER);" in contract
    assert '!Object.hasOwn(runtime, "current_stage")' in contract
    assert "runtime.current_stage !== null" in contract
    assert "!PIPELINE_RUNTIME_STAGES.has(runtime.current_stage)" in contract
    assert 'typeof runtime.updated_at !== "string"' in contract
    assert 'typeof runtime.is_stale !== "boolean"' in contract


def test_dashboard_runtime_rows_select_every_report_and_detail_links_remain_available() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/dashboard.js").text
    row_source = script.split("function createRuntimeRow", maxsplit=1)[1].split(
        "function createRunRow",
        maxsplit=1,
    )[0]

    # Then
    assert "createSelectionButton(runtime.run_id, runtime.entity_id)" in row_source
    assert "createTableCell(runtime.entity_id)" in row_source
    assert 'runtime.status === "completed"' not in row_source
    assert "selectedRunDetailLink.href = buildRunDetailViewPath(runId);" in script
    assert "selectedRunFusionLink.href = buildFusionEngineViewPath(runId);" in script
    assert "selectedRunDetailLink.hidden = !detailAvailable;" in script
    assert "selectedRunFusionLink.hidden = !fusionAvailable;" in script


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
