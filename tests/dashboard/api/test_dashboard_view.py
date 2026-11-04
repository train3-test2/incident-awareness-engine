import mimetypes
import re
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


@pytest.mark.parametrize(
    "path,media_type",
    [
        ("/dashboard-assets/offline-ml.html", "text/html"),
        ("/dashboard-assets/offline-ml.js", "text/javascript"),
        ("/dashboard-assets/offline-ml-contract.mjs", "text/javascript"),
        ("/dashboard-assets/offline-ml.css", "text/css"),
    ],
)
def test_offline_ml_assets_use_existing_static_mount_without_database_access(
    path: str, media_type: str, database_connection_attempts: list[str]
) -> None:
    client = TestClient(create_app())
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert database_connection_attempts == []


def test_offline_ml_navigation_is_separate_from_selected_run() -> None:
    client = TestClient(create_app())
    assert 'href="/dashboard-assets/offline-ml.html"' in client.get("/dashboard").text
    html = client.get("/dashboard-assets/offline-ml.html").text
    assert 'href="/dashboard-assets/dashboard-shell.css"' in html
    assert "오프라인 모델 분석" in html
    assert "실제 공격 확률, 확정 탐지, 공식 성능평가 또는 TTSD 결과가 아닙니다." in html
    assert "RUN-20261019-006" not in html and "RUN-20261019-007" not in html
    for path in ["provenance/usage-record.json", "role5-demo-handoff-20261019-v0.2.zip"]:
        assert client.get(f"/dashboard-assets/{path}").status_code == 404


@pytest.mark.parametrize("registry_type", ["application/javascript", "text/plain"])
def test_javascript_mime_overrides_platform_registry(registry_type, monkeypatch) -> None:
    mimetypes.init()
    monkeypatch.setitem(mimetypes.types_map, ".js", registry_type)
    monkeypatch.setitem(mimetypes.types_map, ".mjs", registry_type)
    client = TestClient(create_app())
    for name in ("offline-ml.js", "offline-ml-contract.mjs"):
        response = client.get(f"/dashboard-assets/{name}")
        assert response.status_code == 200
        assert response.headers["content-type"].split(";", 1)[0] == "text/javascript"


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
    assert "운영 현황" in html
    assert "저장된 실행 보고와 분석 결과" in html
    assert "분석 시각은 원본 관측 구간" in html
    assert "실행 보고 updated_at은 마지막 저장 보고 시각" in html
    assert "최근 실행 보고 조회 결과는" in html
    assert "전체 실행 통계가 아닙니다" in html
    for section in ("실행 보고 요약", "분석 처리 단계", "처리 계측", "관측·분석 목록"):
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
        "runs-visibility-status",
        "dashboard-runs-toggle",
    ):
        assert f'id="{status_id}"' in html
    assert "조회 완료 후 약 5초 간격으로 실행 보고 상태 갱신" in html
    assert '<p class="dashboard-kpi__label">실행 보고</p>' in html
    assert '저장 분석 · 전체 <strong id="total-runs-value">' in html
    # Unmeasured uptime is a measurement-support line, never a KPI card.
    assert "최근 처리 업데이트" not in html
    assert '<strong id="insight-uptime-state">미계측</strong>' in html
    assert '<table class="dashboard-table runtime-table">' in html
    assert '<table class="dashboard-table runs-table">' in html
    assert 'aria-controls="runs-list" hidden>전체 분석 펼치기</button>' in html
    assert "Run Type" not in html
    assert database_connection_attempts == []


def test_dashboard_local_svg_icons_are_available_without_external_resources() -> None:
    # Given
    client = TestClient(create_app())

    # When
    sprite = client.get("/dashboard-assets/dashboard-icons.svg")
    module = client.get("/dashboard-assets/dashboard-icons.mjs")

    # Then
    assert sprite.status_code == 200
    assert sprite.headers["content-type"].startswith("image/svg+xml")
    assert module.status_code == 200
    assert "export function createPipelineIcon" in module.text
    for stage in (
        "artifact_validation",
        "normalization",
        "fusion",
        "fast_handoff",
        "hybrid",
        "persistence",
    ):
        assert f'id="{stage}"' in sprite.text
    assert "<image" not in sprite.text
    assert 'href="http' not in sprite.text
    assert 'from "http' not in module.text


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


def test_dashboard_view_2_uses_real_data_regions_and_defaults_to_summary() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text

    # Then
    # Task 7-S: system status cells come first, then the list, the analysis and its workflow tab.
    region_ids = (
        "system-status-value",
        "pipeline-heading",
        "throughput-heading",
        "latency-heading",
        "insights-heading",
        "runs-heading",
        "selected-run-heading",
        "workflow-heading",
    )
    assert [html.index(f'id="{region_id}"') for region_id in region_ids] == sorted(
        html.index(f'id="{region_id}"') for region_id in region_ids
    )
    for tab in ("summary", "replay", "evidence", "decision", "workflow"):
        assert f'id="dashboard-tab-{tab}"' in html
        assert f'aria-controls="dashboard-panel-{tab}"' in html
        assert f'id="dashboard-panel-{tab}"' in html
        assert f'aria-labelledby="dashboard-tab-{tab}"' in html
    replay_button = html.split('id="dashboard-tab-replay"', maxsplit=1)[1].split(">", maxsplit=1)[0]
    replay_panel = html.split('id="dashboard-panel-replay"', maxsplit=1)[1].split(">", maxsplit=1)[
        0
    ]
    assert 'aria-selected="false"' in replay_button
    assert " hidden" in replay_panel
    summary_button = html.split('id="dashboard-tab-summary"', maxsplit=1)[1].split(">", maxsplit=1)[
        0
    ]
    summary_panel = html.split('id="dashboard-panel-summary"', maxsplit=1)[1].split(
        ">", maxsplit=1
    )[0]
    assert 'aria-selected="true"' in summary_button
    assert " hidden" not in summary_panel
    assert (
        html.index('id="dashboard-panel-replay"')
        < html.index('id="selected-run-chart"')
        < html.index('id="dashboard-panel-evidence"')
    )
    assert 'id="decision-history-list"' in html
    assert 'id="event-type-summary"' in html
    # The 계측 지원 정보 help was removed on request; the unmeasured states themselves stay.
    assert "계측 지원 정보" not in html
    assert "미계측" in html
    assert "증거 목록 연동 전" not in html
    assert 'id="evidence-status" class="status-message dashboard-status" role="status"' in html
    assert 'id="evidence-list"' in html
    assert "게시된 보관 증거" in html
    assert "누적 분석 입력 아님 · 이벤트 시각" in html
    assert 'id="workflow-awareness-form"' in html
    assert 'id="workflow-report-form"' in html
    assert "실제 인증 계정이 아닙니다" in html
    assert "정상 운영 중" not in html
    assert "판단 입력하기" not in html


def test_task6_detail_areas_lead_with_operator_content_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text
    modules = [
        client.get(f"/dashboard-assets/{name}")
        for name in ("dashboard-records.mjs", "dashboard-detail-rows.mjs")
    ]

    # Then
    def headers(markup: str) -> list[str]:
        return re.findall(r'<th scope="col">([^<]+)</th>', markup.split("</thead>", maxsplit=1)[0])

    def ordered(markup: str, markers: tuple[str, ...]) -> bool:
        positions = [markup.index(f'id="{marker}"') for marker in markers]
        return positions == sorted(positions)

    decision_tab = html.split('id="dashboard-tab-decision"', maxsplit=1)[1]
    assert decision_tab.split("</button>", maxsplit=1)[0].endswith(">기록")
    assert 'id="decision-timeline-list"' not in html
    assert ordered(
        html,
        (
            "dashboard-panel-replay",
            "replay-records-open",
            "selected-run-chart",
            "event-type-summary",
            "dashboard-panel-evidence",
        ),
    )
    evidence = html.split('id="dashboard-panel-evidence"', maxsplit=1)[1]
    evidence = evidence.split('id="dashboard-panel-decision"', maxsplit=1)[0]
    assert ordered(
        evidence,
        (
            "provenance-count",
            "provenance-status",
            "provenance-retention-state",
            "evidence-archive-state",
            "provenance-list",
            "evidence-list",
        ),
    )
    assert headers(evidence.split('id="provenance-region"', maxsplit=1)[1]) == [
        "관측 시각 (KST)",
        "관측 내용",
        "대상·프로세스",
        "출처",
        "검증 상태",
        "상세",
    ]
    assert headers(evidence.split('id="evidence-region"', maxsplit=1)[1]) == [
        "관측 시각 (KST)",
        "관측 내용",
        "대상",
        "출처 계층 · 채널",
        "연결 Event",
        "상세",
    ]
    assert ">Evidence ID</th>" not in evidence
    records = html.split('id="dashboard-panel-decision"', maxsplit=1)[1]
    assert ordered(
        records, ("decision-history-list", "workflow-records-list", "dashboard-panel-workflow")
    )
    workflow = html.split('id="dashboard-panel-workflow"', maxsplit=1)[1]
    assert ordered(
        workflow,
        (
            "workflow-heading",
            "workflow-detail-timeline",
            "workflow-task-heading",
            "workflow-next",
            "workflow-compose",
            "kisa-panel",
            "workflow-history",
            "workflow-dev-tools",
            "workflow-synthetic-consent",
        ),
    )
    # Task 7-S: system status moved above the list, so it no longer follows the workflow panel.
    assert html.index('id="system-heading"') < html.index('id="dashboard-panel-workflow"')
    for response in modules:
        assert response.status_code == 200
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert database_connection_attempts == []


def test_processing_observation_shell_exposes_true_scope_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text

    # Then
    assert '<h4 id="processing-observation-heading">최근 처리 관측</h4>' in html
    assert '<strong id="processing-observation-state">조회 중</strong>' in html
    assert '<time id="processing-observation-time">관측 시각 조회 중</time>' in html
    assert 'aria-describedby="processing-observation-details telemetry-throughput-status"' in html
    assert (
        '<strong id="insight-bottleneck-state" role="status" aria-live="polite" '
        'aria-atomic="true">비교 대상 없음</strong>' in html
    )
    # The help disclosure (record list, manual re-query, long definitions) was removed on request.
    assert 'id="insight-bottleneck-refresh"' not in html
    assert '<strong id="insight-sla-state">기준 미설정</strong>' in html
    assert '<strong id="insight-queue-state">미계측</strong>' in html
    assert "최신 이벤트 수신" not in html
    assert "Event 최초 수신 시각이나 시스템 가동 여부가 아닙니다" not in html
    assert "SQS 큐 깊이" in html
    assert "E2E SLA로 사용하지 않습니다" not in html
    assert database_connection_attempts == []


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
    replay_chart = client.get("/dashboard-assets/dashboard-replay-chart.mjs")

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
    assert replay_chart.status_code == 200
    for response in (script, contract, chart, replay_chart):
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES
    assert '} from "./dashboard-contract.mjs";' in script.text
    assert 'from "./dashboard-replay-chart.mjs";' in script.text
    assert 'from "./fusion-score-chart.mjs";' in replay_chart.text
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
    assert 'detailLink.textContent = "기술 상세";' in script
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
    assert "fetchSelectedAnalysis(" in script
    assert "buildRunDetailApiPath(runId)" in script
    assert "buildFusionEngineApiPath(runId)" in script
    assert "buildEventTimelineApiPath(runId, EVENT_TIMELINE_LIMIT, 0)" in script
    assert script.count('Accept: "application/json"') == 4
    assert script.count('cache: "no-store"') == 4
    # Startup and completed-Runtime reconciliation, not a second polling loop.
    assert script.count("void loadOverview();") == 2
    assert script.count("void loadRuns();") == 2
    assert "startRuntimePolling();" in script
    assert 'document.getElementById("runs-status")' in script
    assert 'document.getElementById("runs-list")' in script
    assert 'document.getElementById("runtime-summary-status")' in script
    assert 'document.getElementById("runtime-summary-list")' in script
    assert "setInterval(" not in script
    # Four existing timeouts plus bounded manual Overview/Run reads; no new poll loop.
    assert script.count("setTimeout(") == 5
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "runtimePollTimeoutId = setTimeout(" in script
    assert "void pollRuntimeSummary();" in script
    assert "clearTimeout(timeoutId);" in script
    assert "signal: controller.signal" in script
    poll_source = script.split("async function pollRuntimeSummary()", maxsplit=1)[1].split(
        "if (dashboardView !== null)",
        maxsplit=1,
    )[0]
    assert "if (runtimePending !== null) return runtimePending;" in poll_source
    assert poll_source.index(
        "runtimePending = updateRuntimeSummary().finally("
    ) < poll_source.index("scheduleRuntimePoll();")


def test_main_refresh_is_a_named_keyboard_button_with_nonvisual_status() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard").text
    script = client.get("/dashboard-assets/dashboard.js").text

    # Then
    assert '<button id="dashboard-refresh"' in html
    assert 'aria-label="운영 현황 데이터 새로고침"' in html
    assert 'aria-describedby="dashboard-refresh-status"' in html
    assert 'id="dashboard-refresh-status" class="dashboard-visually-hidden" role="status"' in html
    assert 'dashboardRefreshButton.addEventListener("click", async () =>' in script
    assert "if (manualRefreshPending) return;" in script
    assert "loadOverview(), loadRuns(), pollRuntimeSummary(), telemetryController.poll()" in script
    assert "if (version !== manualRefreshVersion) return;" in script


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
    assert 'class="app-header dashboard-app-header"' in html
    assert 'class="app-navigation"' in html
    assert 'class="app-page dashboard-page"' in html
    assert "@media (max-width: 48rem)" in shell
    assert "@media (max-width: 30rem)" in shell
    assert "@media (max-width: 70rem)" in stylesheet
    assert "@media (max-width: 48rem)" in stylesheet
    assert "@media (max-width: 30rem)" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet
    assert ".dashboard-monitor-grid" in stylesheet
    assert ".dashboard-replay-grid" in stylesheet
    assert ".dashboard-analysis-settings" in stylesheet
    assert "grid-template-columns: repeat(6, minmax(0, 1fr))" in stylesheet
    assert ".dashboard-table-wrapper" in stylesheet
    assert "overflow-x: auto" in stylesheet
    assert "width: min(100%, var(--shell-page-width))" in shell
    assert ".app-page.dashboard-page" in stylesheet
    assert "width: 100%" in stylesheet
    assert "max-width: 116rem" in stylesheet
    monitor_rule = stylesheet.split(".dashboard-monitor-grid {", maxsplit=1)[1].split(
        "}", maxsplit=1
    )[0]
    assert "grid-template-columns: minmax(0, 906fr) minmax(0, 548fr)" in monitor_rule
    assert "minmax(36rem, 0.9fr)" not in stylesheet

    runtime_index = html.index('id="runtime-summary-heading"')
    analysis_index = html.index('id="selected-run-heading"')
    chart_index = html.index('id="replay-chart-heading">증거 누적 점수')
    runs_index = html.index('id="runs-heading"')
    # Task 7-S: system status (with its run table disclosure) sits above the list and analysis.
    assert (
        html.index('id="system-heading"')
        < runtime_index
        < runs_index
        < analysis_index
        < chart_index
    )


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
    assert "displayValue(runMetadata?.scenario_id)" in script
    assert "displayValue(run.target_host)" in script
    assert "createRunTimestamp(run.start_time)" in script
    assert 'time.setAttribute("datetime", value)' in script
    assert 'time.setAttribute("title", formatRunTimestamp(value))' in script
    run_row_source = script.split("function createRunRow(", 1)[1].split(
        "function createRunTimestamp(", 1
    )[0]
    assert "run.run_type" not in run_row_source
    assert "실행 Metadata run_type:" in script
    assert "원본 수집 라벨과 별도" in script
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
    assert "function loadOverview()" in script
    assert "function loadRuns()" in script
    assert "if (overviewPending !== null) return overviewPending;" in script
    assert "if (runsPending !== null) return runsPending;" in script
    assert "async function pollRuntimeSummary()" in script
    assert "async function selectRun(runId, runtimeEntityId = null)" in script
    assert "renderOverviewState(overviewState);" in script
    assert "renderRunListState(runListState);" in script
    assert "renderRuntimeState(runtimeState);" in script
    assert 'overviewStatus.textContent = state.queryState === "success"' in script
    assert 'state.queryState === "empty"' in script
    assert "runsStatus.textContent = state.message;" in script
    # No report is stated once, by the KPI; loading and errors keep their message.
    assert (
        'runtimeSummaryStatus.textContent = state.queryState === "empty" ? "" : state.message;'
        in script
    )
    assert (
        'const topMessage = state.queryState === "success" || state.queryState === "empty" ? "" : state.message;'
        in script
    )
    assert "if (runtimeTopStatus.textContent !== topMessage)" in script
    assert "runtimeTopStatus.textContent = topMessage;" in script
    assert (
        'runtimeTopStatus.classList.toggle("dashboard-visually-hidden", state.queryState === "empty");'
        in script
    )
    assert "systemStatusValue.hidden = !systemStatusValue.textContent;" in script
    assert "pipelineStageContext.hidden = !pipelineStageContext.textContent;" in script
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
    assert script.count("setTimeout(") == 5
    assert "setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS)" in script
    assert "void pollRuntimeSummary();" in script
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


@pytest.mark.parametrize(
    "path",
    (
        "/tests/dashboard/preview/telemetry-preview.html",
        "/dashboard/preview",
        "/dashboard-assets/telemetry-preview-model.mjs",
        "/dashboard-assets/telemetry-preview.mjs",
    ),
)
def test_production_dashboard_does_not_serve_local_preview(path: str) -> None:
    # Given
    client = TestClient(create_app())
    # When
    response = client.get(path)
    # Then
    assert response.status_code == 404
    assert "시연용 샘플 데이터" not in response.text


@pytest.mark.parametrize(
    ("metric", "reason"),
    [
        ("bottleneck", "전체 실행의 확정 병목이 아닙니다"),
        ("sla", "정상 또는 위반 없음이라는 뜻이 아닙니다"),
        ("queue", "미계측은 대기 0건이나 위험 없음이라는 뜻이 아닙니다"),
    ],
)
def test_unavailable_insight_scope_is_served_without_database_or_measurement_requests(
    database_connection_attempts: list[str], metric: str, reason: str
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard")

    # Then
    assert response.status_code == 200
    assert f'aria-labelledby="insight-{metric}-heading"' in response.text
    assert f'aria-describedby="insight-{metric}-scope"' in response.text
    assert response.text.count(f'id="insight-{metric}-scope"') == 1
    assert reason in response.text
    assert database_connection_attempts == []


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
