import { createPipelineIcon } from "./dashboard-icons.mjs";
import {
    buildPipelineStagePresentation,
    canRefreshSelectedAnalysis,
    createSelectedRuntimeTracking,
    displayValue,
    findSelectedRuntime,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
    getRunListVisibilityMessage,
    getSelectedAnalysisScope,
    getSelectedAnalysisSource,
    getSelectedAnalysisState,
    getSelectedAnalysisTargetHost,
    getSelectedRuntimeOutsideQueryLabel,
    getSelectedRuntimeRecheckMessage,
    getStoppingTraceAvailability,
    isRunSelectionTarget,
    recordSelectedRuntimeRecheck,
    resolveInitialRunSelection,
    resolveOverviewQueryState,
    resolveRunListVisibility,
    resolveRunSelectionFocus,
    resolveRunListQueryState,
    resolveRuntimeSummaryQueryState,
    resolveSelectedRuntimeTracking,
    shouldApplySelectedRunResponse,
    shouldRecheckSelectedRuntimeAnalysis,
    shouldRefreshSelectedRunAnalysis,
    shouldUpdateSelectedRunFailureState,
} from "./dashboard-contract.mjs";
import {
    buildFusionEngineApiPath,
    buildFusionEngineViewPath,
    buildScoreTrajectoryModel,
    resolveFusionEngineQueryState,
} from "./fusion-engine-contract.mjs";
import { createDashboardReplayChart } from "./dashboard-replay-chart.mjs";
import { createDashboardTelemetryController } from "./dashboard-telemetry-controller.mjs";
import {
    buildEventTimelineApiPath,
    resolveEventTimelineQueryState,
} from "./event-timeline-contract.mjs";
import {
    getRuntimeProgressPresentation,
    getRuntimeStatePresentation,
    getStageLabel,
} from "./operations-contract.mjs";
import {
    buildRunDetailApiPath,
    buildRunDetailViewPath,
    getDecisionPathLabel,
    getStatusLabel,
    resolveRunDetailQueryState,
} from "./run-detail-contract.mjs";

const OVERVIEW_ENDPOINT = "/overview";
const RUNS_ENDPOINT = "/runs?limit=20";
const RUNTIME_ENDPOINT = "/operations/runtime?limit=5";
const RUNTIME_POLL_INTERVAL_MS = 5000;
const RUNTIME_REQUEST_TIMEOUT_MS = 10000;
const ANALYSIS_REQUEST_TIMEOUT_MS = 10000;
const EVENT_TIMELINE_LIMIT = 50;
const RECENT_RUNS_VISIBLE_COUNT = 5;
// Row controls whose keyboard focus survives a re-render; the class names the control kind.
const SELECTION_ROW_FOCUS_CONTROLS = ["dashboard-run-selector", "dashboard-run-detail-link"];
const SCORE_CHART_DIMENSIONS = {
    width: 960,
    height: 140,
    padding: { top: 50, right: 72, bottom: 23, left: 50 },
};

const dashboardView = document.getElementById("dashboard-view");
const totalRunsValue = document.getElementById("total-runs-value");
const overviewStatus = document.getElementById("overview-status");
const latestRuntimeState = document.getElementById("latest-runtime-state");
const latestRuntimeUpdated = document.getElementById("latest-runtime-updated");
const dashboardHeaderUpdated = document.getElementById("dashboard-header-updated");
const systemStatusValue = document.getElementById("system-status-value");
const activeRuntimeRun = document.getElementById("active-runtime-run");
const runtimeTopStatus = document.getElementById("runtime-top-status");
const pipelineStageContext = document.getElementById("pipeline-stage-context");
const pipelineStageList = document.getElementById("pipeline-stage-list");
const runtimeSummaryStatus = document.getElementById("runtime-summary-status");
const runtimeSummaryList = document.getElementById("runtime-summary-list");
const selectedRunIdElement = document.getElementById("selected-run-id");
const selectedRunScope = document.getElementById("selected-run-scope");
const selectedRunStatus = document.getElementById("selected-run-status");
const selectedRunDetailStatus = document.getElementById("selected-run-detail-status");
const selectedRunSummary = document.getElementById("selected-run-summary");
const selectedRunSettings = document.getElementById("selected-run-settings");
const selectedRunChartStatus = document.getElementById("selected-run-chart-status");
const selectedRunChart = document.getElementById("selected-run-chart");
const selectedRunDetailLink = document.getElementById("selected-run-detail-link");
const selectedRunFusionLink = document.getElementById("selected-run-fusion-link");
const selectedRunRefreshButton = document.getElementById("selected-run-refresh");
const previousRunButton = document.getElementById("dashboard-prev-run");
const nextRunButton = document.getElementById("dashboard-next-run");
const runsStatus = document.getElementById("runs-status");
const runsList = document.getElementById("runs-list");
const runsToggle = document.getElementById("dashboard-runs-toggle");
const runsVisibilityStatus = document.getElementById("runs-visibility-status");
const runSearchInput = document.getElementById("dashboard-run-search");
const runTypeFilter = document.getElementById("dashboard-run-type");
const runFilterReset = document.getElementById("dashboard-run-filter-reset");
const runSearchResults = document.getElementById("dashboard-run-search-results");
const decisionTimelineList = document.getElementById("decision-timeline-list");
const decisionTimelineStatus = document.getElementById("decision-timeline-status");
const eventTypeSummary = document.getElementById("event-type-summary");
const eventTypeSummaryStatus = document.getElementById("event-type-summary-status");
const decisionHistoryList = document.getElementById("decision-history-list");
const decisionHistoryStatus = document.getElementById("decision-history-status");
const selectedRunTabs = [
    {
        button: document.getElementById("dashboard-tab-summary"),
        panel: document.getElementById("dashboard-panel-summary"),
        name: "summary",
    },
    {
        button: document.getElementById("dashboard-tab-replay"),
        panel: document.getElementById("dashboard-panel-replay"),
        name: "replay",
    },
    {
        button: document.getElementById("dashboard-tab-evidence"),
        panel: document.getElementById("dashboard-panel-evidence"),
        name: "evidence",
    },
    {
        button: document.getElementById("dashboard-tab-decision"),
        panel: document.getElementById("dashboard-panel-decision"),
        name: "decision",
    },
    {
        button: document.getElementById("dashboard-tab-workflow"),
        panel: document.getElementById("dashboard-panel-workflow"),
        name: "workflow",
    },
];

let overviewState = resolveOverviewQueryState(null, { kind: "loading" });
let runListState = resolveRunListQueryState(null, { kind: "loading" });
let runtimeState = resolveRuntimeSummaryQueryState(null, { kind: "loading" });
let selectedRunId = null;
let runsExpanded = false;
// Search text for the fetched Runs; it only changes which rows are shown, never runListState.
let runSearchQuery = "";
let runType = "all";
let selectedRuntimeEntityId = null;
let selectedRuntimeTracking = createSelectedRuntimeTracking(null);
let selectedAnalysisQueryStates = null;
let selectedAnalysisState = null;
let selectedAnalysisTargetHost = null;
let selectedAnalysisPendingVersion = null;
let selectedRequestVersion = 0;
let runtimeInitialQuerySettled = false;
let runtimePollTimeoutId = null;
let runtimePollingActive = false;
let runtimeRequestInFlight = false;
const selectedAnalysisAbortControllers = new Set();
let selectedTimelineRequestVersion = 0;
let selectedTimelineAbortController = null;
let restoringSelectionRowFocus = false;

function createStatusBadge(presentation) {
    const badge = document.createElement("span");
    badge.classList.add("status-badge");
    for (const modifier of presentation.modifiers) {
        badge.classList.add(`status-badge--${modifier}`);
    }
    badge.textContent = presentation.statusLabel;
    return badge;
}

function isSelectedTarget(runId, runtimeEntityId) {
    return isRunSelectionTarget(
        selectedRunId,
        selectedRuntimeEntityId,
        runId,
        runtimeEntityId,
    );
}

function createSelectionButton(runId, runtimeEntityId = null) {
    const button = document.createElement("button");
    button.type = "button";
    button.classList.add("dashboard-run-selector");
    button.textContent = runId;
    button.dataset.runId = runId;
    if (runtimeEntityId !== null) {
        button.dataset.entityId = runtimeEntityId;
        button.setAttribute("aria-label", `Run ${runId}, Entity ${runtimeEntityId}`);
    }
    button.setAttribute(
        "aria-pressed",
        String(isSelectedTarget(runId, runtimeEntityId)),
    );
    button.addEventListener("click", () => {
        void selectRun(runId, runtimeEntityId);
    });
    return button;
}

function replaceSelectionRows(list, rows, table, runtimeItems, runItems) {
    const focusedControl = list.contains(document.activeElement)
        ? SELECTION_ROW_FOCUS_CONTROLS.find(
            (control) => document.activeElement.classList.contains(control),
        )
        : undefined;
    const focusedElement = focusedControl === undefined ? null : document.activeElement;
    const focusTarget = resolveRunSelectionFocus(
        focusedElement?.dataset.runId ?? null,
        focusedElement?.dataset.entityId ?? null,
        focusedElement === null ? null : table,
        runtimeItems,
        runItems,
    );
    list.replaceChildren(...rows);
    if (focusTarget === null) {
        return;
    }
    // Same control kind and Run/Entity only; a Run that left the list keeps no focus target.
    const replacement = Array.from(
        list.querySelectorAll(`.${focusedControl}`),
    ).find(
        (control) => (
            control.dataset.runId === focusTarget.runId
            && (control.dataset.entityId ?? null) === focusTarget.entityId
        ),
    );
    restoringSelectionRowFocus = true;
    try {
        replacement?.focus({ preventScroll: true });
    } finally {
        restoringSelectionRowFocus = false;
    }
}

function createTableCell(value, className = null) {
    const cell = document.createElement("td");
    if (className !== null) {
        cell.classList.add(className);
    }
    if (value instanceof Node) {
        cell.append(value);
    } else {
        cell.textContent = value;
    }
    return cell;
}

function createRuntimeRow(runtime, telemetryAvailable) {
    const presentation = getRuntimeStatePresentation(runtime, telemetryAvailable);
    const progress = getRuntimeProgressPresentation(runtime);
    const row = document.createElement("tr");
    if (isSelectedTarget(runtime.run_id, runtime.entity_id)) {
        row.classList.add("dashboard-table__row--selected");
    }

    const progressValue = document.createElement("span");
    progressValue.textContent = progress.processed;
    const remaining = document.createElement("small");
    remaining.textContent = `남은 입력 ${progress.remaining}`;
    progressValue.append(remaining);

    row.append(
        createTableCell(
            createSelectionButton(runtime.run_id, runtime.entity_id),
            "dashboard-table__run",
        ),
        createTableCell(runtime.entity_id),
        createTableCell(createStatusBadge(presentation)),
        createTableCell(getStageLabel(runtime.current_stage)),
        createTableCell(formatRunTimestamp(runtime.updated_at)),
        createTableCell(progressValue, "dashboard-table__progress"),
    );
    return row;
}

function createRunRow(run) {
    const row = document.createElement("tr");
    if (isSelectedTarget(run.run_id, null)) {
        row.classList.add("dashboard-table__row--selected");
    }

    const detailLink = document.createElement("a");
    detailLink.classList.add("dashboard-run-detail-link");
    detailLink.dataset.runId = run.run_id;
    detailLink.href = buildRunDetailViewPath(run.run_id);
    detailLink.textContent = "Run Detail";
    detailLink.addEventListener("focus", () => {
        // Focus restored after a re-render stays where the user left the page scroll.
        if (!restoringSelectionRowFocus) {
            detailLink.scrollIntoView({ block: "nearest", inline: "nearest" });
        }
    });
    const runIdentifier = document.createElement("span");
    const targetHost = document.createElement("small");
    targetHost.textContent = `분석 대상 ${displayValue(run.target_host)}`;
    runIdentifier.append(createSelectionButton(run.run_id), targetHost);

    const matchingRuntime = runtimeState.items.find(
        (runtime) => runtime.run_id === run.run_id && runtime.entity_id === run.target_host,
    );
    const runtimePresentation = matchingRuntime === undefined
        ? null
        : getRuntimeStatePresentation(matchingRuntime, runtimeState.telemetryAvailable);
    const runtimeStatus = runtimePresentation === null
        ? "최근 5건 미포함"
        : runtimePresentation.telemetryLabel === "-"
            ? runtimePresentation.statusLabel
            : `${runtimePresentation.statusLabel} · ${runtimePresentation.telemetryLabel}`;
    const runtimeProgress = matchingRuntime === undefined
        ? "-"
        : getRuntimeProgressPresentation(matchingRuntime).processed;
    const start = Date.parse(run.start_time);
    const end = run.end_time === null ? NaN : Date.parse(run.end_time);
    const observationDuration = Number.isFinite(start) && Number.isFinite(end) && end >= start
        ? `${Math.floor((end - start) / 60000)}분 ${Math.floor((end - start) % 60000 / 1000)}초`
        : "-";

    row.append(
        createTableCell(createRunTimestamp(run.start_time)),
        createTableCell(runIdentifier, "dashboard-table__run"),
        createTableCell(runtimePresentation === null
            ? runtimeStatus
            : createStatusBadge({ ...runtimePresentation, statusLabel: runtimeStatus })),
        createTableCell(displayValue(run.scenario_id)),
        createTableCell(runtimeProgress),
        createTableCell(observationDuration),
        createTableCell(detailLink),
    );
    return row;
}

function createRunTimestamp(value) {
    const date = new Date(value);
    if (!value || Number.isNaN(date.getTime())) {
        return formatRunTimestamp(value);
    }
    const time = document.createElement("time");
    time.classList.add("dashboard-run-time");
    time.setAttribute("datetime", value);
    time.setAttribute("title", formatRunTimestamp(value));
    time.setAttribute("aria-label", formatRunTimestamp(value));
    const day = document.createElement("span");
    day.textContent = [date.getFullYear(), date.getMonth() + 1, date.getDate()]
        .map((part, index) => index === 0 ? String(part) : String(part).padStart(2, "0"))
        .join("-");
    const clock = document.createElement("small");
    clock.textContent = date.toLocaleTimeString("en-GB", {
        hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
        timeZoneName: "short",
    });
    time.append(day, clock);
    return time;
}

function renderOverviewState(state) {
    totalRunsValue.textContent = displayValue(state.totalRuns);
    overviewStatus.textContent = state.queryState === "success"
        ? ""
        : state.queryState === "empty"
            ? state.message
            : state.totalMessage;
}

function getSelectedRuntime() {
    return selectedRuntimeTracking.outsideQuery ? null : selectedRuntimeTracking.report;
}

function renderSelectedScope() {
    selectedRunScope.textContent = getSelectedAnalysisScope(
        selectedRunId,
        selectedRuntimeEntityId,
        selectedAnalysisTargetHost,
    ).message;
}

function getPipelineStageContext(runtime) {
    if (selectedRunId !== null && selectedRuntimeEntityId === null) {
        return (
            "Run 목록 선택 · Entity 미지정 (아래 Runtime 표에서 선택)"
        );
    }
    if (selectedRuntimeTracking.outsideQuery) {
        return `${selectedRunId} · ${selectedRuntimeEntityId} · `
            + getSelectedRuntimeOutsideQueryLabel(selectedRuntimeTracking);
    }
    if (runtime === null) {
        return "선택한 Run의 Runtime 보고가 없어 단계 완료 여부를 확인할 수 없습니다.";
    }
    const statusLabel = getRuntimeStatePresentation(
        runtime,
        runtimeState.telemetryAvailable,
    ).statusLabel;
    const inQuery = findSelectedRuntime(
        runtimeState.items,
        selectedRunId,
        selectedRuntimeEntityId,
    ) !== null;
    return inQuery
        ? `${runtime.run_id} · ${runtime.entity_id} · ${statusLabel}`
        : `${runtime.run_id} · ${runtime.entity_id} · 마지막 확인 ${statusLabel} `
            + "· 최근 5건 조회 범위 밖";
}

function renderPipelineStages() {
    const runtime = getSelectedRuntime();
    const stages = buildPipelineStagePresentation(
        runtime,
        runtimeState.telemetryAvailable,
    );
    pipelineStageContext.textContent = getPipelineStageContext(runtime);
    document.getElementById("pipeline-status-note").textContent = stages.some((stage) => stage.state === "unknown")
        ? "단계 완료 미확인" : "최근 저장 Runtime 기준";

    const items = stages.map((stage, index) => {
        const item = document.createElement("li");
        item.classList.add("pipeline-stage", `pipeline-stage--${stage.state}`);
        const number = document.createElement("span");
        number.classList.add("pipeline-stage__number");
        number.append(createPipelineIcon(stage.stage, document));
        number.setAttribute("aria-hidden", "true");
        item.setAttribute("aria-label", `${index + 1}. ${stage.stageLabel} · ${stage.stateLabel}`);
        const content = document.createElement("span");
        content.classList.add("pipeline-stage__content");
        const label = document.createElement("strong");
        label.textContent = stage.stageLabel;
        const state = document.createElement("span");
        state.textContent = stage.state === "unknown" ? "미확인" : stage.stateLabel;
        content.append(label, state);
        item.append(number, content);
        return item;
    });
    pipelineStageList.replaceChildren(...items);
}

function renderRuntimeState(state) {
    runtimeSummaryStatus.textContent = state.message;
    // Keep the duplicate empty-state announcement accessible without adding a KPI row.
    const topMessage = state.queryState === "success" ? "" : state.message;
    if (runtimeTopStatus.textContent !== topMessage) {
        runtimeTopStatus.textContent = topMessage;
    }
    runtimeTopStatus.classList.toggle("dashboard-visually-hidden", state.queryState === "empty");
    const latest = getLatestRuntimeReport(state.items);
    if (latest === null) {
        latestRuntimeState.textContent = displayValue(null);
        latestRuntimeUpdated.textContent = displayValue(null);
        dashboardHeaderUpdated.textContent = "마지막 저장 보고 확인 불가";
    } else {
        const presentation = getRuntimeStatePresentation(
            latest,
            state.telemetryAvailable,
        );
        latestRuntimeState.textContent = presentation.telemetryLabel === "-"
            ? presentation.statusLabel
            : `${presentation.statusLabel} · ${presentation.telemetryLabel}`;
        latestRuntimeUpdated.textContent = formatRunTimestamp(latest.updated_at);
        dashboardHeaderUpdated.textContent = (
            `마지막 저장 보고 ${formatRunTimestamp(latest.updated_at)}`
        );
    }
    const freshRunning = state.telemetryAvailable
        ? state.items.find((runtime) => runtime.status === "running" && !runtime.is_stale)
        : null;
    const staleRunning = state.telemetryAvailable
        ? state.items.find((runtime) => runtime.status === "running" && runtime.is_stale)
        : null;
    systemStatusValue.textContent = !state.telemetryAvailable
        ? "Runtime 조회 확인 불가"
        : freshRunning !== undefined && freshRunning !== null
            ? "최근 실행 중 보고"
            : staleRunning !== undefined && staleRunning !== null
                ? "오래된 실행 중 보고 · 현재 상태 확인 불가"
                : latest === null
                    ? "최근 Runtime 보고 없음"
                    : "최근 저장 보고 확인";
    activeRuntimeRun.textContent = freshRunning === null || freshRunning === undefined
        ? "최근 실행 중 보고 없음"
        : `${freshRunning.run_id} · ${freshRunning.entity_id}`;
    replaceSelectionRows(
        runtimeSummaryList,
        state.items.map(
            (runtime) => createRuntimeRow(runtime, state.telemetryAvailable),
        ),
        "runtime",
        state.items,
        runListState.items,
    );
    renderPipelineStages();
}

function renderRunListState(state) {
    runsStatus.textContent = state.message;
    runsStatus.hidden = state.queryState === "success";
    replaceSelectionRows(
        runsList,
        state.items.map((run) => createRunRow(run)),
        "runs",
        runtimeState.items,
        state.items,
    );
    updateRunVisibility();
    const selectedIndex = state.items.findIndex((run) => run.run_id === selectedRunId);
    previousRunButton.disabled = selectedIndex < 0 || selectedIndex >= state.items.length - 1;
    nextRunButton.disabled = selectedIndex <= 0;
}

// Rows are rendered from runListState.items in order, so row index and item index match.
function updateRunVisibility() {
    const rows = Array.from(runsList.children);
    const visibility = resolveRunListVisibility(
        runListState.items,
        runSearchQuery,
        runsExpanded,
        RECENT_RUNS_VISIBLE_COUNT,
        selectedRunId,
        runType,
    );
    const focusedRowWillHide = rows.some((row, index) => (
        !visibility.visible[index] && row.contains(document.activeElement)
    ));
    if (focusedRowWillHide) {
        (visibility.filterActive ? runSearchInput : runsToggle).focus({ preventScroll: true });
    }
    for (const [index, row] of rows.entries()) {
        row.hidden = !visibility.visible[index];
    }
    runsToggle.hidden = visibility.toggleHidden;
    runsToggle.setAttribute("aria-expanded", String(runsExpanded));
    runsToggle.textContent = runsExpanded
        ? "최근 5개만 보기"
        : `전체 ${rows.length}개 Run 펼치기`;
    const visibilityMessage = getRunListVisibilityMessage(visibility, selectedRunId);
    if (runsVisibilityStatus.textContent !== visibilityMessage) {
        runsVisibilityStatus.textContent = visibilityMessage;
    }
}

// Only an explicit request moves the viewport; filtering and polling never call this.
function moveToRunSearchResults() {
    const row = Array.from(runsList.children).find((item) => !item.hidden);
    const target = row?.querySelectorAll(".dashboard-run-selector")[0]
        ?? (runListState.queryState === "success" ? runsVisibilityStatus : runsStatus);
    if (target === runsStatus) {
        target.tabIndex = -1;
    }
    target.focus({ preventScroll: true });
    target.scrollIntoView({ block: "center", inline: "nearest" });
}

function renderSelectionRows() {
    renderRuntimeState(runtimeState);
    renderRunListState(runListState);
}

function activateSelectedRunPanel(name) {
    for (const tab of selectedRunTabs) {
        const active = tab.name === name;
        tab.button.setAttribute("aria-selected", String(active));
        tab.button.tabIndex = active ? 0 : -1;
        tab.panel.hidden = !active;
    }
}

function createAnalysisField(label, value, emphasis = "primary") {
    const field = document.createElement("div");
    field.classList.add(
        "dashboard-analysis-field",
        `dashboard-analysis-field--${emphasis}`,
    );
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = value;
    field.append(term, description);
    return field;
}

function clearSelectedAnalysis() {
    selectedRunStatus.hidden = false;
    selectedRunChartStatus.hidden = false;
    selectedRunSummary.replaceChildren();
    selectedRunSettings.replaceChildren();
    selectedRunChart.replaceChildren();
    decisionTimelineList.replaceChildren();
    decisionHistoryList.replaceChildren();
    selectedRunDetailStatus.textContent = "";
    selectedRunChartStatus.textContent = "";
    decisionTimelineStatus.textContent = "저장된 Decision 이력을 불러오는 중입니다.";
    decisionHistoryStatus.textContent = "저장된 Decision 이력을 불러오는 중입니다.";
}

function createDecisionHistoryItem(decision) {
    const item = document.createElement("li");
    const identifier = document.createElement("strong");
    identifier.classList.add("dashboard-decision-id");
    identifier.textContent = decision.decision_id;
    const details = document.createElement("div");
    details.classList.add("dashboard-decision-meta");
    const time = document.createElement("span");
    time.textContent = `t_e · ${formatRunTimestamp(decision.t_e)}`;
    const path = document.createElement("span");
    path.textContent = `판단 경로 · ${getDecisionPathLabel(decision.decision_path)}`;
    details.append(time, path);
    item.append(identifier, details);
    return item;
}

function renderDecisionHistory(detailState) {
    if (detailState.queryState !== "success") {
        decisionTimelineStatus.textContent = detailState.message;
        decisionHistoryStatus.textContent = detailState.message;
        return;
    }
    const history = detailState.payload.decision_history;
    if (!Array.isArray(history) || history.length === 0) {
        decisionTimelineStatus.textContent = "저장된 Decision 이력이 없습니다.";
        decisionHistoryStatus.textContent = "저장된 Decision 이력이 없습니다.";
        return;
    }
    decisionTimelineStatus.textContent = "Run Detail의 저장 Decision 이력입니다.";
    decisionHistoryStatus.textContent = "최신 Decision부터 저장된 순서로 표시합니다.";
    decisionTimelineList.replaceChildren(...history.slice(0, 4).map(createDecisionHistoryItem));
    decisionHistoryList.replaceChildren(...history.map(createDecisionHistoryItem));
}

function renderEventTypeSummary(state) {
    eventTypeSummary.replaceChildren();
    if (state.queryState !== "success") {
        eventTypeSummaryStatus.textContent = state.message;
        return;
    }
    const counts = new Map();
    for (const event of state.payload.items) {
        counts.set(event.event_type, (counts.get(event.event_type) ?? 0) + 1);
    }
    eventTypeSummaryStatus.textContent = `조회된 Event ${state.payload.items.length}건 / 전체 ${state.payload.total}건 · Run 범위`;
    eventTypeSummary.replaceChildren(...Array.from(counts, ([eventType, count]) => {
        const item = document.createElement("li");
        const label = document.createElement("span");
        label.textContent = eventType;
        const value = document.createElement("strong");
        value.textContent = String(count);
        item.append(label, value);
        return item;
    }));
}

function renderSelectedRunFailureState() {
    selectedRequestVersion += 1;
    selectedRunStatus.hidden = false;
    selectedRunChartStatus.hidden = false;
    selectedRunStatus.textContent = (
        "마지막 Runtime 보고가 실패했습니다. 상세 결과 자동 재조회는 수행하지 않습니다."
    );
    if (selectedRunChartStatus.textContent.includes("기다리는 중")) {
        selectedRunChartStatus.textContent = (
            "Pipeline 실패로 Fusion 결과 저장 대기를 종료했습니다."
        );
    }
}

function renderSelectedRefreshControl() {
    selectedRunRefreshButton.hidden = selectedRunId === null;
    selectedRunRefreshButton.disabled = !canRefreshSelectedAnalysis(
        selectedRunId,
        selectedAnalysisPendingVersion !== null,
    );
}

function renderSelectedLinks(runId, detailAvailable, fusionAvailable) {
    selectedRunDetailLink.href = buildRunDetailViewPath(runId);
    selectedRunFusionLink.href = buildFusionEngineViewPath(runId);
    selectedRunDetailLink.hidden = !detailAvailable;
    selectedRunFusionLink.hidden = !fusionAvailable;
}

function renderSelectedAnalysis(detailState, fusionState) {
    selectedRunStatus.hidden = false;
    selectedRunChartStatus.hidden = false;
    const detailPayload = detailState.queryState === "success" ? detailState.payload : null;
    const fusionPayload = fusionState.queryState === "success" ? fusionState.payload : null;
    const decisionConsistency = getDecisionVersionConsistency(
        detailPayload,
        fusionPayload,
    );
    const analysisSource = getSelectedAnalysisSource(detailPayload, fusionPayload);
    const detailDecision = detailPayload?.current_decision?.decision ?? null;
    const fusionDecision = fusionPayload?.current_decision ?? null;
    const decision = analysisSource === "matched" || analysisSource === "run_detail"
        ? detailDecision
        : analysisSource === "fusion_engine"
            ? fusionDecision
            : null;
    const detailFusionResult = detailPayload?.current_decision?.latest_fusion_result ?? null;
    const fusionResult = analysisSource === "matched"
        ? fusionPayload?.fusion_result ?? detailFusionResult
        : analysisSource === "run_detail"
            ? detailFusionResult
            : (
                analysisSource === "fusion_engine"
                || analysisSource === "fusion_engine_without_decision"
            )
                ? fusionPayload?.fusion_result ?? null
                : null;
    const useFusionEngineArtifacts = (
        analysisSource === "matched"
        || analysisSource === "fusion_engine"
        || analysisSource === "fusion_engine_without_decision"
    );
    const runtimeConfig = useFusionEngineArtifacts
        ? fusionPayload?.runtime_config_snapshot ?? null
        : null;
    const stoppingTrace = useFusionEngineArtifacts
        ? fusionPayload?.stopping_trace ?? null
        : null;

    renderDecisionHistory(detailState);

    selectedRunDetailStatus.textContent = [detailState, fusionState]
        .filter((state) => state.queryState !== "success")
        .map((state) => state.message)
        .join(" ");
    selectedRunSummary.replaceChildren(
        createAnalysisField("Fast 상태", getStatusLabel(decision?.fast_status)),
        createAnalysisField(
            "Fusion 상태",
            getStatusLabel(decision?.fusion_status ?? fusionResult?.fusion_status),
        ),
        createAnalysisField(
            "최종 판단 경로",
            getDecisionPathLabel(decision?.decision_path),
        ),
        createAnalysisField(
            "기술적 판정 시각 (t_e)",
            formatRunTimestamp(decision?.t_e),
        ),
    );
    selectedRunSettings.replaceChildren(
        createAnalysisField(
            "Threshold On",
            displayValue(runtimeConfig?.stopping?.threshold_on),
            "setting",
        ),
        createAnalysisField(
            "Threshold Off",
            displayValue(runtimeConfig?.stopping?.threshold_off),
            "setting",
        ),
    );

    const runtime = getSelectedRuntime();
    const analysisState = getSelectedAnalysisState(
        detailState.queryState,
        fusionState.queryState,
        runtime?.status ?? null,
        decision !== null || fusionResult !== null || stoppingTrace !== null,
        decisionConsistency,
    );
    selectedAnalysisState = analysisState;
    if (analysisState === "version_mismatch") {
        selectedRunStatus.textContent = (
            "Run Detail과 Fusion Engine의 Decision 버전이 달라 결과를 결합하지 않았습니다."
        );
        selectedRunChartStatus.textContent = (
            "조회 시점이 일치하지 않아 Fusion Trace를 표시하지 않습니다."
        );
        selectedRunChart.replaceChildren();
        return;
    }

    if (analysisState === "error") {
        if (analysisSource === "run_detail") {
            selectedRunStatus.textContent = (
                "Fusion Engine 조회에 실패해 Run Detail 출처의 결과만 표시합니다."
            );
        } else if (
            analysisSource === "fusion_engine"
            || analysisSource === "fusion_engine_without_decision"
        ) {
            selectedRunStatus.textContent = (
                analysisSource === "fusion_engine_without_decision"
                    ? "Run Detail 조회에 실패했으며 Decision 없는 Fusion Engine 결과만 표시합니다."
                    : "Run Detail 조회에 실패해 Fusion Engine 출처의 결과만 표시합니다."
            );
        } else {
            selectedRunStatus.textContent = "선택한 Run의 상세 결과를 불러오지 못했습니다.";
        }
    } else if (analysisState === "waiting") {
        selectedRunStatus.textContent = (
            "마지막 Runtime 보고는 실행 중이며 결과 저장을 기다리는 중입니다."
        );
    } else if (analysisState === "missing") {
        selectedRunStatus.textContent = (
            getSelectedRuntimeRecheckMessage(selectedRuntimeTracking)
            ?? "선택한 Run에 저장된 상세 결과가 없습니다."
        );
    } else {
        selectedRunStatus.textContent = analysisSource === "run_detail"
            ? "Decision ID를 비교할 수 없어 Run Detail 출처의 결과만 표시합니다."
            : analysisSource === "fusion_engine"
                ? "Decision ID를 비교할 수 없어 Fusion Engine 출처의 결과만 표시합니다."
                : analysisSource === "fusion_engine_without_decision"
                    ? "Decision 없는 Fusion Engine 저장 결과를 단일 출처로 표시합니다."
                    : "저장된 분석 결과를 불러왔습니다.";
    }

    selectedRunStatus.hidden = analysisState === "available" && analysisSource === "matched";

    if (analysisSource === "run_detail") {
        selectedRunChartStatus.textContent = (
            "Fusion Engine Decision ID를 확인할 수 없어 Trace를 결합하지 않았습니다."
        );
        selectedRunChart.replaceChildren();
        return;
    }
    if (analysisSource === "none") {
        selectedRunChartStatus.textContent = "표시할 수 있는 Fusion Engine 판단 결과가 없습니다.";
        selectedRunChart.replaceChildren();
        return;
    }

    if (fusionState.queryState !== "success") {
        selectedRunChartStatus.textContent = (
            fusionState.queryState === "not_found" && runtime?.status === "running"
                ? "Fusion 결과 저장을 기다리는 중입니다."
                : fusionState.message
        );
        selectedRunChart.replaceChildren();
        return;
    }

    const traceAvailability = getStoppingTraceAvailability(stoppingTrace);
    if (traceAvailability === "missing") {
        selectedRunChartStatus.textContent = "저장된 Stopping Trace가 없습니다.";
        selectedRunChart.replaceChildren();
        return;
    }
    if (traceAvailability === "empty") {
        selectedRunChartStatus.textContent = fusionResult?.fusion_status === "not_evaluated"
            ? "Fusion이 평가되지 않아 저장된 Trace point가 없습니다."
            : "Stopping Trace가 비어 있습니다.";
        selectedRunChart.replaceChildren();
        return;
    }

    try {
        const model = buildScoreTrajectoryModel(
            stoppingTrace,
            runtimeConfig,
            SCORE_CHART_DIMENSIONS,
        );
        selectedRunChartStatus.textContent = runtimeConfig === null
            ? "Runtime Config Snapshot이 없어 threshold 기준선을 표시할 수 없습니다."
            : `저장된 Score point ${model.points.length}개와 threshold를 표시합니다.`;
        selectedRunChartStatus.hidden = runtimeConfig !== null;
        selectedRunChart.replaceChildren(createDashboardReplayChart(
            model,
            fusionResult,
            decision?.t_e ?? null,
        ));
    } catch {
        selectedRunChartStatus.hidden = false;
        selectedRunChartStatus.textContent = "저장된 Fusion Trace를 표시할 수 없습니다.";
        selectedRunChart.replaceChildren();
    }
}

async function fetchJson(endpoint, failureMessage) {
    const response = await fetch(endpoint, {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (!response.ok) {
        throw new Error(failureMessage);
    }
    return response.json();
}

function cancelSelectedAnalysisRequests() {
    for (const controller of selectedAnalysisAbortControllers) {
        controller.abort();
    }
    selectedAnalysisAbortControllers.clear();
}

async function fetchSelectedAnalysis(endpoint, failureMessage) {
    const controller = new AbortController();
    selectedAnalysisAbortControllers.add(controller);
    const timeoutId = setTimeout(
        () => controller.abort(),
        ANALYSIS_REQUEST_TIMEOUT_MS,
    );
    try {
        const response = await fetch(endpoint, {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
            signal: controller.signal,
        });
        if (response.status === 404) {
            return { kind: "not_found" };
        }
        if (!response.ok) {
            throw new Error(failureMessage);
        }
        return { kind: "success", payload: await response.json() };
    } finally {
        clearTimeout(timeoutId);
        selectedAnalysisAbortControllers.delete(controller);
    }
}

async function fetchRunDetail(runId) {
    return fetchSelectedAnalysis(
        buildRunDetailApiPath(runId),
        "Run Detail API request failed",
    );
}

async function fetchFusionEngine(runId) {
    return fetchSelectedAnalysis(
        buildFusionEngineApiPath(runId),
        "Fusion Engine API request failed",
    );
}

async function loadRunDetailState(runId) {
    const loading = resolveRunDetailQueryState(null, { kind: "loading" });
    try {
        return resolveRunDetailQueryState(loading, await fetchRunDetail(runId));
    } catch {
        return resolveRunDetailQueryState(loading, { kind: "error" });
    }
}

async function loadFusionEngineState(runId) {
    const loading = resolveFusionEngineQueryState(null, { kind: "loading" });
    try {
        return resolveFusionEngineQueryState(loading, await fetchFusionEngine(runId));
    } catch {
        return resolveFusionEngineQueryState(loading, { kind: "error" });
    }
}

async function loadSelectedEventSummary(runId, selectionVersion) {
    const controller = new AbortController();
    selectedTimelineAbortController = controller;
    const timeoutId = setTimeout(() => controller.abort(), ANALYSIS_REQUEST_TIMEOUT_MS);
    let result;
    try {
        const response = await fetch(buildEventTimelineApiPath(runId, EVENT_TIMELINE_LIMIT, 0), {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
            signal: controller.signal,
        });
        if (response.status === 404) {
            result = { kind: "run_not_found" };
        } else if (!response.ok) {
            result = { kind: "error" };
        } else {
            result = { kind: "success", payload: await response.json() };
        }
        result = resolveEventTimelineQueryState(null, result);
    } catch {
        result = resolveEventTimelineQueryState(null, { kind: "error" });
    } finally {
        clearTimeout(timeoutId);
        if (selectedTimelineAbortController === controller) {
            selectedTimelineAbortController = null;
        }
    }
    if (selectionVersion === selectedTimelineRequestVersion && selectedRunId === runId) {
        renderEventTypeSummary(result);
    }
}

function refreshSelectedEventSummary() {
    if (selectedRunId === null) {
        return;
    }
    const version = ++selectedTimelineRequestVersion;
    selectedTimelineAbortController?.abort();
    selectedTimelineAbortController = null;
    renderEventTypeSummary(resolveEventTimelineQueryState(null, { kind: "loading" }));
    void loadSelectedEventSummary(selectedRunId, version);
}

async function loadSelectedRunAnalysis(runId, loadingMessage) {
    const requestVersion = ++selectedRequestVersion;
    cancelSelectedAnalysisRequests();
    selectedAnalysisPendingVersion = requestVersion;
    selectedAnalysisState = "loading";
    renderSelectedRefreshControl();
    clearSelectedAnalysis();
    selectedRunStatus.textContent = loadingMessage;

    try {
        let [detailState, fusionState] = await Promise.all([
            loadRunDetailState(runId),
            loadFusionEngineState(runId),
        ]);
        if (!shouldApplySelectedRunResponse(requestVersion, selectedRequestVersion)) {
            return;
        }
        const firstDetailPayload = detailState.queryState === "success"
            ? detailState.payload
            : null;
        const firstFusionPayload = fusionState.queryState === "success"
            ? fusionState.payload
            : null;
        if (getDecisionVersionConsistency(firstDetailPayload, firstFusionPayload) === "mismatch") {
            [detailState, fusionState] = await Promise.all([
                loadRunDetailState(runId),
                loadFusionEngineState(runId),
            ]);
            if (!shouldApplySelectedRunResponse(requestVersion, selectedRequestVersion)) {
                return;
            }
        }
        selectedAnalysisQueryStates = { detailState, fusionState };
        selectedAnalysisTargetHost = getSelectedAnalysisTargetHost(
            detailState.queryState === "success" ? detailState.payload : null,
            fusionState.queryState === "success" ? fusionState.payload : null,
        );
        renderSelectedScope();
        renderSelectedLinks(
            runId,
            detailState.queryState === "success",
            fusionState.queryState === "success",
        );
        renderSelectedAnalysis(detailState, fusionState);
    } finally {
        if (selectedAnalysisPendingVersion === requestVersion) {
            selectedAnalysisPendingVersion = null;
        }
        renderSelectedRefreshControl();
    }
}

function rerenderSelectedAnalysis() {
    if (selectedAnalysisQueryStates === null || selectedAnalysisPendingVersion !== null) {
        return;
    }
    renderSelectedAnalysis(
        selectedAnalysisQueryStates.detailState,
        selectedAnalysisQueryStates.fusionState,
    );
}

async function selectRun(runId, runtimeEntityId = null) {
    const timelineVersion = ++selectedTimelineRequestVersion;
    selectedTimelineAbortController?.abort();
    selectedTimelineAbortController = null;
    renderEventTypeSummary(resolveEventTimelineQueryState(null, { kind: "loading" }));
    selectedRunId = runId;
    selectedRuntimeEntityId = runtimeEntityId;
    selectedRuntimeTracking = createSelectedRuntimeTracking(
        findSelectedRuntime(runtimeState.items, runId, runtimeEntityId),
    );
    selectedAnalysisQueryStates = null;
    selectedAnalysisState = null;
    selectedAnalysisTargetHost = null;
    selectedRunIdElement.textContent = runId;
    renderSelectedScope();
    renderSelectedLinks(runId, false, false);
    renderSelectionRows();
    await loadSelectedRunAnalysis(
        runId,
        "선택한 Run의 저장 분석 결과를 불러오는 중입니다.",
    );
    if (timelineVersion === selectedTimelineRequestVersion && selectedRunId === runId) {
        void loadSelectedEventSummary(runId, timelineVersion);
    }
}

function recheckSelectedRuntimeAnalysis() {
    if (
        selectedRunId === null
        || !shouldRecheckSelectedRuntimeAnalysis(
            selectedRuntimeTracking,
            selectedAnalysisPendingVersion !== null,
            selectedAnalysisState === "available",
        )
    ) {
        return;
    }
    selectedRuntimeTracking = recordSelectedRuntimeRecheck(selectedRuntimeTracking);
    void loadSelectedRunAnalysis(
        selectedRunId,
        "조회 범위를 벗어난 Runtime의 저장 분석 결과를 다시 확인하는 중입니다.",
    );
}

function refreshSelectedRunAnalysis() {
    if (!canRefreshSelectedAnalysis(selectedRunId, selectedAnalysisPendingVersion !== null)) {
        return;
    }
    void loadSelectedRunAnalysis(
        selectedRunId,
        "선택한 Run의 저장 분석 결과를 다시 조회하는 중입니다.",
    );
    refreshSelectedEventSummary();
}

function selectDefaultRunIfReady() {
    if (selectedRunId !== null) {
        return;
    }
    const selection = resolveInitialRunSelection(
        selectedRunId,
        selectedRuntimeEntityId,
        runtimeInitialQuerySettled,
        runtimeState.telemetryAvailable,
        runtimeState.items,
        runListState.items,
    );
    if (selection !== null) {
        void selectRun(selection.runId, selection.entityId);
    }
}

function selectAdjacentRun(direction) {
    const selectedIndex = runListState.items.findIndex((run) => run.run_id === selectedRunId);
    const target = runListState.items[selectedIndex + direction];
    if (selectedIndex >= 0 && target !== undefined) {
        void selectRun(target.run_id);
    }
}

async function loadOverview() {
    renderOverviewState(overviewState);
    try {
        const payload = await fetchJson(OVERVIEW_ENDPOINT, "Overview API request failed");
        overviewState = resolveOverviewQueryState(
            overviewState,
            { kind: "success", payload },
        );
    } catch {
        overviewState = resolveOverviewQueryState(overviewState, { kind: "error" });
    }
    renderOverviewState(overviewState);
}

async function loadRuns() {
    renderRunListState(runListState);
    try {
        const payload = await fetchJson(RUNS_ENDPOINT, "Run List API request failed");
        runListState = resolveRunListQueryState(
            runListState,
            { kind: "success", payload },
        );
        selectDefaultRunIfReady();
    } catch {
        runListState = resolveRunListQueryState(runListState, { kind: "error" });
    }
    renderRunListState(runListState);
}

async function fetchRuntimeSummary() {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(RUNTIME_ENDPOINT, {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
            signal: controller.signal,
        });
        if (!response.ok) {
            throw new Error("Runtime Summary API request failed");
        }
        return await response.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

function scheduleRuntimePoll() {
    if (
        !runtimePollingActive
        || runtimeRequestInFlight
        || runtimePollTimeoutId !== null
    ) {
        return;
    }
    runtimePollTimeoutId = setTimeout(() => {
        runtimePollTimeoutId = null;
        void pollRuntimeSummary();
    }, RUNTIME_POLL_INTERVAL_MS);
}

function startRuntimePolling() {
    runtimePollingActive = true;
    if (!runtimeRequestInFlight && runtimePollTimeoutId === null) {
        void pollRuntimeSummary();
    }
}

function stopRuntimePolling() {
    runtimePollingActive = false;
    if (runtimePollTimeoutId !== null) {
        clearTimeout(runtimePollTimeoutId);
        runtimePollTimeoutId = null;
    }
}

async function updateRuntimeSummary() {
    let refreshCompletedSelection = false;
    let updateFailedSelection = false;
    let selectedRuntimeResult = { kind: "error" };
    try {
        const payload = await fetchRuntimeSummary();
        const nextRuntimeState = resolveRuntimeSummaryQueryState(
            runtimeState,
            { kind: "success", payload },
        );
        const previousSelectedRuntimeItems = selectedRuntimeTracking.report === null
            ? []
            : [selectedRuntimeTracking.report];
        refreshCompletedSelection = shouldRefreshSelectedRunAnalysis(
            selectedRunId,
            selectedRuntimeEntityId,
            previousSelectedRuntimeItems,
            nextRuntimeState.items,
        );
        updateFailedSelection = shouldUpdateSelectedRunFailureState(
            selectedRunId,
            selectedRuntimeEntityId,
            previousSelectedRuntimeItems,
            nextRuntimeState.items,
        );
        selectedRuntimeResult = { kind: "success", items: nextRuntimeState.items };
        runtimeState = nextRuntimeState;
    } catch {
        runtimeState = resolveRuntimeSummaryQueryState(runtimeState, { kind: "error" });
    }
    const previousRecheckMessage = getSelectedRuntimeRecheckMessage(selectedRuntimeTracking);
    selectedRuntimeTracking = resolveSelectedRuntimeTracking(
        selectedRuntimeTracking,
        selectedRunId,
        selectedRuntimeEntityId,
        selectedRuntimeResult,
    );
    runtimeInitialQuerySettled = true;
    selectDefaultRunIfReady();
    renderRuntimeState(runtimeState);
    renderRunListState(runListState);
    if (updateFailedSelection) {
        renderSelectedRunFailureState();
    } else if (refreshCompletedSelection && selectedRunId !== null) {
        void loadSelectedRunAnalysis(
            selectedRunId,
            "완료 보고를 확인해 저장된 분석 결과를 다시 불러오는 중입니다.",
        );
        refreshSelectedEventSummary();
    } else {
        if (getSelectedRuntimeRecheckMessage(selectedRuntimeTracking) !== previousRecheckMessage) {
            rerenderSelectedAnalysis();
        }
        recheckSelectedRuntimeAnalysis();
    }
}

async function pollRuntimeSummary() {
    if (!runtimePollingActive || runtimeRequestInFlight) {
        return;
    }
    runtimeRequestInFlight = true;
    try {
        await updateRuntimeSummary();
    } finally {
        runtimeRequestInFlight = false;
        scheduleRuntimePoll();
    }
}

if (dashboardView !== null) {
    const telemetryController = createDashboardTelemetryController(document);
    for (const [index, tab] of selectedRunTabs.entries()) {
        tab.button.addEventListener("click", () => activateSelectedRunPanel(tab.name));
        tab.button.addEventListener("keydown", (event) => {
            let nextIndex;
            if (event.key === "ArrowRight") {
                nextIndex = (index + 1) % selectedRunTabs.length;
            } else if (event.key === "ArrowLeft") {
                nextIndex = (index - 1 + selectedRunTabs.length) % selectedRunTabs.length;
            } else if (event.key === "Home") {
                nextIndex = 0;
            } else if (event.key === "End") {
                nextIndex = selectedRunTabs.length - 1;
            } else {
                return;
            }
            event.preventDefault();
            const nextTab = selectedRunTabs[nextIndex];
            activateSelectedRunPanel(nextTab.name);
            nextTab.button.focus();
            nextTab.button.scrollIntoView({ block: "nearest", inline: "nearest" });
        });
    }
    activateSelectedRunPanel("replay");
    renderOverviewState(overviewState);
    renderRunListState(runListState);
    renderRuntimeState(runtimeState);
    selectedRunRefreshButton.addEventListener("click", refreshSelectedRunAnalysis);
    runsToggle.addEventListener("click", () => {
        runsExpanded = !runsExpanded;
        updateRunVisibility();
    });
    // Filtering only shows or hides rendered rows: no request, re-render, or selection change.
    runSearchQuery = runSearchInput.value;
    runSearchInput.addEventListener("input", () => {
        runSearchQuery = runSearchInput.value;
        updateRunVisibility();
    });
    runSearchInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.isComposing) {
            event.preventDefault();
            moveToRunSearchResults();
        }
    });
    runSearchResults.addEventListener("click", moveToRunSearchResults);
    runType = runTypeFilter.value || "all";
    runTypeFilter.addEventListener("change", () => {
        runType = runTypeFilter.value;
        updateRunVisibility();
    });
    runFilterReset.addEventListener("click", () => {
        runSearchInput.value = "";
        runSearchQuery = "";
        runTypeFilter.value = "all";
        runType = "all";
        updateRunVisibility();
    });
    previousRunButton.addEventListener("click", () => selectAdjacentRun(1));
    nextRunButton.addEventListener("click", () => selectAdjacentRun(-1));
    void loadOverview();
    void loadRuns();
    startRuntimePolling();
    void telemetryController.start();

    window.addEventListener("pagehide", () => {
        stopRuntimePolling();
        telemetryController.stop();
    });
    window.addEventListener("pageshow", (event) => {
        if (event.persisted) {
            startRuntimePolling();
            void telemetryController.start();
        }
    });
}
