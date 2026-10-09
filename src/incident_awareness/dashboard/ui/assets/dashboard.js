import {
    buildPipelineStagePresentation,
    canRefreshSelectedAnalysis,
    createSelectedRuntimeTracking,
    displayValue,
    findSelectedRuntime,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
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
import { createScoreTrajectoryChart } from "./fusion-score-chart.mjs";
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
const SCORE_CHART_DIMENSIONS = {
    width: 960,
    height: 360,
    padding: { top: 28, right: 72, bottom: 44, left: 58 },
};

const dashboardView = document.getElementById("dashboard-view");
const totalRunsValue = document.getElementById("total-runs-value");
const overviewStatus = document.getElementById("overview-status");
const latestRuntimeState = document.getElementById("latest-runtime-state");
const latestRuntimeUpdated = document.getElementById("latest-runtime-updated");
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
const selectedRunChartStatus = document.getElementById("selected-run-chart-status");
const selectedRunChart = document.getElementById("selected-run-chart");
const selectedRunDetailLink = document.getElementById("selected-run-detail-link");
const selectedRunFusionLink = document.getElementById("selected-run-fusion-link");
const selectedRunRefreshButton = document.getElementById("selected-run-refresh");
const runsStatus = document.getElementById("runs-status");
const runsList = document.getElementById("runs-list");

let overviewState = resolveOverviewQueryState(null, { kind: "loading" });
let runListState = resolveRunListQueryState(null, { kind: "loading" });
let runtimeState = resolveRuntimeSummaryQueryState(null, { kind: "loading" });
let selectedRunId = null;
let selectedRuntimeEntityId = null;
let selectedRuntimeTracking = createSelectedRuntimeTracking(null);
let selectedAnalysisQueryStates = null;
let selectedAnalysisState = null;
let selectedAnalysisTargetHost = null;
let selectedAnalysisPendingVersion = null;
let selectedRequestVersion = 0;
let runtimeInitialQuerySettled = false;
let runtimePollTimeoutId = null;

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
    const focusedElement = list.contains(document.activeElement)
        && document.activeElement?.classList.contains("dashboard-run-selector")
        ? document.activeElement
        : null;
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
    const replacement = Array.from(
        list.querySelectorAll(".dashboard-run-selector"),
    ).find(
        (button) => (
            button.dataset.runId === focusTarget.runId
            && (button.dataset.entityId ?? null) === focusTarget.entityId
        ),
    );
    replacement?.focus({ preventScroll: true });
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
    detailLink.href = buildRunDetailViewPath(run.run_id);
    detailLink.textContent = "Run Detail";

    row.append(
        createTableCell(createSelectionButton(run.run_id), "dashboard-table__run"),
        createTableCell(displayValue(run.scenario_id)),
        createTableCell(displayValue(run.target_host)),
        createTableCell(formatRunTimestamp(run.start_time)),
        createTableCell(detailLink),
    );
    return row;
}

function renderOverviewState(state) {
    totalRunsValue.textContent = displayValue(state.totalRuns);
    overviewStatus.textContent = state.totalMessage;
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
            "Run 목록 선택은 Entity를 지정하지 않아 Runtime 단계를 표시하지 않습니다. "
            + "Runtime 표에서 Run과 Entity를 선택하세요."
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

    const items = stages.map((stage, index) => {
        const item = document.createElement("li");
        item.classList.add("pipeline-stage", `pipeline-stage--${stage.state}`);
        const number = document.createElement("span");
        number.classList.add("pipeline-stage__number");
        number.textContent = String(index + 1);
        const content = document.createElement("span");
        content.classList.add("pipeline-stage__content");
        const label = document.createElement("strong");
        label.textContent = stage.stageLabel;
        const state = document.createElement("span");
        state.textContent = stage.stateLabel;
        content.append(label, state);
        item.append(number, content);
        return item;
    });
    pipelineStageList.replaceChildren(...items);
}

function renderRuntimeState(state) {
    runtimeSummaryStatus.textContent = state.message;
    runtimeTopStatus.textContent = state.message;
    const latest = getLatestRuntimeReport(state.items);
    if (latest === null) {
        latestRuntimeState.textContent = displayValue(null);
        latestRuntimeUpdated.textContent = displayValue(null);
    } else {
        const presentation = getRuntimeStatePresentation(
            latest,
            state.telemetryAvailable,
        );
        latestRuntimeState.textContent = presentation.telemetryLabel === "-"
            ? presentation.statusLabel
            : `${presentation.statusLabel} · ${presentation.telemetryLabel}`;
        latestRuntimeUpdated.textContent = formatRunTimestamp(latest.updated_at);
    }
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
    replaceSelectionRows(
        runsList,
        state.items.map((run) => createRunRow(run)),
        "runs",
        runtimeState.items,
        state.items,
    );
}

function renderSelectionRows() {
    renderRuntimeState(runtimeState);
    renderRunListState(runListState);
}

function createAnalysisField(label, value) {
    const field = document.createElement("div");
    field.classList.add("dashboard-analysis-field");
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = value;
    field.append(term, description);
    return field;
}

function clearSelectedAnalysis() {
    selectedRunSummary.replaceChildren();
    selectedRunChart.replaceChildren();
    selectedRunDetailStatus.textContent = "";
    selectedRunChartStatus.textContent = "";
}

function renderSelectedRunFailureState() {
    selectedRequestVersion += 1;
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

    selectedRunDetailStatus.textContent = (
        `${detailState.message} ${fusionState.message}`
    );
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
        createAnalysisField(
            "Threshold On",
            displayValue(runtimeConfig?.stopping?.threshold_on),
        ),
        createAnalysisField(
            "Threshold Off",
            displayValue(runtimeConfig?.stopping?.threshold_off),
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
        selectedRunChart.replaceChildren(createScoreTrajectoryChart(model));
    } catch {
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

async function fetchRunDetail(runId) {
    const response = await fetch(buildRunDetailApiPath(runId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Run Detail API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function fetchFusionEngine(runId) {
    const response = await fetch(buildFusionEngineApiPath(runId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Fusion Engine API request failed");
    }
    return { kind: "success", payload: await response.json() };
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

async function loadSelectedRunAnalysis(runId, loadingMessage) {
    const requestVersion = ++selectedRequestVersion;
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

async function pollRuntimeSummary() {
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
    if (updateFailedSelection) {
        renderSelectedRunFailureState();
    } else if (refreshCompletedSelection && selectedRunId !== null) {
        void loadSelectedRunAnalysis(
            selectedRunId,
            "완료 보고를 확인해 저장된 분석 결과를 다시 불러오는 중입니다.",
        );
    } else {
        if (getSelectedRuntimeRecheckMessage(selectedRuntimeTracking) !== previousRecheckMessage) {
            rerenderSelectedAnalysis();
        }
        recheckSelectedRuntimeAnalysis();
    }
    runtimePollTimeoutId = setTimeout(
        () => void pollRuntimeSummary(),
        RUNTIME_POLL_INTERVAL_MS,
    );
}

if (dashboardView !== null) {
    renderOverviewState(overviewState);
    renderRunListState(runListState);
    renderRuntimeState(runtimeState);
    selectedRunRefreshButton.addEventListener("click", refreshSelectedRunAnalysis);
    void loadOverview();
    void loadRuns();
    void pollRuntimeSummary();

    window.addEventListener("pagehide", () => {
        if (runtimePollTimeoutId !== null) {
            clearTimeout(runtimePollTimeoutId);
        }
    });
}
