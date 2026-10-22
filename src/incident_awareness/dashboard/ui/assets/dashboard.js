import { createPipelineIcon } from "./dashboard-icons.mjs";
import { rawVerificationLabel, normalizeRawVerificationScope, sameRawVerificationScope, analysisStatusLabel, analysisDecisionPresentation, workflowRowLabel, observationDisplayText } from "./dashboard-operator-contract.mjs";
import { createListSummaryController, runInputRange, runRowAnalysis, runRowWorkflow, runRowObservation, EVENT_TYPE_NAMES } from "./dashboard-analysis-list.mjs";
import { createDecisionRecord, createWorkflowRecord } from "./dashboard-records.mjs";
import { restoreRowFocus } from "./dashboard-detail-rows.mjs";
import { createHumanWorkflowController } from "./dashboard-workflow-controller.mjs";
import { createKisaFormController } from "./dashboard-kisa-controller.mjs";
import {
    buildPipelineStagePresentation,
    buildStoredFusionContext,
    canRefreshSelectedAnalysis,
    createSelectedRuntimeTracking,
    displayValue,
    findSelectedRuntime,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
    getRunListVisibilityMessage,
    getSelectedAnalysisScope,
    getStoredCaseScope,
    getSelectedAnalysisSource,
    getSelectedAnalysisState,
    getSelectedAnalysisTargetHost,
    getSelectedRuntimeOutsideQueryLabel,
    getSelectedRuntimeRecheckMessage,
    getStoppingTraceAvailability,
    isRunSelectionTarget,
    recordSelectedRuntimeRecheck,
    resolveAdjacentRuns,
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
    shouldRefreshStoredRunIndex,
    shouldUpdateSelectedRunFailureState,
    summarizePipelineStages,
} from "./dashboard-contract.mjs";
import {
    buildFusionEngineApiPath,
    buildFusionEngineViewPath,
    buildScoreTrajectoryModel,
    resolveFusionEngineQueryState,
} from "./fusion-engine-contract.mjs";
import { createDashboardReplayChart, createDashboardReplayRecords } from "./dashboard-replay-chart.mjs";
import { createSysmonIngestController } from "./dashboard-ingest-controller.mjs";
import { createDashboardTelemetryController } from "./dashboard-telemetry-controller.mjs";
import { createDashboardStageTimingController } from "./dashboard-stage-timing-controller.mjs";
import { createDashboardEvidenceController } from "./dashboard-evidence-controller.mjs";
import { createProvenanceController } from "./dashboard-provenance-controller.mjs";
import { resolveStageTimingTarget } from "./dashboard-stage-timing-contract.mjs";
import { createRuntimeContextController, createPipelineStageReader, scopeKey } from "./dashboard-runtime-context.mjs";
import {
    buildEventTimelineApiPath,
    buildEventTimelineViewPath,
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
    getHybridDecisionNotice,
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
    height: 180,
    padding: { top: 50, right: 72, bottom: 23, left: 50 },
};
// The chart now has the panel's full width; its logical width follows that width so labels keep
// their nominal size instead of being scaled up. A hidden panel falls back to the minimum.
const SCORE_CHART_MAX_WIDTH = 1600;

const dashboardView = document.getElementById("dashboard-view");
let selectedStageEvidence = null;
const stageTimingController = createDashboardStageTimingController(document, {
    onResult(result) {
        if (result === null) {
            if (selectedStageEvidence === null) return;
            selectedStageEvidence = null;
        } else {
            const runtime = getSelectedRuntime();
            if (result.target.runId !== selectedRunId || result.target.entityId !== selectedRuntimeEntityId
                || result.target.executionId !== runtime?.execution_id) return;
            selectedStageEvidence = result;
        }
        renderPipelineStages();
    },
});
const evidenceController = createDashboardEvidenceController(document);
let selectedRawVerification = null;
let operatorContributingIds = null;
let operatorVerificationScope = null;
// Read lazily in 증거; the summary shares its scoped state without extra requests.
const provenanceController = createProvenanceController(document, {
    onSummary(summary) {
        if (summary.runId !== selectedRunId || !sameRawVerificationScope(operatorVerificationScope, summary.scope)) return;
        selectedRawVerification = summary;
        renderVerificationFacts();
    },
});
const kisaController = document.getElementById("kisa-panel")
    ? createKisaFormController(document) : { setDraft: async () => {} };
let selectedWorkflowProgress = null;
const workflowController = createHumanWorkflowController(document, {
    developerTools: new URLSearchParams(window.location?.search ?? "").get("developer_tools") === "1",
    onOpen: () => activateSelectedRunPanel("workflow"),
    onDraft: value => void kisaController.setDraft(value),
    onProgress(progress) {
        if (progress.runId !== selectedRunId) return;
        const label = progress.alerts === null ? null : workflowRowLabel(progress.alerts);
        const previous = selectedWorkflowProgress?.runId === progress.runId && selectedWorkflowProgress.alerts !== null
            ? workflowRowLabel(selectedWorkflowProgress.alerts.filter(alert => alert.entity_id === selectedRunListItem()?.target_host)) : null;
        selectedWorkflowProgress = progress;
        renderSelectedWorkflowSummary();
        // Only the selected row follows the controller; other rows keep the stored list summary.
        if (label !== previous) renderRunListState(runListState);
    },
});
const listSummaryController = createListSummaryController({ onChange() {
    renderRunListState(runListState);
    renderSelectedWorkflowSummary();
    renderVerificationFacts();
} });
const workspace = document.getElementById("dashboard-workspace");
const selectedItemWorkflowStatus = document.getElementById("selected-item-workflow-status");
const selectedItemWorkflowOpen = document.getElementById("selected-item-workflow-open");
const selectedRunIdNote = document.getElementById("selected-run-id-note");
const selectedRunHeading = document.getElementById("selected-run-heading");
const selectedItemStatus = document.getElementById("selected-item-status");
const selectedItemBody = document.getElementById("selected-item-body");
const selectedItemTarget = document.getElementById("selected-item-target");
const selectedItemRange = document.getElementById("selected-item-range");
const selectedItemHeadline = document.getElementById("selected-item-headline");
const selectedItemObservation = document.getElementById("selected-item-observation");
const selectedItemFacts = document.getElementById("selected-item-facts");
const selectedItemOpen = document.getElementById("selected-item-open");
const selectedRunTarget = document.getElementById("selected-run-target");
const selectedRunPaths = document.getElementById("selected-run-paths");
const selectedRunEvidenceOpen = document.getElementById("selected-run-evidence-open");
const selectedRunJudgment = document.getElementById("selected-run-judgment");
const selectedRunJudgmentReason = document.getElementById("selected-run-judgment-reason");
const selectedRunObservations = document.getElementById("selected-run-observations");
const selectedRunObservationsStatus = document.getElementById("selected-run-observations-status");
const selectedRunWorkflowSummary = document.getElementById("selected-run-workflow-summary");
const selectedRunWorkflowOpen = document.getElementById("selected-run-workflow-open");
const selectedRunIdentity = document.getElementById("selected-run-identity");
const totalRunsValue = document.getElementById("total-runs-value");
const overviewStatus = document.getElementById("overview-status");
const latestRuntimeState = document.getElementById("latest-runtime-state");
const latestRuntimeUpdated = document.getElementById("latest-runtime-updated");
const latestRuntimeLine = document.getElementById("latest-runtime-line");
const activeRuntimeLine = document.getElementById("active-runtime-line");
const dashboardRefreshButton = document.getElementById("dashboard-refresh");
const dashboardRefreshStatus = document.getElementById("dashboard-refresh-status");
const systemStatusValue = document.getElementById("system-status-value");
const activeRuntimeRun = document.getElementById("active-runtime-run");
const runtimeTopStatus = document.getElementById("runtime-top-status");
const pipelineStageContext = document.getElementById("pipeline-stage-context");
const pipelineStageList = document.getElementById("pipeline-stage-list");
const pipelineAutoFollow = document.getElementById("pipeline-auto-follow");
let runtimeContext = { queryState: "loading", pipeline: null, scopes: new Map() };
let pipelineStageEvidence = null;
let pipelineStageReadState = "unavailable";
const pipelineStageReader = createPipelineStageReader({ onChange(value, state) {
    pipelineStageEvidence = value;
    pipelineStageReadState = state;
    renderPipelineStages();
} });
const runtimeContextController = createRuntimeContextController({ onChange(value) {
    runtimeContext = value;
    if (value.queryState === "success") pipelineStageReader.retry();
    renderPipelineStages();
    renderRunListState(runListState);
    for (const field of selectedRunIdentity.childNodes) {
        if (field.childNodes?.[0]?.textContent === "실행 보고") field.childNodes[1].textContent = getCaseProcessingStatus();
    }
} });
const runtimeSummaryStatus = document.getElementById("runtime-summary-status");
const runtimeSummaryList = document.getElementById("runtime-summary-list");
const selectedRunIdElement = document.getElementById("selected-run-id");
const selectedRunScope = document.getElementById("selected-run-scope");
const selectedRunStatus = document.getElementById("selected-run-status");
const selectedRunDetailStatus = document.getElementById("selected-run-detail-status");
const selectedRunSummary = document.getElementById("selected-run-summary");
const selectedDecisionSummaryHeading = document.getElementById("selected-decision-summary-heading");
const selectedRunSettings = document.getElementById("selected-run-settings");
const selectedRunChartStatus = document.getElementById("selected-run-chart-status");
const selectedRunChart = document.getElementById("selected-run-chart");
const selectedRunDetailLink = document.getElementById("selected-run-detail-link");
const selectedRunFusionLink = document.getElementById("selected-run-fusion-link");
const selectedRunExplanation = document.getElementById("selected-run-explanation");
const selectedRunMetadataNote = document.getElementById("selected-run-metadata-note");
const selectedRunHybridNote = document.getElementById("selected-run-hybrid-note");
const selectedRunFusionContext = document.getElementById("selected-run-fusion-context");
const selectedRunFusionSummary = document.getElementById("selected-run-fusion-summary");
const selectedRunContributingIds = document.getElementById("selected-run-contributing-ids");
const selectedRunStoredFusionLink = document.getElementById("selected-run-stored-fusion-link");
const selectedRunEventProvenanceLink = document.getElementById("selected-run-event-provenance-link");
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
const eventTypeSummary = document.getElementById("event-type-summary");
const eventTypeSummaryStatus = document.getElementById("event-type-summary-status");
const decisionHistoryList = document.getElementById("decision-history-list");
const decisionHistoryStatus = document.getElementById("decision-history-status");
const workflowRecordsList = document.getElementById("workflow-records-list");
const workflowRecordsStatus = document.getElementById("workflow-records-status");
const replayRecordsOpen = document.getElementById("replay-records-open");
const recordsWorkflowOpen = document.getElementById("records-workflow-open");
const workflowRecordsOpen = document.getElementById("workflow-records-open");
// Rendered record sources; an unchanged source is not rebuilt, so open details and focus stay.
let shownDecisionHistory = null;
let shownWorkflowRecords = null;
// Audit rows opened by the operator; kept across re-renders of the same selection.
let workflowRecordExpanded = new Set();
let workflowRecordButtons = new Map();
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
let runtimePending = null;
let overviewPending = null;
let runsPending = null;
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

function createSelectionButton(runId, runtimeEntityId = null, { label = runId, ariaLabel = null, kind = null } = {}) {
    const button = document.createElement("button");
    button.type = "button";
    button.classList.add("dashboard-run-selector");
    button.textContent = label;
    button.dataset.runId = runId;
    // The future Live list shares this table; kind keeps a stored 분석 distinct from a Live observation.
    if (kind !== null) button.dataset.kind = kind;
    if (runtimeEntityId !== null) {
        button.dataset.entityId = runtimeEntityId;
        button.setAttribute("aria-label", `분석 ${runId}, Entity ${runtimeEntityId}`);
    } else if (ariaLabel !== null) {
        button.setAttribute("aria-label", ariaLabel);
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
    // Same control kind and 분석/Entity only; a 분석 that left the list keeps no focus target.
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

function createStackedCell(primary, secondary = null, className = null) {
    const content = document.createElement("span");
    content.classList.add("dashboard-cell-stack");
    const main = document.createElement("span");
    if (primary instanceof Node) main.append(primary); else main.textContent = primary;
    content.append(main);
    if (secondary !== null) {
        const detail = document.createElement("small");
        if (secondary instanceof Node) detail.append(secondary); else detail.textContent = secondary;
        content.append(detail);
    }
    return createTableCell(content, className);
}

function selectedWorkflowRowLabel(runId) {
    return selectedWorkflowProgress?.runId === runId && runId === selectedRunId && selectedWorkflowProgress.alerts !== null
        ? workflowRowLabel(selectedWorkflowProgress.alerts.filter(alert => alert.entity_id === selectedRunListItem()?.target_host)) : null;
}

// Operator-facing row: where, what and how far; internal identifiers stay available in the last column.
function createRunRow(run) {
    const row = document.createElement("tr");
    row.dataset.kind = "formal_run";
    row.dataset.runId = run.run_id;
    row.dataset.entityId = run.target_host;
    if (isSelectedTarget(run.run_id, null)) {
        row.classList.add("dashboard-table__row--selected");
    }

    const detailLink = document.createElement("a");
    detailLink.classList.add("dashboard-run-detail-link");
    detailLink.dataset.runId = run.run_id;
    detailLink.dataset.kind = "formal_run";
    detailLink.href = buildRunDetailViewPath(run.run_id);
    detailLink.textContent = "기술 상세";
    detailLink.title = `분석 상세 페이지 · ${run.run_id}`;
    detailLink.addEventListener("focus", () => {
        // Focus restored after a re-render stays where the user left the page scroll.
        if (!restoringSelectionRowFocus) {
            detailLink.scrollIntoView({ block: "nearest", inline: "nearest" });
        }
    });
    const identifier = document.createElement("span");
    identifier.classList.add("dashboard-run-identity");
    const runIdText = document.createElement("small");
    runIdText.textContent = run.run_id;
    identifier.append(detailLink, runIdText);

    const range = runInputRange(run);
    const rangeContent = document.createElement("span");
    rangeContent.classList.add("dashboard-run-range");
    rangeContent.title = `${range.title} · 시작 원본 ${run.start_time} · 종료 원본 ${run.end_time ?? "미기록"}`;
    const rangeStart = createRunTimestamp(run.start_time);
    rangeStart.textContent = `${range.start} `;
    const rangeEnd = document.createElement("span");
    rangeEnd.textContent = `~ ${range.end} KST`;
    rangeContent.append(rangeStart, rangeEnd);

    const target = createSelectionButton(run.run_id, null, {
        label: displayValue(run.target_host), kind: "formal_run",
        ariaLabel: `${displayValue(run.target_host)} · 저장 분석 · 입력 ${range.start} 선택`,
    });
    const analysis = runRowAnalysis(listSummaryController.state.analysis, run.run_id, run.target_host);
    const observation = runRowObservation(listSummaryController.state.analysis, run.run_id, run.target_host);
    const matchingRuntime = runtimeContext.scopes.get(scopeKey(run.run_id, run.target_host));
    // A run report is shown only when one exists; its absence is explained once in System status.
    let runtimeNote = null;
    if (matchingRuntime != null) {
        const presentation = getRuntimeStatePresentation(matchingRuntime, runtimeContext.queryState === "success");
        const progress = getRuntimeProgressPresentation(matchingRuntime).processed;
        runtimeNote = createStatusBadge({ ...presentation, statusLabel: `실행 보고 · ${presentation.telemetryLabel === "-"
            ? presentation.statusLabel : `${presentation.statusLabel} · ${presentation.telemetryLabel}`} · ${progress}` });
    }

    row.append(
        createStackedCell(rangeContent, range.span === null ? "입력 범위 확인 불가" : `입력 범위 ${range.span}`),
        createStackedCell(target, null, "dashboard-table__run"),
        // One line per row: the observed Event counts, or the headline when none are stored.
        createStackedCell(observation ?? analysis.headline),
        createStackedCell(analysis.status, runtimeNote),
        createTableCell(selectedWorkflowRowLabel(run.run_id) ?? runRowWorkflow(listSummaryController.state.workflow, run.run_id, run.target_host)),
        createTableCell(identifier, "dashboard-table__identity"),
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
    // KST like every other dashboard clock; en-CA yields YYYY-MM-DD.
    const day = document.createElement("span");
    day.textContent = formatRunTimestamp(value).split(" ")[0];
    const clock = document.createElement("small");
    clock.textContent = formatRunTimestamp(value).split(" ").slice(1).join(" ");
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
    // The KPI's actual 0 and Recent Runs empty state already explain this condition.
    // Keep its live announcement accessible without a duplicate row moving every card.
    overviewStatus.classList.toggle("dashboard-visually-hidden", state.queryState === "empty");
}

function getSelectedRuntime() {
    return selectedRuntimeTracking.outsideQuery ? null : selectedRuntimeTracking.report;
}

function storedCaseScope() {
    return getStoredCaseScope(selectedRunId, runListState.items, selectedAnalysisTargetHost, selectedRuntimeEntityId);
}

function renderSelectedIdentity() {
    const scope = storedCaseScope();
    const target = scope === null ? "선택 항목 없음" : scope.entityId ?? "대상 확인 중";
    selectedRunTarget.textContent = target;
    selectedItemTarget.textContent = scope === null ? "" : target;
    selectedRunIdElement.textContent = scope?.runId ?? "";
    selectedRunIdNote.hidden = scope === null;
    for (const node of [selectedRunHeading, selectedItemBody]) {
        node.dataset.kind = scope?.kind ?? "";
        node.dataset.runId = scope?.runId ?? "";
        node.dataset.entityId = scope?.entityId ?? "";
    }
}

function renderSelectedScope() {
    renderSelectedIdentity();
    selectedRunScope.textContent = getSelectedAnalysisScope(
        selectedRunId,
        selectedRuntimeEntityId,
        selectedAnalysisTargetHost,
    ).message;
}

// Manual scope: every line names the selected item so it is never read as the latest execution.
function getPipelineStageContext(runtime) {
    if (selectedRunId !== null && selectedRuntimeEntityId === null) {
        return (
            "선택 항목 · Entity 미지정 (최근 실행 기록 표에서 선택)"
        );
    }
    if (selectedRuntimeTracking.outsideQuery) {
        return `선택 항목 · ${selectedRunId} · ${selectedRuntimeEntityId} · `
            + getSelectedRuntimeOutsideQueryLabel(selectedRuntimeTracking);
    }
    if (runtime === null) {
        return "선택 항목 · 실행 보고 없음 · 단계 완료 여부 확인 불가";
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
        ? `선택 항목 · ${runtime.run_id} · ${runtime.entity_id} · ${statusLabel}`
        : `선택 항목 · ${runtime.run_id} · ${runtime.entity_id} · 마지막 확인 ${statusLabel} `
            + "· 최근 5건 조회 범위 밖";
}

function renderPipelineStages() {
    void stageTimingController.select(resolveStageTimingTarget({
        runId: selectedRunId,
        entityId: selectedRuntimeEntityId,
        items: runtimeState.items,
        queryFailed: selectedRuntimeTracking.queryFailed || runtimeState.queryState === "error",
        outsideQuery: selectedRuntimeTracking.outsideQuery,
    }));
    const auto = pipelineAutoFollow?.checked !== false;
    const runtime = auto ? runtimeContext.pipeline : getSelectedRuntime();
    pipelineStageReader.select(auto ? runtime : null);
    const stages = buildPipelineStagePresentation(
        runtime,
        auto ? runtimeContext.queryState === "success" : runtimeState.telemetryAvailable,
        auto ? runtime !== null && pipelineStageEvidence !== null && pipelineStageEvidence.executionId === runtime.execution_id ? pipelineStageEvidence.records : null
            : selectedStageEvidence?.target.executionId === runtime?.execution_id
            ? selectedStageEvidence?.records ?? null : null,
    );
    pipelineStageContext.textContent = !auto ? getPipelineStageContext(runtime)
        : runtimeContext.queryState !== "success" ? (runtimeContext.queryState === "loading" ? "최신 실행 보고 조회 중"
            : runtimeContext.queryState === "not_ready" ? "최신 실행 보고 조회 미지원" : "최신 실행 보고 조회 실패 · 이전 상태 표시 안 함")
            : runtime === null ? ""
                : `최신 실행 · 분석 ${runtime.run_id} · Entity ${runtime.entity_id} · ${getRuntimeStatePresentation(runtime, true).statusLabel}`
                    + (runtime.is_stale ? " · 오래된 보고 · 현재 실행 여부 확인 불가" : "")
                    + ` · 보고 ${formatRunTimestamp(runtime.updated_at)}`;
    pipelineStageContext.hidden = !pipelineStageContext.textContent;
    // A missing report says nothing about whether the service is running.
    pipelineStageContext.title = runtime === null && auto && runtimeContext.queryState === "success"
        ? "저장된 실행 보고가 없습니다. 서비스 가동·중단 여부를 뜻하지 않습니다." : pipelineStageContext.textContent;
    // The selected-item scope keeps its query state in the context line above.
    const { text: note, tone: noteTone } = summarizePipelineStages(stages, {
        hasRuntime: runtime !== null,
        queryState: auto ? runtimeContext.queryState : "success",
        readFailed: auto && pipelineStageReadState === "error",
        unconfirmed: !auto && (selectedRuntimeTracking.outsideQuery
            || (selectedRunId !== null && selectedRuntimeEntityId === null)),
    });
    const noteNode = document.getElementById("pipeline-status-note");
    if (noteNode.textContent !== note) noteNode.textContent = note;
    noteNode.setAttribute("data-tone", noteTone);

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
        state.textContent = stage.stateLabel;
        state.title = stage.state === "unknown"
            ? "이 단계의 완료를 확인할 저장 실행 보고가 없습니다. 미실행이나 실패를 뜻하지 않습니다."
            : stage.state === "stale"
                ? "오래된 실행 보고의 마지막 단계입니다. 실시간 진행 상태를 뜻하지 않습니다."
                : stage.stateLabel;
        content.append(label, state);
        item.append(number, content);
        return item;
    });
    pipelineStageList.replaceChildren(...items);
}

function renderRuntimeState(state) {
    // No report is already stated by the KPI ("최근 실행 보고 없음"); loading and errors keep their message.
    runtimeSummaryStatus.textContent = state.queryState === "empty" ? "" : state.message;
    const topMessage = state.queryState === "success" || state.queryState === "empty" ? "" : state.message;
    if (runtimeTopStatus.textContent !== topMessage) {
        runtimeTopStatus.textContent = topMessage;
    }
    runtimeTopStatus.classList.toggle("dashboard-visually-hidden", state.queryState === "empty");
    // One KPI states the report condition; the secondary lines appear only for an actual report.
    const latest = getLatestRuntimeReport(state.items);
    latestRuntimeLine.hidden = latest === null;
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
    const freshRunning = state.telemetryAvailable
        ? state.items.find((runtime) => runtime.status === "running" && !runtime.is_stale)
        : null;
    const staleRunning = state.telemetryAvailable
        ? state.items.find((runtime) => runtime.status === "running" && runtime.is_stale)
        : null;
    systemStatusValue.textContent = state.queryState === "loading"
        ? "확인 중"
        : !state.telemetryAvailable
            ? "실행 보고 조회 실패"
            : freshRunning !== undefined && freshRunning !== null
                ? "실행 중 보고 있음"
                : staleRunning !== undefined && staleRunning !== null
                    ? "오래된 실행 중 보고 · 현재 상태 확인 불가"
                    : latest === null
                        ? ""
                        : "최근 실행 보고 확인";
    systemStatusValue.hidden = !systemStatusValue.textContent;
    const noRuntimeReport = state.telemetryAvailable && latest === null && state.queryState !== "loading";
    const reportCell = document.getElementById("runtime-report-cell");
    if (reportCell) reportCell.hidden = noRuntimeReport;
    const systemStrip = document.getElementById("dashboard-system-strip");
    if (systemStrip) systemStrip.dataset.emptyRuntime = String(noRuntimeReport);
    // Status mark only; "none" (no report) is neither an outage nor a healthy state.
    systemStatusValue.setAttribute("data-tone", state.queryState === "loading" ? "neutral"
        : !state.telemetryAvailable ? "error"
            : freshRunning !== undefined && freshRunning !== null ? "active"
                : staleRunning !== undefined && staleRunning !== null ? "warning"
                    : latest === null ? "none" : "reported");
    const activeRunning = freshRunning !== undefined && freshRunning !== null;
    activeRuntimeLine.hidden = !activeRunning;
    activeRuntimeRun.textContent = activeRunning
        ? `${freshRunning.run_id} · ${freshRunning.entity_id}` : "";
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
}

function updateAdjacentRunButtons() {
    const adjacent = resolveAdjacentRuns(runListState.items, runSearchQuery, runType, selectedRunId);
    previousRunButton.disabled = adjacent.previous === null;
    nextRunButton.disabled = adjacent.next === null;
    const scope = adjacent.selectedShown ? "현재 표시된 목록에서" : "선택 항목이 현재 검색·필터 결과에 없어";
    previousRunButton.title = previousRunButton.disabled ? `${scope} 더 이전 항목이 없습니다.` : "검색·필터가 적용된 목록 순서로 이전 항목 이동";
    nextRunButton.title = nextRunButton.disabled ? `${scope} 더 다음 항목이 없습니다.` : "검색·필터가 적용된 목록 순서로 다음 항목 이동";
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
        : `전체 ${rows.length}개 분석 펼치기`;
    const visibilityMessage = getRunListVisibilityMessage(visibility, selectedRunId);
    if (runsVisibilityStatus.textContent !== visibilityMessage) {
        runsVisibilityStatus.textContent = visibilityMessage;
    }
    workspace.dataset.shortList = String(visibility.visibleCount <= 2);
    updateAdjacentRunButtons();
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
    // The R1 archive is read only while its tab is shown; focus stays on the tab button.
    // Contributing-Evidence verification is read with the selection (see provenanceController).
    void evidenceController.setActive(name === "evidence");
    void provenanceController.setActive(name === "evidence");
}

function openSelectedDetail(name) {
    activateSelectedRunPanel(name);
    const tab = selectedRunTabs.find((item) => item.name === name);
    tab?.button.focus();
    tab?.panel.scrollIntoView?.({ behavior: "smooth", block: "start" });
}

// Observations and the verification fact come only from the scoped provenance summary.
function renderVerificationFacts() {
    const label = rawVerificationLabel(operatorContributingIds, selectedRawVerification, operatorVerificationScope);
    for (const list of [selectedRunSummary, selectedItemFacts]) {
        for (const field of list.childNodes) {
            if (field.childNodes?.[0]?.textContent === "원본 검증") field.childNodes[1].textContent = label;
        }
    }
    const summary = selectedRawVerification;
    const observations = summary?.queryState === "ready" ? summary.observations ?? [] : [];
    const storedObservation = selectedRunId ? runRowObservation(listSummaryController.state.analysis,
        selectedRunId, storedCaseScope()?.entityId) : null;
    selectedItemObservation.textContent = observations.length ? observations.slice(0, 2).map(item => observationDisplayText(item.text, item.observedAt)).join(" · ")
        + (observations.length > 2 ? ` · 나머지 ${observations.length - 2}건은 분석 상세에서 확인` : "")
        : storedObservation ? ""
            : "확인된 관측은 근거·원본 검증 조회 후 표시합니다.";
    selectedRunObservations.replaceChildren(...observations.map((observation) => {
        const item = document.createElement("li");
        item.textContent = observationDisplayText(observation.text, observation.observedAt);
        item.title = `Evidence ${observation.evidenceId} · 관측 원본 ${observation.observedAt ?? "미제공"} · 문장 원문 ${observation.text}`;
        return item;
    }));
    selectedRunObservationsStatus.textContent = operatorVerificationScope === null
        ? (operatorContributingIds === null ? "기여 증거를 확인할 수 없어 관측을 표시하지 않습니다." : "")
        : !operatorVerificationScope.evidenceIds.length ? "기여 증거 없음"
        : summary === null || summary.queryState === "not_requested" ? ""
        : summary.queryState === "loading" ? "원본 검증 확인 중"
        : summary.queryState === "unsupported" ? "이 서버는 원본 검증 정보를 제공하지 않습니다."
        : summary.queryState !== "ready" ? "원본 검증 조회 실패 · 관측을 표시하지 않습니다."
        : observations.length ? `${label}`
        : `${label} · 검증된 관측 요약 없음`;
}

function renderSelectedWorkflowSummary() {
    const progress = selectedWorkflowProgress?.runId === selectedRunId ? selectedWorkflowProgress : null;
    const target = selectedAnalysisTargetHost ?? selectedRunListItem()?.target_host;
    const scoped = progress?.alerts?.filter(alert => alert.entity_id === target);
    selectedItemWorkflowStatus.textContent = progress === null
        ? selectedRunId ? runRowWorkflow(listSummaryController.state.workflow, selectedRunId, target) : "선택 항목 없음"
        : scoped === undefined ? progress.status : workflowRowLabel(scoped);
    selectedRunWorkflowSummary.textContent = progress === null ? "선택 항목의 알림을 조회하면 표시합니다."
        : scoped === undefined ? progress.status
            : [workflowRowLabel(scoped), progress.entityId === target && progress.step && `현재 ${progress.step}`].filter(Boolean).join(" · ");
    renderWorkflowRecords();
}

function selectedRunListItem() {
    return runListState.items.find((run) => run.run_id === selectedRunId) ?? null;
}

// Quick view beside the list. It repeats only the leading facts; the detail holds everything else.
function renderSelectedItemPanel(model) {
    selectedItemBody.hidden = model.state === "empty";
    selectedItemStatus.textContent = model.status;
    selectedItemStatus.hidden = model.state === "ready";
    selectedItemOpen.disabled = model.state !== "ready";
    renderSelectedIdentity();
    if (model.state === "empty") return;
    const run = selectedRunListItem();
    const range = run === null ? null : runInputRange(run);
    renderSelectedIdentity();
    selectedItemRange.textContent = range === null ? "입력 이벤트 범위 확인 불가"
        : `입력 이벤트 ${range.start} ~ ${range.end} KST`;
    selectedItemRange.title = range?.title ?? "";
    selectedItemHeadline.textContent = model.headline ?? "";
    selectedItemFacts.replaceChildren(...(model.facts ?? []).map(([label, value]) => createAnalysisField(label, value, "compact")));
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
    clearStoredAnalysisContext();
    selectedRawVerification = null;
    operatorVerificationScope = null;
    void provenanceController.select(selectedRunId);
    selectedRunStatus.hidden = false;
    selectedRunChartStatus.hidden = false;
    selectedRunSummary.replaceChildren();
    selectedRunPaths.replaceChildren();
    renderSelectedWorkflowSummary();
    selectedDecisionSummaryHeading.textContent = "주요 판단 결과";
    selectedRunJudgment.textContent = "";
    selectedRunJudgmentReason.textContent = "";
    selectedRunJudgmentReason.title = "";
    selectedRunIdentity.replaceChildren();
    selectedRunObservations.replaceChildren();
    selectedItemObservation.textContent = "";
    selectedRunObservationsStatus.textContent = "";
    renderSelectedItemPanel(selectedRunId === null
        ? { state: "empty", status: "목록에서 확인할 항목을 선택하세요." }
        : { state: "loading", status: "선택 항목의 저장 분석 결과를 불러오는 중입니다." });
    selectedRunSettings?.replaceChildren();
    selectedRunChart.replaceChildren();
    decisionHistoryList.replaceChildren();
    shownDecisionHistory = null;
    selectedRunDetailStatus.textContent = "";
    selectedRunChartStatus.textContent = "";
    decisionHistoryStatus.textContent = "저장된 분석 결정 이력을 불러오는 중입니다.";
}

// 기록 tab: the stored Decision head first, then the Decisions it superseded. No storage time
// is shown because the API has none; t_e or alert times never stand in for it.
function renderDecisionHistory(detailState) {
    if (detailState.queryState !== "success") {
        decisionHistoryStatus.textContent = detailState.message;
        return;
    }
    const history = detailState.payload.decision_history;
    if (!Array.isArray(history) || history.length === 0) {
        decisionHistoryStatus.textContent = "저장된 분석 결정 이력이 없습니다.";
        return;
    }
    // Decisions shown: the "현재 결정" / "이전 결정 N" labels carry the order, so no status sentence.
    decisionHistoryStatus.textContent = "";
    if (shownDecisionHistory === history) return;
    shownDecisionHistory = history;
    decisionHistoryList.replaceChildren(...history.map((decision, index) => createDecisionRecord(document, decision, index)));
}

function toggleWorkflowRecord(key) {
    if (workflowRecordExpanded.has(key)) workflowRecordExpanded.delete(key);
    else workflowRecordExpanded.add(key);
    const previous = document.activeElement;
    renderWorkflowRecords(true);
    restoreRowFocus(document, workflowRecordButtons, key, previous);
}

// Audit rows of the alerts the Workflow controller already read; this tab starts no request.
function renderWorkflowRecords(force = false) {
    const progress = selectedWorkflowProgress?.runId === selectedRunId ? selectedWorkflowProgress : null;
    const target = selectedAnalysisTargetHost ?? selectedRunListItem()?.target_host;
    const alerts = progress?.alerts ?? null;
    const scoped = alerts === null ? null : target ? alerts.filter(alert => alert.entity_id === target) : alerts;
    workflowRecordsStatus.textContent = selectedRunId === null ? "분석 항목을 선택하면 저장된 담당자 처리 기록을 표시합니다."
        : scoped === null ? progress?.status || "담당자 처리 기록을 조회하는 중입니다."
        : !scoped.length ? "담당자 처리 기록 없음"
        : "";
    const source = scoped === null ? null : JSON.stringify(scoped);
    if (!force && source === shownWorkflowRecords) return;
    shownWorkflowRecords = source;
    // A narrow viewport scrolls the audit table horizontally. Rebuilding an expanded row must
    // preserve that position, so its focused toggle stays visible after the table is replaced.
    const scrollPositions = new Map([...workflowRecordsList.querySelectorAll(".dashboard-audit-region")]
        .map(region => [region.dataset.alertId, region.scrollLeft]));
    workflowRecordButtons = new Map();
    workflowRecordsList.replaceChildren(...(scoped ?? []).map(alert => createWorkflowRecord(document, alert, {
        expanded: workflowRecordExpanded, onToggle: toggleWorkflowRecord, buttons: workflowRecordButtons })));
    for (const region of workflowRecordsList.querySelectorAll(".dashboard-audit-region")) {
        region.scrollLeft = scrollPositions.get(region.dataset.alertId) ?? 0;
    }
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
    eventTypeSummaryStatus.textContent = `조회 이벤트 ${state.payload.items.length}건 / 전체 ${state.payload.total}건`;
    eventTypeSummary.replaceChildren(...Array.from(counts, ([eventType, count]) => {
        const item = document.createElement("li");
        const label = document.createElement("span");
        // A known stored type reads in Korean; the stored name stays as its title.
        label.textContent = EVENT_TYPE_NAMES[eventType] ?? eventType;
        label.title = eventType;
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
        "마지막 실행 보고가 실패했습니다. 상세 결과 자동 재조회는 수행하지 않습니다."
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

function clearStoredAnalysisContext() {
    selectedRunExplanation.hidden = true;
    selectedRunMetadataNote.textContent = "";
    selectedRunHybridNote.textContent = "";
    selectedRunHybridNote.hidden = true;
    selectedRunHybridNote.title = "";
    selectedRunFusionContext.hidden = true;
    selectedRunFusionSummary.textContent = "";
    selectedRunContributingIds.replaceChildren();
}

function renderStoredAnalysisContext(run, decision, fusion, trace) {
    clearStoredAnalysisContext();
    if (run?.run_id !== selectedRunId) return;
    selectedRunExplanation.hidden = false;
    selectedRunMetadataNote.textContent = `실행 Metadata run_type: ${displayValue(run.run_type)} · 원본 수집 라벨과 별도`;
    const notice = getHybridDecisionNotice(decision);
    if (notice !== null) {
        selectedRunHybridNote.textContent = notice;
        selectedRunHybridNote.title = `저장된 사유: ${decision.decision_reason}`;
        selectedRunHybridNote.hidden = false;
    }
    const context = buildStoredFusionContext(fusion, trace);
    if (context === null) return;
    selectedRunFusionContext.hidden = false;
    selectedRunFusionSummary.textContent = `저장 Trace 최대 ${context.traceMax ?? "미관측"}`
        + ` · 판단 시 score ${context.decisionScore ?? "미확정"}`
        + ` · Episode ${context.episodeCount ?? "미확인"}`
        + ` · 기여 ID ${context.evidenceIds?.length ?? "미확인"}`;
    for (const id of context.evidenceIds ?? []) {
        const item = document.createElement("li");
        item.textContent = id;
        selectedRunContributingIds.append(item);
    }
    selectedRunStoredFusionLink.href = buildFusionEngineViewPath(run.run_id);
    selectedRunEventProvenanceLink.href = buildEventTimelineViewPath(run.run_id);
}

function getCaseProcessingStatus() {
    if (runtimeContext.queryState !== "success") return runtimeContext.queryState === "error" ? "조회 실패"
        : runtimeContext.queryState === "not_ready" ? "조회 미지원" : "확인 중";
    const report = runtimeContext.scopes.get(scopeKey(selectedRunId, selectedAnalysisTargetHost ?? selectedRuntimeEntityId));
    return report ? getRuntimeStatePresentation(report, true).statusLabel : "실행 보고 없음";
}

// The detail section stays visible while the chart's own tab panel may be hidden, so it is measured.
function scoreChartDimensions() {
    const available = (selectedRunChart.closest?.(".dashboard-analysis")?.clientWidth ?? 0) - 64;
    const width = Math.round(Math.min(SCORE_CHART_MAX_WIDTH, Math.max(SCORE_CHART_DIMENSIONS.width, available)));
    return { ...SCORE_CHART_DIMENSIONS, width };
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
    operatorContributingIds = fusionResult?.contributing_evidence_ids ?? null;
    const versionMismatch = decisionConsistency === "mismatch";
    if (versionMismatch) operatorContributingIds = null;
    const nextVerificationScope = versionMismatch ? null : normalizeRawVerificationScope({
        runId: selectedRunId,
        entityId: decision?.entity_id ?? fusionResult?.entity_id ?? selectedAnalysisTargetHost,
        decisionId: decision?.decision_id ?? null,
        evidenceIds: operatorContributingIds,
    });
    if (!sameRawVerificationScope(operatorVerificationScope, nextVerificationScope)) selectedRawVerification = null;
    operatorVerificationScope = nextVerificationScope;
    void provenanceController.select(selectedRunId, operatorVerificationScope);
    const presentation = analysisDecisionPresentation(
        versionMismatch ? null : decision,
        versionMismatch ? null : fusionResult,
        versionMismatch ? "version_mismatch" : detailState.queryState,
    );
    selectedDecisionSummaryHeading.textContent = presentation.headline;
    const timeField = createAnalysisField("탐지 시각", presentation.detectionTime);
    const decisionTime = document.createElement("div");
    const decisionTimeText = document.createElement("small");
    decisionTimeText.textContent = ` · 종합 판단 시각: ${presentation.decisionTime}`;
    const timeSource = versionMismatch ? null : decision ?? fusionResult;
    decisionTime.title = `fusion_time: ${timeSource?.fusion_time ?? "null"} / detector_time: ${timeSource?.detector_time ?? "null"} / t_e: ${timeSource?.t_e ?? "null"}`;
    decisionTime.append(decisionTimeText);
    timeField.childNodes[1].append(decisionTime);
    selectedRunJudgment.textContent = presentation.summary;
    selectedRunJudgmentReason.textContent = presentation.reasonRepeatsSummary ? "" : presentation.reason;
    selectedRunJudgmentReason.hidden = presentation.reasonRepeatsSummary;
    selectedRunJudgmentReason.title = presentation.rawReason ?? "";
    selectedRunSummary.replaceChildren(
        timeField,
        createAnalysisField("기여 증거", Array.isArray(fusionResult?.contributing_evidence_ids)
            ? `${fusionResult.contributing_evidence_ids.length}건` : "미확인"),
        createAnalysisField("원본 검증", rawVerificationLabel(operatorContributingIds, selectedRawVerification, operatorVerificationScope)),
    );
    const fastLabel = analysisStatusLabel(versionMismatch ? null : decision?.fast_status);
    const fusionLabel = analysisStatusLabel(versionMismatch ? null : decision?.fusion_status ?? fusionResult?.fusion_status);
    selectedRunPaths.replaceChildren(createAnalysisField("즉시 규칙 분석", fastLabel, "compact"),
        createAnalysisField("증거 누적 분석", fusionLabel, "compact"));
    const runMetadata = detailPayload?.run ?? fusionPayload?.run;
    selectedRunIdentity.replaceChildren(...[
        ["분석 ID", selectedRunId], ["시나리오 ID", displayValue(runMetadata?.scenario_id)],
        ["Entity ID", displayValue(decision?.entity_id ?? fusionResult?.entity_id ?? selectedAnalysisTargetHost)],
        ["결정 ID", versionMismatch ? "조회 버전 불일치" : displayValue(decision?.decision_id)],
        ["구성·정책 버전", versionMismatch ? "조회 버전 불일치" : displayValue(decision?.config_version)],
        ["Fusion 구성 버전", displayValue(versionMismatch ? null : fusionResult?.scoring_config_version)],
        ["종합 판단 경로", presentation.path], ["종합 판단 시각", presentation.decisionTime],
        ["실행 보고", getCaseProcessingStatus()],
        ["원본 시각", `detector_time: ${versionMismatch ? "미확정" : decision?.detector_time ?? "null"} / fusion_time: ${versionMismatch ? "미확정" : (decision ?? fusionResult)?.fusion_time ?? "null"} / t_e: ${versionMismatch ? "미확정" : decision?.t_e ?? "null"}`],
        ["판단 사유 원문", presentation.rawReason ?? "원문 없음"],
    ].map(([label, value]) => createAnalysisField(label, value, "compact")));
    renderSelectedItemPanel({ state: "ready", status: "", target: runMetadata?.target_host,
        headline: presentation.headline, judgment: presentation.summary,
        facts: [["기여 증거", Array.isArray(operatorContributingIds) ? `${operatorContributingIds.length}건` : "미확인"],
            ["원본 검증", rawVerificationLabel(operatorContributingIds, selectedRawVerification, operatorVerificationScope)]] });
    renderVerificationFacts();
    renderSelectedWorkflowSummary();
    const facts = document.getElementById("operator-case-facts");
    if (facts) facts.textContent = fusionResult === null ? "관측 사실을 확인할 수 없습니다."
        : `관측 사실 · 저장된 탐지 구간 ${fusionResult.fusion_episodes?.length ?? "미확인"}개 · 입력 유형 ${detailPayload?.run?.run_type ?? "미확인"} (탐지 결과와 별개)`;
    selectedRunSettings?.replaceChildren(
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
        clearStoredAnalysisContext();
        selectedRunStatus.textContent = (
            "분석 상세과 Fusion Engine의 분석 결정 버전이 달라 결과를 결합하지 않았습니다."
        );
        selectedRunChartStatus.textContent = (
            "조회 시점이 일치하지 않아 Fusion Trace를 표시하지 않습니다."
        );
        selectedRunChart.replaceChildren();
        return;
    }

    renderStoredAnalysisContext(
        analysisSource === "run_detail" || analysisSource === "matched"
            ? detailPayload?.run : useFusionEngineArtifacts ? fusionPayload?.run : null,
        decision, fusionResult, stoppingTrace,
    );

    if (analysisState === "error") {
        if (analysisSource === "run_detail") {
            selectedRunStatus.textContent = (
                "Fusion Engine 조회에 실패해 분석 상세 출처의 결과만 표시합니다."
            );
        } else if (
            analysisSource === "fusion_engine"
            || analysisSource === "fusion_engine_without_decision"
        ) {
            selectedRunStatus.textContent = (
                analysisSource === "fusion_engine_without_decision"
                    ? "분석 상세 조회에 실패했으며 분석 결정 없는 Fusion Engine 결과만 표시합니다."
                    : "분석 상세 조회에 실패해 Fusion Engine 출처의 결과만 표시합니다."
            );
        } else {
            selectedRunStatus.textContent = "선택한 분석의 상세 결과를 불러오지 못했습니다.";
        }
    } else if (analysisState === "waiting") {
        selectedRunStatus.textContent = (
            "마지막 실행 보고는 실행 중이며 결과 저장을 기다리는 중입니다."
        );
    } else if (analysisState === "missing") {
        selectedRunStatus.textContent = (
            getSelectedRuntimeRecheckMessage(selectedRuntimeTracking)
            ?? "선택한 분석에 저장된 상세 결과가 없습니다."
        );
    } else {
        selectedRunStatus.textContent = analysisSource === "run_detail"
            ? "결정 ID를 비교할 수 없어 분석 상세 출처의 결과만 표시합니다."
            : analysisSource === "fusion_engine"
                ? "결정 ID를 비교할 수 없어 Fusion Engine 출처의 결과만 표시합니다."
                : analysisSource === "fusion_engine_without_decision"
                    ? "분석 결정 없는 Fusion Engine 저장 결과를 단일 출처로 표시합니다."
                    : "저장된 분석 결과를 불러왔습니다.";
    }

    selectedRunStatus.hidden = analysisState === "available" && analysisSource === "matched";

    if (analysisSource === "run_detail") {
        selectedRunChartStatus.textContent = (
            "Fusion Engine 결정 ID를 확인할 수 없어 Trace를 결합하지 않았습니다."
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

    // undefined: no 분석 결정 to describe; null: a stored 분석 결정 whose t_e is not determined.
    const chartDecisionTime = decision === null ? undefined : decision.t_e ?? null;
    const traceAvailability = getStoppingTraceAvailability(stoppingTrace);
    if (traceAvailability === "missing") {
        selectedRunChartStatus.textContent = "저장된 점수 기록 없음";
        selectedRunChart.replaceChildren(createDashboardReplayRecords(fusionResult, chartDecisionTime, presentation.summary));
        return;
    }
    if (traceAvailability === "empty") {
        selectedRunChartStatus.textContent = fusionResult?.fusion_status === "not_evaluated"
            ? "증거 누적 분석 미평가 · 점수 기록 없음"
            : "저장된 점수 0건";
        selectedRunChart.replaceChildren(createDashboardReplayRecords(fusionResult, chartDecisionTime, presentation.summary));
        return;
    }

    try {
        const model = buildScoreTrajectoryModel(
            stoppingTrace,
            runtimeConfig,
            scoreChartDimensions(),
        );
        selectedRunChartStatus.textContent = runtimeConfig === null
            ? "판정 기준 미확인 · 저장 설정 없음"
            : `저장된 점수 기록 ${model.points.length}개 · 시각 KST`;
        selectedRunChartStatus.hidden = runtimeConfig !== null;
        selectedRunChart.replaceChildren(createDashboardReplayChart(
            model,
            fusionResult,
            chartDecisionTime,
            presentation.summary,
        ));
    } catch {
        selectedRunChartStatus.hidden = false;
        selectedRunChartStatus.textContent = "저장된 Fusion Trace를 표시할 수 없습니다.";
        selectedRunChart.replaceChildren(createDashboardReplayRecords(fusionResult, chartDecisionTime, presentation.summary));
    }
}

async function fetchJson(endpoint, failureMessage) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ANALYSIS_REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(endpoint, {
            headers: { Accept: "application/json" },
            cache: "no-store",
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(failureMessage);
        return await response.json();
    } finally {
        clearTimeout(timeout);
    }
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
        "분석 상세 API request failed",
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
    return loadSelectedEventSummary(selectedRunId, version);
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
        const expected = storedCaseScope();
        const matches = state => state.queryState !== "success" || state.payload?.run?.run_id === runId
            && (!expected?.entityId || state.payload?.run?.target_host === expected.entityId);
        if (!matches(detailState)) detailState = resolveRunDetailQueryState(null, { kind: "error" });
        if (!matches(fusionState)) fusionState = resolveFusionEngineQueryState(null, { kind: "error" });
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
    const previous = storedCaseScope();
    const next = getStoredCaseScope(runId, runListState.items, null, runtimeEntityId);
    if (previous?.kind !== next?.kind || previous?.runId !== next?.runId || previous?.entityId !== next?.entityId) {
        activateSelectedRunPanel("summary");
    }
    const timelineVersion = ++selectedTimelineRequestVersion;
    selectedTimelineAbortController?.abort();
    selectedTimelineAbortController = null;
    renderEventTypeSummary(resolveEventTimelineQueryState(null, { kind: "loading" }));
    selectedRawVerification = null; operatorContributingIds = null; operatorVerificationScope = null;
    selectedWorkflowProgress = null;
    workflowRecordExpanded = new Set();
    selectedRunId = runId;
    selectedRuntimeEntityId = runtimeEntityId;
    // 분석-scoped: a different Entity of the same 분석 does not re-read 증거.
    void evidenceController.select(runId);
    void provenanceController.select(runId);
    void workflowController.select(runId, { readOnly: true });
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
        "선택한 분석의 저장 분석 결과를 불러오는 중입니다.",
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
        "조회 범위를 벗어난 실행 보고의 저장 분석 결과를 다시 확인하는 중입니다.",
    );
}

function refreshSelectedRunAnalysis() {
    if (!canRefreshSelectedAnalysis(selectedRunId, selectedAnalysisPendingVersion !== null)) {
        return;
    }
    const analysis = loadSelectedRunAnalysis(
        selectedRunId,
        "선택한 분석의 저장 분석 결과를 다시 조회하는 중입니다.",
    );
    return Promise.all([analysis, refreshSelectedEventSummary(), evidenceController.refresh(), provenanceController.refresh()]);
}

function selectDefaultRunIfReady() {
    if (selectedRunId !== null) {
        return;
    }
    const savedWorkflow = workflowController.savedSelection();
    if (savedWorkflow && runListState.items.some(item => item.run_id === savedWorkflow.runId)) {
        void selectRun(savedWorkflow.runId);
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
    const adjacent = resolveAdjacentRuns(runListState.items, runSearchQuery, runType, selectedRunId);
    const target = direction > 0 ? adjacent.previous : adjacent.next;
    if (target !== null) {
        void selectRun(target);
    }
}

function loadOverview() {
    if (overviewPending !== null) return overviewPending;
    overviewPending = updateOverview().finally(() => { overviewPending = null; });
    return overviewPending;
}

async function updateOverview() {
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

function loadRuns() {
    if (runsPending !== null) return runsPending;
    runsPending = updateRuns().finally(() => { runsPending = null; });
    return runsPending;
}

async function updateRuns() {
    renderRunListState(runListState);
    try {
        const payload = await fetchJson(RUNS_ENDPOINT, "분석 List API request failed");
        runListState = resolveRunListQueryState(
            runListState,
            { kind: "success", payload: { ...payload, runs: payload.runs.filter(run => run.kind == null || run.kind === "formal_run") } },
        );
        selectDefaultRunIfReady();
    } catch {
        runListState = resolveRunListQueryState(runListState, { kind: "error" });
    }
    renderRunListState(runListState);
    // One bounded request per data kind, independently of how many rows match the filter.
    void listSummaryController.refresh(runListState.queryState === "success" ? runListState.items.map(run => run.run_id) : []);
    await runtimeContextController.refresh(runListState.items.map(run => ({ run_id: run.run_id, entity_id: run.target_host })));
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
            throw new Error("실행 보고 Summary API request failed");
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
    const contextRead = runtimeContextController.refresh(runListState.items.map(run => ({ run_id: run.run_id, entity_id: run.target_host })));
    let refreshCompletedSelection = false;
    let refreshStoredRunIndex = false;
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
        refreshStoredRunIndex = runtimeInitialQuerySettled && shouldRefreshStoredRunIndex(
            runtimeState.items, nextRuntimeState.items,
        );
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
    if (refreshStoredRunIndex) {
        // A read begun before commit may return an old snapshot. Reconcile after it
        // settles, coalescing simultaneous terminal reports through existing guards.
        void Promise.all([overviewPending, runsPending]).then(() => {
            void loadOverview();
            void loadRuns();
        });
    }
    if (updateFailedSelection) {
        renderSelectedRunFailureState();
    } else if (refreshCompletedSelection && selectedRunId !== null) {
        void loadSelectedRunAnalysis(
            selectedRunId,
            "완료 보고를 확인해 저장된 분석 결과를 다시 불러오는 중입니다.",
        );
        refreshSelectedEventSummary();
        void evidenceController.refresh({ invalidatePending: true });
        void provenanceController.refresh();
    } else {
        if (getSelectedRuntimeRecheckMessage(selectedRuntimeTracking) !== previousRecheckMessage) {
            rerenderSelectedAnalysis();
        }
        recheckSelectedRuntimeAnalysis();
    }
    await contextRead;
}

async function pollRuntimeSummary() {
    if (!runtimePollingActive) return Promise.resolve();
    if (runtimePending !== null) return runtimePending;
    runtimeRequestInFlight = true;
    runtimePending = updateRuntimeSummary().finally(() => {
        runtimeRequestInFlight = false;
        runtimePending = null;
        scheduleRuntimePoll();
    });
    return runtimePending;
}

if (dashboardView !== null) {
    const ingestController = createSysmonIngestController(document, {
        async onOpenRun(runId) {
            await selectRun(runId);
            selectedRunIdElement.closest("section")?.scrollIntoView({ behavior: "smooth", block: "start" });
        },
        async onCompleted() {
            // Refresh the existing index without changing the user's selected Run,
            // auto-follow preference, active tab, or runtime polling lifecycle.
            await Promise.all([loadOverview(), loadRuns()]);
        },
    });
    void ingestController.start();
    const telemetryController = createDashboardTelemetryController(document);
    // A chart drawn inside a closed disclosure has no width; redraw it at the visible width once opened.
    for (const disclosure of [
        document.getElementById("telemetry-throughput-disclosure"),
        document.getElementById("telemetry-latency-disclosure"),
    ]) {
        disclosure?.addEventListener("toggle", () => {
            if (disclosure.open) void telemetryController.poll();
        });
    }
    let manualRefreshPending = false;
    let manualRefreshVersion = 0;
    dashboardRefreshButton.addEventListener("click", async () => {
        if (manualRefreshPending) return;
        manualRefreshPending = true;
        const version = ++manualRefreshVersion;
        dashboardRefreshButton.setAttribute("aria-disabled", "true");
        dashboardRefreshButton.setAttribute("aria-busy", "true");
        dashboardRefreshStatus.textContent = "운영 현황 데이터를 다시 조회하고 있습니다.";
        try {
            const [, , , telemetryOk] = await Promise.all([
                loadOverview(), loadRuns(), pollRuntimeSummary(), telemetryController.poll(),
            ]);
            if (version !== manualRefreshVersion) return;
            // Reuse selection/version guards; never select another Run or open a closed tab.
            await Promise.all([refreshSelectedRunAnalysis(), stageTimingController.refresh()]);
            if (version !== manualRefreshVersion) return;
            const failed = [overviewState, runListState, runtimeState, runtimeContext].some((state) => state.queryState === "error" || state.queryState === "not_ready")
                || telemetryOk === false;
            dashboardRefreshStatus.textContent = failed
                ? "일부 조회 실패 · 각 영역의 조회 상태를 확인하고 다시 시도하세요."
                : "화면 재조회 완료 · 상세 조회 상태는 각 영역에서 확인하세요.";
        } catch {
            if (version === manualRefreshVersion) {
                dashboardRefreshStatus.textContent = "화면 재조회 실패 · 각 영역의 조회 상태를 확인하고 다시 시도하세요.";
            }
        } finally {
            if (version === manualRefreshVersion) {
                manualRefreshPending = false;
                dashboardRefreshButton.setAttribute("aria-disabled", "false");
                dashboardRefreshButton.setAttribute("aria-busy", "false");
            }
        }
    });
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
    activateSelectedRunPanel("summary");
    renderSelectedItemPanel({ state: "empty", status: "목록에서 확인할 항목을 선택하세요." });
    renderSelectedScope();
    renderSelectedWorkflowSummary();
    renderOverviewState(overviewState);
    renderRunListState(runListState);
    renderRuntimeState(runtimeState);
    selectedRunRefreshButton.addEventListener("click", refreshSelectedRunAnalysis);
    selectedItemOpen.addEventListener("click", () => openSelectedDetail("summary"));
    selectedItemWorkflowOpen.addEventListener("click", () => openSelectedDetail("workflow"));
    selectedRunWorkflowOpen.addEventListener("click", () => openSelectedDetail("workflow"));
    selectedRunEvidenceOpen.addEventListener("click", () => openSelectedDetail("evidence"));
    // Cross-tab links only move between stored views; none of them reads or writes anything.
    replayRecordsOpen.addEventListener("click", () => openSelectedDetail("decision"));
    recordsWorkflowOpen.addEventListener("click", () => openSelectedDetail("workflow"));
    workflowRecordsOpen.addEventListener("click", () => openSelectedDetail("decision"));
    pipelineAutoFollow?.addEventListener("change", () => { renderPipelineStages(); });
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
        ingestController.stop();
        manualRefreshVersion += 1;
        manualRefreshPending = false;
        dashboardRefreshButton.setAttribute("aria-disabled", "false");
        dashboardRefreshButton.setAttribute("aria-busy", "false");
        stopRuntimePolling();
        telemetryController.stop();
        stageTimingController.stop();
        runtimeContextController.stop();
        pipelineStageReader.stop();
        evidenceController.stop();
        provenanceController.stop();
        listSummaryController.stop();
    });
    window.addEventListener("pageshow", (event) => {
        if (event.persisted) {
            void ingestController.start();
            startRuntimePolling();
            void telemetryController.start();
            void stageTimingController.start();
            runtimeContextController.start();
            void evidenceController.start();
            void provenanceController.start();
            listSummaryController.start();
            void listSummaryController.refresh(runListState.items.map(run => run.run_id));
        }
    });
}
