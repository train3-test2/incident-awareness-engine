// Pure Dashboard presentation and query-state helpers.

import {
    getRuntimeQueryMessage,
    getStageLabel,
    resolveRuntimeQueryState,
} from "./operations-contract.mjs";

export const NOT_APPLICABLE = "-";

const RUN_TYPE_LABELS = new Map([
    ["attack", "공격"],
    ["normal", "정상"],
]);
const OVERVIEW_MESSAGES = new Map([
    ["loading", "Recent Runs를 불러오는 중입니다."],
    ["success", "Recent Runs를 불러왔습니다."],
    ["empty", "최근 Run이 없습니다."],
    ["error", "Recent Runs를 불러오지 못했습니다."],
]);
const OVERVIEW_TOTAL_MESSAGES = new Map([
    ["loading", "Total Runs를 불러오는 중입니다."],
    ["success", "Total Runs를 불러왔습니다."],
    ["empty", "Total Runs를 불러왔습니다."],
    ["error", "Total Runs를 불러오지 못했습니다."],
]);
const RUN_LIST_MESSAGES = new Map([
    ["loading", "Run 목록을 불러오는 중입니다."],
    ["empty", "표시할 Run이 없습니다."],
    ["error", "Run 목록을 불러오지 못했습니다."],
]);
const PIPELINE_RUNTIME_STATUSES = new Set(["running", "completed", "failed"]);
export const PIPELINE_STAGE_ORDER = Object.freeze([
    "artifact_validation",
    "normalization",
    "fusion",
    "fast_handoff",
    "hybrid",
    "persistence",
]);
const PIPELINE_RUNTIME_STAGES = new Set(PIPELINE_STAGE_ORDER);

const PIPELINE_STAGE_STATE_LABELS = new Map([
    ["completed", "완료"],
    ["current", "현재 단계 (마지막 보고)"],
    ["stale", "오래된 현재 단계 보고"],
    ["failed", "실패"],
    ["unknown", "완료 여부 확인 불가"],
]);

export function displayValue(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }
    return String(value);
}

export function getRunTypeLabel(runType) {
    if (runType === null || runType === undefined) {
        return NOT_APPLICABLE;
    }
    return RUN_TYPE_LABELS.get(runType) ?? String(runType);
}

export function formatRunTimestamp(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }

    const timestamp = new Date(value);
    if (Number.isNaN(timestamp.getTime())) {
        return String(value);
    }
    return timestamp.toLocaleString("ko-KR", { timeZoneName: "short" });
}

export function getOverviewQueryMessage(queryState) {
    const message = OVERVIEW_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Overview query state: ${queryState}`);
    }
    return message;
}

function getOverviewTotalQueryMessage(queryState) {
    const message = OVERVIEW_TOTAL_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Overview total query state: ${queryState}`);
    }
    return message;
}

function getRunListQueryMessage(queryState, itemCount = 0) {
    if (queryState === "success") {
        return `Run ${itemCount}건을 불러왔습니다.`;
    }
    const message = RUN_LIST_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Run List query state: ${queryState}`);
    }
    return message;
}

export function resolveOverviewQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Overview state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Overview query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            totalRuns: null,
            recentRuns: [],
            totalMessage: getOverviewTotalQueryMessage("loading"),
            message: getOverviewQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Overview payload must be an object");
        }
        if (!Number.isInteger(payload.total_runs) || payload.total_runs < 0) {
            throw new TypeError("Overview total_runs must be a non-negative integer");
        }
        if (!Array.isArray(payload.recent_runs)) {
            throw new TypeError("Overview recent_runs must be an array");
        }
        if (
            payload.recent_runs.some(
                (run) => run === null || typeof run !== "object" || Array.isArray(run),
            )
        ) {
            throw new TypeError("Overview recent_runs items must be objects");
        }

        const queryState = payload.recent_runs.length === 0 ? "empty" : "success";
        return {
            queryState,
            totalRuns: payload.total_runs,
            recentRuns: payload.recent_runs,
            totalMessage: getOverviewTotalQueryMessage(queryState),
            message: getOverviewQueryMessage(queryState),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            totalRuns: null,
            recentRuns: [],
            totalMessage: getOverviewTotalQueryMessage("error"),
            message: getOverviewQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Overview query result kind: ${result.kind}`);
}

export function resolveRunListQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Run List state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Run List query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            items: [],
            message: getRunListQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Run List payload must be an object");
        }
        if (!Array.isArray(payload.runs)) {
            throw new TypeError("Run List runs must be an array");
        }
        if (
            payload.runs.some(
                (run) => run === null || typeof run !== "object" || Array.isArray(run),
            )
        ) {
            throw new TypeError("Run List items must be objects");
        }

        const queryState = payload.runs.length === 0 ? "empty" : "success";
        return {
            queryState,
            items: payload.runs,
            message: getRunListQueryMessage(queryState, payload.runs.length),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            items: [],
            message: getRunListQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Run List query result kind: ${result.kind}`);
}

export function resolveRuntimeSummaryQueryState(previousState, result) {
    if (
        previousState !== null
        && (
            typeof previousState !== "object"
            || Array.isArray(previousState)
            || !Array.isArray(previousState.items)
        )
    ) {
        throw new TypeError("Previous Runtime Summary state must contain an items array");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Runtime Summary query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            items: [],
            telemetryAvailable: false,
            message: getRuntimeQueryMessage("loading"),
        };
    }

    const previousItems = previousState === null ? [] : previousState.items;
    if (result.kind === "success") {
        const payload = result.payload;
        if (
            payload === null
            || typeof payload !== "object"
            || Array.isArray(payload)
            || !Array.isArray(payload.items)
        ) {
            throw new TypeError("Runtime Summary payload must contain an items array");
        }
        if (
            payload.items.some(
                (runtime) => (
                    runtime === null
                    || typeof runtime !== "object"
                    || Array.isArray(runtime)
                    || typeof runtime.run_id !== "string"
                    || !PIPELINE_RUNTIME_STATUSES.has(runtime.status)
                    || !Object.hasOwn(runtime, "current_stage")
                    || (
                        runtime.current_stage !== null
                        && !PIPELINE_RUNTIME_STAGES.has(runtime.current_stage)
                    )
                    || typeof runtime.updated_at !== "string"
                    || typeof runtime.is_stale !== "boolean"
                ),
            )
        ) {
            throw new TypeError(
                "Runtime Summary items must include valid run_id, status, current_stage, "
                + "updated_at, and is_stale fields",
            );
        }

        const state = resolveRuntimeQueryState(
            previousItems,
            { kind: "success", items: payload.items },
        );
        return {
            queryState: state.items.length === 0 ? "empty" : "success",
            ...state,
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            ...resolveRuntimeQueryState(previousItems, { kind: "error" }),
        };
    }
    throw new RangeError(`Unknown Runtime Summary query result kind: ${result.kind}`);
}

export function buildPipelineStagePresentation(runtime, telemetryAvailable) {
    if (runtime !== null && (typeof runtime !== "object" || Array.isArray(runtime))) {
        throw new TypeError("Selected Runtime must be an object or null");
    }
    if (typeof telemetryAvailable !== "boolean") {
        throw new TypeError("Runtime telemetry availability must be a boolean");
    }

    return PIPELINE_STAGE_ORDER.map((stage) => {
        let state = "unknown";
        if (runtime?.status === "completed") {
            state = "completed";
        } else if (runtime?.status === "failed" && runtime.failed_stage === stage) {
            state = "failed";
        } else if (runtime?.status === "running" && runtime.current_stage === stage) {
            if (!telemetryAvailable) {
                state = "unknown";
            } else {
                state = runtime.is_stale ? "stale" : "current";
            }
        }
        return {
            stage,
            stageLabel: getStageLabel(stage),
            state,
            stateLabel: PIPELINE_STAGE_STATE_LABELS.get(state),
        };
    });
}

export function getStoppingTraceAvailability(stoppingTrace) {
    if (stoppingTrace === null) {
        return "missing";
    }
    if (
        typeof stoppingTrace !== "object"
        || Array.isArray(stoppingTrace)
        || !Array.isArray(stoppingTrace.points)
    ) {
        throw new TypeError("Stopping Trace must be null or contain a points array");
    }
    return stoppingTrace.points.length === 0 ? "empty" : "available";
}

export function shouldApplySelectedRunResponse(responseVersion, activeVersion) {
    if (!Number.isInteger(responseVersion) || !Number.isInteger(activeVersion)) {
        throw new TypeError("Selection request versions must be integers");
    }
    return responseVersion === activeVersion;
}

export function resolveInitialRunSelection(
    currentRunId,
    runtimeQuerySettled,
    telemetryAvailable,
    runtimeItems,
    runItems,
) {
    if (currentRunId !== null && typeof currentRunId !== "string") {
        throw new TypeError("Current selected Run ID must be a string or null");
    }
    if (typeof runtimeQuerySettled !== "boolean") {
        throw new TypeError("Runtime query settled state must be a boolean");
    }
    if (typeof telemetryAvailable !== "boolean") {
        throw new TypeError("Runtime telemetry availability must be a boolean");
    }
    if (!Array.isArray(runtimeItems) || !Array.isArray(runItems)) {
        throw new TypeError("Runtime and Run items must be arrays");
    }
    if (currentRunId !== null || !runtimeQuerySettled) {
        return currentRunId;
    }

    const hasRunId = (item) => (
        typeof item?.run_id === "string" && Boolean(item.run_id.trim())
    );
    const currentRunning = runtimeItems.find(
        (runtime) => (
            runtime.status === "running"
            && runtime.is_stale === false
            && hasRunId(runtime)
        ),
    );
    const completed = runtimeItems.find(
        (runtime) => runtime.status === "completed" && hasRunId(runtime),
    );
    const staleRunning = runtimeItems.find(
        (runtime) => (
            runtime.status === "running"
            && runtime.is_stale === true
            && hasRunId(runtime)
        ),
    );
    const runtimeCandidate = telemetryAvailable
        ? currentRunning ?? completed ?? staleRunning
        : null;
    const candidate = runtimeCandidate ?? runItems.find(hasRunId) ?? null;
    return candidate?.run_id ?? null;
}

export function resolveRunSelectionFocus(
    focusedRunId,
    focusedTable,
    runtimeItems,
    runItems,
) {
    if (focusedRunId === null && focusedTable === null) {
        return null;
    }
    if (typeof focusedRunId !== "string" || !focusedRunId) {
        throw new TypeError("Focused Run ID must be a non-empty string or null");
    }
    if (focusedTable !== "runtime" && focusedTable !== "runs") {
        throw new TypeError("Focused Run table must be runtime, runs, or null");
    }
    if (!Array.isArray(runtimeItems) || !Array.isArray(runItems)) {
        throw new TypeError("Runtime and Run items must be arrays");
    }

    const items = focusedTable === "runtime" ? runtimeItems : runItems;
    return items.some((item) => item?.run_id === focusedRunId)
        ? { runId: focusedRunId, table: focusedTable }
        : null;
}

export function getLatestRuntimeReport(runtimeItems) {
    if (!Array.isArray(runtimeItems)) {
        throw new TypeError("Runtime items must be an array");
    }
    return runtimeItems.reduce((latest, candidate) => {
        if (latest === null) {
            return candidate;
        }
        const latestTimestamp = Date.parse(latest.updated_at);
        const candidateTimestamp = Date.parse(candidate.updated_at);
        if (
            Number.isFinite(candidateTimestamp)
            && (!Number.isFinite(latestTimestamp) || candidateTimestamp > latestTimestamp)
        ) {
            return candidate;
        }
        return latest;
    }, null);
}

function getSelectedRunStatusTransition(
    selectedRunId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    if (selectedRunId !== null && typeof selectedRunId !== "string") {
        throw new TypeError("Selected Run ID must be a string or null");
    }
    if (!Array.isArray(previousRuntimeItems) || !Array.isArray(nextRuntimeItems)) {
        throw new TypeError("Previous and next Runtime items must be arrays");
    }
    if (selectedRunId === null) {
        return null;
    }
    const previous = previousRuntimeItems.find(
        (runtime) => runtime.run_id === selectedRunId,
    );
    const next = nextRuntimeItems.find((runtime) => runtime.run_id === selectedRunId);
    return previous?.status === "running" ? next?.status ?? null : null;
}

export function shouldRefreshSelectedRunAnalysis(
    selectedRunId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    return getSelectedRunStatusTransition(
        selectedRunId,
        previousRuntimeItems,
        nextRuntimeItems,
    ) === "completed";
}

export function shouldUpdateSelectedRunFailureState(
    selectedRunId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    return getSelectedRunStatusTransition(
        selectedRunId,
        previousRuntimeItems,
        nextRuntimeItems,
    ) === "failed";
}

export function getDecisionVersionConsistency(runDetailPayload, fusionEnginePayload) {
    const detailDecisionId = runDetailPayload?.current_decision?.decision?.decision_id;
    const fusionDecisionId = fusionEnginePayload?.current_decision?.decision_id;
    if (typeof detailDecisionId !== "string" || typeof fusionDecisionId !== "string") {
        return "unavailable";
    }
    return detailDecisionId === fusionDecisionId ? "match" : "mismatch";
}

export function getSelectedAnalysisSource(runDetailPayload, fusionEnginePayload) {
    const consistency = getDecisionVersionConsistency(
        runDetailPayload,
        fusionEnginePayload,
    );
    if (consistency === "match") {
        return "matched";
    }
    if (typeof runDetailPayload?.current_decision?.decision?.decision_id === "string") {
        return "run_detail";
    }
    if (typeof fusionEnginePayload?.current_decision?.decision_id === "string") {
        return "fusion_engine";
    }
    if (
        fusionEnginePayload?.fusion_result != null
        || fusionEnginePayload?.stopping_trace != null
    ) {
        return "fusion_engine_without_decision";
    }
    return "none";
}

export function getSelectedAnalysisState(
    detailQueryState,
    fusionQueryState,
    runtimeStatus,
    hasStoredAnalysis,
    decisionConsistency,
) {
    if (typeof hasStoredAnalysis !== "boolean") {
        throw new TypeError("Stored analysis availability must be a boolean");
    }
    if (decisionConsistency === "mismatch") {
        return "version_mismatch";
    }
    if (detailQueryState === "error" || fusionQueryState === "error") {
        return "error";
    }
    if (
        detailQueryState === "not_found"
        && fusionQueryState === "not_found"
        && runtimeStatus === "running"
    ) {
        return "waiting";
    }
    if (!hasStoredAnalysis) {
        return runtimeStatus === "running" ? "waiting" : "missing";
    }
    return "available";
}
