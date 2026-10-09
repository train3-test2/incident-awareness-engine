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
// Successful Runtime polls after the selected Running report left the query range.
export const SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS = Object.freeze([1, 3, 7, 15, 31]);

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
                    || typeof runtime.entity_id !== "string"
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
                "Runtime Summary items must include valid run_id, entity_id, status, "
                + "current_stage, updated_at, and is_stale fields",
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
    currentRuntimeEntityId,
    runtimeQuerySettled,
    telemetryAvailable,
    runtimeItems,
    runItems,
) {
    if (currentRunId !== null && typeof currentRunId !== "string") {
        throw new TypeError("Current selected Run ID must be a string or null");
    }
    if (
        currentRuntimeEntityId !== null
        && typeof currentRuntimeEntityId !== "string"
    ) {
        throw new TypeError("Current selected Runtime Entity ID must be a string or null");
    }
    if (currentRunId === null && currentRuntimeEntityId !== null) {
        throw new TypeError("Runtime Entity selection requires a selected Run ID");
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
        return currentRunId === null
            ? null
            : { runId: currentRunId, entityId: currentRuntimeEntityId };
    }

    const hasRunId = (item) => (
        typeof item?.run_id === "string" && Boolean(item.run_id.trim())
    );
    const hasRuntimeIdentity = (item) => (
        hasRunId(item)
        && typeof item?.entity_id === "string"
        && Boolean(item.entity_id)
    );
    const currentRunning = runtimeItems.find(
        (runtime) => (
            runtime.status === "running"
            && runtime.is_stale === false
            && hasRuntimeIdentity(runtime)
        ),
    );
    const completed = runtimeItems.find(
        (runtime) => runtime.status === "completed" && hasRuntimeIdentity(runtime),
    );
    const staleRunning = runtimeItems.find(
        (runtime) => (
            runtime.status === "running"
            && runtime.is_stale === true
            && hasRuntimeIdentity(runtime)
        ),
    );
    const runtimeCandidate = telemetryAvailable
        ? currentRunning ?? completed ?? staleRunning ?? null
        : null;
    if (runtimeCandidate !== null) {
        return {
            runId: runtimeCandidate.run_id,
            entityId: runtimeCandidate.entity_id,
        };
    }
    const runCandidate = runItems.find(hasRunId) ?? null;
    return runCandidate === null
        ? null
        : { runId: runCandidate.run_id, entityId: null };
}

export function resolveRunSelectionFocus(
    focusedRunId,
    focusedRuntimeEntityId,
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
    if (
        focusedRuntimeEntityId !== null
        && typeof focusedRuntimeEntityId !== "string"
    ) {
        throw new TypeError("Focused Runtime Entity ID must be a string or null");
    }
    if (focusedTable !== "runtime" && focusedTable !== "runs") {
        throw new TypeError("Focused Run table must be runtime, runs, or null");
    }
    if (!Array.isArray(runtimeItems) || !Array.isArray(runItems)) {
        throw new TypeError("Runtime and Run items must be arrays");
    }

    if (focusedTable === "runtime") {
        return runtimeItems.some(
            (item) => (
                item?.run_id === focusedRunId
                && item?.entity_id === focusedRuntimeEntityId
            ),
        )
            ? {
                runId: focusedRunId,
                entityId: focusedRuntimeEntityId,
                table: focusedTable,
            }
            : null;
    }
    return runItems.some((item) => item?.run_id === focusedRunId)
        ? { runId: focusedRunId, entityId: null, table: focusedTable }
        : null;
}

export function findSelectedRuntime(runtimeItems, selectedRunId, selectedEntityId) {
    if (!Array.isArray(runtimeItems)) {
        throw new TypeError("Runtime items must be an array");
    }
    if (selectedRunId === null || selectedEntityId === null) {
        return null;
    }
    if (typeof selectedRunId !== "string" || typeof selectedEntityId !== "string") {
        throw new TypeError("Selected Runtime identity must contain string IDs");
    }
    return runtimeItems.find(
        (runtime) => (
            runtime.run_id === selectedRunId
            && runtime.entity_id === selectedEntityId
        ),
    ) ?? null;
}

export function isRunSelectionTarget(selectedRunId, selectedEntityId, runId, entityId) {
    if (selectedRunId !== null && typeof selectedRunId !== "string") {
        throw new TypeError("Selected Run ID must be a string or null");
    }
    if (selectedEntityId !== null && typeof selectedEntityId !== "string") {
        throw new TypeError("Selected Runtime Entity ID must be a string or null");
    }
    if (entityId !== null && typeof entityId !== "string") {
        throw new TypeError("Row Runtime Entity ID must be a string or null");
    }
    return selectedRunId !== null && runId === selectedRunId && entityId === selectedEntityId;
}

function requireSelectedRuntimeTracking(tracking) {
    if (
        tracking === null
        || typeof tracking !== "object"
        || Array.isArray(tracking)
        || (
            tracking.report !== null
            && (typeof tracking.report !== "object" || Array.isArray(tracking.report))
        )
        || typeof tracking.outsideQuery !== "boolean"
        || typeof tracking.queryFailed !== "boolean"
        || !Number.isInteger(tracking.missingPolls)
        || tracking.missingPolls < 0
        || !Number.isInteger(tracking.recheckAttempts)
        || tracking.recheckAttempts < 0
    ) {
        throw new TypeError("Selected Runtime tracking state is invalid");
    }
}

export function createSelectedRuntimeTracking(report) {
    if (report !== null && (typeof report !== "object" || Array.isArray(report))) {
        throw new TypeError("Selected Runtime report must be an object or null");
    }
    return {
        report,
        outsideQuery: false,
        queryFailed: false,
        missingPolls: 0,
        recheckAttempts: 0,
    };
}

export function resolveSelectedRuntimeTracking(
    previousTracking,
    selectedRunId,
    selectedEntityId,
    runtimeResult,
) {
    requireSelectedRuntimeTracking(previousTracking);
    if (
        runtimeResult === null
        || typeof runtimeResult !== "object"
        || Array.isArray(runtimeResult)
    ) {
        throw new TypeError("Runtime query result must be an object");
    }
    if (runtimeResult.kind === "error") {
        return { ...previousTracking, queryFailed: true };
    }
    if (runtimeResult.kind !== "success" || !Array.isArray(runtimeResult.items)) {
        throw new TypeError("Runtime query result must be an error or contain success items");
    }

    const next = findSelectedRuntime(runtimeResult.items, selectedRunId, selectedEntityId);
    if (next !== null) {
        return createSelectedRuntimeTracking(next);
    }
    if (previousTracking.report?.status === "running") {
        return {
            ...previousTracking,
            outsideQuery: true,
            queryFailed: false,
            missingPolls: previousTracking.missingPolls + 1,
        };
    }
    return { ...previousTracking, queryFailed: false };
}

export function recordSelectedRuntimeRecheck(tracking) {
    requireSelectedRuntimeTracking(tracking);
    return { ...tracking, recheckAttempts: tracking.recheckAttempts + 1 };
}

export function shouldRecheckSelectedRuntimeAnalysis(
    tracking,
    analysisRequestPending,
    analysisAvailable,
) {
    requireSelectedRuntimeTracking(tracking);
    if (
        typeof analysisRequestPending !== "boolean"
        || typeof analysisAvailable !== "boolean"
    ) {
        throw new TypeError("Selected analysis request state must be boolean");
    }

    return (
        tracking.outsideQuery
        && !tracking.queryFailed
        && !analysisRequestPending
        && !analysisAvailable
        && tracking.recheckAttempts < SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS.length
        && tracking.missingPolls
            >= SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS[tracking.recheckAttempts]
    );
}

export function canRefreshSelectedAnalysis(selectedRunId, analysisRequestPending) {
    if (selectedRunId !== null && typeof selectedRunId !== "string") {
        throw new TypeError("Selected Run ID must be a string or null");
    }
    if (typeof analysisRequestPending !== "boolean") {
        throw new TypeError("Selected analysis request state must be boolean");
    }
    return selectedRunId !== null && !analysisRequestPending;
}

export function getSelectedRuntimeOutsideQueryLabel(tracking) {
    requireSelectedRuntimeTracking(tracking);
    if (!tracking.outsideQuery) {
        return null;
    }
    return tracking.queryFailed
        ? "Runtime API 조회 실패 · 조회 범위 밖 항목의 현재 상태 확인 불가"
        : "최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)";
}

export function getSelectedRuntimeRecheckMessage(tracking) {
    requireSelectedRuntimeTracking(tracking);
    if (!tracking.outsideQuery) {
        return null;
    }
    if (tracking.queryFailed) {
        return (
            "Runtime API 조회에 실패해 조회 범위를 벗어난 선택 Runtime의 상태를 확인할 수 없습니다. "
            + "저장 결과 재확인은 Runtime 조회가 복구되면 이어서 진행합니다."
        );
    }
    const limit = SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS.length;
    const outsideMessage = (
        "선택한 Runtime이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다."
    );
    return tracking.recheckAttempts >= limit
        ? `${outsideMessage} 저장 결과 재확인 ${limit}회를 마쳤지만 아직 결과가 없습니다. `
            + "결과 다시 조회 버튼으로 저장 결과를 다시 조회할 수 있습니다."
        : `${outsideMessage} 저장 결과를 제한된 간격으로 다시 확인합니다 `
            + `(${tracking.recheckAttempts}/${limit}회).`;
}

export function getSelectedAnalysisTargetHost(runDetailPayload, fusionEnginePayload) {
    const hosts = [
        runDetailPayload?.run?.target_host,
        fusionEnginePayload?.run?.target_host,
    ].filter((host) => typeof host === "string" && Boolean(host));
    if (hosts.length === 0) {
        return null;
    }
    return hosts.every((host) => host === hosts[0]) ? hosts[0] : null;
}

export function getSelectedAnalysisScope(
    selectedRunId,
    selectedEntityId,
    analysisTargetHost,
) {
    if (selectedRunId !== null && typeof selectedRunId !== "string") {
        throw new TypeError("Selected Run ID must be a string or null");
    }
    if (selectedEntityId !== null && typeof selectedEntityId !== "string") {
        throw new TypeError("Selected Runtime Entity ID must be a string or null");
    }
    if (analysisTargetHost !== null && typeof analysisTargetHost !== "string") {
        throw new TypeError("Analysis target host must be a string or null");
    }
    if (selectedRunId === null) {
        return {
            scope: "none",
            message: "Runtime 또는 Run 목록에서 항목을 선택하면 조회 범위를 표시합니다.",
        };
    }
    if (selectedEntityId === null) {
        return {
            scope: "run",
            message: analysisTargetHost === null
                ? "Run 목록 선택: run_id 범위입니다. 저장 분석은 RunMetadata.target_host 기준입니다."
                : "Run 목록 선택: run_id 범위입니다. 저장 분석 대상은 "
                    + `RunMetadata.target_host ${analysisTargetHost}입니다.`,
        };
    }
    if (analysisTargetHost === null) {
        return {
            scope: "runtime_entity_unconfirmed",
            message: `Runtime 선택: Entity ${selectedEntityId}. 저장 분석은 run_id 기준 `
                + "RunMetadata.target_host 결과이며 대상 Host를 확인하지 못해 "
                + `${selectedEntityId} 결과로 간주하지 않습니다.`,
        };
    }
    if (analysisTargetHost === selectedEntityId) {
        return {
            scope: "runtime_entity_match",
            message: `Runtime 선택: Entity ${selectedEntityId}. 저장 분석 대상 `
                + `RunMetadata.target_host도 ${analysisTargetHost}입니다.`,
        };
    }
    return {
        scope: "runtime_entity_mismatch",
        message: `Runtime 선택: Entity ${selectedEntityId}. 아래 저장 분석은 `
            + `RunMetadata.target_host ${analysisTargetHost} 결과이며 `
            + `${selectedEntityId} 결과가 아닙니다.`,
    };
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
    selectedEntityId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    if (selectedRunId !== null && typeof selectedRunId !== "string") {
        throw new TypeError("Selected Run ID must be a string or null");
    }
    if (selectedEntityId !== null && typeof selectedEntityId !== "string") {
        throw new TypeError("Selected Runtime Entity ID must be a string or null");
    }
    if (!Array.isArray(previousRuntimeItems) || !Array.isArray(nextRuntimeItems)) {
        throw new TypeError("Previous and next Runtime items must be arrays");
    }
    if (selectedRunId === null || selectedEntityId === null) {
        return null;
    }
    const previous = findSelectedRuntime(
        previousRuntimeItems,
        selectedRunId,
        selectedEntityId,
    );
    const next = findSelectedRuntime(nextRuntimeItems, selectedRunId, selectedEntityId);
    return previous?.status === "running" ? next?.status ?? null : null;
}

export function shouldRefreshSelectedRunAnalysis(
    selectedRunId,
    selectedEntityId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    return getSelectedRunStatusTransition(
        selectedRunId,
        selectedEntityId,
        previousRuntimeItems,
        nextRuntimeItems,
    ) === "completed";
}

export function shouldUpdateSelectedRunFailureState(
    selectedRunId,
    selectedEntityId,
    previousRuntimeItems,
    nextRuntimeItems,
) {
    return getSelectedRunStatusTransition(
        selectedRunId,
        selectedEntityId,
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
