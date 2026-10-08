// Pure Dashboard presentation and query-state helpers.

import {
    getRuntimeQueryMessage,
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
const PIPELINE_RUNTIME_STAGES = new Set([
    "artifact_validation",
    "normalization",
    "fusion",
    "fast_handoff",
    "hybrid",
    "persistence",
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
