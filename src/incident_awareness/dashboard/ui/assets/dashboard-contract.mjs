// Pure Dashboard presentation and query-state helpers.

export const NOT_APPLICABLE = "-";

const RUN_TYPE_LABELS = new Map([
    ["attack", "공격"],
    ["normal", "정상"],
]);
const OVERVIEW_MESSAGES = new Map([
    ["loading", "Overview 정보를 불러오는 중입니다."],
    ["success", "Overview 정보를 불러왔습니다."],
    ["empty", "최근 Run이 없습니다."],
    ["error", "Overview 정보를 불러오지 못했습니다."],
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
            message: getOverviewQueryMessage(queryState),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            totalRuns: null,
            recentRuns: [],
            message: getOverviewQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Overview query result kind: ${result.kind}`);
}
