// Pure Run Detail presentation, path, and query-state helpers.

import {
    displayValue,
    formatRunTimestamp,
    getRunTypeLabel,
} from "./dashboard-contract.mjs";

export { displayValue, formatRunTimestamp, getRunTypeLabel };

const STATUS_LABELS = new Map([
    ["detected", "탐지"],
    ["miss", "미탐"],
    ["not_evaluated", "평가 안 함"],
]);
const DECISION_PATH_LABELS = new Map([
    ["fast", "Fast"],
    ["fusion", "Fusion"],
    ["fast_and_fusion", "Fast + Fusion"],
    ["none", "없음"],
]);
const WINNING_PATH_LABELS = new Map([
    ["fast", "Fast"],
    ["fusion", "Fusion"],
    ["tie", "동시"],
    ["none", "없음"],
]);
const QUERY_MESSAGES = new Map([
    ["loading", "Run Detail을 불러오는 중입니다."],
    ["success", "Run Detail을 불러왔습니다."],
    ["not_found", "Run을 찾을 수 없습니다."],
    ["error", "Run Detail을 불러오지 못했습니다."],
]);

function requireIdentifier(value, name) {
    if (typeof value !== "string") {
        throw new TypeError(`${name} must be a string`);
    }
    if (!value.trim()) {
        throw new RangeError(`${name} must not be blank`);
    }
    return value;
}

function getRunDetailQueryMessage(queryState) {
    const message = QUERY_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Run Detail query state: ${queryState}`);
    }
    return message;
}

export function buildRunDetailViewPath(runId) {
    return `/dashboard/runs/${encodeURIComponent(requireIdentifier(runId, "runId"))}`;
}

export function buildRunDetailApiPath(runId) {
    return `/runs/${encodeURIComponent(requireIdentifier(runId, "runId"))}`;
}

export function extractRunIdFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/runs\/([^/]+)$/.exec(pathname);
    if (match === null) {
        return null;
    }
    try {
        const runId = decodeURIComponent(match[1]);
        return runId.trim() ? runId : null;
    } catch {
        return null;
    }
}

export function getStatusLabel(status) {
    if (status === null || status === undefined) {
        return displayValue(status);
    }
    return STATUS_LABELS.get(status) ?? String(status);
}

export function getDecisionPathLabel(decisionPath) {
    if (decisionPath === null || decisionPath === undefined) {
        return displayValue(decisionPath);
    }
    return DECISION_PATH_LABELS.get(decisionPath) ?? String(decisionPath);
}

export function getWinningPathLabel(winningPath) {
    if (winningPath === null || winningPath === undefined) {
        return displayValue(winningPath);
    }
    return WINNING_PATH_LABELS.get(winningPath) ?? String(winningPath);
}

export function resolveRunDetailQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Run Detail state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Run Detail query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: getRunDetailQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Run Detail payload must be an object");
        }
        if (payload.run === null || typeof payload.run !== "object" || Array.isArray(payload.run)) {
            throw new TypeError("Run Detail run must be an object");
        }
        if (
            payload.current_decision !== null
            && (
                typeof payload.current_decision !== "object"
                || Array.isArray(payload.current_decision)
            )
        ) {
            throw new TypeError("Run Detail current_decision must be an object or null");
        }
        if (!Array.isArray(payload.decision_history)) {
            throw new TypeError("Run Detail decision_history must be an array");
        }
        return {
            queryState: "success",
            payload,
            message: getRunDetailQueryMessage("success"),
        };
    }
    if (result.kind === "not_found") {
        return {
            queryState: "not_found",
            payload: null,
            message: getRunDetailQueryMessage("not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getRunDetailQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Run Detail query result kind: ${result.kind}`);
}
