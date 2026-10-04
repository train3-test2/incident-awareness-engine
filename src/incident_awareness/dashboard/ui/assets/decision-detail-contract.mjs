// Pure Historical Decision presentation, path, and query-state helpers.

import {
    buildRunDetailViewPath,
    displayValue,
    formatRunTimestamp,
    getDecisionPathLabel,
    getStatusLabel,
    getWinningPathLabel,
} from "./run-detail-contract.mjs";

export {
    buildRunDetailViewPath,
    displayValue,
    formatRunTimestamp,
    getDecisionPathLabel,
    getStatusLabel,
    getWinningPathLabel,
};

const QUERY_MESSAGES = new Map([
    ["loading", "Historical Decision을 불러오는 중입니다."],
    ["success", "Historical Decision을 불러왔습니다."],
    ["not_found", "Decision을 찾을 수 없습니다."],
    ["error", "Historical Decision을 불러오지 못했습니다."],
]);

function requireDecisionId(decisionId) {
    if (typeof decisionId !== "string") {
        throw new TypeError("decisionId must be a string");
    }
    if (!decisionId.trim()) {
        throw new RangeError("decisionId must not be blank");
    }
    return decisionId;
}

function getDecisionDetailQueryMessage(queryState) {
    const message = QUERY_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Historical Decision query state: ${queryState}`);
    }
    return message;
}

export function buildDecisionDetailViewPath(decisionId) {
    return `/dashboard/decisions/${encodeURIComponent(requireDecisionId(decisionId))}`;
}

export function buildDecisionDetailApiPath(decisionId) {
    return `/decisions/${encodeURIComponent(requireDecisionId(decisionId))}`;
}

export function extractDecisionIdFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/decisions\/([^/]+)$/.exec(pathname);
    if (match === null) {
        return null;
    }
    try {
        const decisionId = decodeURIComponent(match[1]);
        return decisionId.trim() ? decisionId : null;
    } catch {
        return null;
    }
}

export function resolveDecisionDetailQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Historical Decision state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Historical Decision query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: getDecisionDetailQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Historical Decision payload must be an object");
        }
        if (
            payload.decision === null
            || typeof payload.decision !== "object"
            || Array.isArray(payload.decision)
        ) {
            throw new TypeError("Historical Decision decision must be an object");
        }
        if (
            payload.runtime_snapshot !== null
            && (
                typeof payload.runtime_snapshot !== "object"
                || Array.isArray(payload.runtime_snapshot)
            )
        ) {
            throw new TypeError("Historical Decision runtime_snapshot must be an object or null");
        }
        return {
            queryState: "success",
            payload,
            message: getDecisionDetailQueryMessage("success"),
        };
    }
    if (result.kind === "not_found") {
        return {
            queryState: "not_found",
            payload: null,
            message: getDecisionDetailQueryMessage("not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getDecisionDetailQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Historical Decision query result kind: ${result.kind}`);
}
