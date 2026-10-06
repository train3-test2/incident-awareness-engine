// Pure Fusion Engine presentation, path, and query-state helpers.

const QUERY_MESSAGES = new Map([
    ["loading", "Fusion Engine 정보를 불러오는 중입니다."],
    ["success", "Fusion Engine 정보를 불러왔습니다."],
    ["not_found", "Run을 찾을 수 없습니다."],
    ["error", "Fusion Engine 정보를 불러오지 못했습니다."],
]);

function requireRunId(runId) {
    if (typeof runId !== "string") {
        throw new TypeError("runId must be a string");
    }
    if (!runId.trim()) {
        throw new RangeError("runId must not be blank");
    }
    return runId;
}

function requireObjectOrNull(value, name) {
    if (value !== null && (typeof value !== "object" || Array.isArray(value))) {
        throw new TypeError(`${name} must be an object or null`);
    }
}

function getQueryMessage(queryState) {
    const message = QUERY_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Fusion Engine query state: ${queryState}`);
    }
    return message;
}

export function buildFusionEngineApiPath(runId) {
    return `/runs/${encodeURIComponent(requireRunId(runId))}/fusion-engine`;
}

export function buildFusionEngineViewPath(runId) {
    return `/dashboard/runs/${encodeURIComponent(requireRunId(runId))}/fusion-engine`;
}

export function extractFusionEngineRunIdFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/runs\/([^/]+)\/fusion-engine$/.exec(pathname);
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

export function resolveFusionEngineQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Fusion Engine state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Fusion Engine query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: getQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Fusion Engine payload must be an object");
        }
        if (payload.run === null || typeof payload.run !== "object" || Array.isArray(payload.run)) {
            throw new TypeError("Fusion Engine run must be an object");
        }
        requireObjectOrNull(payload.current_decision, "Fusion Engine current_decision");
        requireObjectOrNull(payload.fusion_result, "Fusion Engine fusion_result");
        requireObjectOrNull(payload.stopping_trace, "Fusion Engine stopping_trace");
        requireObjectOrNull(
            payload.runtime_config_snapshot,
            "Fusion Engine runtime_config_snapshot",
        );
        return {
            queryState: "success",
            payload,
            message: getQueryMessage("success"),
        };
    }
    if (result.kind === "not_found") {
        return {
            queryState: "not_found",
            payload: null,
            message: getQueryMessage("not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Fusion Engine query result kind: ${result.kind}`);
}
