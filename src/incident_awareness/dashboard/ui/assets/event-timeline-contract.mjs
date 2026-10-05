// Pure Event Timeline path, query-state, and pagination helpers.

const QUERY_MESSAGES = new Map([
    ["loading", "Event Timeline을 불러오는 중입니다."],
    ["success", "Event Timeline을 불러왔습니다."],
    ["empty", "이 Run에 저장된 Event가 없습니다."],
    ["run_not_found", "Run을 찾을 수 없습니다."],
    ["error", "Event Timeline을 불러오지 못했습니다."],
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

function requireLimit(limit) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        throw new RangeError("limit must be an integer from 1 through 200");
    }
    return limit;
}

function requireOffset(offset) {
    if (!Number.isInteger(offset) || offset < 0) {
        throw new RangeError("offset must be a non-negative integer");
    }
    return offset;
}

function getQueryMessage(queryState) {
    const message = QUERY_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Event Timeline query state: ${queryState}`);
    }
    return message;
}

function validateEventItem(item) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new TypeError("Event Timeline items must be objects");
    }
    if (typeof item.event_id !== "string") {
        throw new TypeError("Event Timeline event_id must be a string");
    }
    if (
        !Object.prototype.hasOwnProperty.call(item, "timestamp")
        || item.timestamp === null
        || item.timestamp === undefined
    ) {
        throw new TypeError("Event Timeline timestamp is required");
    }
    if (typeof item.host_id !== "string") {
        throw new TypeError("Event Timeline host_id must be a string");
    }
    if (typeof item.event_type !== "string") {
        throw new TypeError("Event Timeline event_type must be a string");
    }
}

function validatePayload(payload) {
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
        throw new TypeError("Event Timeline payload must be an object");
    }
    if (!Array.isArray(payload.items)) {
        throw new TypeError("Event Timeline items must be an array");
    }
    if (!Number.isInteger(payload.total) || payload.total < 0) {
        throw new TypeError("Event Timeline total must be a non-negative integer");
    }
    requireLimit(payload.limit);
    requireOffset(payload.offset);
    for (const item of payload.items) {
        validateEventItem(item);
    }
    return payload;
}

export function buildEventTimelineViewPath(runId) {
    return `/dashboard/runs/${encodeURIComponent(requireIdentifier(runId, "runId"))}/timeline`;
}

export function buildEventTimelineApiPath(runId, limit, offset) {
    const encodedRunId = encodeURIComponent(requireIdentifier(runId, "runId"));
    const query = new URLSearchParams({
        limit: String(requireLimit(limit)),
        offset: String(requireOffset(offset)),
    });
    return `/runs/${encodedRunId}/timeline?${query.toString()}`;
}

export function extractTimelineRunIdFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/runs\/([^/]+)\/timeline$/.exec(pathname);
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

export function getEventTimelinePagination(payload) {
    const validPayload = validatePayload(payload);
    const itemCount = validPayload.items.length;
    return {
        hasPrevious: validPayload.offset > 0,
        hasNext: validPayload.offset + itemCount < validPayload.total,
        previousOffset: Math.max(0, validPayload.offset - validPayload.limit),
        nextOffset: validPayload.offset + itemCount,
        displayStart: itemCount === 0 ? 0 : validPayload.offset + 1,
        displayEnd: validPayload.offset + itemCount,
    };
}

export function resolveEventTimelineQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Event Timeline state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Event Timeline query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: getQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = validatePayload(result.payload);
        const queryState = payload.total === 0 ? "empty" : "success";
        return {
            queryState,
            payload,
            message: getQueryMessage(queryState),
        };
    }
    if (result.kind === "run_not_found") {
        return {
            queryState: "run_not_found",
            payload: null,
            message: getQueryMessage("run_not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Event Timeline query result kind: ${result.kind}`);
}
