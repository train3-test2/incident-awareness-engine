// Pure Event Detail path, presentation, and query-state helpers.

const QUERY_MESSAGES = new Map([
    ["loading", "Event Detail을 불러오는 중입니다."],
    ["success", "Event Detail을 불러왔습니다."],
    ["not_found", "Run 또는 Event를 찾을 수 없습니다."],
    ["error", "Event Detail을 불러오지 못했습니다."],
]);
const SOURCE_LAYER_LABELS = new Map([
    ["raw_telemetry", "Raw Telemetry"],
    ["detector_output", "Detector Output"],
]);
const STRING_FIELDS = [
    "event_id",
    "run_id",
    "host_id",
    "event_type",
    "source",
    "source_layer",
    "source_event_id",
    "timestamp_source",
];
const NULLABLE_RAW_REFERENCE_FIELDS = [
    "source_record_id",
    "parser_id",
    "parser_version",
];

function requireIdentifier(value, name) {
    if (typeof value !== "string") {
        throw new TypeError(`${name} must be a string`);
    }
    if (!value.trim()) {
        throw new RangeError(`${name} must not be blank`);
    }
    return value;
}

function requireEventId(eventId) {
    if (typeof eventId !== "string") {
        throw new TypeError("eventId must be a string");
    }
    if (eventId === "") {
        throw new RangeError("eventId must not be empty");
    }
    if (eventId === "." || eventId === "..") {
        throw new RangeError("eventId must not be a dot segment");
    }
    return eventId;
}

function validateNullableString(value, name) {
    if (value !== null && typeof value !== "string") {
        throw new TypeError(`${name} must be a string or null`);
    }
}

function validatePositiveInteger(value, name) {
    if (!Number.isInteger(value) || value < 1) {
        throw new TypeError(`${name} must be a positive integer`);
    }
}

function validatePayload(payload) {
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
        throw new TypeError("Event Detail payload must be an object");
    }
    for (const field of STRING_FIELDS) {
        if (typeof payload[field] !== "string") {
            throw new TypeError(`Event Detail ${field} must be a string`);
        }
    }
    if (
        !Object.prototype.hasOwnProperty.call(payload, "timestamp")
        || payload.timestamp === null
        || payload.timestamp === undefined
    ) {
        throw new TypeError("Event Detail timestamp is required");
    }

    const rawReference = payload.raw_ref;
    if (
        rawReference === null
        || typeof rawReference !== "object"
        || Array.isArray(rawReference)
    ) {
        throw new TypeError("Event Detail raw_ref must be an object");
    }
    if (typeof rawReference.raw_log_id !== "string") {
        throw new TypeError("Event Detail raw_log_id must be a string");
    }
    for (const field of NULLABLE_RAW_REFERENCE_FIELDS) {
        validateNullableString(rawReference[field], `Event Detail ${field}`);
    }
    validatePositiveInteger(rawReference.segment_no, "Event Detail segment_no");
    validatePositiveInteger(rawReference.record_no, "Event Detail record_no");
    return payload;
}

export function buildEventDetailViewPath(runId, eventId) {
    const encodedRunId = encodeURIComponent(requireIdentifier(runId, "runId"));
    const encodedEventId = encodeURIComponent(requireEventId(eventId));
    return `/dashboard/runs/${encodedRunId}/events/${encodedEventId}`;
}

export function buildEventDetailApiPath(runId, eventId) {
    const encodedRunId = encodeURIComponent(requireIdentifier(runId, "runId"));
    const encodedEventId = encodeURIComponent(requireEventId(eventId));
    return `/runs/${encodedRunId}/events/${encodedEventId}`;
}

export function extractEventDetailIdsFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/runs\/([^/]+)\/events\/(.+)$/.exec(pathname);
    if (match === null) {
        return null;
    }
    try {
        return {
            runId: requireIdentifier(decodeURIComponent(match[1]), "runId"),
            eventId: requireEventId(decodeURIComponent(match[2])),
        };
    } catch {
        return null;
    }
}

export function getSourceLayerLabel(sourceLayer) {
    return SOURCE_LAYER_LABELS.get(sourceLayer) ?? sourceLayer;
}

export function resolveEventDetailQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Event Detail state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Event Detail query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: QUERY_MESSAGES.get("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = validatePayload(result.payload);
        return {
            queryState: "success",
            payload,
            message: QUERY_MESSAGES.get("success"),
        };
    }
    if (result.kind === "not_found") {
        return {
            queryState: "not_found",
            payload: null,
            message: QUERY_MESSAGES.get("not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: QUERY_MESSAGES.get("error"),
        };
    }
    throw new RangeError(`Unknown Event Detail query result kind: ${result.kind}`);
}
