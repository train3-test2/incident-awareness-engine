// Pure Event Detail path helpers.

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

export function buildEventDetailViewPath(runId, eventId) {
    const encodedRunId = encodeURIComponent(requireIdentifier(runId, "runId"));
    const encodedEventId = encodeURIComponent(requireEventId(eventId));
    return `/dashboard/runs/${encodedRunId}/events/${encodedEventId}`;
}
