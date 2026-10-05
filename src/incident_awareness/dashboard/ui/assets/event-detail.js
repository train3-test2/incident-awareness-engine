import { displayValue, formatRunTimestamp } from "./dashboard-contract.mjs";
import {
    buildEventDetailApiPath,
    extractEventDetailIdsFromPathname,
    getSourceLayerLabel,
    resolveEventDetailQueryState,
} from "./event-detail-contract.mjs";
import { buildEventTimelineViewPath } from "./event-timeline-contract.mjs";
import { buildRunDetailViewPath } from "./run-detail-contract.mjs";

const eventDetailView = document.getElementById("event-detail-view");
const eventDetailStatus = document.getElementById("event-detail-status");
const eventDetailFields = document.getElementById("event-detail-fields");
const rawLogReferenceStatus = document.getElementById("raw-log-reference-status");
const rawLogReferenceFields = document.getElementById("raw-log-reference-fields");
const eventTimelineBackNavigation = document.getElementById(
    "event-timeline-back-navigation",
);
const runDetailBackNavigation = document.getElementById("run-detail-back-navigation");

function createDetailField(label, value) {
    const field = document.createElement("div");
    field.classList.add("detail-field");

    const term = document.createElement("dt");
    term.classList.add("detail-field__label");
    term.textContent = label;

    const description = document.createElement("dd");
    description.classList.add("detail-field__value");
    description.textContent = value;

    field.append(term, description);
    return field;
}

function renderEventMetadata(event) {
    eventDetailFields.replaceChildren(
        createDetailField("Event ID", event.event_id),
        createDetailField("Run ID", event.run_id),
        createDetailField("Timestamp", formatRunTimestamp(event.timestamp)),
        createDetailField("Host ID", event.host_id),
        createDetailField("Event Type", event.event_type),
        createDetailField("Source", event.source),
        createDetailField("Source Layer", getSourceLayerLabel(event.source_layer)),
        createDetailField("Source Event ID", event.source_event_id),
        createDetailField("Timestamp Source", event.timestamp_source),
    );
}

function renderRawLogReference(rawReference) {
    rawLogReferenceStatus.textContent = "Raw Log Reference를 불러왔습니다.";
    rawLogReferenceFields.replaceChildren(
        createDetailField("Raw Log ID", rawReference.raw_log_id),
        createDetailField("Source Record ID", displayValue(rawReference.source_record_id)),
        createDetailField("Segment No", displayValue(rawReference.segment_no)),
        createDetailField("Record No", displayValue(rawReference.record_no)),
        createDetailField("Parser ID", displayValue(rawReference.parser_id)),
        createDetailField("Parser Version", displayValue(rawReference.parser_version)),
    );
}

function clearDetailContent() {
    eventDetailFields.replaceChildren();
    rawLogReferenceFields.replaceChildren();
    rawLogReferenceStatus.textContent = "";
}

function renderEventDetailState(state) {
    eventDetailStatus.textContent = state.message;
    if (state.queryState === "success") {
        renderEventMetadata(state.payload);
        renderRawLogReference(state.payload.raw_ref);
        return;
    }
    clearDetailContent();
}

function createNavigationLink(path, label) {
    const link = document.createElement("a");
    link.href = path;
    link.textContent = label;
    return link;
}

function renderBackNavigation(runId) {
    eventTimelineBackNavigation.replaceChildren(
        createNavigationLink(
            buildEventTimelineViewPath(runId),
            "Event Timeline으로 돌아가기",
        ),
    );
    runDetailBackNavigation.replaceChildren(
        createNavigationLink(buildRunDetailViewPath(runId), "Run Detail로 돌아가기"),
    );
}

async function fetchEventDetail(runId, eventId) {
    const response = await fetch(buildEventDetailApiPath(runId, eventId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Event Detail API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function loadEventDetail() {
    let state = resolveEventDetailQueryState(null, { kind: "loading" });
    renderEventDetailState(state);

    const identifiers = extractEventDetailIdsFromPathname(window.location.pathname);
    if (identifiers === null) {
        state = resolveEventDetailQueryState(state, { kind: "error" });
        renderEventDetailState(state);
        return;
    }

    const { runId, eventId } = identifiers;
    renderBackNavigation(runId);
    try {
        state = resolveEventDetailQueryState(
            state,
            await fetchEventDetail(runId, eventId),
        );
    } catch {
        state = resolveEventDetailQueryState(state, { kind: "error" });
    }
    renderEventDetailState(state);
}

if (
    eventDetailView !== null
    && eventDetailStatus !== null
    && eventDetailFields !== null
    && rawLogReferenceStatus !== null
    && rawLogReferenceFields !== null
    && eventTimelineBackNavigation !== null
    && runDetailBackNavigation !== null
) {
    void loadEventDetail();
}
