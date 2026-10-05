import { formatRunTimestamp } from "./dashboard-contract.mjs";
import { buildEventDetailViewPath } from "./event-detail-contract.mjs";
import {
    buildEventTimelineApiPath,
    extractTimelineRunIdFromPathname,
    getEventTimelinePagination,
    resolveEventTimelineQueryState,
} from "./event-timeline-contract.mjs";
import { buildRunDetailViewPath } from "./run-detail-contract.mjs";

const DEFAULT_LIMIT = 50;
const INITIAL_OFFSET = 0;

const eventTimelineView = document.getElementById("event-timeline-view");
const eventTimelineStatus = document.getElementById("event-timeline-status");
const eventTimelineSummary = document.getElementById("event-timeline-summary");
const eventTimelineList = document.getElementById("event-timeline-list");
const eventTimelinePagination = document.getElementById("event-timeline-pagination");
const runDetailBackNavigation = document.getElementById("run-detail-back-navigation");

let timelineState = null;

function createDetailField(label, value) {
    const field = document.createElement("div");
    field.classList.add("detail-field");

    const term = document.createElement("dt");
    term.classList.add("detail-field__label");
    term.textContent = label;

    const description = document.createElement("dd");
    description.classList.add("detail-field__value");
    description.textContent = String(value);

    field.append(term, description);
    return field;
}

function renderSummary(runId, payload, pagination) {
    eventTimelineSummary.replaceChildren(
        createDetailField("Run ID", runId),
        createDetailField("전체 Event 수", payload.total),
        createDetailField(
            "현재 표시 범위",
            `${pagination.displayStart}–${pagination.displayEnd} / ${payload.total}`,
        ),
    );
}

function createEventCard(runId, event) {
    const card = document.createElement("article");
    card.classList.add("event-timeline-card");

    const heading = document.createElement("h3");
    heading.classList.add("event-timeline-card__title");

    const link = document.createElement("a");
    link.href = buildEventDetailViewPath(runId, event.event_id);
    link.textContent = event.event_id;
    heading.append(link);

    const fields = document.createElement("dl");
    fields.classList.add("detail-fields");
    fields.append(
        createDetailField("Timestamp", formatRunTimestamp(event.timestamp)),
        createDetailField("Host ID", event.host_id),
        createDetailField("Event Type", event.event_type),
    );

    card.append(heading, fields);
    return card;
}

function setPaginationDisabled(disabled) {
    for (const button of eventTimelinePagination.querySelectorAll("button")) {
        button.disabled = disabled;
    }
}

function createPaginationButton(label, disabled, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.disabled = disabled;
    button.addEventListener("click", onClick);
    return button;
}

function renderPagination(runId, payload, pagination) {
    const previousButton = createPaginationButton(
        "이전",
        !pagination.hasPrevious,
        () => {
            setPaginationDisabled(true);
            void loadEventTimelinePage(runId, pagination.previousOffset);
        },
    );
    const nextButton = createPaginationButton(
        "다음",
        !pagination.hasNext,
        () => {
            setPaginationDisabled(true);
            void loadEventTimelinePage(runId, pagination.nextOffset);
        },
    );
    eventTimelinePagination.replaceChildren(previousButton, nextButton);
}

function renderTimelinePayload(runId, payload) {
    const pagination = getEventTimelinePagination(payload);
    renderSummary(runId, payload, pagination);
    eventTimelineList.replaceChildren(
        ...payload.items.map((event) => createEventCard(runId, event)),
    );
    renderPagination(runId, payload, pagination);
}

function clearTimelineContent() {
    eventTimelineSummary.replaceChildren();
    eventTimelineList.replaceChildren();
    eventTimelinePagination.replaceChildren();
}

function renderTimelineState(state, runId) {
    eventTimelineStatus.textContent = state.message;
    if (state.queryState === "loading") {
        setPaginationDisabled(true);
        return;
    }
    if (state.queryState === "success" || state.queryState === "empty") {
        renderTimelinePayload(runId, state.payload);
        return;
    }
    clearTimelineContent();
}

function renderRunDetailBackNavigation(runId) {
    const link = document.createElement("a");
    link.href = buildRunDetailViewPath(runId);
    link.textContent = "Run Detail로 돌아가기";
    runDetailBackNavigation.replaceChildren(link);
}

async function fetchEventTimeline(runId, offset) {
    const response = await fetch(buildEventTimelineApiPath(runId, DEFAULT_LIMIT, offset), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "run_not_found" };
    }
    if (!response.ok) {
        throw new Error("Event Timeline API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function loadEventTimelinePage(runId, offset) {
    timelineState = resolveEventTimelineQueryState(timelineState, { kind: "loading" });
    renderTimelineState(timelineState, runId);

    try {
        timelineState = resolveEventTimelineQueryState(
            timelineState,
            await fetchEventTimeline(runId, offset),
        );
    } catch {
        timelineState = resolveEventTimelineQueryState(timelineState, { kind: "error" });
    }
    renderTimelineState(timelineState, runId);
}

function loadEventTimeline() {
    const runId = extractTimelineRunIdFromPathname(window.location.pathname);
    if (runId === null) {
        timelineState = resolveEventTimelineQueryState(null, { kind: "error" });
        renderTimelineState(timelineState, "");
        return;
    }

    renderRunDetailBackNavigation(runId);
    void loadEventTimelinePage(runId, INITIAL_OFFSET);
}

if (
    eventTimelineView !== null
    && eventTimelineStatus !== null
    && eventTimelineSummary !== null
    && eventTimelineList !== null
    && eventTimelinePagination !== null
    && runDetailBackNavigation !== null
) {
    loadEventTimeline();
}
