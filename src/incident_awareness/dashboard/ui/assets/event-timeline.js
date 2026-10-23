import { formatRunTimestamp } from "./dashboard-contract.mjs";
import { buildEventDetailViewPath } from "./event-detail-contract.mjs";
import {
    buildEventTimelineApiPath,
    extractTimelineRunIdFromPathname,
    filterEventTimelinePage,
    getEventTimelinePagination,
    getEventTimelinePagePosition,
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
const eventTypeFilter = document.getElementById("event-timeline-type");
const eventFilterReset = document.getElementById("event-timeline-filter-reset");
const eventFilterStatus = document.getElementById("event-timeline-filter-status");

let timelineState = null;
let eventType = "all";
// Page control ("previous" or "next") that held keyboard focus when a page load started.
let pendingPaginationFocus = null;

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
    const position = getEventTimelinePagePosition(payload);
    eventTimelineSummary.replaceChildren(
        createDetailField("분석 ID", runId),
        createDetailField("전체 Event 수", payload.total),
        createDetailField(
            "현재 표시 범위",
            `${pagination.displayStart}–${pagination.displayEnd} / ${payload.total}`,
        ),
        createDetailField(
            "현재 페이지 / 전체 페이지",
            `${position.currentPage} / ${position.totalPages}`,
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
    const timestamp = createDetailField("Timestamp", formatRunTimestamp(event.timestamp));
    const time = document.createElement("time");
    time.setAttribute("datetime", event.timestamp);
    time.textContent = formatRunTimestamp(event.timestamp);
    const precision = document.createElement("small");
    precision.classList.add("event-timeline-timestamp");
    precision.textContent = event.timestamp;
    const original = document.createElement("details");
    const originalTitle = document.createElement("summary");
    originalTitle.textContent = "시각 원문·UTC";
    original.append(originalTitle, precision);
    timestamp.children[1].replaceChildren(time, original);
    fields.append(
        timestamp,
        createDetailField("Host ID", event.host_id),
        createDetailField("Event Type", event.event_type),
    );

    card.append(heading, fields);
    return card;
}

function updateEventTypeFilter() {
    if (timelineState.payload === null) {
        return;
    }
    const items = timelineState.payload.items;
    const matches = new Set(filterEventTimelinePage(items, eventType));
    for (const [index, card] of Array.from(eventTimelineList.children).entries()) {
        card.hidden = !matches.has(items[index]);
    }
    const message = items.length === 0
        ? "현재 페이지에 표시할 Event가 없습니다."
        : matches.size === 0
            ? `현재 페이지에서 유형 ${eventType}의 Event가 없습니다. · 0 / ${items.length}건 표시`
            : `현재 페이지 ${items.length}건 중 ${matches.size}건 표시 · 유형 ${eventType === "all" ? "전체" : eventType}`;
    if (eventFilterStatus.textContent !== message) {
        eventFilterStatus.textContent = message;
    }
}

function renderEventTypeOptions(items) {
    const values = [...new Set(["all", eventType, ...items.map((event) => event.event_type)])];
    eventTypeFilter.replaceChildren(...values.map((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value === "all" ? "전체 유형" : value;
        return option;
    }));
    eventTypeFilter.value = eventType;
}

function setPaginationDisabled(disabled) {
    for (const button of eventTimelinePagination.querySelectorAll("button")) {
        button.disabled = disabled;
    }
}

function createPaginationButton(label, control, disabled, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.dataset.paginationControl = control;
    button.disabled = disabled;
    button.addEventListener("click", onClick);
    return button;
}

function navigateToPage(runId, offset, control) {
    // A pointer activation that did not focus the control leaves focus untouched.
    pendingPaginationFocus = eventTimelinePagination.contains(document.activeElement)
        ? control
        : null;
    setPaginationDisabled(true);
    void loadEventTimelinePage(runId, offset);
}

function renderPagination(runId, payload, pagination) {
    const previousButton = createPaginationButton(
        "이전",
        "previous",
        !pagination.hasPrevious,
        () => navigateToPage(runId, pagination.previousOffset, "previous"),
    );
    const nextButton = createPaginationButton(
        "다음",
        "next",
        !pagination.hasNext,
        () => navigateToPage(runId, pagination.nextOffset, "next"),
    );
    eventTimelinePagination.replaceChildren(previousButton, nextButton);
}

// Returns the activated control unless focus moved to another element while loading;
// disabling or replacing the control itself only drops focus to the document body.
function takePaginationFocus() {
    const control = pendingPaginationFocus;
    pendingPaginationFocus = null;
    const activeElement = document.activeElement;
    const focusUnclaimed = activeElement === null
        || activeElement === document.body
        || eventTimelinePagination.contains(activeElement);
    return focusUnclaimed ? control : null;
}

function restorePaginationFocus(control) {
    if (control === null) {
        return;
    }
    const buttons = Array.from(eventTimelinePagination.querySelectorAll("button"))
        .filter((button) => !button.disabled);
    // The same control, else the remaining page control (the last page disables "다음").
    const target = buttons.find((button) => button.dataset.paginationControl === control)
        ?? buttons[0]
        ?? null;
    if (target === null) {
        // No page control is operable: keep the keyboard position on the page status
        // without adding the status message to the Tab order.
        eventTimelineStatus.tabIndex = -1;
    }
    const focusTarget = target ?? eventTimelineStatus;
    focusTarget.focus({ preventScroll: true });
    focusTarget.scrollIntoView({ block: "nearest", inline: "nearest" });
}

function renderTimelinePayload(runId, payload) {
    const pagination = getEventTimelinePagination(payload);
    renderSummary(runId, payload, pagination);
    eventTimelineList.replaceChildren(
        ...payload.items.map((event) => createEventCard(runId, event)),
    );
    renderPagination(runId, payload, pagination);
    renderEventTypeOptions(payload.items);
    updateEventTypeFilter();
}

function clearTimelineContent() {
    eventTimelineSummary.replaceChildren();
    eventTimelineList.replaceChildren();
    eventTimelinePagination.replaceChildren();
}

function renderTimelineState(state, runId) {
    eventTimelineStatus.textContent = state.message;
    eventTimelineList.setAttribute("aria-busy", String(state.queryState === "loading"));
    eventTypeFilter.disabled = state.queryState !== "success" && state.queryState !== "empty";
    eventFilterReset.disabled = eventTypeFilter.disabled;
    if (state.queryState === "loading") {
        eventFilterStatus.textContent = "현재 페이지 조회 중";
        setPaginationDisabled(true);
        return;
    }
    const focusControl = takePaginationFocus();
    if (state.queryState === "success" || state.queryState === "empty") {
        renderTimelinePayload(runId, state.payload);
    } else {
        clearTimelineContent();
        eventFilterStatus.textContent = "현재 페이지를 조회하지 못해 필터 결과를 표시할 수 없습니다.";
    }
    restorePaginationFocus(focusControl);
}

function renderRunDetailBackNavigation(runId) {
    const link = document.createElement("a");
    link.href = buildRunDetailViewPath(runId);
    link.textContent = "분석 상세로 돌아가기";
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
    eventTypeFilter.addEventListener("change", () => {
        eventType = eventTypeFilter.value;
        updateEventTypeFilter();
    });
    eventFilterReset.addEventListener("click", () => {
        eventType = "all";
        eventTypeFilter.value = "all";
        updateEventTypeFilter();
    });
    loadEventTimeline();
}
