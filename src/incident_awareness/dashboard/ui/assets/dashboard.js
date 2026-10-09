import {
    displayValue,
    formatRunTimestamp,
    getRunTypeLabel,
    resolveOverviewQueryState,
    resolveRunListQueryState,
    resolveRuntimeSummaryQueryState,
} from "./dashboard-contract.mjs";
import {
    getRuntimeStatePresentation,
    getStageLabel,
} from "./operations-contract.mjs";
import { buildRunDetailViewPath } from "./run-detail-contract.mjs";

const OVERVIEW_ENDPOINT = "/overview";
const RUNS_ENDPOINT = "/runs";
const RUNTIME_ENDPOINT = "/operations/runtime?limit=5";
const RUNTIME_REQUEST_TIMEOUT_MS = 10000;

const dashboardView = document.getElementById("dashboard-view");
const totalRunsValue = document.getElementById("total-runs-value");
const overviewStatus = document.getElementById("overview-status");
const recentRunsStatus = document.getElementById("recent-runs-status");
const recentRunsList = document.getElementById("recent-runs-list");
const runsStatus = document.getElementById("runs-status");
const runsList = document.getElementById("runs-list");
const runtimeSummaryStatus = document.getElementById("runtime-summary-status");
const runtimeSummaryList = document.getElementById("runtime-summary-list");

function createRunField(label, value) {
    const field = document.createElement("div");
    field.classList.add("recent-run-field");

    const term = document.createElement("dt");
    term.classList.add("recent-run-field__label");
    term.textContent = label;

    const description = document.createElement("dd");
    description.classList.add("recent-run-field__value");
    description.textContent = value;

    field.append(term, description);
    return field;
}

function createRunCard(run) {
    const card = document.createElement("article");
    card.classList.add("recent-run-card");

    const heading = document.createElement("h3");
    heading.classList.add("recent-run-card__title");
    if (typeof run.run_id === "string" && run.run_id.trim()) {
        const link = document.createElement("a");
        link.href = buildRunDetailViewPath(run.run_id);
        link.textContent = run.run_id;
        heading.append(link);
    } else {
        heading.textContent = displayValue(run.run_id);
    }

    const fields = document.createElement("dl");
    fields.classList.add("recent-run-card__fields");
    fields.append(
        createRunField("Scenario", displayValue(run.scenario_id)),
        createRunField("Type", getRunTypeLabel(run.run_type)),
        createRunField("Target", displayValue(run.target_host)),
        createRunField("Start", formatRunTimestamp(run.start_time)),
        createRunField("End", formatRunTimestamp(run.end_time)),
    );

    card.append(heading, fields);
    return card;
}

function createRuntimeSummaryField(label, value) {
    const field = document.createElement("div");
    field.classList.add("runtime-summary-field");

    const term = document.createElement("dt");
    term.classList.add("runtime-summary-field__label");
    term.textContent = label;

    const description = document.createElement("dd");
    description.classList.add("runtime-summary-field__value");
    description.textContent = value;

    field.append(term, description);
    return field;
}

function createRuntimeSummaryCard(runtime, telemetryAvailable) {
    const presentation = getRuntimeStatePresentation(runtime, telemetryAvailable);
    const card = document.createElement("article");
    card.classList.add("runtime-summary-card");
    for (const modifier of presentation.modifiers) {
        card.classList.add(`runtime-summary-card--${modifier}`);
    }

    const heading = document.createElement("h3");
    heading.classList.add("runtime-summary-card__title");
    if (runtime.status === "completed" && runtime.run_id.trim()) {
        const link = document.createElement("a");
        link.href = buildRunDetailViewPath(runtime.run_id);
        link.textContent = runtime.run_id;
        heading.append(link);
    } else {
        heading.textContent = runtime.run_id;
    }

    const badge = document.createElement("span");
    badge.classList.add("status-badge");
    for (const modifier of presentation.modifiers) {
        badge.classList.add(`status-badge--${modifier}`);
    }
    badge.textContent = presentation.statusLabel;

    const header = document.createElement("div");
    header.classList.add("runtime-summary-card__header");
    header.append(heading, badge);

    const fields = document.createElement("dl");
    fields.classList.add("runtime-summary-card__fields");
    fields.append(
        createRuntimeSummaryField("현재 단계", getStageLabel(runtime.current_stage)),
        createRuntimeSummaryField("마지막 갱신", formatRunTimestamp(runtime.updated_at)),
        createRuntimeSummaryField("Telemetry", presentation.telemetryLabel),
    );
    if (presentation.livenessLabel !== null) {
        fields.append(
            createRuntimeSummaryField("현재 실행 여부", presentation.livenessLabel),
        );
    }

    card.append(header, fields);
    return card;
}

function renderOverviewState(state) {
    totalRunsValue.textContent = displayValue(state.totalRuns);
    overviewStatus.textContent = state.totalMessage;
    recentRunsStatus.textContent = state.message;
    const cards = state.recentRuns.map((run) => createRunCard(run));
    recentRunsList.replaceChildren(...cards);
}

function renderRunListState(state) {
    runsStatus.textContent = state.message;
    const cards = state.items.map((run) => createRunCard(run));
    runsList.replaceChildren(...cards);
}

function renderRuntimeSummaryState(state) {
    runtimeSummaryStatus.textContent = state.message;
    const cards = state.items.map(
        (runtime) => createRuntimeSummaryCard(runtime, state.telemetryAvailable),
    );
    runtimeSummaryList.replaceChildren(...cards);
}

async function fetchOverview() {
    const response = await fetch(OVERVIEW_ENDPOINT, {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (!response.ok) {
        throw new Error("Overview API request failed");
    }
    return response.json();
}

async function loadOverview() {
    let state = resolveOverviewQueryState(null, { kind: "loading" });
    renderOverviewState(state);

    try {
        const payload = await fetchOverview();
        state = resolveOverviewQueryState(state, { kind: "success", payload });
    } catch {
        state = resolveOverviewQueryState(state, { kind: "error" });
    }
    renderOverviewState(state);
}

async function fetchRuns() {
    const response = await fetch(RUNS_ENDPOINT, {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (!response.ok) {
        throw new Error("Run List API request failed");
    }
    return response.json();
}

async function loadRuns() {
    let state = resolveRunListQueryState(null, { kind: "loading" });
    renderRunListState(state);

    try {
        const payload = await fetchRuns();
        state = resolveRunListQueryState(state, { kind: "success", payload });
    } catch {
        state = resolveRunListQueryState(state, { kind: "error" });
    }
    renderRunListState(state);
}

async function fetchRuntimeSummary() {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS);

    try {
        const response = await fetch(RUNTIME_ENDPOINT, {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
            signal: controller.signal,
        });
        if (!response.ok) {
            throw new Error("Runtime Summary API request failed");
        }
        return await response.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

async function loadRuntimeSummary() {
    let state = resolveRuntimeSummaryQueryState(null, { kind: "loading" });
    renderRuntimeSummaryState(state);

    try {
        const payload = await fetchRuntimeSummary();
        state = resolveRuntimeSummaryQueryState(state, { kind: "success", payload });
    } catch {
        state = resolveRuntimeSummaryQueryState(state, { kind: "error" });
    }
    renderRuntimeSummaryState(state);
}

if (
    dashboardView !== null
    && totalRunsValue !== null
    && overviewStatus !== null
    && recentRunsStatus !== null
    && recentRunsList !== null
) {
    void loadOverview();
}

if (
    dashboardView !== null
    && runsStatus !== null
    && runsList !== null
) {
    void loadRuns();
}

if (
    dashboardView !== null
    && runtimeSummaryStatus !== null
    && runtimeSummaryList !== null
) {
    void loadRuntimeSummary();
}
