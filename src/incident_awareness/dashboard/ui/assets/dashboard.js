import {
    displayValue,
    formatRunTimestamp,
    getRunTypeLabel,
    resolveOverviewQueryState,
    resolveRunListQueryState,
} from "./dashboard-contract.mjs";
import { buildRunDetailViewPath } from "./run-detail-contract.mjs";

const OVERVIEW_ENDPOINT = "/overview";
const RUNS_ENDPOINT = "/runs";

const dashboardView = document.getElementById("dashboard-view");
const totalRunsValue = document.getElementById("total-runs-value");
const overviewStatus = document.getElementById("overview-status");
const recentRunsStatus = document.getElementById("recent-runs-status");
const recentRunsList = document.getElementById("recent-runs-list");
const runsStatus = document.getElementById("runs-status");
const runsList = document.getElementById("runs-list");

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
