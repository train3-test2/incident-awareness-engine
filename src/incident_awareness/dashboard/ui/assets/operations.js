import {
    NOT_APPLICABLE,
    displayValue,
    getRuntimeProgressPresentation,
    getRuntimeQueryMessage,
    getRuntimeStatePresentation,
    getStageLabel,
    resolveRuntimeQueryState,
} from "./operations-contract.mjs";

const RUNTIME_ENDPOINT = "/operations/runtime";
const POLL_INTERVAL_MS = 5000;
// Upper bound for one Runtime request; separate from the delay between polls.
const RUNTIME_REQUEST_TIMEOUT_MS = 10000;

const runtimeStatus = document.getElementById("runtime-status");
const runtimeList = document.getElementById("runtime-list");
let latestRuntimeItems = [];

function updateRuntimeStatus(message) {
    if (runtimeStatus.textContent !== message) {
        runtimeStatus.textContent = message;
    }
}

function formatTimestamp(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }
    return date.toLocaleString("ko-KR", { timeZoneName: "short" });
}

function createField(label, value) {
    const field = document.createElement("div");
    field.classList.add("runtime-field");

    const term = document.createElement("dt");
    term.classList.add("runtime-field__label");
    term.textContent = label;

    const description = document.createElement("dd");
    description.classList.add("runtime-field__value");
    description.textContent = value;

    field.append(term, description);
    return field;
}

function createRuntimeCard(runtime, telemetryAvailable) {
    const presentation = getRuntimeStatePresentation(runtime, telemetryAvailable);
    const progress = getRuntimeProgressPresentation(runtime);

    const card = document.createElement("article");
    card.classList.add("runtime-card");
    for (const modifier of presentation.modifiers) {
        card.classList.add(`runtime-card--${modifier}`);
    }

    const heading = document.createElement("h3");
    heading.classList.add("runtime-card__title");
    heading.textContent = displayValue(runtime.run_id);

    const fields = document.createElement("dl");
    fields.classList.add("runtime-card__fields");
    fields.append(
        createField("Entity ID", displayValue(runtime.entity_id)),
        createField("상태", presentation.statusLabel),
        createField("Telemetry", presentation.telemetryLabel),
    );
    if (presentation.livenessLabel !== null) {
        fields.append(createField("현재 실행 여부", presentation.livenessLabel));
    }
    fields.append(
        createField("현재 단계", getStageLabel(runtime.current_stage)),
        createField("진행", progress.processed),
        createField("남은 항목", progress.remaining),
        createField("시작", formatTimestamp(runtime.started_at)),
        createField("단계 시작", formatTimestamp(runtime.stage_started_at)),
        createField("마지막 갱신", formatTimestamp(runtime.updated_at)),
        createField("완료", formatTimestamp(runtime.completed_at)),
        createField("실패 단계", getStageLabel(runtime.failed_stage)),
    );

    card.append(heading, fields);
    return card;
}

// Keeps the API order; cards are built before the list is replaced so a rendering
// failure leaves the last successful list untouched.
function renderRuntimeItems(items, telemetryAvailable) {
    const cards = items.map((runtime) => createRuntimeCard(runtime, telemetryAvailable));
    runtimeList.replaceChildren(...cards);
}

function validateRuntimePayload(payload) {
    if (
        payload === null
        || typeof payload !== "object"
        || Array.isArray(payload)
        || !Array.isArray(payload.items)
    ) {
        throw new Error("Runtime API response is invalid");
    }
}

async function fetchRuntimeItems() {
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
            throw new Error("Runtime API request failed");
        }

        const payload = await response.json();
        validateRuntimePayload(payload);
        return payload.items;
    } finally {
        clearTimeout(timeoutId);
    }
}

async function pollRuntime() {
    try {
        const items = await fetchRuntimeItems();
        const next = resolveRuntimeQueryState(
            latestRuntimeItems,
            { kind: "success", items },
        );
        renderRuntimeItems(next.items, next.telemetryAvailable);
        latestRuntimeItems = next.items;
        updateRuntimeStatus(next.message);
    } catch {
        const next = resolveRuntimeQueryState(latestRuntimeItems, { kind: "error" });
        updateRuntimeStatus(next.message);
        renderRuntimeItems(next.items, next.telemetryAvailable);
    } finally {
        setTimeout(pollRuntime, POLL_INTERVAL_MS);
    }
}

function startRuntimePolling() {
    updateRuntimeStatus(getRuntimeQueryMessage("loading"));
    void pollRuntime();
}

if (runtimeStatus !== null && runtimeList !== null) {
    startRuntimePolling();
}
