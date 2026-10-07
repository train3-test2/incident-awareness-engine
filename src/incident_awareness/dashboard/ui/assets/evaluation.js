import {
    getEvaluationStatusPresentations,
    getPurposePresentation,
    projectEvaluationSections,
    projectExclusions,
    projectSnapshotSummary,
    resolveEvaluationQueryState,
} from "./evaluation-contract.mjs";

const EVALUATION_ENDPOINT = "/evaluation";
const DEFERRED_SECTION_MESSAGE = "상세 결과를 불러왔습니다.";

const evaluationView = document.getElementById("evaluation-view");
const evaluationStatus = document.getElementById("evaluation-status");
const evaluationContent = document.getElementById("evaluation-content");
const purposeNotice = document.getElementById("evaluation-purpose-notice");
const snapshotSummary = document.getElementById("evaluation-snapshot-summary");
const coverageStatuses = document.getElementById("evaluation-coverage-statuses");
const exclusions = document.getElementById("evaluation-exclusions");
const methodComparison = document.getElementById("method-comparison");
const normalAlertBurden = document.getElementById("normal-alert-burden");
const pairedTiming = document.getElementById("paired-timing");
const runLevelPairedTiming = document.getElementById("run-level-paired-timing");

function createSummaryField(field) {
    const container = document.createElement("div");
    container.classList.add("evaluation-summary__field");

    const term = document.createElement("dt");
    term.classList.add("evaluation-summary__label");
    term.textContent = field.label;

    const description = document.createElement("dd");
    description.classList.add("evaluation-summary__value", "identifier");
    description.textContent = field.value;

    container.append(term, description);
    return container;
}

function renderSnapshotSummary(payload) {
    const fields = projectSnapshotSummary(payload).map((field) => createSummaryField(field));
    snapshotSummary.replaceChildren(...fields);

    const presentation = getPurposePresentation(payload.plan.purpose);
    const title = document.createElement("strong");
    title.textContent = presentation.title;
    const description = document.createElement("p");
    description.textContent = presentation.description;
    purposeNotice.classList.remove(
        "evaluation-purpose-notice--smoke",
        "evaluation-purpose-notice--performance",
    );
    purposeNotice.classList.add(`evaluation-purpose-notice--${presentation.modifier}`);
    purposeNotice.replaceChildren(title, description);
}

function createCoverageCard(status) {
    const card = document.createElement("article");
    card.classList.add("evaluation-status-card");

    const label = document.createElement("h3");
    label.classList.add("evaluation-status-card__label");
    label.textContent = status.label;

    const value = document.createElement("span");
    value.classList.add(
        "status-badge",
        status.complete ? "status-badge--completed" : "status-badge--stale",
    );
    value.textContent = status.statusLabel;

    card.append(label, value);
    return card;
}

function createExclusionCard(exclusion) {
    const card = document.createElement("article");
    card.classList.add("evaluation-exclusion");

    const runId = document.createElement("strong");
    runId.classList.add("identifier");
    runId.textContent = exclusion.runId;

    const detail = document.createElement("span");
    detail.textContent = `${exclusion.method} · ${exclusion.reason}`;

    card.append(runId, detail);
    return card;
}

function renderEvaluationCoverage(payload) {
    const statuses = getEvaluationStatusPresentations(payload).map(
        (status) => createCoverageCard(status),
    );
    coverageStatuses.replaceChildren(...statuses);

    const items = projectExclusions(payload);
    if (items.length === 0) {
        const empty = document.createElement("p");
        empty.classList.add("evaluation-empty-message");
        empty.textContent = "평가 제외 Run 없음";
        exclusions.replaceChildren(empty);
        return;
    }
    exclusions.replaceChildren(...items.map((item) => createExclusionCard(item)));
}

function renderDeferredSection(container) {
    const message = document.createElement("p");
    message.classList.add("evaluation-deferred-message");
    message.textContent = DEFERRED_SECTION_MESSAGE;
    container.replaceChildren(message);
}

function renderMethodComparison(payload) {
    projectEvaluationSections(payload);
    renderDeferredSection(methodComparison);
}

function renderNormalAlertBurden(payload) {
    projectEvaluationSections(payload);
    renderDeferredSection(normalAlertBurden);
}

function renderPairedTiming(payload) {
    projectEvaluationSections(payload);
    renderDeferredSection(pairedTiming);
}

function renderRunLevelPairedTiming(payload) {
    projectEvaluationSections(payload);
    renderDeferredSection(runLevelPairedTiming);
}

function clearEvaluationContent() {
    purposeNotice.replaceChildren();
    snapshotSummary.replaceChildren();
    coverageStatuses.replaceChildren();
    exclusions.replaceChildren();
    methodComparison.replaceChildren();
    normalAlertBurden.replaceChildren();
    pairedTiming.replaceChildren();
    runLevelPairedTiming.replaceChildren();
}

function renderEvaluationState(state) {
    evaluationStatus.textContent = state.message;
    evaluationStatus.classList.remove(
        "evaluation-status--success",
        "evaluation-status--error",
    );
    if (state.queryState !== "success") {
        if (state.queryState === "error") {
            evaluationStatus.classList.add("evaluation-status--error");
        }
        evaluationContent.hidden = true;
        clearEvaluationContent();
        return;
    }

    evaluationStatus.classList.add("evaluation-status--success");
    evaluationContent.hidden = false;
    renderSnapshotSummary(state.payload);
    renderEvaluationCoverage(state.payload);
    renderMethodComparison(state.payload);
    renderNormalAlertBurden(state.payload);
    renderPairedTiming(state.payload);
    renderRunLevelPairedTiming(state.payload);
}

async function fetchEvaluation() {
    const response = await fetch(EVALUATION_ENDPOINT, {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    let payload = null;
    try {
        payload = await response.json();
    } catch {
        if (response.ok) {
            throw new Error("Evaluation API returned invalid JSON");
        }
    }
    if (!response.ok) {
        return {
            kind: "error",
            status: response.status,
            detail: payload?.detail,
        };
    }
    return { kind: "success", payload };
}

async function loadEvaluation() {
    let state = resolveEvaluationQueryState(null, { kind: "loading" });
    renderEvaluationState(state);

    try {
        const result = await fetchEvaluation();
        state = resolveEvaluationQueryState(state, result);
    } catch {
        state = resolveEvaluationQueryState(state, { kind: "error" });
    }
    renderEvaluationState(state);
}

if (
    evaluationView !== null
    && evaluationStatus !== null
    && evaluationContent !== null
    && purposeNotice !== null
    && snapshotSummary !== null
    && coverageStatuses !== null
    && exclusions !== null
    && methodComparison !== null
    && normalAlertBurden !== null
    && pairedTiming !== null
    && runLevelPairedTiming !== null
) {
    void loadEvaluation();
}
