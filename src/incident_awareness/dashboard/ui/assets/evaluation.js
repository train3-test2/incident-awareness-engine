import {
    buildAlertBurden,
    buildMethodComparison,
    buildPairedTimingRows,
    buildPairedTimingSummary,
    getEvaluationStatusPresentations,
    getPurposePresentation,
    projectExclusions,
    projectSnapshotSummary,
    resolveEvaluationQueryState,
} from "./evaluation-contract.mjs";

const EVALUATION_ENDPOINT = "/evaluation";

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

function createDefinitionField(field, className = "evaluation-metric") {
    const container = document.createElement("div");
    container.classList.add(className);

    const term = document.createElement("dt");
    term.classList.add(`${className}__label`);
    term.textContent = field.label;

    const description = document.createElement("dd");
    description.classList.add(`${className}__value`);
    if (field.progressValue === null || field.progressValue === undefined) {
        description.textContent = field.value;
    } else {
        description.classList.add(`${className}__value--bounded`);
        const value = document.createElement("span");
        value.textContent = field.value;
        const progress = document.createElement("progress");
        progress.classList.add("evaluation-metric__progress");
        progress.max = 1;
        progress.value = field.progressValue;
        progress.setAttribute("aria-label", `${field.label} ${field.value}`);
        description.append(value, progress);
    }

    container.append(term, description);
    return container;
}

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

function createFieldList(fields, className = "evaluation-metrics") {
    const list = document.createElement("dl");
    list.classList.add(className);
    list.append(...fields.map((field) => createDefinitionField(field)));
    return list;
}

function createEmptyMessage(message) {
    const empty = document.createElement("p");
    empty.classList.add("evaluation-empty-message");
    empty.textContent = message;
    return empty;
}

function createTable(captionText, columns, rows, emptyMessage) {
    const scroll = document.createElement("div");
    scroll.classList.add("evaluation-table-scroll");

    const table = document.createElement("table");
    table.classList.add("evaluation-table");

    const caption = document.createElement("caption");
    caption.textContent = captionText;

    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const column of columns) {
        const header = document.createElement("th");
        header.setAttribute("scope", "col");
        header.textContent = column.label;
        headerRow.append(header);
    }
    head.append(headerRow);

    const body = document.createElement("tbody");
    if (rows.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.setAttribute("colspan", String(columns.length));
        cell.classList.add("evaluation-table__empty");
        cell.textContent = emptyMessage;
        row.append(cell);
        body.append(row);
    } else {
        for (const item of rows) {
            const row = document.createElement("tr");
            for (const column of columns) {
                const cell = document.createElement("td");
                cell.textContent = item[column.key];
                if (column.identifier === true) {
                    cell.classList.add("identifier");
                }
                row.append(cell);
            }
            body.append(row);
        }
    }

    table.append(caption, head, body);
    scroll.append(table);
    return scroll;
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
        exclusions.replaceChildren(createEmptyMessage("평가 제외 Run 없음"));
        return;
    }
    exclusions.replaceChildren(...items.map((item) => createExclusionCard(item)));
}

function createMethodCard(method) {
    const card = document.createElement("article");
    card.classList.add("evaluation-result-card");

    const heading = document.createElement("h3");
    heading.classList.add("evaluation-result-card__heading");
    heading.textContent = method.method;
    card.append(heading);
    if (!method.available) {
        card.append(createEmptyMessage(method.emptyMessage));
        return card;
    }
    card.append(createFieldList(method.fields));
    return card;
}

function renderMethodComparison(payload) {
    const cards = buildMethodComparison(payload).map((method) => createMethodCard(method));
    const grid = document.createElement("div");
    grid.classList.add("evaluation-method-grid");
    grid.append(...cards);

    const note = document.createElement("p");
    note.classList.add("evaluation-interpretation-note");
    note.textContent = "TTSD는 검출된 Attack Run 기준이며 Run Recall과 함께 해석해야 합니다.";
    methodComparison.replaceChildren(grid, note);
}

function createBurdenCard(burden) {
    const card = document.createElement("article");
    card.classList.add("evaluation-result-card", "evaluation-burden-card");

    const heading = document.createElement("h3");
    heading.classList.add("evaluation-result-card__heading");
    heading.textContent = burden.method;

    const columns = [
        { key: "runId", label: "Run ID", identifier: true },
        { key: "entityId", label: "Entity", identifier: true },
        { key: "familyId", label: "Family", identifier: true },
        { key: "variationId", label: "Variation", identifier: true },
        { key: "repetition", label: "Repetition" },
        { key: "falseAlertEpisodes", label: "False Alert Episodes" },
        { key: "observationSeconds", label: "Observation Seconds" },
    ];
    card.append(
        heading,
        createFieldList(burden.fields),
        createTable(`${burden.method} Normal Run Details`, columns, burden.rows, "대상 Run 없음"),
    );
    return card;
}

function renderNormalAlertBurden(payload) {
    const cards = buildAlertBurden(payload).map((burden) => createBurdenCard(burden));
    const grid = document.createElement("div");
    grid.classList.add("evaluation-burden-grid");
    grid.append(...cards);
    const note = document.createElement("p");
    note.classList.add("evaluation-interpretation-note");
    note.textContent = "FA/BH는 관측된 Benign Run 시간과 함께 해석해야 합니다.";
    normalAlertBurden.replaceChildren(grid, note);
}

function createSummaryGroup(titleText, fields) {
    const group = document.createElement("article");
    group.classList.add("evaluation-summary-group");
    const title = document.createElement("h3");
    title.classList.add("evaluation-result-card__heading");
    title.textContent = titleText;
    group.append(title, createFieldList(fields, "evaluation-paired-summary-grid"));
    return group;
}

function renderPairedTiming(payload) {
    const summary = buildPairedTimingSummary(payload);
    const explanation = document.createElement("p");
    explanation.classList.add("evaluation-interpretation-note");
    explanation.textContent = `${summary.deltaExplanation} Earlier Eligible Path는 Runtime의 최종 경로 선택과는 별개입니다.`;
    pairedTiming.replaceChildren(
        createSummaryGroup("Outcome Counts", summary.counts),
        createSummaryGroup("Both-detected Summary", summary.bothDetected),
        explanation,
    );
}

function renderRunLevelPairedTiming(payload) {
    const columns = [
        { key: "runId", label: "Run ID", identifier: true },
        { key: "fastStatus", label: "Fast Status" },
        { key: "fastEligibleTime", label: "Fast Eligible Time", identifier: true },
        { key: "fastTtsd", label: "Fast TTSD" },
        { key: "fusionStatus", label: "Fusion Status" },
        { key: "fusionEligibleTime", label: "Fusion Eligible Time", identifier: true },
        { key: "fusionTtsd", label: "Fusion TTSD" },
        { key: "outcome", label: "Outcome" },
        { key: "fusionMinusFast", label: "Fusion - Fast" },
        { key: "earlierEligiblePath", label: "Earlier Eligible Path" },
    ];
    runLevelPairedTiming.replaceChildren(
        createTable(
            "Run-level Paired Timing",
            columns,
            buildPairedTimingRows(payload),
            "대상 Run 없음",
        ),
    );
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
