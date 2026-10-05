import {
    buildRunDetailApiPath,
    displayValue,
    extractRunIdFromPathname,
    formatRunTimestamp,
    getDecisionPathLabel,
    getRunTypeLabel,
    getStatusLabel,
    getWinningPathLabel,
    resolveRunDetailQueryState,
} from "./run-detail-contract.mjs";
import { buildDecisionDetailViewPath } from "./decision-detail-contract.mjs";
import { buildEventTimelineViewPath } from "./event-timeline-contract.mjs";

const runDetailView = document.getElementById("run-detail-view");
const runDetailStatus = document.getElementById("run-detail-status");
const runMetadata = document.getElementById("run-metadata");
const currentDecisionStatus = document.getElementById("current-decision-status");
const currentDecision = document.getElementById("current-decision");
const detectionRuntimeStatus = document.getElementById("detection-runtime-status");
const detectionRuntime = document.getElementById("detection-runtime");
const fusionRuntimeStatus = document.getElementById("fusion-runtime-status");
const fusionRuntime = document.getElementById("fusion-runtime");
const decisionHistoryStatus = document.getElementById("decision-history-status");
const decisionHistoryList = document.getElementById("decision-history-list");
const eventTimelineNavigation = document.getElementById("event-timeline-navigation");

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

function renderFields(container, fields) {
    container.replaceChildren(
        ...fields.map(([label, value]) => createDetailField(label, value)),
    );
}

function formatIdentifierList(values) {
    if (!Array.isArray(values) || values.length === 0) {
        return displayValue(null);
    }
    return values.map((value) => displayValue(value)).join(", ");
}

function renderRunMetadata(run) {
    renderFields(runMetadata, [
        ["Run ID", displayValue(run.run_id)],
        ["Scenario ID", displayValue(run.scenario_id)],
        ["Run Type", getRunTypeLabel(run.run_type)],
        ["Target Host", displayValue(run.target_host)],
        ["Start Time", formatRunTimestamp(run.start_time)],
        ["End Time", formatRunTimestamp(run.end_time)],
        ["Family ID", displayValue(run.family_id)],
        ["Variation ID", displayValue(run.variation_id)],
        ["Repetition", displayValue(run.repetition)],
        ["VM Snapshot", displayValue(run.vm_snapshot)],
        ["Sysmon Config Version", displayValue(run.sysmon_config_version)],
        ["Detector Set Version", displayValue(run.detector_set_version)],
        ["Scenario Version", displayValue(run.scenario_version)],
    ]);
}

function renderDecision(decision) {
    renderFields(currentDecision, [
        ["Decision ID", displayValue(decision.decision_id)],
        ["Entity ID", displayValue(decision.entity_id)],
        ["Fast Status", getStatusLabel(decision.fast_status)],
        ["Fusion Status", getStatusLabel(decision.fusion_status)],
        ["Detector Time", formatRunTimestamp(decision.detector_time)],
        ["Fusion Time", formatRunTimestamp(decision.fusion_time)],
        ["기술적 판정 시각 (t_e)", formatRunTimestamp(decision.t_e)],
        ["Decision Path", getDecisionPathLabel(decision.decision_path)],
        ["Winning Path", getWinningPathLabel(decision.winning_path)],
        ["Decision Reason", displayValue(decision.decision_reason)],
        ["Config Version", displayValue(decision.config_version)],
        ["Model Version", displayValue(decision.model_version)],
        ["Rule Version", displayValue(decision.rule_version)],
        ["Detector Set Version", displayValue(decision.detector_set_version)],
    ]);
}

function renderDetectionRuntime(detection) {
    renderFields(detectionRuntime, [
        ["Detector Status", getStatusLabel(detection.detector_status)],
        ["Detector Time", formatRunTimestamp(detection.detector_time)],
        ["Detector ID", displayValue(detection.detector_id)],
        ["Rule ID", displayValue(detection.rule_id)],
        ["Rule Version", displayValue(detection.rule_version)],
        ["Severity", displayValue(detection.severity)],
    ]);
}

function renderFusionRuntime(fusion) {
    renderFields(fusionRuntime, [
        ["Fusion Status", getStatusLabel(fusion.fusion_status)],
        ["Fusion Time", formatRunTimestamp(fusion.fusion_time)],
        ["Score at Decision", displayValue(fusion.score_at_decision)],
        ["Scoring Config Version", displayValue(fusion.scoring_config_version)],
        ["Scoring Profile ID", displayValue(fusion.scoring_profile_id)],
        ["Scoring Method", displayValue(fusion.scoring_method)],
        ["Scorer Version", displayValue(fusion.scorer_version)],
        ["Model Version", displayValue(fusion.model_version)],
        [
            "Contributing Evidence IDs",
            formatIdentifierList(fusion.contributing_evidence_ids),
        ],
    ]);
}

function createDecisionHistoryCard(decision) {
    const card = document.createElement("article");
    card.classList.add("decision-history-card");

    const heading = document.createElement("h3");
    heading.classList.add("decision-history-card__title");
    if (typeof decision.decision_id === "string" && decision.decision_id.trim()) {
        const link = document.createElement("a");
        link.href = buildDecisionDetailViewPath(decision.decision_id);
        link.textContent = decision.decision_id;
        heading.append(link);
    } else {
        heading.textContent = displayValue(decision.decision_id);
    }

    const fields = document.createElement("dl");
    fields.classList.add("detail-fields");
    fields.append(
        createDetailField("Fast Status", getStatusLabel(decision.fast_status)),
        createDetailField("Fusion Status", getStatusLabel(decision.fusion_status)),
        createDetailField("기술적 판정 시각 (t_e)", formatRunTimestamp(decision.t_e)),
        createDetailField("Decision Path", getDecisionPathLabel(decision.decision_path)),
        createDetailField("Winning Path", getWinningPathLabel(decision.winning_path)),
        createDetailField(
            "Supersedes Decision ID",
            displayValue(decision.supersedes_decision_id),
        ),
    );

    card.append(heading, fields);
    return card;
}

function renderDecisionHistory(history) {
    if (history.length === 0) {
        decisionHistoryStatus.textContent = "Decision History가 없습니다.";
        decisionHistoryList.replaceChildren();
        return;
    }
    decisionHistoryStatus.textContent = `Decision History ${history.length}건을 불러왔습니다.`;
    decisionHistoryList.replaceChildren(
        ...history.map((decision) => createDecisionHistoryCard(decision)),
    );
}

function clearDetailContent() {
    runMetadata.replaceChildren();
    currentDecision.replaceChildren();
    detectionRuntime.replaceChildren();
    fusionRuntime.replaceChildren();
    decisionHistoryList.replaceChildren();
    currentDecisionStatus.textContent = "";
    detectionRuntimeStatus.textContent = "";
    fusionRuntimeStatus.textContent = "";
    decisionHistoryStatus.textContent = "";
}

function renderEventTimelineNavigation(runId) {
    const link = document.createElement("a");
    link.href = buildEventTimelineViewPath(runId);
    link.textContent = "Event Timeline 보기";
    eventTimelineNavigation.replaceChildren(link);
}

function renderSuccess(payload) {
    renderRunMetadata(payload.run);
    renderDecisionHistory(payload.decision_history);

    const current = payload.current_decision;
    if (current === null) {
        currentDecisionStatus.textContent = "Current Decision이 없습니다.";
        detectionRuntimeStatus.textContent = "저장된 최신 Detection Runtime 결과가 없습니다.";
        fusionRuntimeStatus.textContent = "저장된 최신 Fusion Runtime 결과가 없습니다.";
        currentDecision.replaceChildren();
        detectionRuntime.replaceChildren();
        fusionRuntime.replaceChildren();
        return;
    }

    currentDecisionStatus.textContent = "Current Decision을 불러왔습니다.";
    renderDecision(current.decision ?? {});

    const detection = current.latest_detection_result;
    if (detection === null || detection === undefined) {
        detectionRuntimeStatus.textContent = "저장된 최신 Detection Runtime 결과가 없습니다.";
        detectionRuntime.replaceChildren();
    } else {
        detectionRuntimeStatus.textContent = "Current Detection Runtime을 불러왔습니다.";
        renderDetectionRuntime(detection);
    }

    const fusion = current.latest_fusion_result;
    if (fusion === null || fusion === undefined) {
        fusionRuntimeStatus.textContent = "저장된 최신 Fusion Runtime 결과가 없습니다.";
        fusionRuntime.replaceChildren();
    } else {
        fusionRuntimeStatus.textContent = "Current Fusion Runtime을 불러왔습니다.";
        renderFusionRuntime(fusion);
    }
}

function renderRunDetailState(state) {
    runDetailStatus.textContent = state.message;
    if (state.queryState === "success") {
        renderSuccess(state.payload);
        return;
    }
    clearDetailContent();
}

async function fetchRunDetail(runId) {
    const response = await fetch(buildRunDetailApiPath(runId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Run Detail API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function loadRunDetail() {
    let state = resolveRunDetailQueryState(null, { kind: "loading" });
    renderRunDetailState(state);

    const runId = extractRunIdFromPathname(window.location.pathname);
    if (runId === null) {
        state = resolveRunDetailQueryState(state, { kind: "error" });
        renderRunDetailState(state);
        return;
    }
    renderEventTimelineNavigation(runId);

    try {
        state = resolveRunDetailQueryState(state, await fetchRunDetail(runId));
    } catch {
        state = resolveRunDetailQueryState(state, { kind: "error" });
    }
    renderRunDetailState(state);
}

if (
    runDetailView !== null
    && runDetailStatus !== null
    && runMetadata !== null
    && currentDecisionStatus !== null
    && currentDecision !== null
    && detectionRuntimeStatus !== null
    && detectionRuntime !== null
    && fusionRuntimeStatus !== null
    && fusionRuntime !== null
    && decisionHistoryStatus !== null
    && decisionHistoryList !== null
    && eventTimelineNavigation !== null
) {
    void loadRunDetail();
}
