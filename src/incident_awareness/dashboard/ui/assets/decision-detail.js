import {
    buildDecisionDetailApiPath,
    buildRunDetailViewPath,
    displayValue,
    extractDecisionIdFromPathname,
    formatRunTimestamp,
    getDecisionPathLabel,
    getStatusLabel,
    getWinningPathLabel,
    resolveDecisionDetailQueryState,
} from "./decision-detail-contract.mjs";

const decisionDetailView = document.getElementById("decision-detail-view");
const decisionDetailStatus = document.getElementById("decision-detail-status");
const historicalDecision = document.getElementById("historical-decision");
const runtimeSnapshotStatus = document.getElementById("runtime-snapshot-status");
const historicalDetectionStatus = document.getElementById("historical-detection-status");
const historicalDetection = document.getElementById("historical-detection");
const historicalFusionStatus = document.getElementById("historical-fusion-status");
const historicalFusion = document.getElementById("historical-fusion");
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

function renderDecision(decision) {
    renderFields(historicalDecision, [
        ["Decision ID", displayValue(decision.decision_id)],
        ["Run ID", displayValue(decision.run_id)],
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
        ["Supersedes Decision ID", displayValue(decision.supersedes_decision_id)],
    ]);
}

function renderDetectionRuntime(detection) {
    renderFields(historicalDetection, [
        ["Detector Status", getStatusLabel(detection.detector_status)],
        ["Detector Time", formatRunTimestamp(detection.detector_time)],
        ["Detector ID", displayValue(detection.detector_id)],
        ["Rule ID", displayValue(detection.rule_id)],
        ["Rule Version", displayValue(detection.rule_version)],
        ["Severity", displayValue(detection.severity)],
    ]);
}

function renderFusionRuntime(fusion) {
    renderFields(historicalFusion, [
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

function renderBackNavigation(runId) {
    runDetailBackNavigation.replaceChildren();
    if (typeof runId !== "string" || !runId.trim()) {
        return;
    }
    const link = document.createElement("a");
    link.href = buildRunDetailViewPath(runId);
    link.textContent = "Run Detail로 돌아가기";
    runDetailBackNavigation.append(link);
}

function clearDetailContent() {
    historicalDecision.replaceChildren();
    historicalDetection.replaceChildren();
    historicalFusion.replaceChildren();
    runtimeSnapshotStatus.textContent = "";
    historicalDetectionStatus.textContent = "";
    historicalFusionStatus.textContent = "";
    runDetailBackNavigation.replaceChildren();
}

function renderSuccess(payload) {
    renderDecision(payload.decision);
    renderBackNavigation(payload.decision.run_id);

    const snapshot = payload.runtime_snapshot;
    if (snapshot === null) {
        runtimeSnapshotStatus.textContent = "저장된 Historical Runtime Snapshot이 없습니다.";
        historicalDetectionStatus.textContent = "저장된 Historical Detection Runtime이 없습니다.";
        historicalFusionStatus.textContent = "저장된 Historical Fusion Runtime이 없습니다.";
        historicalDetection.replaceChildren();
        historicalFusion.replaceChildren();
        return;
    }

    runtimeSnapshotStatus.textContent = "Historical Runtime Snapshot을 불러왔습니다.";
    historicalDetectionStatus.textContent = "Historical Detection Runtime을 불러왔습니다.";
    historicalFusionStatus.textContent = "Historical Fusion Runtime을 불러왔습니다.";
    renderDetectionRuntime(snapshot.detection_result);
    renderFusionRuntime(snapshot.fusion_result);
}

function renderDecisionDetailState(state) {
    decisionDetailStatus.textContent = state.message;
    if (state.queryState === "success") {
        renderSuccess(state.payload);
        return;
    }
    clearDetailContent();
}

async function fetchDecisionDetail(decisionId) {
    const response = await fetch(buildDecisionDetailApiPath(decisionId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Historical Decision API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function loadDecisionDetail() {
    let state = resolveDecisionDetailQueryState(null, { kind: "loading" });
    renderDecisionDetailState(state);

    const decisionId = extractDecisionIdFromPathname(window.location.pathname);
    if (decisionId === null) {
        state = resolveDecisionDetailQueryState(state, { kind: "error" });
        renderDecisionDetailState(state);
        return;
    }

    try {
        state = resolveDecisionDetailQueryState(state, await fetchDecisionDetail(decisionId));
    } catch {
        state = resolveDecisionDetailQueryState(state, { kind: "error" });
    }
    renderDecisionDetailState(state);
}

if (
    decisionDetailView !== null
    && decisionDetailStatus !== null
    && historicalDecision !== null
    && runtimeSnapshotStatus !== null
    && historicalDetectionStatus !== null
    && historicalDetection !== null
    && historicalFusionStatus !== null
    && historicalFusion !== null
    && runDetailBackNavigation !== null
) {
    void loadDecisionDetail();
}
