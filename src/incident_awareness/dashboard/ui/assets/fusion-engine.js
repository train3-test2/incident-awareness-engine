import {
    buildFusionEngineApiPath,
    buildScoreTrajectoryModel,
    extractFusionEngineRunIdFromPathname,
    resolveFusionEngineQueryState,
} from "./fusion-engine-contract.mjs";
import { buildRunDetailViewPath } from "./run-detail-contract.mjs";
import {
    displayValue,
    formatRunTimestamp,
    getDecisionPathLabel,
    getStatusLabel,
    getWinningPathLabel,
} from "./run-detail-contract.mjs";

const fusionEngineView = document.getElementById("fusion-engine-view");
const fusionEngineStatus = document.getElementById("fusion-engine-status");
const fusionRuntimeStatus = document.getElementById("fusion-runtime-status");
const fusionRuntimeSummary = document.getElementById("fusion-runtime-summary");
const runtimeConfigStatus = document.getElementById("runtime-config-status");
const runtimeConfigSummary = document.getElementById("runtime-config-summary");
const stoppingTraceStatus = document.getElementById("stopping-trace-status");
const stoppingTraceSummary = document.getElementById("stopping-trace-summary");
const fusionScoreTrajectoryStatus = document.getElementById(
    "fusion-score-trajectory-status",
);
const fusionScoreTrajectory = document.getElementById("fusion-score-trajectory");
const decisionTimingStatus = document.getElementById("decision-timing-status");
const decisionTimingSummary = document.getElementById("decision-timing-summary");
const fusionEpisodesStatus = document.getElementById("fusion-episodes-status");
const fusionEpisodesList = document.getElementById("fusion-episodes-list");
const runDetailBackNavigation = document.getElementById("run-detail-back-navigation");

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const SCORE_CHART_DIMENSIONS = {
    width: 960,
    height: 420,
    padding: { top: 32, right: 72, bottom: 52, left: 58 },
};

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

function renderFusionRuntime(run, fusion) {
    if (fusion === null) {
        fusionRuntimeStatus.textContent = "저장된 최신 Fusion Runtime 결과가 없습니다.";
        renderFields(fusionRuntimeSummary, [
            ["Run ID", displayValue(run.run_id)],
            ["Target Host", displayValue(run.target_host)],
        ]);
        return;
    }
    fusionRuntimeStatus.textContent = "Fusion Runtime을 불러왔습니다.";
    renderFields(fusionRuntimeSummary, [
        ["Run ID", displayValue(run.run_id)],
        ["Target Host", displayValue(run.target_host)],
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

function renderRuntimeConfig(config) {
    if (config === null) {
        runtimeConfigStatus.textContent = "Runtime Config Snapshot이 없습니다.";
        runtimeConfigSummary.replaceChildren();
        return;
    }
    runtimeConfigStatus.textContent = "Runtime Config Snapshot을 불러왔습니다.";
    renderFields(runtimeConfigSummary, [
        ["Run ID", displayValue(config.run_id)],
        ["Entity ID", displayValue(config.entity_id)],
        ["Config Version", displayValue(config.config_version)],
        ["Model Version", displayValue(config.model_version)],
        ["Window Size (sec)", displayValue(config.window.window_size_sec)],
        ["Replay Step (sec)", displayValue(config.replay.step_size_sec)],
        ["Scoring Method", displayValue(config.scoring.method)],
        ["Scorer Version", displayValue(config.scoring.scorer_version)],
        ["Scoring Profile ID", displayValue(config.scoring.profile_id)],
        ["Evidence Types", formatIdentifierList(config.scoring.evidence_types)],
        ["Threshold On", displayValue(config.stopping.threshold_on)],
        ["Threshold Off", displayValue(config.stopping.threshold_off)],
        ["Persistence K", displayValue(config.stopping.persistence_k)],
    ]);
}

function renderStoppingTrace(trace) {
    if (trace === null) {
        stoppingTraceStatus.textContent = "저장된 Stopping Trace가 없습니다.";
        stoppingTraceSummary.replaceChildren();
        return;
    }
    stoppingTraceStatus.textContent = trace.points.length === 0
        ? "Stopping Trace point가 없습니다."
        : `Stopping Trace point ${trace.points.length}개를 불러왔습니다.`;
    renderFields(stoppingTraceSummary, [
        ["Run ID", displayValue(trace.run_id)],
        ["Entity ID", displayValue(trace.entity_id)],
        ["Scoring Config Version", displayValue(trace.scoring_config_version)],
        ["Point Count", displayValue(trace.points.length)],
    ]);
}

function createSvgElement(name, className = null) {
    const element = document.createElementNS(SVG_NAMESPACE, name);
    if (className !== null) {
        element.setAttribute("class", className);
    }
    return element;
}

function createSvgText(className, x, y, value) {
    const text = createSvgElement("text", className);
    text.setAttribute("x", String(x));
    text.setAttribute("y", String(y));
    text.textContent = value;
    return text;
}

function createChartLegend(model) {
    const legend = document.createElement("ul");
    legend.classList.add("fusion-score-chart__legend");
    const entries = [
        ["score", "Score"],
        ...model.thresholds.map((threshold) => [
            `threshold-${threshold.kind}`,
            `${threshold.label} ${threshold.value.toFixed(2)}`,
        ]),
        ["policy-on", "Policy ON"],
        ["policy-off", "Policy OFF"],
    ];
    for (const [kind, label] of entries) {
        const item = document.createElement("li");
        const symbol = document.createElement("span");
        symbol.classList.add("fusion-score-chart__legend-symbol");
        symbol.classList.add(`fusion-score-chart__legend-symbol--${kind}`);
        symbol.setAttribute("aria-hidden", "true");
        const text = document.createElement("span");
        text.textContent = label;
        item.append(symbol, text);
        legend.append(item);
    }
    return legend;
}

export function createTraceTable(points) {
    const details = document.createElement("details");
    details.classList.add("fusion-trace-details");
    const summary = document.createElement("summary");
    summary.textContent = `전체 Point ${points.length}개 보기`;

    const wrapper = document.createElement("div");
    wrapper.classList.add("fusion-trace-table-wrapper");
    const table = document.createElement("table");
    table.classList.add("fusion-trace-table");

    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const heading of [
        "Timestamp",
        "Score",
        "Policy State",
        "Persistence Count",
    ]) {
        const cell = document.createElement("th");
        cell.setAttribute("scope", "col");
        cell.textContent = heading;
        headerRow.append(cell);
    }
    head.append(headerRow);

    const body = document.createElement("tbody");
    for (const point of points) {
        const row = document.createElement("tr");
        const values = [
            formatRunTimestamp(point.timestamp),
            displayValue(point.score),
            point.policy_state === "on" ? "Policy ON" : "Policy OFF",
            displayValue(point.persistence_count),
        ];
        for (const value of values) {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.append(cell);
        }
        body.append(row);
    }
    table.append(head, body);
    wrapper.append(table);
    details.append(summary, wrapper);
    return details;
}

function createScoreTrajectoryChart(model) {
    const chart = document.createElement("div");
    chart.classList.add("fusion-score-chart");

    const svg = createSvgElement("svg", "fusion-score-chart__svg");
    svg.setAttribute("viewBox", `0 0 ${model.width} ${model.height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute(
        "aria-labelledby",
        "fusion-score-chart-title fusion-score-chart-description",
    );

    const title = createSvgElement("title");
    title.setAttribute("id", "fusion-score-chart-title");
    title.textContent = "Temporal Fusion score trajectory";
    const description = createSvgElement("desc");
    description.setAttribute("id", "fusion-score-chart-description");
    description.textContent = (
        "저장된 FusionStoppingTrace score와 Runtime Config threshold를 표시합니다."
    );
    svg.append(title, description);

    for (const tick of model.yTicks) {
        const grid = createSvgElement("line", "fusion-score-chart__grid");
        grid.setAttribute("x1", String(model.plot.left));
        grid.setAttribute("x2", String(model.plot.right));
        grid.setAttribute("y1", String(tick.y));
        grid.setAttribute("y2", String(tick.y));
        const label = createSvgText(
            "fusion-score-chart__axis-label",
            model.plot.left - 12,
            tick.y + 4,
            tick.label,
        );
        label.setAttribute("text-anchor", "end");
        svg.append(grid, label);
    }

    for (const threshold of model.thresholds) {
        const line = createSvgElement(
            "line",
            `fusion-score-chart__threshold fusion-score-chart__threshold--${threshold.kind}`,
        );
        line.setAttribute("x1", String(model.plot.left));
        line.setAttribute("x2", String(model.plot.right));
        line.setAttribute("y1", String(threshold.y));
        line.setAttribute("y2", String(threshold.y));
        const label = createSvgText(
            "fusion-score-chart__threshold-label",
            model.plot.right + 8,
            threshold.y + 4,
            `${threshold.label} ${threshold.value.toFixed(2)}`,
        );
        svg.append(line, label);
    }

    const trajectory = createSvgElement("polyline", "fusion-score-chart__trajectory");
    trajectory.setAttribute(
        "points",
        model.points.map((point) => `${point.x},${point.y}`).join(" "),
    );
    svg.append(trajectory);

    for (const point of model.points) {
        const marker = point.policy_state === "on"
            ? createSvgElement(
                "rect",
                "fusion-score-chart__point fusion-score-chart__point--on",
            )
            : createSvgElement(
                "circle",
                "fusion-score-chart__point fusion-score-chart__point--off",
            );
        if (point.policy_state === "on") {
            marker.setAttribute("x", String(point.x - 5));
            marker.setAttribute("y", String(point.y - 5));
            marker.setAttribute("width", "10");
            marker.setAttribute("height", "10");
        } else {
            marker.setAttribute("cx", String(point.x));
            marker.setAttribute("cy", String(point.y));
            marker.setAttribute("r", "5");
        }
        const markerTitle = createSvgElement("title");
        markerTitle.textContent = `${formatRunTimestamp(point.timestamp)}, score ${point.score}, ${
            point.policy_state === "on" ? "Policy ON" : "Policy OFF"
        }`;
        marker.append(markerTitle);
        svg.append(marker);
    }

    chart.append(svg, createChartLegend(model), createTraceTable(model.points));
    return chart;
}

function renderScoreTrajectory(trace, runtimeConfig) {
    if (trace === null) {
        fusionScoreTrajectoryStatus.textContent = "저장된 Stopping Trace가 없습니다.";
        fusionScoreTrajectory.replaceChildren();
        return;
    }
    if (trace.points.length === 0) {
        fusionScoreTrajectoryStatus.textContent = "Stopping Trace point가 없습니다.";
        fusionScoreTrajectory.replaceChildren();
        return;
    }

    const model = buildScoreTrajectoryModel(
        trace,
        runtimeConfig,
        SCORE_CHART_DIMENSIONS,
    );
    fusionScoreTrajectoryStatus.textContent = runtimeConfig === null
        ? "Runtime Config Snapshot이 없어 threshold 기준선을 표시할 수 없습니다."
        : `Score point ${model.points.length}개와 threshold 기준선을 표시합니다.`;
    fusionScoreTrajectory.replaceChildren(createScoreTrajectoryChart(model));
}

function renderDecisionTiming(decision) {
    if (decision === null) {
        decisionTimingStatus.textContent = "Current Decision이 없습니다.";
        decisionTimingSummary.replaceChildren();
        return;
    }
    decisionTimingStatus.textContent = "Current Decision timing을 불러왔습니다.";
    renderFields(decisionTimingSummary, [
        ["Decision ID", displayValue(decision.decision_id)],
        ["Entity ID", displayValue(decision.entity_id)],
        ["Fast Status", getStatusLabel(decision.fast_status)],
        ["Fusion Status", getStatusLabel(decision.fusion_status)],
        ["Detector Time", formatRunTimestamp(decision.detector_time)],
        ["Fusion Time", formatRunTimestamp(decision.fusion_time)],
        ["기술적 판정 시각 (t_e)", formatRunTimestamp(decision.t_e)],
        ["Decision Path", getDecisionPathLabel(decision.decision_path)],
        ["Winning Path", getWinningPathLabel(decision.winning_path)],
    ]);
}

function createFusionEpisodeCard(episode) {
    const card = document.createElement("article");
    card.classList.add("fusion-engine-episode");

    const heading = document.createElement("h3");
    heading.classList.add("fusion-engine-episode__title");
    heading.textContent = displayValue(episode.episode_id);

    const fields = document.createElement("dl");
    fields.classList.add("detail-fields");
    fields.append(
        createDetailField("Start Time", formatRunTimestamp(episode.start_time)),
        createDetailField("End Time", formatRunTimestamp(episode.end_time)),
        createDetailField("End Reason", displayValue(episode.end_reason)),
        createDetailField("Score at Start", displayValue(episode.score_at_start)),
        createDetailField("Peak Score", displayValue(episode.peak_score)),
        createDetailField(
            "Contributing Evidence IDs",
            formatIdentifierList(episode.contributing_evidence_ids),
        ),
    );

    card.append(heading, fields);
    return card;
}

function renderFusionEpisodes(fusion) {
    if (fusion === null) {
        fusionEpisodesStatus.textContent = "Fusion Runtime이 없어 Episode를 표시할 수 없습니다.";
        fusionEpisodesList.replaceChildren();
        return;
    }
    const episodes = fusion.fusion_episodes;
    if (episodes.length === 0) {
        fusionEpisodesStatus.textContent = "저장된 Fusion Episode가 없습니다.";
        fusionEpisodesList.replaceChildren();
        return;
    }
    fusionEpisodesStatus.textContent = `Fusion Episode ${episodes.length}건을 불러왔습니다.`;
    fusionEpisodesList.replaceChildren(
        ...episodes.map((episode) => createFusionEpisodeCard(episode)),
    );
}

function clearContent() {
    fusionRuntimeSummary.replaceChildren();
    runtimeConfigSummary.replaceChildren();
    stoppingTraceSummary.replaceChildren();
    fusionScoreTrajectory.replaceChildren();
    decisionTimingSummary.replaceChildren();
    fusionEpisodesList.replaceChildren();
    fusionRuntimeStatus.textContent = "";
    runtimeConfigStatus.textContent = "";
    stoppingTraceStatus.textContent = "";
    fusionScoreTrajectoryStatus.textContent = "";
    decisionTimingStatus.textContent = "";
    fusionEpisodesStatus.textContent = "";
}

function renderSuccess(payload) {
    renderFusionRuntime(payload.run, payload.fusion_result);
    renderRuntimeConfig(payload.runtime_config_snapshot);
    renderStoppingTrace(payload.stopping_trace);
    renderScoreTrajectory(payload.stopping_trace, payload.runtime_config_snapshot);
    renderDecisionTiming(payload.current_decision);
    renderFusionEpisodes(payload.fusion_result);
}

function renderFusionEngineState(state) {
    fusionEngineStatus.textContent = state.message;
    if (state.queryState === "success") {
        renderSuccess(state.payload);
        return;
    }
    clearContent();
}

function renderRunDetailNavigation(runId) {
    const link = document.createElement("a");
    link.href = buildRunDetailViewPath(runId);
    link.textContent = "Run Detail로 돌아가기";
    runDetailBackNavigation.replaceChildren(link);
}

async function fetchFusionEngine(runId) {
    const response = await fetch(buildFusionEngineApiPath(runId), {
        headers: {
            Accept: "application/json",
        },
        cache: "no-store",
    });
    if (response.status === 404) {
        return { kind: "not_found" };
    }
    if (!response.ok) {
        throw new Error("Fusion Engine API request failed");
    }
    return { kind: "success", payload: await response.json() };
}

async function loadFusionEngine() {
    let state = resolveFusionEngineQueryState(null, { kind: "loading" });
    renderFusionEngineState(state);

    const runId = extractFusionEngineRunIdFromPathname(window.location.pathname);
    if (runId === null) {
        state = resolveFusionEngineQueryState(state, { kind: "error" });
        renderFusionEngineState(state);
        return;
    }
    renderRunDetailNavigation(runId);

    try {
        state = resolveFusionEngineQueryState(state, await fetchFusionEngine(runId));
    } catch {
        state = resolveFusionEngineQueryState(state, { kind: "error" });
    }
    renderFusionEngineState(state);
}

if (
    fusionEngineView !== null
    && fusionEngineStatus !== null
    && fusionRuntimeStatus !== null
    && fusionRuntimeSummary !== null
    && runtimeConfigStatus !== null
    && runtimeConfigSummary !== null
    && stoppingTraceStatus !== null
    && stoppingTraceSummary !== null
    && fusionScoreTrajectoryStatus !== null
    && fusionScoreTrajectory !== null
    && decisionTimingStatus !== null
    && decisionTimingSummary !== null
    && fusionEpisodesStatus !== null
    && fusionEpisodesList !== null
    && runDetailBackNavigation !== null
) {
    void loadFusionEngine();
}
