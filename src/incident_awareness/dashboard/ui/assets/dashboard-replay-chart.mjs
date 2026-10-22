import { formatOperatorTimestamp } from "./dashboard-contract.mjs";
import { createScoreTrajectoryChart, scoreTimestampDetails } from "./fusion-score-chart.mjs";

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
// Widest callout ("HH:mm:ss 탐지 구간 종료 · 재생 경계") at the 14px bold callout font.
const CALLOUT_MAX_WIDTH = 260;

function instant(value) {
    return typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? Date.parse(value) : NaN;
}

function chartX(model, timestamp) {
    if (model.points.length === 0 || !Number.isFinite(timestamp)) return null;
    const first = instant(model.points[0].timestamp);
    const last = instant(model.points.at(-1).timestamp);
    if (timestamp < first || timestamp > last) return null;
    if (first === last) return model.points[0].x;
    return model.plot.left + ((timestamp - first) / (last - first)) * model.plot.width;
}

// Stored Episode fields define transitions. Trace state and tick positions never create events.
// decisionTime: undefined when no Decision is known, null when the stored Decision has no t_e.
export function buildDashboardReplayPresentation(model, fusionResult, decisionTime) {
    const points = model.points;
    const first = points.length === 0 ? null : instant(points[0].timestamp);
    const last = points.length === 0 ? null : instant(points.at(-1).timestamp);
    const episodes = Array.isArray(fusionResult?.fusion_episodes) ? fusionResult.fusion_episodes : [];
    const bands = [];
    const transitions = [];
    const openEpisodes = [];
    let unavailable = 0;
    for (const [index, episode] of episodes.entries()) {
        const start = instant(episode?.start_time);
        const end = instant(episode?.end_time);
        const episodeLabel = episode?.episode_id ?? `구간 ${index + 1}`;
        if (!Number.isFinite(start)) { unavailable += 1; continue; }
        transitions.push({ kind: "start", label: "탐지 구간 시작", timestamp: episode.start_time,
            x: chartX(model, start), episodeLabel, reason: null, source: "fusion_episodes.start_time" });
        if (episode.end_time == null) { openEpisodes.push(episodeLabel); continue; }
        if (!Number.isFinite(end) || end < start) { unavailable += 1; continue; }
        const label = episode.end_reason === "released" ? "탐지 구간 해제"
            : episode.end_reason === "run_end" ? "탐지 구간 종료 · 관측 경계"
                : episode.end_reason === "replay_end" ? "탐지 구간 종료 · 재생 경계"
                    : "탐지 구간 종료 · 사유 미확인";
        transitions.push({ kind: episode.end_reason === "released" ? "end" : "boundary", label,
            timestamp: episode.end_time, x: chartX(model, end), episodeLabel,
            reason: episode.end_reason ?? null, source: "fusion_episodes.end_time" });
        if (first !== null && end > first && start < last && end > start) {
            bands.push({ startX: chartX(model, Math.max(first, start)),
                endX: chartX(model, Math.min(last, end)) });
        }
    }
    // Even coincident times remain separate stored facts: t_e is never inferred from Fusion.
    const technicalDecisionTime = instant(decisionTime);
    if (Number.isFinite(technicalDecisionTime)) {
        transitions.push({ kind: "decision", label: "종합 판단 시각 (t_e)", timestamp: decisionTime,
            x: chartX(model, technicalDecisionTime), source: "Decision.t_e", reason: null });
    }
    const decisionStatus = decisionTime === undefined ? null
        : decisionTime === null ? "pending"
            : Number.isFinite(technicalDecisionTime) ? "recorded" : "invalid";
    transitions.sort((left, right) => instant(left.timestamp) - instant(right.timestamp));
    const highlightedIndices = new Set();
    if (points.length > 0) { highlightedIndices.add(0); highlightedIndices.add(points.length - 1); }
    for (let index = 1; index < points.length; index += 1) {
        if (points[index].policy_state !== points[index - 1].policy_state) highlightedIndices.add(index);
    }
    for (const transition of transitions) {
        const index = points.findIndex(point => instant(point.timestamp) === instant(transition.timestamp));
        if (index !== -1) highlightedIndices.add(index);
    }
    const clocks = model.xTicks.map(tick => scoreTimestampDetails(tick.timestamp));
    const milliseconds = new Set(clocks.map(clock => clock.time)).size < clocks.length;
    return { bands, transitions, highlightedIndices, unavailable, openEpisodes, decisionStatus,
        decisionOriginal: decisionStatus === "invalid" ? String(decisionTime) : null,
        tickLabels: clocks.map(clock => milliseconds ? clock.kst.slice(11, 23) : clock.time) };
}

function createSvgElement(tagName, className) {
    const element = document.createElementNS(SVG_NAMESPACE, tagName);
    element.setAttribute("class", className);
    return element;
}

function createTransitionRecords(presentation, judgment = null) {
    const section = document.createElement("section");
    section.classList.add("dashboard-replay-chart__records");
    section.setAttribute("aria-label", "저장된 전환 기록 · KST");
    const heading = document.createElement("h4");
    heading.textContent = "전환 기록 · KST";
    section.append(heading);
    if (judgment !== null) {
        const result = document.createElement("p");
        result.classList.add("dashboard-replay-chart__judgment");
        result.textContent = `저장된 판단: ${judgment}`;
        section.append(result);
    }
    const list = document.createElement("ol");
    for (const transition of presentation.transitions) {
        const clock = scoreTimestampDetails(transition.timestamp);
        const item = document.createElement("li");
        const line = document.createElement("span");
        line.textContent = `${formatOperatorTimestamp(transition.timestamp, { precise: true })} — ${transition.label}`
            + (transition.episodeLabel ? ` · ${transition.episodeLabel}` : "");
        item.append(line);
        const details = document.createElement("details");
        const summary = document.createElement("summary");
        summary.textContent = "시각·원천 상세";
        const source = document.createElement("p");
        source.textContent = `UTC ${clock.utc} · 원본 ${clock.original} · 원천 ${transition.source}`
            + (transition.reason === null ? "" : ` · 종료 사유 ${transition.reason}`);
        details.append(summary, source);
        item.append(details);
        list.append(item);
    }
    section.append(list);
    if (!presentation.transitions.some(item => item.kind !== "decision")) {
        const empty = document.createElement("p");
        empty.textContent = "탐지 구간 전환 기록 없음";
        section.append(empty);
    }
    for (const episodeLabel of presentation.openEpisodes) {
        const open = document.createElement("p");
        open.textContent = `${episodeLabel} · 종료 시각 저장 없음`;
        section.append(open);
    }
    if (presentation.unavailable > 0) {
        const unavailable = document.createElement("p");
        unavailable.textContent = `시각이 없거나 유효하지 않아 표시할 수 없는 저장 구간 항목 ${presentation.unavailable}건`;
        section.append(unavailable);
    }
    if (presentation.decisionStatus === "pending" || presentation.decisionStatus === "invalid") {
        const decision = document.createElement("p");
        decision.textContent = presentation.decisionStatus === "pending"
            ? "종합 판단 시각: 미확정"
            : `종합 판단 시각: 확인 불가 · 원본 ${presentation.decisionOriginal}`;
        section.append(decision);
    }
    return section;
}

export function createDashboardReplayRecords(fusionResult, decisionTime, judgment = null) {
    return createTransitionRecords(buildDashboardReplayPresentation({ points: [], xTicks: [] }, fusionResult, decisionTime), judgment);
}

export function createDashboardReplayChart(model, fusionResult, decisionTime, judgment = null) {
    const chart = createScoreTrajectoryChart(model, { showCriteria: false });
    chart.classList.add("dashboard-replay-chart");
    const svg = chart.querySelector(".fusion-score-chart__svg");
    const presentation = buildDashboardReplayPresentation(model, fusionResult, decisionTime);
    const bandLayer = createSvgElement("g", "dashboard-replay-chart__bands");
    bandLayer.setAttribute("pointer-events", "none");
    for (const band of presentation.bands) {
        const rect = createSvgElement("rect", "dashboard-replay-chart__episode");
        rect.setAttribute("x", String(band.startX));
        rect.setAttribute("y", String(model.plot.top));
        rect.setAttribute("width", String(band.endX - band.startX));
        rect.setAttribute("height", String(model.plot.height));
        bandLayer.append(rect);
    }
    const trajectory = svg.querySelector(".fusion-score-chart__trajectory");
    if (model.points.length > 1) {
        const area = createSvgElement("polygon", "dashboard-replay-chart__area");
        area.setAttribute("points", [
            `${model.points[0].x},${model.plot.bottom}`,
            ...model.points.map(point => `${point.x},${point.y}`),
            `${model.points.at(-1).x},${model.plot.bottom}`,
        ].join(" "));
        bandLayer.append(area);
    }
    trajectory.before(bandLayer);
    const pointMarkers = svg.querySelectorAll(".fusion-score-chart__point");
    for (const [index, marker] of pointMarkers.entries()) {
        marker.classList.add(presentation.highlightedIndices.has(index)
            ? "dashboard-replay-chart__point--key" : "dashboard-replay-chart__point--quiet");
    }
    const description = svg.querySelector("desc");
    if (presentation.transitions.length > 0) {
        description.textContent += ` 저장된 전환: ${presentation.transitions.map(
            transition => `${transition.label} ${scoreTimestampDetails(transition.timestamp).kst}`,
        ).join(", ")}.`;
    }
    const transitionLayer = createSvgElement("g", "dashboard-replay-chart__transitions");
    transitionLayer.setAttribute("pointer-events", "none");
    for (const [index, transition] of presentation.transitions.filter(item => item.x !== null).entries()) {
        const line = createSvgElement("line",
            `dashboard-replay-chart__transition dashboard-replay-chart__transition--${transition.kind}`);
        line.setAttribute("x1", String(transition.x));
        line.setAttribute("x2", String(transition.x));
        line.setAttribute("y1", String(model.plot.top));
        line.setAttribute("y2", String(model.plot.bottom));
        // The exact stored clock sits on the marker so it is never read off a nearby tick.
        const clock = scoreTimestampDetails(transition.timestamp);
        const anchorEnd = transition.x + 8 + CALLOUT_MAX_WIDTH > model.width;
        const label = createSvgElement("text", "dashboard-replay-chart__callout");
        label.setAttribute("x", String(anchorEnd ? transition.x - 8 : transition.x + 8));
        label.setAttribute("y", String(16 + (index % 3) * 15));
        label.setAttribute("text-anchor", anchorEnd ? "end" : "start");
        label.textContent = `${clock.time} ${transition.label}`;
        const title = document.createElementNS(SVG_NAMESPACE, "title");
        title.textContent = `${clock.kst} · UTC ${clock.utc} · 원본 ${clock.original}`;
        label.append(title);
        transitionLayer.append(line, label);
    }
    svg.append(transitionLayer);
    if (presentation.bands.length > 0) {
        const item = document.createElement("li");
        const symbol = document.createElement("span");
        symbol.classList.add("dashboard-replay-chart__episode-legend");
        symbol.setAttribute("aria-hidden", "true");
        const text = document.createElement("span");
        text.textContent = "탐지 구간";
        item.append(symbol, text);
        chart.querySelector(".fusion-score-chart__legend").append(item);
    }
    // Reading order: chart, stored transition records, then the full score table and details.
    const records = createTransitionRecords(presentation, judgment);
    const technical = chart.querySelector(".fusion-score-chart__technical");
    if (technical) technical.before(records);
    else chart.append(records);
    return chart;
}
