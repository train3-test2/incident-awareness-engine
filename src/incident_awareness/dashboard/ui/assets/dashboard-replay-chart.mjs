import { formatRunTimestamp } from "./run-detail-contract.mjs";
import { createScoreTrajectoryChart } from "./fusion-score-chart.mjs";

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";

function chartX(model, timestamp) {
    const first = Date.parse(model.points[0].timestamp);
    const last = Date.parse(model.points.at(-1).timestamp);
    if (first === last) {
        return model.points[0].x;
    }
    return model.plot.left + ((timestamp - first) / (last - first)) * model.plot.width;
}

function compactTimestamp(timestamp, includeMilliseconds) {
    const date = new Date(timestamp);
    const time = date.toLocaleTimeString("ko-KR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
    return includeMilliseconds
        ? `${time}.${String(date.getMilliseconds()).padStart(3, "0")}`
        : time;
}

export function buildDashboardReplayPresentation(model, fusionResult, decisionTime = null) {
    const points = model.points;
    const first = points.length === 0 ? null : Date.parse(points[0].timestamp);
    const last = points.length === 0 ? null : Date.parse(points.at(-1).timestamp);
    const episodes = Array.isArray(fusionResult?.fusion_episodes)
        ? fusionResult.fusion_episodes
        : [];
    const bands = [];
    const transitions = [];

    for (const episode of episodes) {
        const start = Date.parse(episode.start_time);
        const end = episode.end_time === null ? null : Date.parse(episode.end_time);
        if (first === null || !Number.isFinite(start) || start < first || start > last) {
            continue;
        }
        transitions.push({
            kind: "start",
            label: "판단 진입",
            timestamp: episode.start_time,
            x: chartX(model, start),
        });
        if (end !== null && Number.isFinite(end) && end >= start && end <= last) {
            if (end > start) {
                bands.push({ startX: chartX(model, start), endX: chartX(model, end) });
            }
            transitions.push({
                kind: "end",
                label: episode.end_reason === "released" ? "판단 해제" : "Episode 종료",
                timestamp: episode.end_time,
                x: chartX(model, end),
            });
        }
    }
    const technicalDecisionTime = decisionTime === null ? NaN : Date.parse(decisionTime);
    if (
        first !== null
        && Number.isFinite(technicalDecisionTime)
        && technicalDecisionTime >= first
        && technicalDecisionTime <= last
    ) {
        const matchingTransition = transitions.find(
            (transition) => Date.parse(transition.timestamp) === technicalDecisionTime,
        );
        if (matchingTransition === undefined) {
            transitions.push({
                kind: "decision",
                label: "기술적 판단 t_e",
                timestamp: decisionTime,
                x: chartX(model, technicalDecisionTime),
            });
        } else {
            matchingTransition.label += " · t_e";
        }
    }

    const highlightedIndices = new Set();
    if (points.length > 0) {
        highlightedIndices.add(0);
        highlightedIndices.add(points.length - 1);
    }
    for (let index = 1; index < points.length; index += 1) {
        if (points[index].policy_state !== points[index - 1].policy_state) {
            highlightedIndices.add(index);
        }
    }
    for (const transition of transitions) {
        const index = points.findIndex((point) => Date.parse(point.timestamp)
            === Date.parse(transition.timestamp));
        if (index !== -1) {
            highlightedIndices.add(index);
        }
    }

    const formattedTicks = model.xTicks.map((tick) => formatRunTimestamp(tick.timestamp));
    const includeMilliseconds = new Set(formattedTicks).size < formattedTicks.length;
    return {
        bands,
        transitions,
        highlightedIndices,
        tickLabels: model.xTicks.map((tick) => compactTimestamp(
            tick.timestamp,
            includeMilliseconds,
        )),
    };
}

function createSvgElement(tagName, className) {
    const element = document.createElementNS(SVG_NAMESPACE, tagName);
    element.setAttribute("class", className);
    return element;
}

export function createDashboardReplayChart(model, fusionResult, decisionTime = null) {
    const chart = createScoreTrajectoryChart(model);
    chart.classList.add("dashboard-replay-chart");
    const svg = chart.querySelector(".fusion-score-chart__svg");
    const presentation = buildDashboardReplayPresentation(model, fusionResult, decisionTime);

    const bandLayer = createSvgElement("g", "dashboard-replay-chart__bands");
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
            ...model.points.map((point) => `${point.x},${point.y}`),
            `${model.points.at(-1).x},${model.plot.bottom}`,
        ].join(" "));
        bandLayer.append(area);
    }
    trajectory.before(bandLayer);

    const pointMarkers = svg.querySelectorAll(".fusion-score-chart__point");
    for (const [index, marker] of pointMarkers.entries()) {
        marker.classList.add(presentation.highlightedIndices.has(index)
            ? "dashboard-replay-chart__point--key"
            : "dashboard-replay-chart__point--quiet");
    }

    const tickLabels = svg.querySelectorAll(".fusion-score-chart__axis-label--x");
    for (const [index, label] of tickLabels.entries()) {
        const title = label.querySelector("title");
        label.textContent = presentation.tickLabels[index];
        if (title !== null) {
            label.append(title);
        }
    }
    const description = svg.querySelector("desc");
    description.textContent += ` 화면 눈금 ${presentation.tickLabels.join(", ")}.`;
    if (presentation.transitions.length > 0) {
        description.textContent += ` 저장된 Episode 전환: ${presentation.transitions.map(
            (transition) => `${transition.label} ${formatRunTimestamp(transition.timestamp)}`,
        ).join(", ")}.`;
    }

    const transitionLayer = createSvgElement("g", "dashboard-replay-chart__transitions");
    for (const [index, transition] of presentation.transitions.entries()) {
        const line = createSvgElement(
            "line",
            `dashboard-replay-chart__transition dashboard-replay-chart__transition--${transition.kind}`,
        );
        line.setAttribute("x1", String(transition.x));
        line.setAttribute("x2", String(transition.x));
        line.setAttribute("y1", String(model.plot.top));
        line.setAttribute("y2", String(model.plot.bottom));
        const label = createSvgElement("text", "dashboard-replay-chart__callout");
        label.setAttribute("x", String(Math.min(transition.x + 8, model.plot.right - 95)));
        label.setAttribute("y", String(16 + (index % 3) * 15));
        label.textContent = transition.label;
        const title = document.createElementNS(SVG_NAMESPACE, "title");
        title.textContent = formatRunTimestamp(transition.timestamp);
        label.append(title);
        transitionLayer.append(line, label);
    }
    svg.append(transitionLayer);
    if (presentation.bands.length > 0) {
        const item = document.createElement("li");
        const symbol = document.createElement("span");
        symbol.classList.add("dashboard-replay-chart__episode-legend");
        symbol.setAttribute("aria-hidden", "true");
        item.append(symbol, document.createTextNode("Episode 구간"));
        chart.querySelector(".fusion-score-chart__legend").append(item);
    }
    return chart;
}
