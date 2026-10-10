import {
    displayValue,
    formatRunTimestamp,
} from "./run-detail-contract.mjs";

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";

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

export function createScoreTrajectoryChart(model) {
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
