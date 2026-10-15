// Sparse, read-only SVG charts for the already validated Pipeline Telemetry model.
// An absent one-second bucket is never replaced with an observed zero.

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const WIDTH = 960;
const HEIGHT = 210;
const PLOT = Object.freeze({ left: 64, right: 24, top: 16, bottom: 41 });
const PLOT_WIDTH = WIDTH - PLOT.left - PLOT.right;
const PLOT_HEIGHT = HEIGHT - PLOT.top - PLOT.bottom;
const CHART_KINDS = new Set(["throughput", "latency"]);

const SERIES_DEFINITIONS = Object.freeze([
    { key: "inputAcceptedCount", label: "입력 수락", kind: "input" },
    { key: "processingCompletedCount", label: "처리 완료", kind: "completed" },
]);

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString("ko-KR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
    });
}

function formatNumber(value, kind) {
    if (kind === "throughput") {
        return String(value);
    }
    return value.toLocaleString("ko-KR", { maximumFractionDigits: 6 });
}

function axisMaximum(maximum, kind) {
    if (kind === "throughput") {
        return Math.max(1, Math.ceil(maximum / 4) * 4);
    }
    if (maximum <= 0) {
        return 1;
    }
    const magnitude = 10 ** Math.floor(Math.log10(maximum));
    const interval = magnitude / 4;
    return Math.ceil(maximum / interval) * interval;
}

function pointX(index, length) {
    return PLOT.left + ((index + 0.5) / length) * PLOT_WIDTH;
}

function pointY(value, yMaximum) {
    return PLOT.top + PLOT_HEIGHT * (1 - value / yMaximum);
}

function axisTimeTicks(model) {
    const start = Date.parse(model.rangeStart);
    const end = Date.parse(model.rangeEnd);
    return [0, 0.25, 0.5, 0.75, 1].map((ratio) => ({
        x: PLOT.left + ratio * PLOT_WIDTH,
        label: formatTime(new Date(start + (end - start) * ratio).toISOString()),
    }));
}

function requireChartModel(model, kind) {
    if (!CHART_KINDS.has(kind)) {
        throw new RangeError(`Unknown Telemetry chart kind: ${kind}`);
    }
    if (
        model === null
        || typeof model !== "object"
        || !Array.isArray(model.seconds)
        || model.seconds.length < 60
        || model.seconds.length > 300
    ) {
        throw new TypeError("A validated Telemetry chart model is required");
    }
    if (!Number.isFinite(Date.parse(model.rangeStart)) || !Number.isFinite(Date.parse(model.rangeEnd))) {
        throw new TypeError("Telemetry chart range timestamps are required");
    }
}

/**
 * Layout data only. Missing seconds generate no marks or connecting lines.
 * A real observed value of zero generates a visible marker at the baseline.
 */
export function buildTelemetryChartPresentation(model, kind) {
    requireChartModel(model, kind);
    const values = [];
    for (const second of model.seconds) {
        if (!second.observed) {
            continue;
        }
        if (kind === "throughput") {
            for (const definition of SERIES_DEFINITIONS) {
                const value = second[definition.key];
                if (value !== null) {
                    values.push(value);
                }
            }
        } else if (second.processingLatencyMeanMs !== null) {
            values.push(second.processingLatencyMeanMs);
        }
    }
    const yMaximum = axisMaximum(Math.max(0, ...values), kind);
    const zeroY = pointY(0, yMaximum);
    const makeMark = (second, index, value, seriesKind) => ({
        x: pointX(index, model.seconds.length),
        y: pointY(value, yMaximum),
        zeroY,
        value,
        timestamp: second.timestamp,
        seriesKind,
        tooltip: `${formatTime(second.timestamp)} · ${formatNumber(value, kind)} ${kind === "throughput" ? "건/초" : "ms"}`,
    });

    const series = kind === "throughput"
        ? SERIES_DEFINITIONS.map((definition) => ({
            ...definition,
            marks: model.seconds.flatMap((second, index) => (
                second.observed && second[definition.key] !== null
                    ? [makeMark(second, index, second[definition.key], definition.kind)]
                    : []
            )),
            segments: [],
        }))
        : [{
            key: "processingLatencyMeanMs",
            label: "Normalization + Evidence 지연",
            kind: "latency",
            marks: model.seconds.flatMap((second, index) => (
                second.observed && second.processingLatencyMeanMs !== null
                    ? [makeMark(second, index, second.processingLatencyMeanMs, "latency")]
                    : []
            )),
            segments: [],
        }];

    if (kind === "latency") {
        let previousMark = null;
        let previousIndex = -2;
        for (const [index, second] of model.seconds.entries()) {
            if (!second.observed || second.processingLatencyMeanMs === null) {
                previousMark = null;
                continue;
            }
            const mark = makeMark(second, index, second.processingLatencyMeanMs, "latency");
            if (previousMark !== null && index === previousIndex + 1) {
                series[0].segments.push({ from: previousMark, to: mark });
            }
            previousMark = mark;
            previousIndex = index;
        }
    }

    return {
        kind,
        width: WIDTH,
        height: HEIGHT,
        plot: { ...PLOT, width: PLOT_WIDTH, height: PLOT_HEIGHT },
        yMaximum,
        yTicks: Array.from({ length: 5 }, (_, index) => {
            const value = (yMaximum * index) / 4;
            return {
                value,
                label: formatNumber(value, kind),
                y: pointY(value, yMaximum),
            };
        }),
        xTicks: axisTimeTicks(model),
        series,
        markCount: series.reduce((total, item) => total + item.marks.length, 0),
    };
}

function svgNode(doc, tag, className = null) {
    const node = doc.createElementNS(SVG_NAMESPACE, tag);
    if (className !== null) {
        node.setAttribute("class", className);
    }
    return node;
}

function addText(doc, parent, x, y, value, className) {
    const item = svgNode(doc, "text", className);
    item.setAttribute("x", String(x));
    item.setAttribute("y", String(y));
    item.textContent = value;
    parent.append(item);
}

function addLine(doc, parent, x1, y1, x2, y2, className) {
    const item = svgNode(doc, "line", className);
    item.setAttribute("x1", String(x1));
    item.setAttribute("y1", String(y1));
    item.setAttribute("x2", String(x2));
    item.setAttribute("y2", String(y2));
    parent.append(item);
}

/** Return a responsive figure. SVG elements contain no synthesized observations. */
export function createTelemetryChart(model, kind, doc = document) {
    const presentation = buildTelemetryChartPresentation(model, kind);
    const figure = doc.createElement("figure");
    figure.classList.add("dashboard-telemetry-chart");
    figure.classList.add(`dashboard-telemetry-chart--${kind}`);

    const svg = svgNode(doc, "svg", "dashboard-telemetry-chart__svg");
    svg.setAttribute("viewBox", `0 0 ${WIDTH} ${HEIGHT}`);
    svg.setAttribute("role", "img");
    const titleId = `dashboard-telemetry-${kind}-chart-title`;
    const descriptionId = `dashboard-telemetry-${kind}-chart-description`;
    svg.setAttribute("aria-labelledby", `${titleId} ${descriptionId}`);
    const title = svgNode(doc, "title");
    title.setAttribute("id", titleId);
    title.textContent = kind === "throughput" ? "실측 입력·처리량" : "실측 처리 지연";
    const description = svgNode(doc, "desc");
    description.setAttribute("id", descriptionId);
    description.textContent = presentation.markCount === 0
        ? "표시할 측정 샘플이 없습니다. 미관측 구간은 0으로 계산하지 않습니다."
        : "실제로 관측된 1초 구간만 표시합니다. 비어 있는 구간은 미관측이며 0건이 아닙니다.";
    svg.append(title, description);

    const grid = svgNode(doc, "g", "dashboard-telemetry-chart__grid");
    for (const tick of presentation.yTicks) {
        addLine(
            doc, grid, PLOT.left, tick.y,
            PLOT.left + PLOT_WIDTH, tick.y,
            "dashboard-telemetry-chart__grid-line",
        );
        addText(doc, grid, PLOT.left - 10, tick.y + 4, tick.label,
            "dashboard-telemetry-chart__y-label");
    }
    for (const tick of presentation.xTicks) {
        addText(doc, grid, tick.x, HEIGHT - 13, tick.label,
            "dashboard-telemetry-chart__x-label");
    }
    svg.append(grid);

    const dataLayer = svgNode(doc, "g", "dashboard-telemetry-chart__data");
    for (const series of presentation.series) {
        const group = svgNode(doc, "g", `dashboard-telemetry-chart__series--${series.kind}`);
        for (const segment of series.segments) {
            addLine(doc, group, segment.from.x, segment.from.y, segment.to.x, segment.to.y,
                "dashboard-telemetry-chart__segment");
        }
        for (const mark of series.marks) {
            if (kind === "throughput" && mark.value > 0) {
                addLine(doc, group, mark.x, mark.zeroY, mark.x, mark.y,
                    "dashboard-telemetry-chart__stem");
            }
            const circle = svgNode(doc, "circle", "dashboard-telemetry-chart__mark");
            circle.setAttribute("cx", String(mark.x));
            circle.setAttribute("cy", String(mark.y));
            circle.setAttribute("r", kind === "latency" ? "3" : "2.5");
            const tooltip = svgNode(doc, "title");
            tooltip.textContent = `${series.label} · ${mark.tooltip}`;
            circle.append(tooltip);
            group.append(circle);
        }
        dataLayer.append(group);
    }
    svg.append(dataLayer);
    figure.append(svg);

    const legend = doc.createElement("ul");
    legend.classList.add("dashboard-telemetry-chart__legend");
    for (const series of presentation.series) {
        const item = doc.createElement("li");
        const swatch = doc.createElement("span");
        swatch.classList.add("dashboard-telemetry-chart__swatch");
        swatch.classList.add(`dashboard-telemetry-chart__swatch--${series.kind}`);
        swatch.setAttribute("aria-hidden", "true");
        item.append(swatch, doc.createTextNode(series.label));
        legend.append(item);
    }
    figure.append(legend);

    if (presentation.markCount === 0) {
        const empty = doc.createElement("figcaption");
        empty.classList.add("dashboard-telemetry-chart__empty");
        empty.textContent = kind === "throughput"
            ? "해당 조회 구간에 관측된 처리량이 없습니다."
            : "해당 조회 구간에 측정된 처리 지연 샘플이 없습니다.";
        figure.append(empty);
    }
    return figure;
}
