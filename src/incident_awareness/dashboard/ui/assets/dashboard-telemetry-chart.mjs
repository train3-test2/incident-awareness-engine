// Sparse, read-only SVG charts for the already validated Pipeline Telemetry model.
// An absent one-second bucket is never replaced with an observed zero.

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const WIDTH = 640;
const HEIGHT = 240;
const PLOT = Object.freeze({ left: 72, right: 40, top: 28, bottom: 41 });
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
    return value.toLocaleString("ko-KR", { maximumFractionDigits: 9 });
}

function formatCompactLatency(value) {
    return value.toLocaleString("ko-KR", value > 0 && value < 0.001
        ? { maximumSignificantDigits: 3 } : { maximumFractionDigits: 3 });
}

function formatBucketTime(timestamp) {
    return new Date(timestamp).toLocaleString("ko-KR", { hour12: false, timeZoneName: "short" });
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

function pointX(index, length, plot) {
    return plot.left + ((index + 0.5) / length) * plot.width;
}

function pointY(value, yMaximum, plot) {
    return plot.top + plot.height * (1 - value / yMaximum);
}

function axisTimeTicks(model, plot) {
    const start = Date.parse(model.rangeStart);
    const end = Date.parse(model.rangeEnd);
    const ratios = plot.width < 380 ? [0, 0.5, 1] : [0, 0.25, 0.5, 0.75, 1];
    return ratios.map((ratio) => ({
        x: plot.left + ratio * plot.width,
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
export function buildTelemetryChartPresentation(model, kind, dimensions = null) {
    requireChartModel(model, kind);
    // Presentation only: adapt the plot, not the samples or the time window.
    const compact = Number.isFinite(dimensions?.width);
    const width = compact ? Math.max(300, Math.min(960, dimensions.width)) : WIDTH;
    const height = compact ? (kind === "latency" ? 112 : 128) : HEIGHT;
    const padding = compact ? { left: 58, right: 34, top: 20, bottom: 28 } : PLOT;
    const plot = {
        ...padding,
        width: compact ? width - padding.left - padding.right : PLOT_WIDTH,
        height: compact ? height - padding.top - padding.bottom : PLOT_HEIGHT,
    };
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
    const zeroY = pointY(0, yMaximum, plot);
    const makeMark = (second, index, value, seriesKind) => ({
        x: pointX(index, model.seconds.length, plot),
        y: pointY(value, yMaximum, plot),
        zeroY,
        value,
        timestamp: second.timestamp,
        seriesKind,
        isolated: ![index - 1, index + 1].some((neighbor) => {
            const candidate = model.seconds[neighbor];
            const key = seriesKind === "latency" ? "processingLatencyMeanMs"
                : seriesKind === "input" ? "inputAcceptedCount" : "processingCompletedCount";
            return candidate?.observed && candidate[key] !== null;
        }),
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

    // Each series owns its continuity. A missing bucket or null value breaks it,
    // while an observed zero is a real endpoint (never a synthesized sample).
    for (const item of series) {
        let previousMark = null;
        let previousIndex = -2;
        for (const [index, second] of model.seconds.entries()) {
            if (!second.observed || second[item.key] === null) {
                previousMark = null;
                continue;
            }
            const mark = makeMark(second, index, second[item.key], item.kind);
            if (previousMark !== null && index === previousIndex + 1) {
                item.segments.push({ from: previousMark, to: mark });
            }
            previousMark = mark;
            previousIndex = index;
        }
    }

    return {
        kind,
        width,
        height,
        compact,
        plot,
        yMaximum,
        yTicks: Array.from({ length: 5 }, (_, index) => {
            const value = (yMaximum * index) / 4;
            return {
                value,
                label: kind === "throughput" ? formatNumber(value, kind)
                    : value > 0 && (value < 0.001 || value >= 1000000)
                        ? value.toExponential(1) : value.toLocaleString("ko-KR", { maximumSignificantDigits: 3 }),
                y: pointY(value, yMaximum, plot),
            };
        }),
        xTicks: axisTimeTicks(model, plot),
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
export function createTelemetryChart(model, kind, doc = document, dimensions = null) {
    const presentation = buildTelemetryChartPresentation(model, kind, dimensions);
    const { width, height, plot: bounds } = presentation;
    const figure = doc.createElement("figure");
    figure.classList.add("dashboard-telemetry-chart");
    figure.classList.add(`dashboard-telemetry-chart--${kind}`);
    if (presentation.compact) figure.classList.add("dashboard-telemetry-chart--compact");

    const svg = svgNode(doc, "svg", "dashboard-telemetry-chart__svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
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
        : "실제로 관측된 인접 1초 버킷만 선으로 연결합니다. 선은 초 내부 순간 처리율이 아닙니다. 비어 있는 구간과 null은 연결하지 않으며 관측된 0만 기준선에 표시합니다.";
    svg.append(title, description);

    const grid = svgNode(doc, "g", "dashboard-telemetry-chart__grid");
    for (const tick of presentation.yTicks) {
        addLine(
            doc, grid, bounds.left, tick.y,
            bounds.left + bounds.width, tick.y,
            "dashboard-telemetry-chart__grid-line",
        );
        addText(doc, grid, bounds.left - 10, tick.y + 4, tick.label,
            "dashboard-telemetry-chart__y-label");
    }
    for (const tick of presentation.xTicks) {
        addText(doc, grid, tick.x, height - (presentation.compact ? 8 : 13), tick.label,
            "dashboard-telemetry-chart__x-label");
    }
    svg.append(grid);
    addText(doc, svg, bounds.left, presentation.compact ? 13 : 20, kind === "throughput" ? "건/초" : "ms",
        "dashboard-telemetry-chart__unit");

    const dataLayer = svgNode(doc, "g", "dashboard-telemetry-chart__data");
    for (const series of presentation.series) {
        const group = svgNode(doc, "g", `dashboard-telemetry-chart__series--${series.kind}`);
        for (const segment of series.segments) {
            addLine(doc, group, segment.from.x, segment.from.y, segment.to.x, segment.to.y,
                "dashboard-telemetry-chart__segment");
        }
        for (const mark of series.marks) {
            const circle = svgNode(doc, "circle", "dashboard-telemetry-chart__mark");
            circle.setAttribute("cx", String(mark.x));
            circle.setAttribute("cy", String(mark.y));
            circle.setAttribute("r", String(mark.isolated
                ? series.kind === "input" ? 8 : 4.5
                : presentation.compact ? (series.kind === "input" ? 1.75 : 1.5)
                    : series.kind === "input" ? 3.5 : 2.5));
            const accessibleValue = `${series.label} · ${formatBucketTime(mark.timestamp)} · ${mark.tooltip}`;
            circle.setAttribute("aria-label", accessibleValue);
            circle.setAttribute("role", "img");
            circle.setAttribute("data-timestamp", mark.timestamp);
            circle.setAttribute("data-series", series.kind);
            if (mark.isolated) circle.setAttribute("tabindex", "0");
            const tooltip = svgNode(doc, "title");
            tooltip.textContent = accessibleValue;
            circle.append(tooltip);
            group.append(circle);
        }
        dataLayer.append(group);
    }
    svg.append(dataLayer);
    const plot = doc.createElement("div");
    plot.classList.add("dashboard-telemetry-chart__plot");
    plot.setAttribute("tabindex", "0");
    plot.setAttribute("role", "region");
    plot.setAttribute("aria-label", `${kind === "throughput" ? "처리량" : "처리 지연"} 시간축 · 좁은 화면에서 좌우 스크롤`);
    plot.append(svg);
    figure.append(plot);

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

    const observations = model.seconds.filter((second) => second.observed);
    if (observations.length > 0) {
        const observation = doc.createElement("div");
        observation.classList.add("dashboard-telemetry-chart__observation");
        const latest = observations.at(-1);
        const time = doc.createElement("p");
        time.textContent = `최근 5분 관측 ${observations.length}버킷 · ${observations.length === 1 ? "관측" : "최종 관측"} 버킷 ${formatBucketTime(latest.timestamp)}`;
        observation.append(time);
        if (observations.length === 1) {
            const values = doc.createElement("strong");
            values.textContent = kind === "throughput"
                ? `입력 수락 ${latest.inputAcceptedCount}건 · 처리 완료 ${latest.processingCompletedCount}건`
                : latest.processingLatencyMeanMs === null ? "해당 버킷의 지연 샘플 미관측"
                    : `버킷 평균 ${formatCompactLatency(latest.processingLatencyMeanMs)} ms`;
            observation.append(values);
        }
        if (model.observedBucketCount === 0) {
            const historical = doc.createElement("p");
            historical.textContent = "최근 60초 미관측 · 위 값은 최근 5분 내 과거 실측이며 현재 처리량이 아닙니다.";
            observation.append(historical);
        }
        figure.append(observation);
        description.textContent += ` ${observation.textContent}`;
    }

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
