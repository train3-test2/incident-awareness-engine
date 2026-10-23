import { formatOperatorTimestamp } from "./dashboard-contract.mjs";
import {
    displayValue,
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

// All chart clocks are explicit KST. The original string remains available verbatim.
export function scoreTimestampDetails(timestamp) {
    const instant = typeof timestamp === "string"
        && /(?:Z|[+-]\d{2}:\d{2})$/i.test(timestamp) ? Date.parse(timestamp) : NaN;
    if (!Number.isFinite(instant)) {
        return { date: null, time: "시각 미확인", kst: "시각 미확인", utc: "시각 미확인", original: timestamp ?? "없음" };
    }
    const utc = new Date(instant).toISOString();
    const kst = new Date(instant + 9 * 60 * 60 * 1000).toISOString();
    return {
        date: kst.slice(0, 10),
        time: kst.slice(11, 19),
        kst: `${kst.slice(0, 10)} ${kst.slice(11, 23)} KST`,
        utc,
        original: timestamp,
    };
}

// Date context for the HH:mm:ss axis, taken from the first and last stored records.
export function scoreClockText(model) {
    const days = [model.points[0], model.points.at(-1)]
        .map(point => point === undefined ? null : scoreTimestampDetails(point.timestamp).date);
    if (days.includes(null)) return "시각 기준 KST";
    return `${days[0] === days[1] ? days[0] : `${days[0]} – ${days[1]}`} · KST`;
}

export function scorePointDetails(point) {
    const clock = scoreTimestampDetails(point.timestamp);
    const state = point.policy_state === "on" ? "탐지 구간 활성"
        : point.policy_state === "off" ? "탐지 구간 비활성" : "탐지 구간 상태 미확인";
    return `${clock.kst} · UTC ${clock.utc} · 원본 ${clock.original}`
        + ` · 증거 누적 점수 ${displayValue(point.score)} · ${state}`;
}

export function scoreCriteriaText(model) {
    const on = model.thresholds.find(threshold => threshold.kind === "on");
    const off = model.thresholds.find(threshold => threshold.kind === "off");
    if (!on || !off) return "저장된 설정 없음 · 진입·해제 기준 미확인";
    const persistence = model.persistenceK === null ? "연속 충족 횟수 미확인" : `${model.persistenceK}회 연속`;
    return `진입 기준 ${on.value.toFixed(2)} 이상 · ${persistence}`
        + ` / 해제 기준 ${off.value.toFixed(2)} 미만`;
}

function buildXAxisTickPresentation(xTicks) {
    const clocks = xTicks.map(tick => scoreTimestampDetails(tick.timestamp));
    const includeMilliseconds = new Set(clocks.map(clock => clock.time)).size < clocks.length;
    return clocks.map(clock => ({
        label: includeMilliseconds ? clock.kst.slice(11, 23) : clock.time,
        title: `${clock.kst} · UTC ${clock.utc} · 원본 ${clock.original}`,
    }));
}

const MARKER_KEY_OFFSETS = new Map([["ArrowLeft", -1], ["ArrowRight", 1]]);

// The trajectory is one tab stop; arrow keys walk every stored ScorePoint in order.
function moveMarkerFocus(markers, marker, event) {
    const index = markers.indexOf(marker);
    const target = event.key === "Home" ? 0
        : event.key === "End" ? markers.length - 1
            : index + (MARKER_KEY_OFFSETS.get(event.key) ?? NaN);
    if (!(target >= 0 && target < markers.length)) return;
    event.preventDefault();
    markers[target].focus();
}

// Threshold lines carry their own labels, so the legend only explains marks and states.
function createChartLegend() {
    const legend = document.createElement("ul");
    legend.classList.add("fusion-score-chart__legend");
    const entries = [
        ["score", "증거 누적 점수"],
        ["policy-on", "탐지 구간 활성"],
        ["policy-off", "탐지 구간 비활성"],
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
    summary.textContent = `점수 기록 ${points.length}개`;

    const wrapper = document.createElement("div");
    wrapper.classList.add("fusion-trace-table-wrapper");
    const table = document.createElement("table");
    table.classList.add("fusion-trace-table");

    const head = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const heading of [
        "시각 (KST · 밀리초)",
        "증거 누적 점수",
        "탐지 구간 상태",
        "연속 충족 횟수",
        "UTC 시각",
        "원본 시각",
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
        const clock = scoreTimestampDetails(point.timestamp);
        const values = [
            clock.kst,
            displayValue(point.score),
            point.policy_state === "on" ? "탐지 구간 활성"
                : point.policy_state === "off" ? "탐지 구간 비활성" : "상태 미확인",
            displayValue(point.persistence_count),
            clock.utc,
            clock.original,
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

export function createScoreTrajectoryChart(model, { showCriteria = true } = {}) {
    const chart = document.createElement("div");
    chart.classList.add("fusion-score-chart");

    const svg = createSvgElement("svg", "fusion-score-chart__svg");
    svg.setAttribute("viewBox", `0 0 ${model.width} ${model.height}`);
    svg.setAttribute("role", "group");
    svg.setAttribute(
        "aria-labelledby",
        "fusion-score-chart-title fusion-score-chart-description",
    );

    const title = createSvgElement("title");
    title.setAttribute("id", "fusion-score-chart-title");
    title.textContent = "증거 누적 점수 · KST";
    const xTickPresentation = buildXAxisTickPresentation(model.xTicks);
    const xAxisDescription = xTickPresentation.length === 0
        ? "시간축 눈금은 없습니다."
        : `시간축 눈금 ${xTickPresentation.length}개: ${xTickPresentation.map(
            (tick) => tick.label,
        ).join(", ")}.`;
    const description = createSvgElement("desc");
    description.setAttribute("id", "fusion-score-chart-description");
    description.textContent = (
        (showCriteria ? "저장된 FusionStoppingTrace의 증거 누적 점수와 저장 설정의 기준선을 KST 시간축에 표시합니다. " : "저장된 점수와 탐지 구간을 KST 시간축에 표시합니다. ")
        + xAxisDescription
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

    const xTickEnd = model.plot.bottom
        + (model.height - model.plot.bottom) * 0.16;
    const xLabelY = model.plot.bottom
        + (model.height - model.plot.bottom) * 0.58;
    for (const [index, tick] of model.xTicks.entries()) {
        const tickLine = createSvgElement("line", "fusion-score-chart__x-tick");
        tickLine.setAttribute("x1", String(tick.x));
        tickLine.setAttribute("x2", String(tick.x));
        tickLine.setAttribute("y1", String(model.plot.bottom));
        tickLine.setAttribute("y2", String(xTickEnd));

        const tickPresentation = xTickPresentation[index];
        const label = createSvgText(
            "fusion-score-chart__axis-label fusion-score-chart__axis-label--x",
            tick.x,
            xLabelY,
            tickPresentation.label,
        );
        label.setAttribute("text-anchor", tick.textAnchor);
        const labelTitle = createSvgElement("title");
        labelTitle.textContent = tickPresentation.title;
        label.append(labelTitle);
        svg.append(tickLine, label);
    }

    for (const threshold of showCriteria ? model.thresholds : []) {
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
            model.plot.right - 6,
            threshold.y - 6,
            `${threshold.label} ${threshold.value.toFixed(2)}`,
        );
        label.setAttribute("text-anchor", "end");
        svg.append(line, label);
    }

    const trajectory = createSvgElement("polyline", "fusion-score-chart__trajectory");
    trajectory.setAttribute(
        "points",
        model.points.map((point) => `${point.x},${point.y}`).join(" "),
    );
    svg.append(trajectory);

    // Focused markers already announce their aria-label; this line mirrors it visually.
    const pointDetail = document.createElement("p");
    pointDetail.classList.add("fusion-score-chart__point-detail");
    pointDetail.textContent = "점에 마우스를 올리거나 Tab으로 이동한 뒤 ←·→·Home·End 키로 점수 기록을 선택하면"
        + " 시각·점수·상태를 표시합니다.";

    const markers = [];
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
        const details = scorePointDetails(point);
        marker.setAttribute("tabindex", markers.length === 0 ? "0" : "-1");
        marker.setAttribute("role", "img");
        const visibleDetails = `${formatOperatorTimestamp(point.timestamp, {precise: true})} · 증거 누적 점수 ${displayValue(point.score)} · ${point.policy_state === "on" ? "탐지 구간 활성" : point.policy_state === "off" ? "탐지 구간 비활성" : "탐지 구간 상태 미확인"}`;
        marker.setAttribute("aria-label", visibleDetails);
        const showDetails = () => { pointDetail.textContent = visibleDetails; };
        marker.addEventListener("mouseenter", showDetails);
        marker.addEventListener("focus", () => {
            for (const other of markers) {
                other.setAttribute("tabindex", other === marker ? "0" : "-1");
            }
            showDetails();
        });
        marker.addEventListener("keydown", (event) => moveMarkerFocus(markers, marker, event));
        const markerTitle = createSvgElement("title");
        markerTitle.textContent = details;
        marker.append(markerTitle);
        markers.push(marker);
        svg.append(marker);
    }

    const clock = document.createElement("p");
    clock.classList.add("fusion-score-chart__clock");
    clock.textContent = scoreClockText(model);
    const criteria = document.createElement("p");
    criteria.classList.add("fusion-score-chart__criteria");
    criteria.textContent = scoreCriteriaText(model);
    const explanation = document.createElement("p");
    explanation.classList.add("fusion-score-chart__explanation");
    explanation.textContent = "증거 누적 점수는 공격 확률이나 종합 판단 결과가 아닙니다. "
        + "선은 저장된 점수를 연결한 것이며, 눈금은 탐지 구간 전환 시각과 다를 수 있습니다.";
    if (showCriteria) {
        chart.append(clock, criteria, svg, createChartLegend(), pointDetail, explanation, createTraceTable(model.points));
        return chart;
    }
    chart.append(clock, svg, createChartLegend(), pointDetail);
    const technical = document.createElement("details");
    technical.classList.add("fusion-score-chart__technical");
    const technicalTitle = document.createElement("summary");
    technicalTitle.textContent = "판정 기준·기술 상세";
    technical.append(technicalTitle);
    if (!showCriteria) technical.append(criteria);
    technical.append(explanation, createTraceTable(model.points));
    chart.append(technical);
    return chart;
}
