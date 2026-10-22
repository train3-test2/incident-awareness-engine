// Independent, bounded Telemetry polling for the operations Dashboard.
// Observations are never synthesized; API errors must not look like zero throughput.

import { buildTelemetryChartModel, TELEMETRY_ENDPOINT } from "./dashboard-telemetry-contract.mjs";
import { formatOperatorTimestamp } from "./dashboard-contract.mjs";
import { createTelemetryChart } from "./dashboard-telemetry-chart.mjs";

const POLL_INTERVAL_MS = 5000;
const REQUEST_TIMEOUT_MS = 10000;

const REQUIRED_IDS = Object.freeze({
    throughputFrame: "telemetry-throughput-chart",
    throughputSummary: "telemetry-throughput-summary",
    throughputDetails: "telemetry-throughput-details",
    throughputStatus: "telemetry-throughput-status",
    throughputNote: "telemetry-throughput-note",
    latencyFrame: "telemetry-latency-chart",
    latencySummary: "telemetry-latency-summary",
    latencyDetails: "telemetry-latency-details",
    latencyStatus: "telemetry-latency-status",
    latencyNote: "telemetry-latency-note",
});

// Optional: standalone Telemetry chart pages intentionally have no Insight card.
const OBSERVATION_IDS = Object.freeze({
    state: "processing-observation-state",
    time: "processing-observation-time",
    details: "processing-observation-details",
});

function formatObservedTime(timestamp) {
    if (timestamp === null) {
        return "마지막 관측 시각: 확인 불가";
    }
    return `마지막 관측: ${formatOperatorTimestamp(timestamp)}`;
}

function formatCount(value) {
    return value === null ? "미관측" : `${value.toLocaleString("ko-KR")}건`;
}

function formatLatency(value, compact = false) {
    if (compact && value !== null) {
        // Main cards cannot fit long fractional means. Keep the exact API value in
        // title/aria-label; never round a positive sub-millisecond value to zero.
        return `${value > 0 && (value < 0.01 || value >= 10000)
            ? value.toExponential(1) : value.toLocaleString("ko-KR", { maximumSignificantDigits: 3 })} ms`;
    }
    return value === null
        ? "미관측"
        : `${value.toLocaleString("ko-KR", { maximumFractionDigits: 6 })} ms`;
}

function replaceWithNotice(doc, frame, notice) {
    frame.setAttribute("data-empty", "true");
    const restoreFocus = doc.activeElement && frame.contains?.(doc.activeElement);
    const label = doc.createElement("span");
    label.textContent = notice;
    frame.replaceChildren(label);
    if (restoreFocus) frame.focus?.({ preventScroll: true });
}

function replaceObservedChart(doc, frame, model, kind, details) {
    frame.setAttribute("data-empty", "false");
    const active = doc.activeElement;
    const restoreFocus = active && frame.contains?.(active);
    const previousPlot = frame.querySelector?.(".dashboard-telemetry-chart__plot");
    const timestamp = active?.getAttribute?.("data-timestamp");
    const series = active?.getAttribute?.("data-series");
    const summary = doc.getElementById("dashboard-view") !== null
        ? details?.closest?.("details")?.querySelector("summary") : null;
    const dimensions = Number.isFinite(frame.clientWidth) && frame.clientWidth > 0
        ? { width: Math.max(300, frame.clientWidth - 2),
            ...(summary ? { height: kind === "throughput" ? 102 : 78 } : {}) } : null;
    const chart = createTelemetryChart(model, kind, doc, dimensions);
    let observation = "";
    if (summary) {
        // Main cards have a fixed desktop footprint. Preserve the visible legend in
        // their existing summary row; detailed observations remain in the disclosure
        // and the SVG accessible description. Standalone pages keep their full figure.
        summary.querySelector(".dashboard-telemetry-chart__legend")?.remove();
        const legend = chart.querySelector(".dashboard-telemetry-chart__legend");
        const compactLegend = doc.createElement("span");
        compactLegend.classList.add("dashboard-telemetry-chart__legend");
        compactLegend.setAttribute("role", "list");
        compactLegend.setAttribute("aria-label", "그래프 범례");
        for (const item of Array.from(legend.children)) {
            const key = doc.createElement("span");
            key.setAttribute("role", "listitem");
            key.append(...Array.from(item.childNodes));
            compactLegend.append(key);
        }
        summary.append(compactLegend);
        legend.remove();
        const note = chart.querySelector(".dashboard-telemetry-chart__observation");
        observation = note?.textContent ?? "";
        note?.remove();
    }
    frame.replaceChildren(chart);
    const plot = frame.querySelector?.(".dashboard-telemetry-chart__plot");
    if (plot) plot.scrollLeft = previousPlot ? previousPlot.scrollLeft : plot.scrollWidth;
    if (restoreFocus) {
        const marker = timestamp && [...frame.querySelectorAll("circle")].find((circle) => (
            circle.getAttribute("data-timestamp") === timestamp
            && circle.getAttribute("data-series") === series
        ));
        (marker || plot || frame).focus?.({ preventScroll: true });
    }
    return observation;
}

function clearMainLegend(node) {
    node.closest?.("details")?.querySelector("summary .dashboard-telemetry-chart__legend")?.remove();
}

function updateStatusText(element, message) {
    if (element.textContent !== message) {
        element.textContent = message;
    }
}

function renderProcessingObservation(nodes, model, queryState = "success") {
    if (Object.values(nodes).some((node) => node === null)) {
        return;
    }
    let label;
    let tone = "neutral";
    let timestamp = null;
    let timeText = "관측 시각 확인 불가";
    let detail;
    if (queryState !== "success") {
        label = queryState === "loading" ? "조회 중" : "조회 실패";
        tone = queryState === "loading" ? "neutral" : "error";
        timeText = queryState === "loading" ? "관측 시각 조회 중" : timeText;
        detail = queryState === "loading" ? "Telemetry 처리 관측 정보를 조회하고 있습니다."
            : "Telemetry API 조회에 실패했습니다. 이전 관측 시각을 현재 실측으로 표시하지 않습니다.";
    } else {
        timestamp = model.lastObservedAt;
        const observed = model.seconds.some((second) => second.observed);
        const hasHistory = timestamp !== null || observed;
        const freshness = model.freshnessStatus === "stale" ? "오래됨"
            : model.freshnessStatus === "unknown" ? "최근성 불명" : "최근";
        if (model.qualityStatus === "partial") {
            label = `부분 관측 · ${freshness}`;
            tone = "warning";
        } else if (model.qualityStatus === "no_samples" || !observed) {
            label = hasHistory ? `구간 미관측 · ${freshness}` : "조회 구간 미관측";
            tone = hasHistory && model.freshnessStatus === "stale" ? "warning" : "neutral";
        } else {
            label = model.freshnessStatus === "stale" ? "오래된 관측"
                : model.freshnessStatus === "unknown" ? "최근성 불명" : "최근 관측";
            tone = model.freshnessStatus === "stale" ? "warning"
                : model.freshnessStatus === "unknown" ? "neutral" : "observed";
        }
        // Operator clocks use KST; the original UTC string remains in datetime/title.
        timeText = timestamp === null ? "관측 시각 없음"
            : formatOperatorTimestamp(timestamp);
        detail = `Telemetry 처리 관측 · 품질 ${model.qualityStatus} · 최근성 ${model.freshnessStatus}. `
            + `최근 60초 관측 ${model.observedBucketCount}초 / 미관측 ${model.missingBucketCount}초. `
            + `입력 ${formatCount(model.recent60s.inputAcceptedCount)} / 처리 ${formatCount(model.recent60s.processingCompletedCount)}. `
            + (timestamp === null ? "마지막 관측 시각 없음. " : `마지막 관측 시각 ${timestamp}. `)
            + "Event 최초 수신 시각이나 시스템 가동 여부가 아닙니다.";
    }
    updateStatusText(nodes.state, label);
    updateStatusText(nodes.time, timestamp === null ? "" : timeText);
    nodes.time.hidden = timestamp === null;
    updateStatusText(nodes.details, detail);
    if (nodes.state.getAttribute("data-observation-tone") !== tone) {
        nodes.state.setAttribute("data-observation-tone", tone);
    }
    if (timestamp === null) {
        nodes.time.removeAttribute("datetime");
        nodes.time.removeAttribute("title");
    } else if (nodes.time.getAttribute("datetime") !== timestamp) {
        nodes.time.setAttribute("datetime", timestamp);
        nodes.time.setAttribute("title", timestamp);
    }
    // This card describes itself via the existing Telemetry live region. Dates/counts
    // remain non-live, so numeric updates do not produce a second announcement.
}

function renderUnavailable(doc, nodes, kind) {
    nodes.latencySummary.removeAttribute("title");
    nodes.latencySummary.removeAttribute("aria-label");
    clearMainLegend(nodes.throughputDetails);
    clearMainLegend(nodes.latencyDetails);
    replaceWithNotice(doc, nodes.throughputFrame,
        kind === "loading" ? "처리량 관측값 조회 중" : "처리량 조회 실패");
    replaceWithNotice(doc, nodes.latencyFrame,
        kind === "loading" ? "처리 지연 관측값 조회 중" : "처리 지연 조회 실패");
    nodes.throughputSummary.textContent = kind === "loading" ? "조회 중" : "조회 실패";
    nodes.latencySummary.textContent = kind === "loading" ? "조회 중" : "조회 실패";
    nodes.throughputDetails.textContent = kind === "loading" ? "최근 60초 실측값 확인 중" : "최근 60초 조회 실패";
    nodes.latencyDetails.textContent = kind === "loading" ? "최근 60초 실측값 확인 중" : "최근 60초 조회 실패";
    updateStatusText(nodes.throughputStatus, kind === "loading"
        ? "처리량 측정 데이터를 조회하고 있습니다."
        : "처리량 API 조회에 실패했습니다. 이전 측정값을 현재 값으로 표시하지 않습니다.");
    updateStatusText(nodes.latencyStatus, kind === "loading"
        ? "처리 지연 데이터를 조회하고 있습니다."
        : "처리 지연 API 조회에 실패했습니다. 이전 측정값을 현재 값으로 표시하지 않습니다.");
    // Keep the same explanation visible in the disclosure and available in the live region.
    nodes.throughputDetails.textContent += ` · ${nodes.throughputStatus.textContent}`;
    nodes.latencyDetails.textContent += ` · ${nodes.latencyStatus.textContent}`;
    nodes.throughputNote.textContent = kind === "loading" ? "조회 중" : "조회 오류";
    nodes.latencyNote.textContent = kind === "loading" ? "조회 중" : "조회 오류";
}

function renderTelemetry(doc, nodes, model) {
    const observed = model.seconds.some((second) => second.observed);
    let throughputObservation = "", latencyObservation = "";
    if (!observed) {
        clearMainLegend(nodes.throughputDetails);
        clearMainLegend(nodes.latencyDetails);
        replaceWithNotice(doc, nodes.throughputFrame, "실제 관측 데이터 없음");
        replaceWithNotice(doc, nodes.latencyFrame, "실제 처리 지연 데이터 없음");
    } else {
        throughputObservation = replaceObservedChart(doc, nodes.throughputFrame, model, "throughput", nodes.throughputDetails);
        if (model.seconds.some(second => second.processingLatencyMeanMs !== null)) {
            latencyObservation = replaceObservedChart(doc, nodes.latencyFrame, model, "latency", nodes.latencyDetails);
        } else {
            clearMainLegend(nodes.latencyDetails);
            replaceWithNotice(doc, nodes.latencyFrame, "실제 처리 지연 데이터 없음");
        }
    }

    const recent = model.recent60s;
    nodes.throughputSummary.textContent =
        `입력 ${formatCount(recent.inputAcceptedCount)} / 처리 ${formatCount(recent.processingCompletedCount)}`;
    const mainCard = doc.getElementById("dashboard-view") !== null;
    if (mainCard) {
        const input = doc.createElement("span");
        input.classList.add("dashboard-throughput-total-row");
        input.textContent = `입력 ${formatCount(recent.inputAcceptedCount)}`;
        input.setAttribute("aria-label", `최근 60초 입력 수락 ${formatCount(recent.inputAcceptedCount)}`);
        const separator = doc.createElement("span");
        separator.classList.add("dashboard-visually-hidden");
        separator.textContent = " / ";
        const completed = doc.createElement("span");
        completed.classList.add("dashboard-throughput-total-row");
        completed.textContent = `처리 ${formatCount(recent.processingCompletedCount)}`;
        completed.setAttribute("aria-label", `최근 60초 처리 완료 ${formatCount(recent.processingCompletedCount)}`);
        nodes.throughputSummary.replaceChildren(input, separator, completed);
    }
    nodes.latencySummary.textContent = formatLatency(recent.processingLatencyMeanMs, mainCard);
    if (mainCard && recent.processingLatencyMeanMs !== null) {
        const exact = `최근 60초 Normalization + 증거 평균 지연 ${recent.processingLatencyMeanMs} ms · 카드 표시는 반올림`;
        nodes.latencySummary.setAttribute("title", exact);
        nodes.latencySummary.setAttribute("aria-label", exact);
    } else {
        nodes.latencySummary.removeAttribute("title");
        nodes.latencySummary.removeAttribute("aria-label");
    }
    const coverage = `최근 60초 관측 ${model.observedBucketCount}초 · 미관측 ${model.missingBucketCount}초`;
    nodes.throughputDetails.textContent = coverage;
    nodes.latencyDetails.textContent = coverage;

    const statusParts = [];
    if (observed && model.observedBucketCount === 0) {
        statusParts.push("최근 60초 미관측 · 그래프에는 과거 관측만 표시됩니다.");
    }
    if (model.qualityStatus === "no_samples" || !observed) {
        statusParts.push("해당 조회 구간에 관측된 데이터가 없습니다. 미관측을 0건으로 계산하지 않습니다.");
    }
    if (model.qualityStatus === "partial") {
        statusParts.push("일부 Execution의 관측이 불완전합니다.");
    } else if (observed && model.qualityStatus !== "no_samples") {
        statusParts.push("보고된 Execution에서 실측값을 조회했습니다. 누락 초는 미관측입니다.");
    }
    if (model.freshnessStatus === "stale") {
        statusParts.push("마지막 관측이 지연되었습니다. Worker 장애로 단정하지 않습니다.");
    } else if (model.freshnessStatus === "unknown") {
        statusParts.push("최근 관측 여부를 확인할 수 없습니다.");
    }
    // Counts and timestamps belong to the disclosure, not the live region:
    // an otherwise unchanged observation state must not be announced each poll.
    const status = statusParts.join(" ");
    updateStatusText(nodes.throughputStatus, status);
    updateStatusText(nodes.latencyStatus, status);
    // The status sentences stay in the screen-reader live region only; the disclosure keeps coverage and time.
    const detail = formatObservedTime(model.lastObservedAt);
    nodes.throughputDetails.textContent += ` · ${detail}`;
    nodes.latencyDetails.textContent += ` · ${detail}`;
    if (throughputObservation) nodes.throughputDetails.textContent += ` · ${throughputObservation}`;
    if (latencyObservation) nodes.latencyDetails.textContent += ` · ${latencyObservation}`;
    const qualityLabel = model.qualityStatus === "partial"
        ? "부분 관측"
        : model.qualityStatus === "no_samples" || !observed ? "미관측" : "실측";
    const freshnessLabel = model.freshnessStatus === "stale"
        ? " · 관측 지연" : model.freshnessStatus === "unknown" ? " · 최신 여부 미확인" : "";
    nodes.throughputNote.textContent = qualityLabel + freshnessLabel;
    nodes.latencyNote.textContent = qualityLabel + freshnessLabel;
}

/** Polls Telemetry independently of Runtime. Repeated start or poll never duplicates a request. */
export function createDashboardTelemetryController(doc, {
    fetchImpl = (...args) => fetch(...args),
    setTimeoutImpl = (...args) => setTimeout(...args),
    clearTimeoutImpl = (id) => clearTimeout(id),
} = {}) {
    const nodes = {};
    for (const [name, id] of Object.entries(REQUIRED_IDS)) {
        const element = doc.getElementById(id);
        if (element === null) {
            throw new Error(`Missing Dashboard Telemetry element: ${id}`);
        }
        nodes[name] = element;
    }
    const observationNodes = Object.fromEntries(Object.entries(OBSERVATION_IDS).map(
        ([name, id]) => [name, doc.getElementById(id)],
    ));
    let running = false;
    let pending = null;
    let nextTimer = null;
    let requestController = null;
    let requestGeneration = 0;

    function schedule() {
        if (!running || nextTimer !== null || pending !== null) {
            return;
        }
        nextTimer = setTimeoutImpl(() => {
            nextTimer = null;
            void poll();
        }, POLL_INTERVAL_MS);
    }

    function poll() {
        if (!running) {
            return Promise.resolve();
        }
        if (pending !== null) {
            return pending;
        }
        const generation = ++requestGeneration;
        const controller = new AbortController();
        requestController = controller;
        const timeout = setTimeoutImpl(() => controller.abort(), REQUEST_TIMEOUT_MS);
        const operation = (async () => {
            try {
                const response = await fetchImpl(TELEMETRY_ENDPOINT, {
                    headers: { Accept: "application/json" },
                    cache: "no-store",
                    signal: controller.signal,
                });
                if (!response.ok) {
                    throw new Error(`Telemetry API returned HTTP ${response.status}`);
                }
                const model = buildTelemetryChartModel(await response.json());
                if (running && generation === requestGeneration) {
                    renderTelemetry(doc, nodes, model);
                    renderProcessingObservation(observationNodes, model);
                    return true;
                }
            } catch {
                if (running && generation === requestGeneration) {
                    renderUnavailable(doc, nodes, "error");
                    renderProcessingObservation(observationNodes, null, "error");
                    return false;
                }
            } finally {
                clearTimeoutImpl(timeout);
                if (requestController === controller) {
                    requestController = null;
                }
            }
        })();
        pending = operation;
        void operation.finally(() => {
            if (pending === operation) {
                pending = null;
            }
            schedule();
        });
        return operation;
    }

    function start() {
        if (running) {
            return pending ?? Promise.resolve();
        }
        running = true;
        renderUnavailable(doc, nodes, "loading");
        renderProcessingObservation(observationNodes, null, "loading");
        return poll();
    }

    function stop() {
        running = false;
        requestGeneration += 1;
        if (nextTimer !== null) {
            clearTimeoutImpl(nextTimer);
            nextTimer = null;
        }
        requestController?.abort();
        pending = null;
    }

    return { start, stop, poll };
}
