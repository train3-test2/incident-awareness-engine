// Independent, bounded Telemetry polling for the operations Dashboard.
// Observations are never synthesized; API errors must not look like zero throughput.

import { buildTelemetryChartModel, TELEMETRY_ENDPOINT } from "./dashboard-telemetry-contract.mjs";
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

function formatObservedTime(timestamp) {
    if (timestamp === null) {
        return "마지막 관측 시각: 확인 불가";
    }
    return `마지막 관측: ${new Date(timestamp).toLocaleString("ko-KR")}`;
}

function formatCount(value) {
    return value === null ? "미관측" : `${value.toLocaleString("ko-KR")}건`;
}

function formatLatency(value) {
    return value === null
        ? "미관측"
        : `${value.toLocaleString("ko-KR", { maximumFractionDigits: 6 })} ms`;
}

function replaceWithNotice(doc, frame, notice) {
    const restoreFocus = doc.activeElement && frame.contains?.(doc.activeElement);
    const label = doc.createElement("span");
    label.textContent = notice;
    frame.replaceChildren(label);
    if (restoreFocus) frame.focus?.({ preventScroll: true });
}

function replaceObservedChart(doc, frame, model, kind) {
    const active = doc.activeElement;
    const restoreFocus = active && frame.contains?.(active);
    const previousPlot = frame.querySelector?.(".dashboard-telemetry-chart__plot");
    const timestamp = active?.getAttribute?.("data-timestamp");
    const series = active?.getAttribute?.("data-series");
    const dimensions = Number.isFinite(frame.clientWidth) && frame.clientWidth > 0
        ? { width: Math.max(300, frame.clientWidth - 2) } : null;
    frame.replaceChildren(createTelemetryChart(model, kind, doc, dimensions));
    const plot = frame.querySelector?.(".dashboard-telemetry-chart__plot");
    if (plot) plot.scrollLeft = previousPlot ? previousPlot.scrollLeft : plot.scrollWidth;
    if (restoreFocus) {
        const marker = timestamp && [...frame.querySelectorAll("circle")].find((circle) => (
            circle.getAttribute("data-timestamp") === timestamp
            && circle.getAttribute("data-series") === series
        ));
        (marker || plot || frame).focus?.({ preventScroll: true });
    }
}

function updateStatusText(element, message) {
    if (element.textContent !== message) {
        element.textContent = message;
    }
}

function renderUnavailable(doc, nodes, kind) {
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
    if (!observed) {
        replaceWithNotice(doc, nodes.throughputFrame, "실제 관측 데이터 없음");
        replaceWithNotice(doc, nodes.latencyFrame, "실제 처리 지연 데이터 없음");
    } else {
        replaceObservedChart(doc, nodes.throughputFrame, model, "throughput");
        replaceObservedChart(doc, nodes.latencyFrame, model, "latency");
    }

    const recent = model.recent60s;
    nodes.throughputSummary.textContent =
        `입력 ${formatCount(recent.inputAcceptedCount)} / 처리 ${formatCount(recent.processingCompletedCount)}`;
    nodes.latencySummary.textContent = formatLatency(recent.processingLatencyMeanMs);
    const coverage = `최근 60초 관측 ${model.observedBucketCount}초 · 미관측 ${model.missingBucketCount}초`;
    nodes.throughputDetails.textContent = coverage;
    nodes.latencyDetails.textContent = `${coverage} · 지연 샘플 ${formatCount(recent.processingLatencySampleCount)}`;

    const statusParts = [];
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
    const detail = `${status} · ${formatObservedTime(model.lastObservedAt)}`;
    nodes.throughputDetails.textContent += ` · ${detail}`;
    nodes.latencyDetails.textContent += ` · ${detail}`;
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
                }
            } catch {
                if (running && generation === requestGeneration) {
                    renderUnavailable(doc, nodes, "error");
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
