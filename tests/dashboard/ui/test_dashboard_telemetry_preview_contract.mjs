import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { buildPreviewPayload, createPreviewSource, SCENARIOS } from "../preview/telemetry-preview-model.mjs";
import { buildTelemetryChartModel, TELEMETRY_ENDPOINT } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-contract.mjs";
import { buildTelemetryChartPresentation } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-chart.mjs";
import { createDashboardTelemetryController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-controller.mjs";

class Node {
    constructor(tag) {
        this.tag = tag;
        this.children = [];
        this.attributes = {};
        this.text = "";
        this.classList = { add() {} };
    }
    set textContent(value) { this.text = value; this.children = []; }
    get textContent() { return this.text + this.children.map((item) => item.textContent).join(""); }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.text = ""; this.children = items; }
    setAttribute(key, value) { this.attributes[key] = value; }
}
function fakeDocument() {
    const nodes = new Map();
    for (const kind of ["throughput", "latency"]) {
        for (const part of ["chart", "summary", "details", "status", "note"]) {
            nodes.set(`telemetry-${kind}-${part}`, new Node("div"));
        }
    }
    return {
        getElementById: (id) => nodes.get(id) ?? null,
        createElement: (tag) => new Node(tag),
        createElementNS: (_namespace, tag) => new Node(tag),
        createTextNode: (value) => Object.assign(new Node("#text"), { text: value }),
    };
}
function clock() {
    let now = 0;
    let id = 0;
    const timers = new Map();
    return {
        nowImpl: () => now,
        setTimeoutImpl: (callback, delay) => { timers.set(++id, { callback, at: now + delay }); return id; },
        clearTimeoutImpl: (key) => timers.delete(key),
        async advance(ms) {
            now += ms;
            for (const [key, timer] of [...timers]) {
                if (timer.at <= now) { timers.delete(key); timer.callback(); }
            }
            // Flush fetch/json/render/finally, including the next 5s schedule.
            for (let turn = 0; turn < 8; turn += 1) await Promise.resolve();
        },
    };
}

test("All synthetic scenarios use the real validator and weighted recent-60s summary", () => {
    // Given / When
    for (const scenario of SCENARIOS) {
        const payload = buildPreviewPayload(25, scenario);
        const model = buildTelemetryChartModel(payload);
        // Then
        assert.equal(model.seconds.length, 300);
        assert.equal(payload.range_end, "2026-10-16T00:05:25.000Z");
        assert.equal(payload.input_scope, "validated_batch_admission");
        const recent = payload.points.filter((point) => point.bucket_start >= payload.recent_60s_summary.range_start);
        const summary = payload.recent_60s_summary;
        assert.equal(summary.observed_bucket_count, recent.length);
        assert.equal(summary.missing_bucket_count, 60 - recent.length);
        for (const key of ["input_accepted_count", "processing_completed_count", "processing_failed_count",
            "processing_latency_sample_count", "processing_latency_sum_ns"]) {
            assert.equal(summary[key], recent.length ? recent.reduce((total, point) => total + point[key], 0) : null);
        }
        assert.equal(summary.processing_latency_mean_ms, summary.processing_latency_sample_count
            ? summary.processing_latency_sum_ns / summary.processing_latency_sample_count / 1000000 : null);
        assert.ok(payload.points.every((point) => point.input_accepted_count + point.processing_completed_count > 0));
        assert.ok(payload.points.every((point, index) => index === 0 || payload.points[index - 1].bucket_start < point.bucket_start));
        assert.ok(payload.points.every((point) => /^\d{4}-.*\.\d{3}Z$/.test(point.observed_at)));
    }
});

test("The production controller updates both SVGs and summaries over three 5s polls", async () => {
    // Given
    const time = clock();
    const received = [];
    const source = createPreviewSource({ ...time, onResponse: (response) => received.push(response) });
    const doc = fakeDocument();
    const controller = createDashboardTelemetryController(doc, { ...time, fetchImpl: source.fetchImpl });
    const snapshots = [];
    source.start();
    await controller.start();
    snapshots.push(JSON.stringify(doc.getElementById("telemetry-throughput-chart")));
    const latency = [JSON.stringify(doc.getElementById("telemetry-latency-chart"))];
    const summaries = [doc.getElementById("telemetry-throughput-summary").textContent];
    // When
    for (let i = 0; i < 3; i += 1) {
        await time.advance(5000);
        snapshots.push(JSON.stringify(doc.getElementById("telemetry-throughput-chart")));
        latency.push(JSON.stringify(doc.getElementById("telemetry-latency-chart")));
        summaries.push(doc.getElementById("telemetry-throughput-summary").textContent);
    }
    // Then
    assert.deepEqual(received.map((response) => response.elapsedSeconds), [0, 5, 10, 15]);
    assert.equal(new Set(snapshots).size, 4);
    assert.equal(new Set(latency).size, 4);
    assert.ok(new Set(summaries).size > 1);
    assert.equal(received[3].payload.points[0].bucket_start, received[0].payload.points[15].bucket_start);
    assert.ok(!received[3].payload.points.some((point) => point.bucket_start === received[0].payload.points[0].bucket_start));
    controller.stop();
    source.pause();
    await time.advance(20000);
    assert.equal(received.length, 4);
    assert.equal(source.elapsedSeconds, 15);
    source.start();
    await controller.start();
    assert.equal(received.at(-1).elapsedSeconds, 15);
    await time.advance(5000);
    assert.equal(received.at(-1).elapsedSeconds, 20);
    controller.stop();
    source.reset();
    assert.equal(source.elapsedSeconds, 0);
    await assert.rejects(source.fetchImpl("/operations/runs"), /only the Telemetry/);
    await assert.rejects(source.fetchImpl(TELEMETRY_ENDPOINT, { signal: AbortSignal.abort() }), /stopped/);
});

test("Sparse/zero/null/stale/unknown semantics and 500/503 errors reach the actual UI", async () => {
    // Given
    const time = clock();
    const source = createPreviewSource(time);
    const doc = fakeDocument();
    const controller = createDashboardTelemetryController(doc, { ...time, fetchImpl: source.fetchImpl });
    const note = () => doc.getElementById("telemetry-throughput-note").textContent;
    for (const [scenario, expected] of [["no_samples", /미관측/], ["partial", /부분 관측/],
        ["unknown", /최신 여부 미확인/], ["api_500", /조회 오류/], ["api_503", /조회 오류/]]) {
        // When
        source.reset(scenario); source.start(); await controller.start();
        // Then
        assert.match(note(), expected);
        if (scenario.startsWith("api_")) assert.match(doc.getElementById("telemetry-throughput-summary").textContent, /조회 실패/);
        controller.stop();
    }
    source.reset("stale"); source.start(); await controller.start();
    assert.equal(note(), "실측");
    await time.advance(15000);
    assert.match(note(), /관측 지연/);
    controller.stop();
    const sparse = buildTelemetryChartPresentation(buildTelemetryChartModel(buildPreviewPayload(0, "sparse")), "throughput");
    assert.ok(sparse.series[0].segments.length < sparse.series[0].marks.length - 1);
    const zero = buildTelemetryChartModel(buildPreviewPayload(0, "observed_zero"));
    assert.ok(zero.seconds.some((second) => second.observed && second.processingCompletedCount === 0));
    assert.ok(zero.seconds.some((second) => second.observed && second.processingLatencyMeanMs === null));
    assert.ok(zero.seconds.some((second) => second.observed && second.processingLatencyMeanMs === 0));
});

test("Partial observations remain a warning even when no point falls in the current window", async () => {
    // Given
    const time = clock();
    const doc = fakeDocument();
    const payload = buildPreviewPayload(0, "no_samples");
    payload.observation_quality.status = "partial";
    const controller = createDashboardTelemetryController(doc, {
        ...time, fetchImpl: async () => ({ ok: true, json: async () => payload }),
    });
    // When
    await controller.start();
    // Then
    assert.match(doc.getElementById("telemetry-throughput-status").textContent, /관측된 데이터가 없습니다/);
    assert.match(doc.getElementById("telemetry-throughput-status").textContent, /불완전/);
    assert.match(doc.getElementById("telemetry-throughput-note").textContent, /부분 관측/);
    assert.match(doc.getElementById("telemetry-throughput-summary").textContent, /미관측/);
    controller.stop();
});

test("Preview is opt-in local-only; the production entry points never import synthetic sources", async () => {
    // Given / When
    const root = new URL("../../../", import.meta.url);
    for (const name of ["dashboard.js", "dashboard-telemetry-controller.mjs", "dashboard-telemetry-contract.mjs", "dashboard-telemetry-chart.mjs"]) {
        const source = await readFile(new URL(`src/incident_awareness/dashboard/ui/assets/${name}`, root), "utf8");
        // Then
        assert.doesNotMatch(source, /preview|buildPreviewPayload|createPreviewSource/i);
    }
    const html = await readFile(new URL("tests/dashboard/preview/telemetry-preview.html", root), "utf8");
    assert.match(html, /시연용 샘플 데이터 · 실제 관측 아님/);
    assert.doesNotMatch(html, /selected-run-chart|dashboard-replay/);
    const entry = await readFile(new URL("tests/dashboard/preview/telemetry-preview.mjs", root), "utf8");
    assert.match(entry, /createDashboardTelemetryController\(document, \{ fetchImpl: source.fetchImpl \}\)/);
    assert.doesNotMatch(entry, /(?:window|globalThis)\.fetch\s*=/);
});
