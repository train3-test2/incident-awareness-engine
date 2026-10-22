import assert from "node:assert/strict";
import test from "node:test";

import { createDashboardTelemetryController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-controller.mjs";
import { TELEMETRY_ENDPOINT } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-contract.mjs";

const elementIds = [
    "telemetry-throughput-chart", "telemetry-throughput-summary", "telemetry-throughput-details",
    "telemetry-throughput-status", "telemetry-throughput-note",
    "telemetry-latency-chart", "telemetry-latency-summary", "telemetry-latency-details",
    "telemetry-latency-status", "telemetry-latency-note",
];

test("Manual Telemetry poll reports success or failure and shares a pending request", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    let resolve;
    let calls = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...timers, fetchImpl: () => { calls += 1; return new Promise(done => { resolve = done; }); },
    });
    // When
    const startup = controller.start();
    const joined = controller.poll();
    resolve({ ok: true, json: async () => payload() });
    // Then
    assert.equal(startup, joined);
    assert.equal(await joined, true);
    assert.equal(calls, 1);
    // When / Then
    const retry = controller.poll();
    resolve({ ok: false, status: 503 });
    assert.equal(await retry, false);
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 실패");
    controller.stop();
});

class FakeNode {
    constructor(tagName) {
        this.tagName = tagName;
        this.children = [];
        this.ownText = "";
        this.textContentWrites = 0;
        this.attributes = new Map();
        this.classes = new Set();
        this.classList = { add: (...names) => names.forEach((name) => this.classes.add(name)) };
    }

    get textContent() {
        return this.ownText + this.children.map((child) => child.textContent).join("");
    }

    set textContent(value) {
        this.textContentWrites += 1;
        this.ownText = String(value);
        this.children = [];
    }

    append(...children) {
        this.children.push(...children);
    }

    replaceChildren(...children) {
        this.ownText = "";
        this.children = [...children];
    }

    setAttribute(name, value) {
        this.attributes.set(name, String(value));
    }

    getAttribute(name) {
        return this.attributes.get(name) ?? null;
    }

    removeAttribute(name) {
        this.attributes.delete(name);
    }
}

function makeDocument({ insight = false } = {}) {
    const elements = new Map(elementIds.map((id) => [id, new FakeNode("div")]));
    if (insight) {
        for (const part of ["state", "time", "details"]) {
            elements.set(`processing-observation-${part}`, new FakeNode(part === "time" ? "time" : "span"));
        }
    }
    return {
        elements,
        getElementById: (id) => elements.get(id) ?? null,
        createElement: (name) => new FakeNode(name),
        createElementNS: (_namespace, name) => new FakeNode(name),
        createTextNode: (content) => {
            const node = new FakeNode("#text");
            node.textContent = content;
            return node;
        },
    };
}

function fakeTimers() {
    const timers = new Map();
    let nextId = 1;
    return {
        timers,
        setTimeoutImpl: (callback, delay) => {
            const id = nextId++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutImpl: (id) => timers.delete(id),
    };
}

test("Main cards keep one visible legend and move observation detail without losing accessibility", async () => {
    // Given: a minimal main-only DOM. Standalone documents continue using the original fake DOM.
    class MainNode extends FakeNode {
        get childNodes() { return this.children; }
        append(...nodes) { super.append(...nodes); for (const node of nodes) node.parent = this; }
        replaceChildren(...nodes) { super.replaceChildren(...nodes); for (const node of nodes) node.parent = this; }
        remove() { if (this.parent) this.parent.children = this.parent.children.filter(node => node !== this); }
        querySelector(selector) {
            const parts = selector.split(" ");
            if (parts.length > 1) return this.querySelector(parts[0])?.querySelector(parts.slice(1).join(" ")) ?? null;
            const match = node => selector.startsWith(".")
                ? node.classes.has(selector.slice(1)) || (node.getAttribute("class") ?? "").split(" ").includes(selector.slice(1))
                : node.tagName === selector;
            for (const child of this.children) {
                if (match(child)) return child;
                const found = child.querySelector(selector);
                if (found) return found;
            }
            return null;
        }
    }
    const doc = makeDocument();
    for (const id of elementIds) doc.elements.set(id, new MainNode("div"));
    doc.elements.set("dashboard-view", new MainNode("main"));
    doc.createElement = name => new MainNode(name);
    doc.createElementNS = (_, name) => new MainNode(name);
    doc.createTextNode = text => { const node = new MainNode("text"); node.textContent = text; return node; };
    const summaries = [];
    for (const kind of ["throughput", "latency"]) {
        const disclosure = new MainNode("details"), summary = new MainNode("summary");
        disclosure.append(summary); summaries.push(summary);
        doc.elements.get(`telemetry-${kind}-details`).closest = () => disclosure;
        doc.elements.get(`telemetry-${kind}-chart`).clientWidth = kind === "throughput" ? 700 : 350;
    }
    let fail = false;
    let response = payload();
    const timers = fakeTimers();
    const controller = createDashboardTelemetryController(doc, { ...timers,
        fetchImpl: async () => fail ? { ok: false } : { ok: true, json: async () => response },
    });
    // When
    await controller.start();
    await controller.poll();
    // Then
    assert.ok(summaries.every(summary => summary.children.length === 1));
    assert.ok(summaries.every(summary => summary.children[0].getAttribute("role") === "list"));
    const frame = doc.elements.get("telemetry-throughput-chart");
    assert.equal(frame.querySelector(".dashboard-telemetry-chart__observation"), null);
    assert.match(frame.querySelector("desc").textContent, /관측 버킷/);
    assert.match(doc.elements.get("telemetry-throughput-details").textContent, /관측 버킷/);
    assert.match(doc.elements.get("telemetry-latency-chart").querySelector("svg").getAttribute("viewBox"), /78$/);
    const mean = doc.elements.get("telemetry-latency-summary");
    assert.equal(mean.textContent, "0.775 ms");
    assert.match(mean.getAttribute("title"), /0\.775214 ms/);
    const totals = doc.elements.get("telemetry-throughput-summary");
    assert.deepEqual(totals.children.filter(node => node.classes.has("dashboard-throughput-total-row"))
        .map(node => node.getAttribute("aria-label")), ["최근 60초 입력 수락 2건", "최근 60초 처리 완료 2건"]);
    assert.equal(totals.textContent, "입력 2건 / 처리 2건");
    response.points[0].processing_latency_mean_ms = 0.000000123;
    response.recent_60s_summary.processing_latency_mean_ms = 0.000000123;
    await controller.poll();
    assert.equal(mean.textContent, "1.2e-7 ms");
    assert.match(mean.getAttribute("aria-label"), /1\.23e-7 ms/);
    response.points[0].processing_latency_mean_ms = 0;
    response.recent_60s_summary.processing_latency_mean_ms = 0;
    await controller.poll();
    assert.equal(mean.textContent, "0 ms");
    response = withoutCurrentSamples(payload());
    await controller.poll();
    assert.equal(mean.textContent, "미관측");
    assert.equal(mean.getAttribute("title"), null);
    assert.equal(totals.textContent, "입력 미관측 / 처리 미관측");
    // When / Then: a failed query removes the visible legend and stale measurements.
    fail = true;
    await controller.poll();
    assert.ok(summaries.every(summary => summary.children.length === 0));
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 실패");
    controller.stop();
});

function payload() {
    return {
        schema_version: "pipeline_telemetry_read_v1",
        scope: "reported",
        range_start: "2026-10-15T05:22:20.000Z",
        range_end: "2026-10-15T05:23:20.000Z",
        resolution_seconds: 1,
        points: [{
            bucket_start: "2026-10-15T05:23:17.000Z",
            bucket_end: "2026-10-15T05:23:18.000Z",
            input_accepted_count: 2,
            processing_completed_count: 2,
            processing_failed_count: 0,
            processing_latency_sample_count: 2,
            processing_latency_mean_ms: 0.775214,
        }],
        recent_60s_summary: {
            observed_bucket_count: 1,
            missing_bucket_count: 59,
            input_accepted_count: 2,
            processing_completed_count: 2,
            processing_failed_count: 0,
            processing_latency_sample_count: 2,
            processing_latency_mean_ms: 0.775214,
        },
        observation_quality: { status: "observed" },
        freshness: { status: "recent" },
        last_observed_at: "2026-10-15T05:23:17.642Z",
    };
}

test("Operator compact metrics distinguish no observations, real zero and returning samples", async () => {
    // Given
    const doc = makeDocument();
    let response = withoutCurrentSamples(payload());
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ok: true, json: async () => response}),
    });
    // When / Then: missing is compact, never a zero-valued chart.
    await controller.start();
    assert.equal(doc.elements.get("telemetry-throughput-chart").getAttribute("data-empty"), "true");
    assert.equal(doc.elements.get("telemetry-latency-chart").getAttribute("data-empty"), "true");
    // When / Then: genuine measured zero remains an observed chart.
    response = payload();
    response.points[0].input_accepted_count = 1;
    response.points[0].processing_completed_count = 0;
    response.points[0].processing_latency_sample_count = 0;
    response.points[0].processing_latency_mean_ms = null;
    Object.assign(response.recent_60s_summary, {input_accepted_count:1,processing_completed_count:0,processing_latency_sample_count:0,processing_latency_mean_ms:null});
    await controller.poll();
    assert.equal(doc.elements.get("telemetry-throughput-chart").getAttribute("data-empty"), "false");
    assert.equal(doc.elements.get("telemetry-latency-chart").getAttribute("data-empty"), "true");
    assert.match(doc.elements.get("telemetry-throughput-summary").textContent, /처리 0건/);
    response = payload();
    await controller.poll();
    assert.equal(doc.elements.get("telemetry-latency-chart").getAttribute("data-empty"), "false");
    controller.stop();
});

function descendants(node, tagName) {
    return node.children.flatMap((child) => [
        ...(child.tagName === tagName ? [child] : []),
        ...descendants(child, tagName),
    ]);
}

function withoutCurrentSamples(response, { last = null, quality = "no_samples", freshness = "unknown" } = {}) {
    response.points = [];
    response.last_observed_at = last;
    response.observation_quality.status = quality;
    response.freshness.status = freshness;
    Object.assign(response.recent_60s_summary, {
        observed_bucket_count: 0, missing_bucket_count: 60,
        input_accepted_count: null, processing_completed_count: null,
        processing_failed_count: null, processing_latency_sample_count: null,
        processing_latency_mean_ms: null,
    });
    return response;
}

for (const [name, alter, label, tone] of [
    ["recent", () => {}, "최근 관측", "observed"],
    ["stale", (p) => { p.freshness.status = "stale"; }, "오래된 관측", "warning"],
    ["no history", (p) => withoutCurrentSamples(p), "조회 구간 미관측", "neutral"],
    ["partial", (p) => { p.observation_quality.status = "partial"; }, "부분 관측 · 최근", "warning"],
    ["partial stale", (p) => { p.observation_quality.status = "partial"; p.freshness.status = "stale"; }, "부분 관측 · 오래됨", "warning"],
    ["unknown", (p) => { p.freshness.status = "unknown"; }, "최근성 불명", "neutral"],
    ["partial without samples", (p) => withoutCurrentSamples(p, { quality: "partial" }), "부분 관측 · 최근성 불명", "warning"],
    ["historical outside the window", (p) => withoutCurrentSamples(p, { last: "2026-10-15T04:00:00.000Z", freshness: "stale" }), "구간 미관측 · 오래됨", "warning"],
    ["observed quality without buckets", (p) => withoutCurrentSamples(p, { quality: "observed" }), "조회 구간 미관측", "neutral"],
]) {
    test(`Processing observation Insight distinguishes ${name} using the chart response`, async () => {
        // Given
        const doc = makeDocument({ insight: true });
        const response = payload();
        alter(response);
        let calls = 0;
        const controller = createDashboardTelemetryController(doc, {
            ...fakeTimers(),
            fetchImpl: async (url) => {
                assert.equal(url, TELEMETRY_ENDPOINT);
                calls += 1;
                return { ok: true, json: async () => response };
            },
        });

        // When
        await controller.start();

        // Then
        assert.equal(calls, 1, "One response updates both charts and the Insight");
        assert.equal(doc.elements.get("processing-observation-state").textContent, label);
        assert.equal(doc.elements.get("processing-observation-state").getAttribute("data-observation-tone"), tone);
        assert.equal(doc.elements.get("processing-observation-time").getAttribute("datetime"), response.last_observed_at);
        const detail = doc.elements.get("processing-observation-details").textContent;
        assert.match(detail, /Event 최초 수신 시각이나 시스템 가동 여부가 아닙니다/);
        assert.ok(detail.includes(`최근성 ${response.freshness.status}`));
        assert.ok(detail.includes(`미관측 ${response.recent_60s_summary.missing_bucket_count}초`));
        controller.stop();
    });
}

test("Processing observation preserves measured zero, null recent summary, and explicit UTC precision", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    let response = payload();
    response.points[0].input_accepted_count = 0;
    response.recent_60s_summary.input_accepted_count = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
    });

    // When / Then
    await controller.start();
    assert.equal(doc.elements.get("processing-observation-state").textContent, "최근 관측");
    assert.match(doc.elements.get("processing-observation-details").textContent, /입력 0건 \/ 처리 2건/);
    const time = doc.elements.get("processing-observation-time");
    assert.equal(time.textContent, "2026.10.15 14:23:17.642 KST");
    assert.equal(time.getAttribute("title"), "2026-10-15T05:23:17.642Z");
    assert.equal(time.getAttribute("datetime"), "2026-10-15T05:23:17.642Z");
    response.points[0].processing_completed_count = 0;
    response.points[0].processing_failed_count = 1;
    response.points[0].processing_latency_sample_count = 0;
    response.points[0].processing_latency_mean_ms = null;
    Object.assign(response.recent_60s_summary, {
        processing_completed_count: 0, processing_failed_count: 1,
        processing_latency_sample_count: 0, processing_latency_mean_ms: null,
    });
    await controller.poll();
    assert.equal(doc.elements.get("processing-observation-state").textContent, "최근 관측");
    assert.match(doc.elements.get("processing-observation-details").textContent, /입력 0건 \/ 처리 0건/);
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "미관측");
    response = withoutCurrentSamples(payload(), { last: "2026-10-15T04:00:00.000Z", freshness: "stale" });
    await controller.poll();
    assert.match(doc.elements.get("processing-observation-details").textContent, /입력 미관측 \/ 처리 미관측/);
    assert.equal(time.textContent, "2026.10.15 13:00:00 KST");
    assert.match(doc.elements.get("processing-observation-state").textContent, /구간 미관측/);
    controller.stop();
});

test("Processing observation clears old values on API failure and loading, and recovers without extra polling", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    const timers = fakeTimers();
    let fail = false;
    let calls = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...timers, fetchImpl: async () => { calls += 1; return fail ? { ok: false, status: 503 } : { ok: true, json: async () => payload() }; },
    });

    // When
    const first = controller.start();
    assert.equal(doc.elements.get("processing-observation-state").textContent, "조회 중");
    await first;
    fail = true;
    await controller.poll();

    // Then
    assert.equal(doc.elements.get("processing-observation-state").textContent, "조회 실패");
    assert.equal(doc.elements.get("processing-observation-time").textContent, "");
    assert.equal(doc.elements.get("processing-observation-time").hidden, true);
    assert.equal(doc.elements.get("processing-observation-time").getAttribute("datetime"), null);
    assert.equal(doc.elements.get("processing-observation-time").getAttribute("title"), null);
    assert.doesNotMatch(doc.elements.get("processing-observation-details").textContent, /2026-10-15/);
    assert.match(doc.elements.get("processing-observation-details").textContent, /이전 관측 시각을 현재 실측으로 표시하지 않습니다/);
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 실패");
    fail = false;
    await controller.poll();
    assert.equal(doc.elements.get("processing-observation-state").textContent, "최근 관측");
    assert.equal(calls, 3);
    assert.equal([...timers.timers.values()].filter((timer) => timer.delay === 5000).length, 1);
    controller.stop();
    const restarted = controller.start();
    assert.equal(doc.elements.get("processing-observation-time").getAttribute("datetime"), null);
    assert.equal(doc.elements.get("processing-observation-state").textContent, "조회 중");
    await restarted;
    controller.stop();
});

test("Processing observation uses guarded non-live text and the existing shared chart announcement", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    let response = payload();
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
    });
    await controller.start();
    const state = doc.elements.get("processing-observation-state");
    const time = doc.elements.get("processing-observation-time");
    const detail = doc.elements.get("processing-observation-details");
    const live = doc.elements.get("telemetry-throughput-status");
    const before = [state, time, detail, live].map((node) => node.textContentWrites);

    // When / Then
    await controller.poll();
    assert.deepEqual([state, time, detail, live].map((node) => node.textContentWrites), before);
    response = payload();
    response.last_observed_at = "2026-10-15T05:23:18.642Z";
    response.recent_60s_summary.input_accepted_count = 3;
    await controller.poll();
    assert.equal(state.textContentWrites, before[0]);
    assert.equal(live.textContentWrites, before[3]);
    assert.equal(time.textContentWrites, before[1] + 1);
    assert.match(detail.textContent, /입력 3건/);
    controller.stop();
});

test("Invalid Telemetry model cannot leave a previously observed Insight visible", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    const response = payload();
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
    });
    await controller.start();

    // When
    response.scope = "run";
    await controller.poll();

    // Then
    assert.equal(doc.elements.get("processing-observation-state").textContent, "조회 실패");
    assert.equal(doc.elements.get("processing-observation-time").getAttribute("datetime"), null);
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 실패");
    controller.stop();
});

test("Processing observation restart rejects late successful and failed responses from the old lifecycle", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    const timers = fakeTimers();
    const pending = [];
    const controller = createDashboardTelemetryController(doc, {
        ...timers, fetchImpl: () => new Promise((resolve) => pending.push(resolve)),
    });
    const old = controller.start();
    void controller.start();
    void controller.poll();
    assert.equal(pending.length, 1);
    controller.stop();
    const current = controller.start();
    assert.equal(pending.length, 2);

    // When
    pending[1]({ ok: true, json: async () => payload() });
    await current;
    const currentText = doc.elements.get("processing-observation-details").textContent;
    pending[0]({ ok: false, status: 503 });
    await old;

    // Then
    assert.equal(doc.elements.get("processing-observation-details").textContent, currentText);
    assert.equal(doc.elements.get("processing-observation-state").textContent, "최근 관측");
    const stopped = controller.poll();
    controller.stop();
    pending[2]({ ok: true, json: async () => withoutCurrentSamples(payload()) });
    await stopped;
    assert.equal(doc.elements.get("processing-observation-details").textContent, currentText);
    assert.equal(timers.timers.size, 0);
});

test("Telemetry Preview without any or with an incomplete optional Insight DOM keeps both charts", async () => {
    // Given
    for (const partial of [false, true]) {
        const doc = makeDocument();
        if (partial) doc.elements.set("processing-observation-state", new FakeNode("strong"));
        const controller = createDashboardTelemetryController(doc, {
            ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => payload() }),
        });

        // When
        await controller.start();

        // Then
        assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 2건 / 처리 2건");
        assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "0.775214 ms");
        assert.equal(doc.elements.get("telemetry-throughput-note").textContent, "실측");
        assert.equal(descendants(doc.elements.get("telemetry-throughput-chart"), "figure").length, 1);
        controller.stop();
    }
});

test("Telemetry redraw preserves keyboard focus on a stored marker, then falls back safely when empty", async () => {
    // Given
    const doc = makeDocument();
    const frame = doc.elements.get("telemetry-throughput-chart");
    const createElement = doc.createElement;
    doc.createElement = (name) => {
        const node = createElement(name);
        node.scrollWidth = 120;
        node.focus = () => { doc.activeElement = node; };
        return node;
    };
    const createElementNS = doc.createElementNS;
    doc.createElementNS = (namespace, name) => {
        const node = createElementNS(namespace, name);
        node.getAttribute = (key) => node.attributes.get(key) ?? null;
        node.focus = () => { doc.activeElement = node; };
        return node;
    };
    frame.contains = (node) => node === frame || descendants(frame, node?.tagName).includes(node);
    frame.querySelector = () => descendants(frame, "div").find((node) => node.classes.has("dashboard-telemetry-chart__plot"));
    frame.querySelectorAll = (name) => descendants(frame, name);
    frame.focus = () => { doc.activeElement = frame; };
    let failed = false;
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => failed ? { ok: false, status: 503 }
            : { ok: true, json: async () => payload() },
    });
    await controller.start();
    const original = descendants(frame, "circle")[0];
    assert.equal(frame.querySelector().scrollLeft, 120, "Initial narrow plot opens at the latest observation");
    original.focus();
    frame.querySelector().scrollLeft = 30;

    // When
    await controller.poll();

    // Then
    assert.notStrictEqual(doc.activeElement, original);
    assert.equal(doc.activeElement.getAttribute("data-timestamp"), original.getAttribute("data-timestamp"));
    assert.equal(doc.activeElement.getAttribute("data-series"), "input");
    assert.equal(frame.querySelector().scrollLeft, 30);
    failed = true;
    await controller.poll();
    assert.strictEqual(doc.activeElement, frame);
    assert.match(frame.textContent, /조회 실패/);
    controller.stop();
});

test("New numeric observations and timestamps do not reannounce unchanged live status", async () => {
    // Given
    const doc = makeDocument();
    let current = payload();
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => current }),
    });
    await controller.start();
    const status = doc.elements.get("telemetry-throughput-status");
    const writes = status.textContentWrites;
    const originalDetails = doc.elements.get("telemetry-throughput-details").textContent;

    // When
    current = payload();
    current.last_observed_at = "2026-10-15T05:23:18.642Z";
    current.recent_60s_summary.input_accepted_count = 3;
    await controller.poll();

    // Then
    assert.equal(status.textContentWrites, writes);
    assert.equal(doc.elements.get("telemetry-latency-status").textContentWrites, writes);
    assert.notEqual(doc.elements.get("telemetry-throughput-details").textContent, originalDetails);
    assert.match(doc.elements.get("telemetry-throughput-summary").textContent, /입력 3건/);
    assert.doesNotMatch(status.textContent, /마지막 관측:/);
    current.observation_quality.status = "partial";
    await controller.poll();
    assert.equal(status.textContentWrites, writes + 1);
    assert.match(status.textContent, /불완전/);
    controller.stop();
});

test("Telemetry UI shows live stored AWS samples with proper units and coverage", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    const calls = [];
    const controller = createDashboardTelemetryController(doc, {
        ...timers,
        fetchImpl: async (...args) => {
            calls.push(args);
            return { ok: true, json: async () => payload() };
        },
    });

    // When
    await controller.start();

    // Then
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], TELEMETRY_ENDPOINT);
    assert.equal(calls[0][1].cache, "no-store");
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 2건 / 처리 2건");
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "0.775214 ms");
    assert.match(doc.elements.get("telemetry-throughput-details").textContent, /미관측 59초/);
    assert.equal(descendants(doc.elements.get("telemetry-throughput-chart"), "figure").length, 1);
    assert.equal(descendants(doc.elements.get("telemetry-latency-chart"), "figure").length, 1);
    await Promise.resolve();
    assert.equal([...timers.timers.values()].filter((item) => item.delay === 5000).length, 1);
    controller.stop();
    assert.equal(timers.timers.size, 0);
});

test("Telemetry UI no_samples and stale are distinct from measured zero or worker failure", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    const empty = payload();
    empty.points = [];
    Object.assign(empty.recent_60s_summary, {
        observed_bucket_count: 0,
        missing_bucket_count: 60,
        input_accepted_count: null,
        processing_completed_count: null,
        processing_failed_count: null,
        processing_latency_sample_count: null,
        processing_latency_mean_ms: null,
    });
    empty.observation_quality.status = "no_samples";
    empty.freshness.status = "unknown";
    empty.last_observed_at = null;
    const controller = createDashboardTelemetryController(doc, {
        ...timers,
        fetchImpl: async () => ({ ok: true, json: async () => empty }),
    });

    // When
    await controller.start();

    // Then
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 미관측 / 처리 미관측");
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "미관측");
    assert.equal(descendants(doc.elements.get("telemetry-throughput-chart"), "figure").length, 0);
    assert.match(doc.elements.get("telemetry-throughput-status").textContent, /0건으로 계산하지/);
    assert.match(doc.elements.get("telemetry-throughput-status").textContent, /최근 관측 여부/);
    controller.stop();
});

test("Past observations in the five-minute window never replace a null recent-60s summary", async () => {
    // Given
    const doc = makeDocument();
    const response = payload();
    response.range_start = "2026-10-15T05:18:20.000Z";
    response.points[0].bucket_start = "2026-10-15T05:21:17.000Z";
    response.points[0].bucket_end = "2026-10-15T05:21:18.000Z";
    response.last_observed_at = "2026-10-15T05:21:17.642Z";
    response.freshness.status = "stale";
    Object.assign(response.recent_60s_summary, {
        observed_bucket_count: 0, missing_bucket_count: 60,
        input_accepted_count: null, processing_completed_count: null,
        processing_failed_count: null, processing_latency_sample_count: null,
        processing_latency_mean_ms: null,
    });
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
    });

    // When
    await controller.start();

    // Then
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 미관측 / 처리 미관측");
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "미관측");
    for (const kind of ["throughput", "latency"]) {
        assert.match(doc.elements.get(`telemetry-${kind}-chart`).textContent, /최근 60초 미관측.*과거 실측/);
        assert.equal(doc.elements.get(`telemetry-${kind}-note`).textContent, "실측 · 관측 지연");
    }
    response.points = [];
    response.observation_quality.status = "no_samples";
    await controller.poll();
    assert.doesNotMatch(doc.elements.get("telemetry-throughput-chart").textContent, /입력 수락 2건|과거 실측/);
    assert.match(doc.elements.get("telemetry-throughput-chart").textContent, /실제 관측 데이터 없음/);
    controller.stop();
});

test("Telemetry HTTP failure clears earlier chart instead of preserving it as a current value", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    let requests = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...timers,
        fetchImpl: async () => {
            requests += 1;
            return requests === 1
                ? { ok: true, json: async () => payload() }
                : { ok: false, status: 503 };
        },
    });
    await controller.start();

    // When
    await controller.poll();

    // Then
    assert.equal(requests, 2);
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "조회 실패");
    assert.equal(descendants(doc.elements.get("telemetry-throughput-chart"), "figure").length, 0);
    assert.match(doc.elements.get("telemetry-throughput-status").textContent, /이전 측정값/);
    controller.stop();
});

for (const quality of ["no_samples", "observed", "partial"]) {
    for (const freshness of ["recent", "stale", "unknown"]) {
        test(`No observed buckets: ${quality}/${freshness} preserves missing data and quality warnings`, async (t) => {
            // Given
            const doc = makeDocument();
            const response = payload();
            response.points = [];
            response.observation_quality.status = quality;
            response.freshness.status = freshness;
            Object.assign(response.recent_60s_summary, {
                observed_bucket_count: 0, missing_bucket_count: 60,
                input_accepted_count: null, processing_completed_count: null,
                processing_failed_count: null, processing_latency_sample_count: null,
                processing_latency_mean_ms: null,
            });
            const controller = createDashboardTelemetryController(doc, {
                ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
            });
            t.after(controller.stop);

            // When
            await controller.start();

            // Then
            const qualityLabel = quality === "partial" ? "부분 관측" : "미관측";
            const freshnessLabel = freshness === "stale" ? " · 관측 지연"
                : freshness === "unknown" ? " · 최신 여부 미확인" : "";
            for (const kind of ["throughput", "latency"]) {
                assert.equal(doc.elements.get(`telemetry-${kind}-note`).textContent, qualityLabel + freshnessLabel);
                assert.equal(descendants(doc.elements.get(`telemetry-${kind}-chart`), "figure").length, 0);
                assert.match(doc.elements.get(`telemetry-${kind}-summary`).textContent, /미관측/);
                const status = doc.elements.get(`telemetry-${kind}-status`).textContent;
                assert.match(status, /관측된 데이터가 없습니다/);
                if (quality === "partial") assert.match(status, /불완전/);
                if (freshness === "stale") assert.match(status, /관측이 지연/);
            }
        });
    }
}

test("Telemetry repeated start avoids overlapping requests and stop ignores late responses", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    let resolveFetch;
    let requests = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...timers,
        fetchImpl: () => {
            requests += 1;
            return new Promise((resolve) => { resolveFetch = resolve; });
        },
    });

    // When
    const first = controller.start();
    void controller.start();
    void controller.poll();
    controller.stop();
    resolveFetch({ ok: true, json: async () => payload() });
    await first;

    // Then
    assert.equal(requests, 1);
    assert.notEqual(doc.elements.get("telemetry-throughput-summary").textContent, "입력 2건 / 처리 2건");
    assert.equal(timers.timers.size, 0);
});

test("Telemetry view reports invalid API contract as an error, not observed data", async () => {
    // Given
    const doc = makeDocument();
    const invalid = payload();
    invalid.scope = "run";
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(),
        fetchImpl: async () => ({ ok: true, json: async () => invalid }),
    });

    // When
    await controller.start();

    // Then
    assert.equal(doc.elements.get("telemetry-throughput-note").textContent, "조회 오류");
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "조회 실패");
    controller.stop();
});

test("Partial observations and stale timestamps are labeled without asserting worker failure", async () => {
    // Given
    const doc = makeDocument();
    const response = payload();
    response.observation_quality.status = "partial";
    response.freshness.status = "stale";
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(),
        fetchImpl: async () => ({ ok: true, json: async () => response }),
    });

    // When
    await controller.start();

    // Then
    assert.equal(doc.elements.get("telemetry-throughput-note").textContent, "부분 관측 · 관측 지연");
    assert.match(doc.elements.get("telemetry-latency-status").textContent, /Worker 장애로 단정하지/);
    // Status sentences stay in the live region only; the disclosure keeps coverage and time.
    assert.equal(doc.elements.get("telemetry-latency-details").textContent.includes(
        doc.elements.get("telemetry-latency-status").textContent,
    ), false);
    assert.match(doc.elements.get("telemetry-latency-details").textContent, /^최근 60초 관측 \d+초 · 미관측 \d+초 · 마지막 관측/);
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "0.775214 ms");
    controller.stop();
});

test("Telemetry live messages announce changed no_samples and error states without duplicate polls", async () => {
    // Given
    const doc = makeDocument();
    const response = payload();
    response.points = [];
    response.observation_quality.status = "no_samples";
    response.freshness.status = "unknown";
    response.last_observed_at = null;
    Object.assign(response.recent_60s_summary, {
        observed_bucket_count: 0, missing_bucket_count: 60,
        input_accepted_count: null, processing_completed_count: null,
        processing_failed_count: null, processing_latency_sample_count: null,
        processing_latency_mean_ms: null,
    });
    let failed = false;
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(),
        fetchImpl: async () => failed
            ? { ok: false, status: 503 }
            : { ok: true, json: async () => response },
    });

    // When / Then
    await controller.start();
    for (const kind of ["throughput", "latency"]) {
        const status = doc.elements.get(`telemetry-${kind}-status`);
        assert.match(status.textContent, /관측된 데이터가 없습니다.*최근 관측 여부/);
        assert.equal(doc.elements.get(`telemetry-${kind}-details`).textContent.includes(status.textContent), false);
        assert.doesNotMatch(doc.elements.get(`telemetry-${kind}-details`).textContent, /관측된 데이터가 없습니다|지연 샘플/);
    }
    const status = doc.elements.get("telemetry-throughput-status");
    let writes = status.textContentWrites;
    await controller.poll();
    assert.equal(status.textContentWrites, writes);
    failed = true;
    await controller.poll();
    assert.equal(status.textContentWrites, ++writes);
    assert.match(status.textContent, /API 조회에 실패/);
    assert.ok(doc.elements.get("telemetry-throughput-details").textContent.includes(status.textContent));
    await controller.poll();
    assert.equal(status.textContentWrites, writes);
    failed = false;
    await controller.poll();
    assert.equal(status.textContentWrites, ++writes);
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "미관측");
    controller.stop();
});

test("An observed zero stays measured in the live message and summary", async () => {
    // Given
    const doc = makeDocument();
    const response = payload();
    response.points[0].input_accepted_count = 0;
    response.recent_60s_summary.input_accepted_count = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => ({ ok: true, json: async () => response }),
    });

    // When
    await controller.start();

    // Then
    assert.match(doc.elements.get("telemetry-throughput-summary").textContent, /입력 0건/);
    assert.match(doc.elements.get("telemetry-throughput-status").textContent, /실측값을 조회/);
    assert.doesNotMatch(doc.elements.get("telemetry-throughput-status").textContent, /관측된 데이터가 없습니다/);
    assert.equal(doc.elements.get("telemetry-throughput-note").textContent, "실측");
    controller.stop();
});

test("Telemetry observations, partial data, stale state and API failures never infer unsupported Insight metrics", async () => {
    // Given
    const doc = makeDocument({ insight: true });
    const unsupported = [
        ["insight-bottleneck-state", "미계측"],
        ["insight-sla-state", "기준 미설정"],
        ["insight-queue-state", "미계측"],
    ];
    for (const [id, label] of unsupported) {
        const node = new FakeNode("strong");
        node.textContent = label;
        doc.elements.set(id, node);
    }
    let response = payload();
    let failed = false;
    let requests = 0;
    const controller = createDashboardTelemetryController(doc, {
        ...fakeTimers(), fetchImpl: async () => {
            requests += 1;
            return failed ? { ok: false, status: 503 } : { ok: true, json: async () => response };
        },
    });

    // When
    await controller.start();
    response.observation_quality.status = "partial";
    response.freshness.status = "stale";
    response.recent_60s_summary.input_accepted_count = 100;
    response.points[0].input_accepted_count = 100;
    await controller.poll();
    failed = true;
    await controller.poll();

    // Then
    assert.equal(requests, 3, "Three explicit polls must not create per-Insight requests");
    assert.equal(doc.elements.get("processing-observation-state").textContent, "조회 실패");
    for (const [id, label] of unsupported) {
        assert.equal(doc.elements.get(id).textContent, label);
        assert.equal(doc.elements.get(id).textContentWrites, 1, "Unsupported metrics must never be derived from counts or freshness");
    }
    controller.stop();
});

test("Telemetry restart after pagehide starts a new request while the old fetch is pending", async () => {
    // Given
    const doc = makeDocument();
    const timers = fakeTimers();
    const responses = [];
    const controller = createDashboardTelemetryController(doc, {
        ...timers,
        fetchImpl: () => new Promise((resolve) => { responses.push(resolve); }),
    });

    // When
    const original = controller.start();
    controller.stop();
    const restored = controller.start();

    // Then
    assert.equal(responses.length, 2, "Restored view must fetch immediately");

    responses[0]({ ok: true, json: async () => payload() });
    await original;
    await Promise.resolve();

    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 중");
    assert.equal([...timers.timers.values()].filter((timer) => timer.delay === 5000).length, 0);

    responses[1]({ ok: true, json: async () => payload() });
    await restored;
    await Promise.resolve();

    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 2건 / 처리 2건");
    assert.equal([...timers.timers.values()].filter((timer) => timer.delay === 5000).length, 1);

    controller.stop();
    assert.equal(timers.timers.size, 0);
});


test("Controlled admitted records grow, expire from recent totals, and never survive a failed read", async () => {
    // Given: real zero processing within an observed input bucket.
    const doc = makeDocument({insight: true});
    let value = payload(), failed = false;
    const calls = [];
    value.points[0].processing_completed_count = 0;
    value.points[0].processing_latency_sample_count = 0;
    value.points[0].processing_latency_mean_ms = null;
    Object.assign(value.recent_60s_summary, {processing_completed_count: 0,
        processing_latency_sample_count: 0, processing_latency_mean_ms: null});
    const controller = createDashboardTelemetryController(doc, {...fakeTimers(), fetchImpl: async url => {
        calls.push(url); return failed ? {ok: false, status: 503} : {ok: true, json: async () => value};
    }});
    // When / Then
    await controller.start();
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 2건 / 처리 0건");
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "미관측");
    value = payload();
    value.points[0].input_accepted_count = 9;
    value.recent_60s_summary.input_accepted_count = 9;
    await controller.poll();
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 9건 / 처리 2건");
    // When: retained history remains in the five-minute graph but leaves the recent window.
    value.range_end = "2026-10-15T05:24:20.000Z";
    value.range_start = "2026-10-15T05:19:20.000Z";
    value.recent_60s_summary = {...withoutCurrentSamples(payload()).recent_60s_summary};
    value.freshness.status = "stale";
    await controller.poll();
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "입력 미관측 / 처리 미관측");
    assert.equal(doc.elements.get("telemetry-throughput-chart").getAttribute("data-empty"), "false");
    assert.match(doc.elements.get("telemetry-throughput-details").textContent, /최근 60초 관측 0초 · 미관측 60초/);
    assert.match(doc.elements.get("telemetry-throughput-status").textContent, /최근 60초 미관측/);
    failed = true;
    await controller.poll();
    assert.equal(doc.elements.get("telemetry-throughput-summary").textContent, "조회 실패");
    assert.equal(doc.elements.get("telemetry-throughput-chart").getAttribute("data-empty"), "true");
    assert.equal(doc.elements.get("processing-observation-time").getAttribute("datetime"), null);
    assert.ok(calls.every(url => url === TELEMETRY_ENDPOINT));
    controller.stop();
});
