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

class FakeNode {
    constructor(tagName) {
        this.tagName = tagName;
        this.children = [];
        this.ownText = "";
        this.attributes = new Map();
        this.classes = new Set();
        this.classList = { add: (...names) => names.forEach((name) => this.classes.add(name)) };
    }

    get textContent() {
        return this.ownText + this.children.map((child) => child.textContent).join("");
    }

    set textContent(value) {
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
}

function makeDocument() {
    const elements = new Map(elementIds.map((id) => [id, new FakeNode("div")]));
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

function descendants(node, tagName) {
    return node.children.flatMap((child) => [
        ...(child.tagName === tagName ? [child] : []),
        ...descendants(child, tagName),
    ]);
}

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
    assert.equal(doc.elements.get("telemetry-latency-summary").textContent, "0.775214 ms");
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
