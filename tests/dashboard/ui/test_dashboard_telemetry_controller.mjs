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
    assert.ok(doc.elements.get("telemetry-latency-details").textContent.includes(
        doc.elements.get("telemetry-latency-status").textContent,
    ));
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
        assert.ok(doc.elements.get(`telemetry-${kind}-details`).textContent.includes(status.textContent));
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
