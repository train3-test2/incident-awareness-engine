import assert from "node:assert/strict";
import test from "node:test";

import {
    buildTelemetryChartModel,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-contract.mjs";
import {
    buildTelemetryChartPresentation,
    createTelemetryChart,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-chart.mjs";

function makeResponse() {
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

function shiftedPoint(second, values = {}) {
    return {
        bucket_start: `2026-10-15T05:23:${String(second).padStart(2, "0")}.000Z`,
        bucket_end: `2026-10-15T05:23:${String(second + 1).padStart(2, "0")}.000Z`,
        input_accepted_count: 0,
        processing_completed_count: 1,
        processing_failed_count: 0,
        processing_latency_sample_count: 1,
        processing_latency_mean_ms: 0.5,
        ...values,
    };
}

class FakeNode {
    constructor(tagName) {
        this.tagName = tagName;
        this.attributes = new Map();
        this.children = [];
        this.ownText = "";
        this.classes = new Set();
        this.classList = { add: (...items) => items.forEach((item) => this.classes.add(item)) };
    }

    setAttribute(key, value) {
        this.attributes.set(key, String(value));
    }

    set textContent(value) {
        this.ownText = String(value);
        this.children = [];
    }

    get textContent() {
        return this.ownText + this.children.map((child) => child.textContent).join("");
    }

    append(...nodes) {
        this.children.push(...nodes);
    }
}

const fakeDocument = {
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (value) => {
        const node = new FakeNode("#text");
        node.textContent = value;
        return node;
    },
};

function descendants(node, tag) {
    return node.children.flatMap((child) => [
        ...(child.tagName === tag ? [child] : []),
        ...descendants(child, tag),
    ]);
}

test("Compact asymmetric charts adapt ticks without changing observations or connecting gaps", () => {
    // Given
    const model = buildTelemetryChartModel(makeResponse());
    const original = JSON.stringify(model);
    // When / Then
    for (const kind of ["throughput", "latency"]) {
        const normal = buildTelemetryChartPresentation(model, kind);
        for (const width of [300, 342, 700]) {
            const compact = buildTelemetryChartPresentation(model, kind, { width });
            assert.equal(compact.width, width);
            assert.equal(compact.height, kind === "latency" ? 112 : 128);
            assert.equal(compact.xTicks.length, width < 472 ? 3 : 5);
            assert.deepEqual(compact.series.map((series) => series.marks.map(({ value, timestamp }) => ({ value, timestamp }))),
                normal.series.map((series) => series.marks.map(({ value, timestamp }) => ({ value, timestamp }))));
            assert.ok(compact.series.every((series) => series.segments.length === 0));
            assert.ok(compact.series.flatMap((series) => series.marks).every((mark) => (
                mark.x >= compact.plot.left && mark.x <= width - compact.plot.right
                && mark.y >= compact.plot.top && mark.y <= compact.height - compact.plot.bottom
            )));
            const figure = createTelemetryChart(model, kind, fakeDocument, { width });
            assert.ok(figure.classes.has("dashboard-telemetry-chart--compact"));
            assert.equal(descendants(figure, "svg")[0].attributes.get("viewBox"), `0 0 ${width} ${compact.height}`);
            assert.ok(descendants(figure, "circle").every((mark) => mark.attributes.get("aria-label").includes("GMT")
                || mark.attributes.get("aria-label").includes("UTC")));
        }
    }
    assert.equal(JSON.stringify(model), original);
});

test("Actual AWS bucket plots one input and one completion mark, plus server latency", () => {
    // Given
    const model = buildTelemetryChartModel(makeResponse());

    // When
    const throughput = buildTelemetryChartPresentation(model, "throughput");
    const latency = buildTelemetryChartPresentation(model, "latency");

    // Then
    assert.deepEqual(throughput.series.map((item) => item.marks.map((mark) => mark.value)), [[2], [2]]);
    assert.equal(throughput.markCount, 2);
    assert.equal(latency.markCount, 1);
    assert.equal(latency.series[0].marks[0].value, 0.775214);
    assert.equal(latency.series[0].segments.length, 0);
    assert.match(createTelemetryChart(model, "throughput", fakeDocument).textContent,
        /입력 수락 2건 · 처리 완료 2건/);
});

test("Missing second buckets do not create marks or connecting lines", () => {
    // Given
    const response = makeResponse();
    response.points = [shiftedPoint(15), shiftedPoint(17)];
    const model = buildTelemetryChartModel(response);

    // When
    const throughput = buildTelemetryChartPresentation(model, "throughput");
    const latency = buildTelemetryChartPresentation(model, "latency");

    // Then
    assert.deepEqual(throughput.series.map((item) => item.marks.length), [2, 2]);
    assert.deepEqual(throughput.series.map((item) => item.segments.length), [0, 0]);
    assert.equal(latency.series[0].segments.length, 0);
    assert.equal(model.seconds[36].observed, false);
});

test("Adjacent observed latency samples may connect, but gap resets the segment", () => {
    // Given
    const response = makeResponse();
    response.points = [shiftedPoint(14), shiftedPoint(15), shiftedPoint(17)];
    const model = buildTelemetryChartModel(response);

    // When
    const view = buildTelemetryChartPresentation(model, "latency");

    // Then
    assert.equal(view.series[0].marks.length, 3);
    assert.equal(view.series[0].segments.length, 1);
});

test("An actually observed zero throughput remains visible at the baseline", () => {
    // Given
    const response = makeResponse();
    response.points[0].input_accepted_count = 0;
    const model = buildTelemetryChartModel(response);

    // When
    const view = buildTelemetryChartPresentation(model, "throughput");

    // Then
    assert.equal(view.series[0].marks.length, 1);
    assert.equal(view.series[0].marks[0].value, 0);
    assert.equal(view.series[0].marks[0].y, view.series[0].marks[0].zeroY);
});

test("No latency samples does not turn the measured latency into zero", () => {
    // Given
    const response = makeResponse();
    response.points[0].processing_latency_sample_count = 0;
    response.points[0].processing_latency_mean_ms = null;
    const model = buildTelemetryChartModel(response);

    // When
    const view = buildTelemetryChartPresentation(model, "latency");

    // Then
    assert.equal(view.series[0].marks.length, 0);
    assert.equal(view.markCount, 0);
});

test("SVG charts have accessible descriptions and do not synthesize missing markers", () => {
    // Given
    const response = makeResponse();
    response.points = [];
    response.observation_quality.status = "no_samples";
    response.freshness.status = "unknown";
    response.last_observed_at = null;
    const model = buildTelemetryChartModel(response);

    // When
    const chart = createTelemetryChart(model, "throughput", fakeDocument);

    // Then
    assert.equal(descendants(chart, "svg").length, 1);
    assert.equal(descendants(chart, "circle").length, 0);
    assert.equal(descendants(chart, "figcaption").length, 1);
    assert.match(chart.textContent, /관측된 처리량이 없습니다/);
    assert.match(descendants(chart, "svg")[0].attributes.get("aria-labelledby"), /throughput/);
});

test("Latency chart renders one real mark and its accessible tooltip", () => {
    // Given
    const model = buildTelemetryChartModel(makeResponse());

    // When
    const chart = createTelemetryChart(model, "latency", fakeDocument);

    // Then
    assert.equal(descendants(chart, "circle").length, 1);
    assert.equal(descendants(chart, "figcaption").length, 0);
    assert.match(descendants(chart, "circle")[0].textContent, /0.775214 ms/);
});

test("Invalid chart mode is rejected", () => {
    // Given
    const model = buildTelemetryChartModel(makeResponse());

    // When / Then
    assert.throws(() => buildTelemetryChartPresentation(model, "unknown"), /Unknown Telemetry chart kind/);
});

test("A synthetic 7/7 single-bucket example keeps two concentric marks, time and precise latency", () => {
    // Given: reconstruction of user-provided values, not an original AWS response.
    const response = makeResponse();
    Object.assign(response.points[0], {
        input_accepted_count: 7, processing_completed_count: 7,
        processing_latency_sample_count: 7, processing_latency_mean_ms: 0.354226857,
    });
    const model = buildTelemetryChartModel(response);

    // When
    const throughput = createTelemetryChart(model, "throughput", fakeDocument);
    const latency = createTelemetryChart(model, "latency", fakeDocument);
    const marks = descendants(throughput, "circle");

    // Then
    assert.equal(marks.length, 2);
    assert.equal(marks[0].attributes.get("cx"), marks[1].attributes.get("cx"));
    assert.equal(marks[0].attributes.get("cy"), marks[1].attributes.get("cy"));
    assert.ok(Number(marks[0].attributes.get("r")) > Number(marks[1].attributes.get("r")));
    assert.ok(marks.every((mark) => mark.attributes.get("tabindex") === "0"));
    assert.match(marks[0].attributes.get("aria-label"), /입력 수락.*7 건\/초/);
    assert.match(marks[1].attributes.get("aria-label"), /처리 완료.*7 건\/초/);
    assert.match(throughput.textContent, /입력 수락 7건 · 처리 완료 7건/);
    assert.match(throughput.textContent, /관측 버킷/);
    assert.match(descendants(throughput, "desc")[0].textContent, /입력 수락 7건/);
    assert.match(latency.textContent, /버킷 평균 0.354 ms/);
    assert.match(descendants(latency, "circle")[0].textContent, /0.354226857 ms/);
    for (const kind of ["throughput", "latency"]) {
        assert.ok(buildTelemetryChartPresentation(model, kind).series.every((series) => series.segments.length === 0));
    }
});

test("Throughput connects only adjacent observations independently in each series", () => {
    // Given
    const response = makeResponse();
    response.points = [shiftedPoint(14), shiftedPoint(15), shiftedPoint(16), shiftedPoint(18)];
    const model = buildTelemetryChartModel(response);
    // Model-level defensive check: one series may have a missing value independently.
    model.seconds.find((second) => second.timestamp === shiftedPoint(15).bucket_start).inputAcceptedCount = null;

    // When
    const view = buildTelemetryChartPresentation(model, "throughput");

    // Then
    assert.deepEqual(view.series.map((item) => item.segments.length), [0, 2]);
    assert.deepEqual(view.series[0].marks.map((mark) => mark.value), [0, 0, 0]);
    const chart = createTelemetryChart(model, "throughput", fakeDocument);
    assert.equal(descendants(chart, "line").filter((line) =>
        line.attributes.get("class") === "dashboard-telemetry-chart__segment").length, 2);
    assert.equal(descendants(chart, "line").filter((line) =>
        line.attributes.get("class") === "dashboard-telemetry-chart__stem").length, 0);
    assert.match(chart.textContent, /건\/초/);
});

test("An adjacent null latency bucket breaks the line without hiding observed zero", () => {
    // Given
    const response = makeResponse();
    response.points = [shiftedPoint(14, { processing_latency_mean_ms: 0 }),
        shiftedPoint(15, { processing_latency_sample_count: 0, processing_latency_mean_ms: null }),
        shiftedPoint(16), shiftedPoint(17)];

    // When
    const view = buildTelemetryChartPresentation(buildTelemetryChartModel(response), "latency");

    // Then
    assert.equal(view.series[0].segments.length, 1);
    assert.equal(view.series[0].marks.length, 3);
    assert.equal(view.series[0].marks[0].value, 0);
    assert.equal(view.series[0].marks[0].y, view.series[0].marks[0].zeroY);
});

test("Compact dense markers shrink without altering samples, coordinates or isolated keyboard targets", () => {
    // Given
    const response = makeResponse();
    response.points = [shiftedPoint(14), shiftedPoint(15), shiftedPoint(18)];
    const model = buildTelemetryChartModel(response);
    const expected = buildTelemetryChartPresentation(model, "throughput", { width: 540 });
    // When
    const chart = createTelemetryChart(model, "throughput", fakeDocument, { width: 540 });
    const marks = descendants(chart, "circle");
    // Then
    assert.equal(marks.length, expected.markCount);
    for (const [index, mark] of marks.entries()) {
        const sample = expected.series.flatMap(series => series.marks)[index];
        assert.equal(Number(mark.attributes.get("cx")), sample.x);
        assert.equal(Number(mark.attributes.get("cy")), sample.y);
        assert.equal(mark.attributes.get("data-timestamp"), sample.timestamp);
        assert.match(mark.textContent, /건\/초/);
        assert.equal(mark.attributes.get("tabindex"), sample.isolated ? "0" : undefined);
        assert.ok(Number(mark.attributes.get("r")) >= (sample.isolated ? 4.5 : 1.5));
    }
    assert.equal(expected.series[0].segments.length, 1);
});
