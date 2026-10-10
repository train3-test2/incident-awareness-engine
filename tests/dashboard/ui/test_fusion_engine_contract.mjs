// Fusion Engine UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_fusion_engine_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    buildFusionEngineApiPath,
    buildFusionEngineViewPath,
    buildScoreTrajectoryModel,
    extractFusionEngineRunIdFromPathname,
    resolveFusionEngineQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";
import {
    formatRunTimestamp,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";

const CHART_DIMENSIONS = {
    width: 100,
    height: 100,
    padding: { top: 10, right: 10, bottom: 10, left: 10 },
};

function makeTrace(points = [
    {
        timestamp: "2026-10-05T01:00:00.000Z",
        score: 0,
        persistence_count: null,
        policy_state: "off",
    },
    {
        timestamp: "2026-10-05T01:00:10.000Z",
        score: 0.5,
        persistence_count: 1,
        policy_state: "off",
    },
    {
        timestamp: "2026-10-05T01:00:20.000Z",
        score: 1,
        persistence_count: 2,
        policy_state: "on",
    },
]) {
    return { points };
}

function makeRuntimeConfig() {
    return {
        stopping: {
            threshold_on: 0.8,
            threshold_off: 0.4,
            persistence_k: 2,
        },
    };
}

function makeSyntheticPolicyConsistentPoints(count = 67) {
    return Array.from({ length: count }, (_, index) => {
        const reachesThreshold = index >= 40;
        const activatesPolicy = index >= 41;
        let persistenceCount = null;
        if (index === 40) {
            persistenceCount = 1;
        } else if (index === 41) {
            persistenceCount = 2;
        }
        return {
            timestamp: new Date(Date.UTC(2026, 9, 6, 0, 0, index)).toISOString(),
            score: reachesThreshold ? 0.85 : 0.3,
            persistence_count: persistenceCount,
            policy_state: activatesPolicy ? "on" : "off",
        };
    });
}

function assertFiniteGeometry(value) {
    if (typeof value === "number") {
        assert.equal(Number.isFinite(value), true);
        return;
    }
    if (Array.isArray(value)) {
        for (const item of value) {
            assertFiniteGeometry(item);
        }
        return;
    }
    if (value !== null && typeof value === "object") {
        for (const item of Object.values(value)) {
            assertFiniteGeometry(item);
        }
    }
}

function createFakeElement(tagName) {
    let text = "";
    return {
        tagName: tagName.toUpperCase(),
        children: [],
        attributes: new Map(),
        classList: {
            values: new Set(),
            add(...values) {
                for (const value of values) {
                    this.values.add(value);
                }
            },
        },
        append(...children) {
            this.children.push(...children);
        },
        setAttribute(name, value) {
            this.attributes.set(name, String(value));
        },
        get textContent() {
            return text;
        },
        set textContent(value) {
            text = String(value);
        },
    };
}

function findFakeElements(root, predicate) {
    const matches = [];
    if (predicate(root)) {
        matches.push(root);
    }
    for (const child of root.children) {
        matches.push(...findFakeElements(child, predicate));
    }
    return matches;
}

function makePayload() {
    return {
        run: { run_id: "RUN-20261005-001", target_host: "WIN-01" },
        current_decision: { decision_id: "DEC-001", t_e: null },
        fusion_result: { fusion_status: "miss", fusion_episodes: [] },
        stopping_trace: { points: [] },
        runtime_config_snapshot: { config_version: "fusion-v1" },
    };
}

test("Fusion Engine view and API paths URL-encode the Run ID", () => {
    // Given
    const runId = "RUN 20261005/001";

    // When
    const viewPath = buildFusionEngineViewPath(runId);
    const apiPath = buildFusionEngineApiPath(runId);

    // Then
    assert.equal(viewPath, "/dashboard/runs/RUN%2020261005%2F001/fusion-engine");
    assert.equal(apiPath, "/runs/RUN%2020261005%2F001/fusion-engine");
});

test("Fusion Engine path builders reject missing and blank Run IDs", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];

    // When / Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildFusionEngineViewPath(runId));
        assert.throws(() => buildFusionEngineApiPath(runId));
    }
});

test("Fusion Engine pathname extracts and decodes the Run ID", () => {
    // Given
    const pathname = "/dashboard/runs/RUN%2020261005%2F001/fusion-engine";

    // When
    const runId = extractFusionEngineRunIdFromPathname(pathname);

    // Then
    assert.equal(runId, "RUN 20261005/001");
});

test("Fusion Engine pathname rejects malformed or unrelated paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/runs/",
        "/dashboard/runs/RUN-001",
        "/dashboard/runs/RUN-001/timeline",
        "/runs/RUN-001/fusion-engine",
        "/dashboard/runs/%/fusion-engine",
        "/dashboard/runs/%20/fusion-engine",
        "/dashboard/runs/RUN-001/fusion-engine/extra",
    ];

    // When
    const runIds = invalidPathnames.map((pathname) => (
        extractFusionEngineRunIdFromPathname(pathname)
    ));

    // Then
    assert.deepEqual(runIds, [null, null, null, null, null, null, null, null]);
});

test("Fusion Engine loading state exposes no payload", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveFusionEngineQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        payload: null,
        message: "Fusion Engine 정보를 불러오는 중입니다.",
    });
});

test("Fusion Engine success preserves the complete payload", () => {
    // Given
    const previousState = resolveFusionEngineQueryState(null, { kind: "loading" });
    const payload = makePayload();
    const payloadSnapshot = structuredClone(payload);

    // When
    const state = resolveFusionEngineQueryState(previousState, {
        kind: "success",
        payload,
    });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload, payload);
    assert.deepEqual(payload, payloadSnapshot);
});

test("Fusion Engine not-found and error states expose distinct messages", () => {
    // Given
    const loading = resolveFusionEngineQueryState(null, { kind: "loading" });

    // When
    const notFound = resolveFusionEngineQueryState(loading, { kind: "not_found" });
    const error = resolveFusionEngineQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(notFound, {
        queryState: "not_found",
        payload: null,
        message: "Run을 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "Fusion Engine 정보를 불러오지 못했습니다.",
    });
});

test("Fusion Engine success accepts each partial Runtime combination", () => {
    // Given
    const runtimeFields = [
        "current_decision",
        "fusion_result",
        "stopping_trace",
        "runtime_config_snapshot",
    ];
    const payloads = runtimeFields.map((field) => ({
        ...makePayload(),
        [field]: null,
    }));

    // When
    const states = payloads.map((payload) => resolveFusionEngineQueryState(null, {
        kind: "success",
        payload,
    }));

    // Then
    for (const [index, field] of runtimeFields.entries()) {
        assert.equal(states[index].queryState, "success");
        assert.equal(states[index].payload[field], null);
    }
});

test("Fusion Engine success preserves four nullable Runtime fields", () => {
    // Given
    const payload = {
        ...makePayload(),
        current_decision: null,
        fusion_result: null,
        stopping_trace: null,
        runtime_config_snapshot: null,
    };

    // When
    const state = resolveFusionEngineQueryState(null, { kind: "success", payload });

    // Then
    assert.strictEqual(state.payload, payload);
    assert.equal(state.payload.current_decision, null);
    assert.equal(state.payload.fusion_result, null);
    assert.equal(state.payload.stopping_trace, null);
    assert.equal(state.payload.runtime_config_snapshot, null);
});

test("Fusion Engine query state rejects malformed results and payloads", () => {
    // Given
    const malformedPayloads = [
        null,
        [],
        { ...makePayload(), run: null },
        { ...makePayload(), run: [] },
        { ...makePayload(), current_decision: [] },
        { ...makePayload(), fusion_result: "miss" },
        { ...makePayload(), stopping_trace: [] },
        { ...makePayload(), runtime_config_snapshot: undefined },
    ];

    // When / Then
    assert.throws(() => resolveFusionEngineQueryState([], { kind: "error" }), TypeError);
    assert.throws(() => resolveFusionEngineQueryState(null, null), TypeError);
    for (const payload of malformedPayloads) {
        assert.throws(() => resolveFusionEngineQueryState(null, {
            kind: "success",
            payload,
        }));
    }
    assert.throws(
        () => resolveFusionEngineQueryState(null, { kind: "unknown" }),
        RangeError,
    );
});

test("Score trajectory preserves point order and maps score zero and one", () => {
    // Given
    const trace = makeTrace();

    // When
    const model = buildScoreTrajectoryModel(trace, makeRuntimeConfig(), CHART_DIMENSIONS);

    // Then
    assert.deepEqual(
        model.points.map((point) => point.timestamp),
        trace.points.map((point) => point.timestamp),
    );
    assert.equal(model.points[0].y, 90);
    assert.equal(model.points[1].y, 50);
    assert.equal(model.points[2].y, 10);
});

test("Score trajectory maps intermediate scores without changing them", () => {
    // Given
    const trace = makeTrace([
        {
            timestamp: "2026-10-05T01:00:00.000Z",
            score: 0.25,
            persistence_count: null,
            policy_state: "off",
        },
    ]);

    // When
    const model = buildScoreTrajectoryModel(trace, null, CHART_DIMENSIONS);

    // Then
    assert.equal(model.points[0].score, 0.25);
    assert.equal(model.points[0].y, 70);
});

test("Single score point uses a finite centered x-coordinate", () => {
    // Given
    const trace = makeTrace([makeTrace().points[0]]);

    // When
    const model = buildScoreTrajectoryModel(trace, makeRuntimeConfig(), CHART_DIMENSIONS);

    // Then
    assert.equal(model.points[0].x, 50);
    assert.equal(Number.isFinite(model.points[0].x), true);
    assert.deepEqual(model.xTicks, [
        {
            timestamp: "2026-10-05T01:00:00.000Z",
            x: 50,
            textAnchor: "middle",
        },
    ]);
});

test("Multiple timestamps map monotonically without reordering", () => {
    // Given
    const trace = makeTrace();

    // When
    const model = buildScoreTrajectoryModel(trace, null, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(model.points.map((point) => point.x), [10, 50, 90]);
    assert.strictEqual(model.points[0].timestamp, trace.points[0].timestamp);
    assert.strictEqual(model.points[2].timestamp, trace.points[2].timestamp);
    assert.deepEqual(model.xTicks, [
        {
            timestamp: "2026-10-05T01:00:00.000Z",
            x: 10,
            textAnchor: "start",
        },
        {
            timestamp: "2026-10-05T01:00:10.000Z",
            x: 50,
            textAnchor: "middle",
        },
        {
            timestamp: "2026-10-05T01:00:20.000Z",
            x: 90,
            textAnchor: "end",
        },
    ]);
});

test("Score trajectory uses elapsed time for uneven points and bounded ticks", () => {
    // Given
    const trace = makeTrace([
        {
            timestamp: "2026-10-05T01:00:00.000Z",
            score: 0.2,
            persistence_count: null,
            policy_state: "off",
        },
        {
            timestamp: "2026-10-05T01:00:01.000Z",
            score: 0.4,
            persistence_count: null,
            policy_state: "off",
        },
        {
            timestamp: "2026-10-05T01:01:40.000Z",
            score: 0.6,
            persistence_count: 1,
            policy_state: "off",
        },
    ]);

    // When
    const model = buildScoreTrajectoryModel(trace, null, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(model.points.map((point) => point.x), [10, 10.8, 90]);
    assert.deepEqual(
        model.xTicks.map(({ timestamp, x }) => ({ timestamp, x })),
        [
            { timestamp: "2026-10-05T01:00:00.000Z", x: 10 },
            { timestamp: "2026-10-05T01:00:50.000Z", x: 50 },
            { timestamp: "2026-10-05T01:01:40.000Z", x: 90 },
        ],
    );
    assert.equal(model.xTicks.length <= 3, true);
});

test("Score trajectory preserves short, long, date-boundary, and offset timestamps", () => {
    // Given
    const shortTrace = makeTrace([
        { ...makeTrace().points[0], timestamp: "2026-10-05T01:00:00.000Z" },
        { ...makeTrace().points[1], timestamp: "2026-10-05T01:00:00.002Z" },
    ]);
    const longTrace = makeTrace([
        { ...makeTrace().points[0], timestamp: "2026-10-05T23:59:59.000Z" },
        { ...makeTrace().points[1], timestamp: "2026-11-04T00:00:01.000Z" },
    ]);
    const offsetTrace = makeTrace([
        { ...makeTrace().points[0], timestamp: "2026-10-05T10:00:00.000+09:00" },
        { ...makeTrace().points[1], timestamp: "2026-10-05T10:00:02.000+09:00" },
    ]);

    // When
    const shortModel = buildScoreTrajectoryModel(shortTrace, null, CHART_DIMENSIONS);
    const longModel = buildScoreTrajectoryModel(longTrace, null, CHART_DIMENSIONS);
    const offsetModel = buildScoreTrajectoryModel(offsetTrace, null, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(shortModel.xTicks.map((tick) => tick.timestamp), [
        "2026-10-05T01:00:00.000Z",
        "2026-10-05T01:00:00.001Z",
        "2026-10-05T01:00:00.002Z",
    ]);
    assert.equal(longModel.xTicks.length, 3);
    assert.notEqual(
        longModel.xTicks[0].timestamp.slice(0, 10),
        longModel.xTicks[2].timestamp.slice(0, 10),
    );
    assert.equal(offsetModel.xTicks[0].timestamp, "2026-10-05T01:00:00.000Z");
    assert.equal(
        formatRunTimestamp(offsetModel.xTicks[0].timestamp),
        formatRunTimestamp(offsetTrace.points[0].timestamp),
    );
});

test("Score trajectory rejects duplicate and intermediate out-of-order timestamps", () => {
    // Given
    const duplicate = makeTrace([
        { ...makeTrace().points[0], timestamp: "2026-10-05T01:00:00.000Z" },
        { ...makeTrace().points[1], timestamp: "2026-10-05T01:00:00.000Z" },
    ]);
    const outOfOrder = makeTrace([
        { ...makeTrace().points[0], timestamp: "2026-10-05T01:00:00.000Z" },
        { ...makeTrace().points[1], timestamp: "2026-10-05T01:00:20.000Z" },
        { ...makeTrace().points[2], timestamp: "2026-10-05T01:00:10.000Z" },
        { ...makeTrace().points[2], timestamp: "2026-10-05T01:00:30.000Z" },
    ]);

    // When / Then
    assert.throws(
        () => buildScoreTrajectoryModel(duplicate, null, CHART_DIMENSIONS),
        /strictly increasing/,
    );
    assert.throws(
        () => buildScoreTrajectoryModel(outOfOrder, null, CHART_DIMENSIONS),
        /strictly increasing/,
    );
});

test("Score trajectory maps stored threshold geometry without classifying points", () => {
    // Given
    const config = makeRuntimeConfig();

    // When
    const model = buildScoreTrajectoryModel(makeTrace(), config, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(
        model.thresholds.map(({ kind, label, value }) => ({ kind, label, value })),
        [
            { kind: "on", label: "T_on", value: 0.8 },
            { kind: "off", label: "T_off", value: 0.4 },
        ],
    );
    assert.ok(Math.abs(model.thresholds[0].y - 26) < Number.EPSILON * 100);
    assert.ok(Math.abs(model.thresholds[1].y - 58) < Number.EPSILON * 100);
});

test("Score trajectory omits thresholds when Runtime Config is absent", () => {
    // Given
    const trace = makeTrace();

    // When
    const model = buildScoreTrajectoryModel(trace, null, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(model.thresholds, []);
    assert.equal(model.points.length, trace.points.length);
});

test("Score trajectory handles empty points without invalid geometry", () => {
    // Given
    const trace = makeTrace([]);

    // When
    const model = buildScoreTrajectoryModel(trace, null, CHART_DIMENSIONS);

    // Then
    assert.deepEqual(model.points, []);
    assert.deepEqual(model.xTicks, []);
    assertFiniteGeometry(model);
});

test("Synthetic zero-point and 67-point traces preserve every point in order", () => {
    // Given
    const emptyTrace = { run_id: "RUN-SYNTHETIC-EMPTY", points: [] };
    const points = makeSyntheticPolicyConsistentPoints();
    const populatedTrace = { run_id: "RUN-SYNTHETIC-067", points };

    // When
    const emptyModel = buildScoreTrajectoryModel(emptyTrace, null, CHART_DIMENSIONS);
    const populatedModel = buildScoreTrajectoryModel(
        populatedTrace,
        makeRuntimeConfig(),
        CHART_DIMENSIONS,
    );

    // Then
    assert.equal(emptyModel.points.length, 0);
    assert.equal(emptyModel.xTicks.length, 0);
    assert.equal(populatedModel.points.length, 67);
    assert.equal(populatedModel.xTicks.length, 3);
    assert.deepEqual(
        populatedModel.points.map((point) => point.timestamp),
        points.map((point) => point.timestamp),
    );
    assert.deepEqual(
        populatedModel.points.map((point) => point.persistence_count),
        points.map((point) => point.persistence_count),
    );
    assert.equal(points[40].policy_state, "off");
    assert.equal(points[40].persistence_count, 1);
    assert.equal(points[41].policy_state, "on");
    assert.equal(points[41].persistence_count, 2);
});

test("Fusion Point table is collapsed without dropping stored point rows", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");
    const tableSource = script.slice(
        script.indexOf("function createTraceTable"),
        script.indexOf("function createScoreTrajectoryChart"),
    );

    // Then
    assert.match(tableSource, /document\.createElement\("details"\)/);
    assert.match(tableSource, /document\.createElement\("summary"\)/);
    assert.match(tableSource, /for \(const point of points\)/);
    assert.match(tableSource, /전체 Point \$\{points\.length\}개 보기/);
    assert.match(tableSource, /details\.append\(summary, wrapper\)/);
});

test("Fusion details DOM starts closed and contains all 67 synthetic rows", async () => {
    // Given
    const originalDocument = globalThis.document;
    globalThis.document = {
        createElement: createFakeElement,
        getElementById() {
            return null;
        },
    };
    const moduleUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs",
        import.meta.url,
    );
    const points = makeSyntheticPolicyConsistentPoints();

    try {
        const { createTraceTable } = await import(moduleUrl.href);

        // When
        const details = createTraceTable(points);
        const summary = details.children[0];
        const table = details.children[1].children[0];
        const rows = table.children[1].children;

        // Then
        assert.equal(details.tagName, "DETAILS");
        assert.equal(details.attributes.has("open"), false);
        assert.equal(summary.textContent, "전체 Point 67개 보기");
        assert.equal(rows.length, 67);
        assert.deepEqual(
            rows.map((row) => row.children[1].textContent),
            points.map((point) => String(point.score)),
        );
        assert.equal(rows[40].children[2].textContent, "Policy OFF");
        assert.equal(rows[40].children[3].textContent, "1");
        assert.equal(rows[41].children[2].textContent, "Policy ON");
        assert.equal(rows[41].children[3].textContent, "2");
    } finally {
        if (originalDocument === undefined) {
            delete globalThis.document;
        } else {
            globalThis.document = originalDocument;
        }
    }
});

test("Score trajectory renderer draws bounded accessible timestamp labels", async () => {
    // Given
    const originalDocument = globalThis.document;
    globalThis.document = {
        createElement: createFakeElement,
        createElementNS(_namespace, tagName) {
            return createFakeElement(tagName);
        },
    };
    const moduleUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs",
        import.meta.url,
    );
    const model = buildScoreTrajectoryModel(
        makeTrace(),
        makeRuntimeConfig(),
        CHART_DIMENSIONS,
    );

    try {
        const { createScoreTrajectoryChart } = await import(moduleUrl.href);

        // When
        const chart = createScoreTrajectoryChart(model);
        const svg = chart.children[0];
        const tickLines = findFakeElements(
            svg,
            (element) => element.attributes.get("class") === "fusion-score-chart__x-tick",
        );
        const tickLabels = findFakeElements(
            svg,
            (element) => element.attributes.get("class")?.includes(
                "fusion-score-chart__axis-label--x",
            ) === true,
        );

        // Then
        assert.equal(svg.attributes.get("role"), "img");
        assert.equal(tickLines.length, 3);
        assert.equal(tickLabels.length, 3);
        assert.deepEqual(
            tickLabels.map((label) => label.textContent),
            model.xTicks.map((tick) => formatRunTimestamp(tick.timestamp)),
        );
        assert.deepEqual(
            tickLabels.map((label) => label.attributes.get("text-anchor")),
            ["start", "middle", "end"],
        );
        assert.deepEqual(
            tickLabels.map((label) => Number(label.attributes.get("x"))),
            model.xTicks.map((tick) => tick.x),
        );
        assert.equal(
            tickLabels.every((label) => (
                Number(label.attributes.get("x")) >= model.plot.left
                && Number(label.attributes.get("x")) <= model.plot.right
                && label.children[0].tagName === "TITLE"
                && label.children[0].textContent.includes("2026-10-05T01:00:")
            )),
            true,
        );

        const shortModel = buildScoreTrajectoryModel(
            makeTrace([
                { ...makeTrace().points[0], timestamp: "2026-10-05T01:00:00.000Z" },
                { ...makeTrace().points[1], timestamp: "2026-10-05T01:00:00.002Z" },
            ]),
            null,
            CHART_DIMENSIONS,
        );
        const shortLabels = findFakeElements(
            createScoreTrajectoryChart(shortModel).children[0],
            (element) => element.attributes.get("class")?.includes(
                "fusion-score-chart__axis-label--x",
            ) === true,
        );
        assert.equal(shortLabels.length, 3);
        assert.equal(new Set(shortLabels.map((label) => label.textContent)).size, 3);
        assert.deepEqual(
            shortLabels.map((label) => label.textContent.match(/\d{3} ms$/)?.[0]),
            ["000 ms", "001 ms", "002 ms"],
        );
    } finally {
        if (originalDocument === undefined) {
            delete globalThis.document;
        } else {
            globalThis.document = originalDocument;
        }
    }
});

test("Score trajectory preserves policy state and nullable persistence count", () => {
    // Given
    const trace = makeTrace();

    // When
    const model = buildScoreTrajectoryModel(trace, makeRuntimeConfig(), CHART_DIMENSIONS);

    // Then
    assert.deepEqual(
        model.points.map((point) => point.policy_state),
        ["off", "off", "on"],
    );
    assert.deepEqual(
        model.points.map((point) => point.persistence_count),
        [null, 1, 2],
    );
});

test("Score trajectory does not mutate inputs or emit NaN and Infinity", () => {
    // Given
    const trace = makeTrace();
    const config = makeRuntimeConfig();
    const dimensions = structuredClone(CHART_DIMENSIONS);
    const inputsBefore = structuredClone({ trace, config, dimensions });

    // When
    const model = buildScoreTrajectoryModel(trace, config, dimensions);

    // Then
    assert.deepEqual({ trace, config, dimensions }, inputsBefore);
    assertFiniteGeometry(model);
});

test("Score trajectory rejects malformed trace and dimensions", () => {
    // Given
    const invalidDimensions = {
        width: 20,
        height: 20,
        padding: { top: 10, right: 10, bottom: 10, left: 10 },
    };

    // When / Then
    assert.throws(
        () => buildScoreTrajectoryModel(null, null, CHART_DIMENSIONS),
        TypeError,
    );
    assert.throws(
        () => buildScoreTrajectoryModel({ points: null }, null, CHART_DIMENSIONS),
        TypeError,
    );
    assert.throws(
        () => buildScoreTrajectoryModel(makeTrace(), null, invalidDimensions),
        RangeError,
    );
});

test("Fusion Engine contract remains independent of browser and network APIs", async () => {
    // Given
    const contractUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs",
        import.meta.url,
    );

    // When
    const source = await readFile(contractUrl, "utf8");

    // Then
    for (const forbiddenApi of [
        "document",
        "window",
        "location",
        "fetch(",
        "setTimeout(",
        "setInterval(",
        "AbortController",
        ".sort(",
        ".toSorted(",
        ".reverse(",
        ".toReversed(",
    ]) {
        assert.equal(source.includes(forbiddenApi), false);
    }
});
