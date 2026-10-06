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
    assertFiniteGeometry(model);
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
