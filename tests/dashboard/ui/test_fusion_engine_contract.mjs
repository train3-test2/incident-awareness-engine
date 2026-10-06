// Fusion Engine UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_fusion_engine_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    buildFusionEngineApiPath,
    buildFusionEngineViewPath,
    extractFusionEngineRunIdFromPathname,
    resolveFusionEngineQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";

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
    ]) {
        assert.equal(source.includes(forbiddenApi), false);
    }
});
