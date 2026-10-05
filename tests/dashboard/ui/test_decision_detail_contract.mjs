// Historical Decision UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_decision_detail_contract.mjs
import assert from "node:assert/strict";
import test from "node:test";

import {
    buildDecisionDetailApiPath,
    buildDecisionDetailViewPath,
    extractDecisionIdFromPathname,
    getDecisionPathLabel,
    getStatusLabel,
    getWinningPathLabel,
    resolveDecisionDetailQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/decision-detail-contract.mjs";

function makePayload() {
    return {
        decision: {
            decision_id: "DEC-002",
            run_id: "RUN-20261005-001",
        },
        runtime_snapshot: {
            decision_id: "DEC-002",
            run_id: "RUN-20261005-001",
            entity_id: "host-001",
            detection_result: { detector_status: "detected" },
            fusion_result: { fusion_status: "detected" },
            fusion_stopping_trace: { points: [] },
            fusion_runtime_config_snapshot: null,
        },
    };
}

test("Decision Detail view and API paths URL-encode the Decision ID", () => {
    // Given
    const decisionId = "DEC 002/child";

    // When
    const viewPath = buildDecisionDetailViewPath(decisionId);
    const apiPath = buildDecisionDetailApiPath(decisionId);

    // Then
    assert.equal(viewPath, "/dashboard/decisions/DEC%20002%2Fchild");
    assert.equal(apiPath, "/decisions/DEC%20002%2Fchild");
});

test("Decision Detail path builders reject missing, blank, and dot-segment identifiers", () => {
    // Given
    const invalidDecisionIds = [null, undefined, "", "   ", ".", ".."];

    // When / Then
    for (const decisionId of invalidDecisionIds) {
        assert.throws(() => buildDecisionDetailViewPath(decisionId));
        assert.throws(() => buildDecisionDetailApiPath(decisionId));
    }
});

test("Decision Detail pathname extracts and decodes the Decision ID", () => {
    // Given
    const pathname = "/dashboard/decisions/DEC%20002%2Fchild";

    // When
    const decisionId = extractDecisionIdFromPathname(pathname);

    // Then
    assert.equal(decisionId, "DEC 002/child");
});

test("Decision Detail pathname rejects malformed or unrelated paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/decisions/",
        "/dashboard/decisions/A/B",
        "/dashboard/runs/DEC-002",
        "/dashboard/decisions/%",
        "/dashboard/decisions/%20",
    ];

    // When
    const decisionIds = invalidPathnames.map(
        (pathname) => extractDecisionIdFromPathname(pathname),
    );

    // Then
    assert.deepEqual(decisionIds, [null, null, null, null, null, null]);
});

test("Historical Decision loading, not-found, and error states are distinct", () => {
    // Given
    const previousState = null;

    // When
    const loading = resolveDecisionDetailQueryState(previousState, { kind: "loading" });
    const notFound = resolveDecisionDetailQueryState(loading, { kind: "not_found" });
    const error = resolveDecisionDetailQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(loading, {
        queryState: "loading",
        payload: null,
        message: "Historical Decision을 불러오는 중입니다.",
    });
    assert.deepEqual(notFound, {
        queryState: "not_found",
        payload: null,
        message: "Decision을 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "Historical Decision을 불러오지 못했습니다.",
    });
});

test("Historical Decision success preserves the Runtime Snapshot without mutation", () => {
    // Given
    const previousState = resolveDecisionDetailQueryState(null, { kind: "loading" });
    const payload = makePayload();
    const payloadSnapshot = structuredClone(payload);
    const runtimeSnapshot = payload.runtime_snapshot;

    // When
    const state = resolveDecisionDetailQueryState(previousState, {
        kind: "success",
        payload,
    });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload, payload);
    assert.strictEqual(state.payload.runtime_snapshot, runtimeSnapshot);
    assert.deepEqual(payload, payloadSnapshot);
});

test("Historical Decision success accepts an absent Runtime Snapshot", () => {
    // Given
    const previousState = resolveDecisionDetailQueryState(null, { kind: "loading" });
    const payload = makePayload();
    payload.runtime_snapshot = null;

    // When
    const state = resolveDecisionDetailQueryState(previousState, {
        kind: "success",
        payload,
    });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload, payload);
    assert.equal(state.payload.runtime_snapshot, null);
});

test("Historical Decision reuses status and path presentation contracts", () => {
    // Given
    const statuses = ["detected", "miss", "not_evaluated", "future_status"];
    const decisionPaths = ["fast", "fusion", "fast_and_fusion", "none", null];
    const winningPaths = ["fast", "fusion", "tie", "none", null];

    // When
    const statusLabels = statuses.map((status) => getStatusLabel(status));
    const decisionPathLabels = decisionPaths.map((path) => getDecisionPathLabel(path));
    const winningPathLabels = winningPaths.map((path) => getWinningPathLabel(path));

    // Then
    assert.deepEqual(statusLabels, ["탐지", "미탐", "평가 안 함", "future_status"]);
    assert.deepEqual(decisionPathLabels, ["Fast", "Fusion", "Fast + Fusion", "없음", "-"]);
    assert.deepEqual(winningPathLabels, ["Fast", "Fusion", "동시", "없음", "-"]);
});

test("Historical Decision query state rejects malformed results and payloads", () => {
    // Given
    const previousState = resolveDecisionDetailQueryState(null, { kind: "loading" });
    const malformedPayloads = [
        null,
        [],
        { decision: null, runtime_snapshot: null },
        { decision: [], runtime_snapshot: null },
        { decision: {}, runtime_snapshot: [] },
    ];

    // When / Then
    assert.throws(() => resolveDecisionDetailQueryState([], { kind: "error" }), TypeError);
    assert.throws(() => resolveDecisionDetailQueryState(previousState, null), TypeError);
    for (const payload of malformedPayloads) {
        assert.throws(
            () => resolveDecisionDetailQueryState(previousState, { kind: "success", payload }),
            TypeError,
        );
    }
    assert.throws(
        () => resolveDecisionDetailQueryState(previousState, { kind: "unknown" }),
        RangeError,
    );
});
