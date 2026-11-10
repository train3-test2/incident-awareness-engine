// Run Detail UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_run_detail_contract.mjs
import assert from "node:assert/strict";
import test from "node:test";

import { buildDecisionDetailViewPath } from "../../../src/incident_awareness/dashboard/ui/assets/decision-detail-contract.mjs";
import { buildEventTimelineViewPath } from "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs";
import { buildFusionEngineViewPath } from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";
import {
    buildRunDetailApiPath,
    buildRunDetailViewPath,
    extractRunIdFromPathname,
    getDecisionPathLabel,
    getFusionStatusLabel,
    getHybridDecisionNotice,
    getStatusLabel,
    getWinningPathLabel,
    resolveRunDetailQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/run-detail-contract.mjs";

test("Fusion miss describes the threshold result without changing the stored status", () => {
    assert.equal(getFusionStatusLabel("miss"), "기준 미충족 (miss)");
    assert.equal(getFusionStatusLabel("detected"), "탐지");
    assert.equal(getFusionStatusLabel("not_evaluated"), "평가 안 함");
    assert.equal(getStatusLabel("miss"), "미탐");
});

test("Hybrid notice requires the explicit saved parallel reason and keeps null timing unchanged", () => {
    const decision = { t_e: null, fast_status: "not_evaluated", config_version: "parallel-v0.2",
        decision_reason: "Required parallel evaluation was not completed", decision_path: null,
        fusion_status: "detected", winning_path: null };
    const original = JSON.stringify(decision);
    assert.equal(getHybridDecisionNotice(decision), "종합 판단 미완료 · 즉시 규칙 분석 미평가");
    for (const change of [{ t_e: "2026-10-20T00:00:00Z" }, { fast_status: "miss" }, { decision_path: "fusion" },
        { winning_path: "fusion" }, { fusion_status: "future" },
        { config_version: "other" }, { decision_reason: null }, { t_e: undefined }]) {
        assert.equal(getHybridDecisionNotice({ ...decision, ...change }), null);
    }
    assert.equal(getHybridDecisionNotice(null), null);
    assert.equal(JSON.stringify(decision), original);
});

function makePayload() {
    return {
        run: { run_id: "RUN-20261005-001" },
        current_decision: {
            decision: { decision_id: "DEC-002" },
            latest_detection_result: null,
            latest_fusion_result: null,
            latest_fusion_stopping_trace: null,
        },
        decision_history: [
            { decision_id: "DEC-002" },
            { decision_id: "DEC-001" },
        ],
    };
}

test("Run Detail view and API paths URL-encode the Run ID", () => {
    // Given
    const runId = "RUN 20261005/001";

    // When
    const viewPath = buildRunDetailViewPath(runId);
    const apiPath = buildRunDetailApiPath(runId);

    // Then
    assert.equal(viewPath, "/dashboard/runs/RUN%2020261005%2F001");
    assert.equal(apiPath, "/runs/RUN%2020261005%2F001");
});

test("Run Detail Event Timeline navigation uses the product path helper", () => {
    // Given
    const runId = "RUN 20261005/001";

    // When
    const timelinePath = buildEventTimelineViewPath(runId);

    // Then
    assert.equal(timelinePath, "/dashboard/runs/RUN%2020261005%2F001/timeline");
});

test("Run Detail Fusion Engine navigation uses the product path helper", () => {
    // Given
    const runId = "RUN 20261005/001";

    // When
    const fusionEnginePath = buildFusionEngineViewPath(runId);

    // Then
    assert.equal(
        fusionEnginePath,
        "/dashboard/runs/RUN%2020261005%2F001/fusion-engine",
    );
});

test("Run Detail path builders reject missing and blank identifiers", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];

    // When / Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildRunDetailViewPath(runId));
        assert.throws(() => buildRunDetailApiPath(runId));
    }
});

test("Run Detail pathname extracts and decodes the Run ID", () => {
    // Given
    const pathname = "/dashboard/runs/RUN%2020261005%2F001";

    // When
    const runId = extractRunIdFromPathname(pathname);

    // Then
    assert.equal(runId, "RUN 20261005/001");
});

test("Run Detail pathname rejects malformed or unrelated paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/runs/",
        "/dashboard/runs/RUN-001/extra",
        "/runs/RUN-001",
        "/dashboard/runs/%",
        "/dashboard/runs/%20",
    ];

    // When
    const runIds = invalidPathnames.map((pathname) => extractRunIdFromPathname(pathname));

    // Then
    assert.deepEqual(runIds, [null, null, null, null, null, null]);
});

test("Run Detail status presentation maps known values with a safe fallback", () => {
    // Given
    const statuses = ["detected", "miss", "not_evaluated", "future_status", null];

    // When
    const labels = statuses.map((status) => getStatusLabel(status));

    // Then
    assert.deepEqual(labels, ["탐지", "미탐", "평가 안 함", "future_status", "-"]);
});

test("Representative persisted statuses keep not-evaluated distinct from miss", () => {
    // Given
    const runs = [
        {
            runId: "RUN-STATE-NOT-EVALUATED",
            fastStatus: "not_evaluated",
            fusionStatus: "not_evaluated",
            stoppingTraceCount: 0,
        },
        {
            runId: "RUN-STATE-FUSION-MISS",
            fastStatus: "not_evaluated",
            fusionStatus: "miss",
            stoppingTraceCount: 67,
        },
    ];

    // When
    const presentations = runs.map((run) => ({
        runId: run.runId,
        fastStatus: getStatusLabel(run.fastStatus),
        fusionStatus: getStatusLabel(run.fusionStatus),
        stoppingTraceCount: run.stoppingTraceCount,
    }));

    // Then
    assert.deepEqual(presentations, [
        {
            runId: "RUN-STATE-NOT-EVALUATED",
            fastStatus: "평가 안 함",
            fusionStatus: "평가 안 함",
            stoppingTraceCount: 0,
        },
        {
            runId: "RUN-STATE-FUSION-MISS",
            fastStatus: "평가 안 함",
            fusionStatus: "미탐",
            stoppingTraceCount: 67,
        },
    ]);
});

test("Run Detail decision path presentation preserves the persisted vocabulary", () => {
    // Given
    const paths = ["fast", "fusion", "fast_and_fusion", "none", null, "future_path"];

    // When
    const labels = paths.map((path) => getDecisionPathLabel(path));

    // Then
    assert.deepEqual(labels, ["Fast", "Fusion", "Fast + Fusion", "없음", "-", "future_path"]);
});

test("Run Detail winning path presentation maps known values with a safe fallback", () => {
    // Given
    const paths = ["fast", "fusion", "tie", "none", null, "future_path"];

    // When
    const labels = paths.map((path) => getWinningPathLabel(path));

    // Then
    assert.deepEqual(labels, ["Fast", "Fusion", "동시", "없음", "-", "future_path"]);
});

test("Run Detail loading, not-found, and error states expose distinct messages", () => {
    // Given
    const previousState = null;

    // When
    const loading = resolveRunDetailQueryState(previousState, { kind: "loading" });
    const notFound = resolveRunDetailQueryState(loading, { kind: "not_found" });
    const error = resolveRunDetailQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(loading, {
        queryState: "loading",
        payload: null,
        message: "분석 상세을 불러오는 중입니다.",
    });
    assert.deepEqual(notFound, {
        queryState: "not_found",
        payload: null,
        message: "분석을 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "분석 상세을 불러오지 못했습니다.",
    });
});

test("Run Detail success preserves the payload and Decision History order", () => {
    // Given
    const previousState = resolveRunDetailQueryState(null, { kind: "loading" });
    const payload = makePayload();
    const payloadSnapshot = structuredClone(payload);
    const history = payload.decision_history;

    // When
    const state = resolveRunDetailQueryState(previousState, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload, payload);
    assert.strictEqual(state.payload.decision_history, history);
    assert.deepEqual(
        state.payload.decision_history.map((decision) => decision.decision_id),
        ["DEC-002", "DEC-001"],
    );
    assert.deepEqual(payload, payloadSnapshot);
});

test("Run Detail Decision History links preserve order and URL-encode Decision IDs", () => {
    // Given
    const payload = makePayload();
    payload.decision_history = [
        { decision_id: "DEC 002/child" },
        { decision_id: "DEC-001" },
    ];

    // When
    const paths = payload.decision_history.map(
        (decision) => buildDecisionDetailViewPath(decision.decision_id),
    );

    // Then
    assert.deepEqual(paths, [
        "/dashboard/decisions/DEC%20002%2Fchild",
        "/dashboard/decisions/DEC-001",
    ]);
    assert.deepEqual(
        payload.decision_history.map((decision) => decision.decision_id),
        ["DEC 002/child", "DEC-001"],
    );
});

test("Run Detail success accepts an absent Current Decision", () => {
    // Given
    const previousState = resolveRunDetailQueryState(null, { kind: "loading" });
    const payload = makePayload();
    payload.current_decision = null;

    // When
    const state = resolveRunDetailQueryState(previousState, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload, payload);
    assert.equal(state.payload.current_decision, null);
});

test("Run Detail query state rejects malformed results and payloads", () => {
    // Given
    const previousState = resolveRunDetailQueryState(null, { kind: "loading" });
    const malformedPayloads = [
        null,
        [],
        { run: null, current_decision: null, decision_history: [] },
        { run: [], current_decision: null, decision_history: [] },
        { run: {}, current_decision: [], decision_history: [] },
        { run: {}, current_decision: null, decision_history: null },
    ];

    // When / Then
    assert.throws(() => resolveRunDetailQueryState([], { kind: "error" }), TypeError);
    assert.throws(() => resolveRunDetailQueryState(previousState, null), TypeError);
    for (const payload of malformedPayloads) {
        assert.throws(
            () => resolveRunDetailQueryState(previousState, { kind: "success", payload }),
            TypeError,
        );
    }
    assert.throws(
        () => resolveRunDetailQueryState(previousState, { kind: "unknown" }),
        RangeError,
    );
});


test("Parallel notice supports either missing path without interpreting an unknown policy", () => {
    // Given
    const decision = {fast_status:"detected",fusion_status:"not_evaluated",t_e:null,decision_path:null,
        winning_path:null,config_version:"parallel-v0.2",decision_reason:"Required parallel evaluation was not completed"};
    // When / Then
    assert.equal(getHybridDecisionNotice(decision), "종합 판단 미완료 · 증거 누적 분석 미평가");
    assert.equal(getHybridDecisionNotice({...decision,fast_status:"not_evaluated"}),
        "종합 판단 미완료 · 즉시 규칙 분석·증거 누적 분석 미평가");
    assert.equal(getHybridDecisionNotice({...decision,config_version:"future"}), null);
});
