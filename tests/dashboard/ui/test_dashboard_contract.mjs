// Dashboard UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    formatRunTimestamp,
    getOverviewQueryMessage,
    getRunTypeLabel,
    resolveOverviewQueryState,
    resolveRunListQueryState,
    resolveRuntimeSummaryQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";
import {
    getRuntimeStatePresentation,
} from "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs";

test("Run Type presentation maps the persisted vocabulary with a safe fallback", () => {
    // Given
    const runTypes = ["attack", "normal", "future_type", null, undefined];

    // When
    const labels = runTypes.map((runType) => getRunTypeLabel(runType));

    // Then
    assert.deepEqual(labels, ["공격", "정상", "future_type", NOT_APPLICABLE, NOT_APPLICABLE]);
});

test("timestamp presentation handles valid, missing, and invalid values", () => {
    // Given
    const timestamp = "2026-09-11T01:00:00Z";

    // When
    const formatted = formatRunTimestamp(timestamp);

    // Then
    assert.equal(typeof formatted, "string");
    assert.notEqual(formatted, timestamp);
    assert.match(formatted, /2026/);
    assert.equal(formatRunTimestamp(null), NOT_APPLICABLE);
    assert.equal(formatRunTimestamp(undefined), NOT_APPLICABLE);
    assert.equal(formatRunTimestamp("not-a-timestamp"), "not-a-timestamp");
});

test("Overview loading has no data and a loading message", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveOverviewQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        totalRuns: null,
        recentRuns: [],
        totalMessage: "Total Runs를 불러오는 중입니다.",
        message: "Recent Runs를 불러오는 중입니다.",
    });
});

test("Overview success preserves total and recent Runs without mutation", () => {
    // Given
    const previousState = resolveOverviewQueryState(null, { kind: "loading" });
    const payload = {
        total_runs: 3,
        recent_runs: [
            {
                run_id: "RUN-20260911-001",
                scenario_id: "scenario-001",
                run_type: "attack",
                target_host: "WIN-01",
                start_time: "2026-09-11T01:00:00Z",
                end_time: null,
            },
        ],
    };
    const payloadSnapshot = structuredClone(payload);

    // When
    const state = resolveOverviewQueryState(previousState, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.equal(state.totalRuns, 3);
    assert.strictEqual(state.recentRuns, payload.recent_runs);
    assert.equal(state.totalMessage, "Total Runs를 불러왔습니다.");
    assert.equal(state.message, "Recent Runs를 불러왔습니다.");
    assert.deepEqual(payload, payloadSnapshot);
});

test("Overview empty preserves the reported total and shows the empty message", () => {
    // Given
    const previousState = resolveOverviewQueryState(null, { kind: "loading" });
    const emptyPayload = { total_runs: 0, recent_runs: [] };
    const nonzeroTotalPayload = { total_runs: 7, recent_runs: [] };

    // When
    const empty = resolveOverviewQueryState(previousState, {
        kind: "success",
        payload: emptyPayload,
    });
    const nonzeroTotal = resolveOverviewQueryState(previousState, {
        kind: "success",
        payload: nonzeroTotalPayload,
    });

    // Then
    assert.deepEqual(empty, {
        queryState: "empty",
        totalRuns: 0,
        recentRuns: [],
        totalMessage: "Total Runs를 불러왔습니다.",
        message: "최근 Run이 없습니다.",
    });
    assert.equal(nonzeroTotal.queryState, "empty");
    assert.equal(nonzeroTotal.totalRuns, 7);
    assert.strictEqual(nonzeroTotal.recentRuns, nonzeroTotalPayload.recent_runs);
});

test("Overview error is a query failure without Pipeline or Run failure semantics", () => {
    // Given
    const previousState = resolveOverviewQueryState(null, { kind: "loading" });

    // When
    const state = resolveOverviewQueryState(previousState, { kind: "error" });

    // Then
    assert.deepEqual(state, {
        queryState: "error",
        totalRuns: null,
        recentRuns: [],
        totalMessage: "Total Runs를 불러오지 못했습니다.",
        message: "Recent Runs를 불러오지 못했습니다.",
    });
    assert.doesNotMatch(state.message, /Pipeline failed|Run failed/i);
});

test("Overview query messages reject an unknown state", () => {
    // Given / When / Then
    assert.throws(() => getOverviewQueryMessage("refreshing"), RangeError);
});

test("Overview query state rejects malformed results and payloads", () => {
    // Given
    const previousState = resolveOverviewQueryState(null, { kind: "loading" });
    const invalidCalls = [
        () => resolveOverviewQueryState([], { kind: "error" }),
        () => resolveOverviewQueryState(previousState, null),
        () => resolveOverviewQueryState(previousState, { kind: "success", payload: null }),
        () => resolveOverviewQueryState(previousState, {
            kind: "success",
            payload: { total_runs: "3", recent_runs: [] },
        }),
        () => resolveOverviewQueryState(previousState, {
            kind: "success",
            payload: { total_runs: 3, recent_runs: null },
        }),
        () => resolveOverviewQueryState(previousState, { kind: "unknown" }),
    ];
    const invalidRecentRunItems = [null, []];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
    for (const invalidItem of invalidRecentRunItems) {
        assert.throws(
            () => resolveOverviewQueryState(previousState, {
                kind: "success",
                payload: { total_runs: 1, recent_runs: [invalidItem] },
            }),
            TypeError,
        );
    }
});

test("Run List loading has no items and a loading message", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveRunListQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        items: [],
        message: "Run 목록을 불러오는 중입니다.",
    });
});

test("Run List success preserves API order and reports the item count", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });
    const payload = {
        runs: [
            { run_id: "RUN-2" },
            { run_id: "RUN-1" },
        ],
    };
    const payloadSnapshot = structuredClone(payload);

    // When
    const state = resolveRunListQueryState(previousState, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.items, payload.runs);
    assert.deepEqual(state.items.map((run) => run.run_id), ["RUN-2", "RUN-1"]);
    assert.equal(state.message, "Run 2건을 불러왔습니다.");
    assert.deepEqual(payload, payloadSnapshot);
});

test("Run List empty returns no items and an empty message", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });
    const payload = { runs: [] };

    // When
    const state = resolveRunListQueryState(previousState, { kind: "success", payload });

    // Then
    assert.deepEqual(state, {
        queryState: "empty",
        items: [],
        message: "표시할 Run이 없습니다.",
    });
    assert.strictEqual(state.items, payload.runs);
});

test("Run List error is a generalized query failure", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });

    // When
    const state = resolveRunListQueryState(previousState, { kind: "error" });

    // Then
    assert.deepEqual(state, {
        queryState: "error",
        items: [],
        message: "Run 목록을 불러오지 못했습니다.",
    });
    assert.doesNotMatch(state.message, /Pipeline failed|Run failed/i);
});

test("Overview success is preserved when Run List fails", () => {
    // Given
    const overviewLoading = resolveOverviewQueryState(null, { kind: "loading" });
    const runListLoading = resolveRunListQueryState(null, { kind: "loading" });
    const overviewPayload = {
        total_runs: 2,
        recent_runs: [{ run_id: "RUN-2" }],
    };

    // When
    const overviewState = resolveOverviewQueryState(overviewLoading, {
        kind: "success",
        payload: overviewPayload,
    });
    const runListState = resolveRunListQueryState(runListLoading, { kind: "error" });

    // Then
    assert.equal(overviewState.queryState, "success");
    assert.equal(overviewState.totalRuns, 2);
    assert.strictEqual(overviewState.recentRuns, overviewPayload.recent_runs);
    assert.deepEqual(overviewState.recentRuns, [{ run_id: "RUN-2" }]);
    assert.equal(runListState.queryState, "error");
    assert.deepEqual(runListState.items, []);
});

test("Run List success is preserved when Overview fails", () => {
    // Given
    const overviewLoading = resolveOverviewQueryState(null, { kind: "loading" });
    const runListLoading = resolveRunListQueryState(null, { kind: "loading" });
    const runListPayload = {
        runs: [
            { run_id: "RUN-2" },
            { run_id: "RUN-1" },
        ],
    };

    // When
    const overviewState = resolveOverviewQueryState(overviewLoading, { kind: "error" });
    const runListState = resolveRunListQueryState(runListLoading, {
        kind: "success",
        payload: runListPayload,
    });

    // Then
    assert.equal(overviewState.queryState, "error");
    assert.equal(overviewState.totalRuns, null);
    assert.deepEqual(overviewState.recentRuns, []);
    assert.equal(runListState.queryState, "success");
    assert.strictEqual(runListState.items, runListPayload.runs);
    assert.deepEqual(runListState.items.map((run) => run.run_id), ["RUN-2", "RUN-1"]);
});

test("Run List query state rejects malformed results and payloads", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });
    const invalidCalls = [
        () => resolveRunListQueryState([], { kind: "error" }),
        () => resolveRunListQueryState(previousState, null),
        () => resolveRunListQueryState(previousState, { kind: "success", payload: null }),
        () => resolveRunListQueryState(previousState, {
            kind: "success",
            payload: { runs: null },
        }),
        () => resolveRunListQueryState(previousState, { kind: "unknown" }),
    ];
    const invalidRunItems = [null, []];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
    for (const invalidItem of invalidRunItems) {
        assert.throws(
            () => resolveRunListQueryState(previousState, {
                kind: "success",
                payload: { runs: [invalidItem] },
            }),
            TypeError,
        );
    }
});

test("Runtime Summary loading is independent and exposes no inferred Runtime data", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveRuntimeSummaryQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        items: [],
        telemetryAvailable: false,
        message: "Runtime 정보를 불러오는 중입니다.",
    });
});

test("Runtime Summary success preserves API order and empty state", () => {
    // Given
    const loading = resolveRuntimeSummaryQueryState(null, { kind: "loading" });
    const payload = {
        items: [
            {
                run_id: "RUN-2",
                status: "completed",
                current_stage: null,
                updated_at: "2026-10-09T00:02:00.000Z",
                is_stale: false,
            },
            {
                run_id: "RUN-1",
                status: "running",
                current_stage: "fusion",
                updated_at: "2026-10-09T00:01:00.000Z",
                is_stale: true,
            },
        ],
    };
    const payloadSnapshot = structuredClone(payload);

    // When
    const success = resolveRuntimeSummaryQueryState(loading, { kind: "success", payload });
    const empty = resolveRuntimeSummaryQueryState(success, {
        kind: "success",
        payload: { items: [] },
    });

    // Then
    assert.equal(success.queryState, "success");
    assert.strictEqual(success.items, payload.items);
    assert.deepEqual(success.items.map((runtime) => runtime.run_id), ["RUN-2", "RUN-1"]);
    assert.equal(success.telemetryAvailable, true);
    assert.equal(success.message, "Runtime 2건을 불러왔습니다.");
    assert.deepEqual(empty, {
        queryState: "empty",
        items: [],
        telemetryAvailable: true,
        message: "표시할 Runtime 정보가 없습니다.",
    });
    assert.deepEqual(payload, payloadSnapshot);
});

test("Runtime Summary accepts null current_stage for terminal states", () => {
    // Given
    const payload = {
        items: [
            {
                run_id: "RUN-COMPLETED",
                status: "completed",
                current_stage: null,
                updated_at: "2026-10-09T00:02:00.000Z",
                is_stale: false,
            },
            {
                run_id: "RUN-FAILED",
                status: "failed",
                current_stage: null,
                updated_at: "2026-10-09T00:03:00.000Z",
                is_stale: false,
            },
        ],
    };

    // When
    const state = resolveRuntimeSummaryQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.deepEqual(state.items.map((runtime) => runtime.current_stage), [null, null]);
});

test("Runtime Summary stale Running success preserves the Operations display contract", () => {
    // Given
    const staleRunning = {
        run_id: "RUN-1",
        status: "running",
        current_stage: "fusion",
        updated_at: "2026-10-09T00:01:00.000Z",
        is_stale: true,
    };

    // When
    const state = resolveRuntimeSummaryQueryState(null, {
        kind: "success",
        payload: { items: [staleRunning] },
    });
    const presentation = getRuntimeStatePresentation(
        state.items[0],
        state.telemetryAvailable,
    );

    // Then
    assert.equal(state.queryState, "success");
    assert.equal(state.telemetryAvailable, true);
    assert.deepEqual(presentation, {
        modifiers: ["running", "stale"],
        statusLabel: "실행 중(마지막 보고)",
        telemetryLabel: "오래됨",
        livenessLabel: "확인 불가",
    });
    assert.doesNotMatch(JSON.stringify(presentation), /현재 실행 중/);
});

test("Runtime Summary error retains only its own last data without claiming liveness", () => {
    // Given
    const staleRunning = {
        run_id: "RUN-1",
        status: "running",
        current_stage: "fusion",
        updated_at: "2026-10-09T00:01:00.000Z",
        is_stale: true,
    };
    const success = resolveRuntimeSummaryQueryState(null, {
        kind: "success",
        payload: { items: [staleRunning] },
    });

    // When
    const failedQuery = resolveRuntimeSummaryQueryState(success, { kind: "error" });
    const presentation = getRuntimeStatePresentation(
        failedQuery.items[0],
        failedQuery.telemetryAvailable,
    );

    // Then
    assert.equal(failedQuery.queryState, "error");
    assert.strictEqual(failedQuery.items, success.items);
    assert.equal(failedQuery.message, "Runtime 정보를 불러오지 못했습니다.");
    assert.equal(failedQuery.telemetryAvailable, false);
    assert.equal(presentation.statusLabel, "실행 중(마지막 보고)");
    assert.equal(presentation.telemetryLabel, "확인 불가 (조회 실패)");
    assert.equal(presentation.livenessLabel, "확인 불가");
    assert.doesNotMatch(JSON.stringify(presentation), /현재 실행 중/);
});

test("Runtime Summary state rejects malformed results and payloads", () => {
    // Given
    const loading = resolveRuntimeSummaryQueryState(null, { kind: "loading" });
    const validRuntime = {
        run_id: "RUN-1",
        status: "running",
        current_stage: "fusion",
        updated_at: "2026-10-09T00:01:00.000Z",
        is_stale: false,
    };
    const invalidCalls = [
        () => resolveRuntimeSummaryQueryState([], { kind: "error" }),
        () => resolveRuntimeSummaryQueryState({}, { kind: "error" }),
        () => resolveRuntimeSummaryQueryState(loading, null),
        () => resolveRuntimeSummaryQueryState(loading, { kind: "success", payload: null }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: null },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [null] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: {
                items: [{
                    run_id: "RUN-1",
                    status: "running",
                    current_stage: "fusion",
                    updated_at: "2026-10-09T00:01:00.000Z",
                }],
            },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, is_stale: null }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, is_stale: "false" }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, run_id: null }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, status: null }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, status: "queued" }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: {
                items: [{
                    run_id: "RUN-1",
                    status: "running",
                    updated_at: "2026-10-09T00:01:00.000Z",
                    is_stale: false,
                }],
            },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, current_stage: 1 }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: {
                items: [{
                    run_id: "RUN-1",
                    status: "running",
                    current_stage: "fusion",
                    is_stale: false,
                }],
            },
        }),
        () => resolveRuntimeSummaryQueryState(loading, {
            kind: "success",
            payload: { items: [{ ...validRuntime, updated_at: null }] },
        }),
        () => resolveRuntimeSummaryQueryState(loading, { kind: "refreshing" }),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
});

test("Dashboard connects Runtime Summary through the existing Operations contract", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");

    // Then
    assert.match(script, /const RUNTIME_ENDPOINT = "\/operations\/runtime\?limit=5";/);
    assert.match(script, /const RUNTIME_REQUEST_TIMEOUT_MS = 10000;/);
    assert.match(script, /fetch\(RUNTIME_ENDPOINT/);
    assert.match(script, /const controller = new AbortController\(\);/);
    assert.match(
        script,
        /setTimeout\(\(\) => controller\.abort\(\), RUNTIME_REQUEST_TIMEOUT_MS\)/,
    );
    assert.match(script, /signal: controller\.signal/);
    assert.match(script, /clearTimeout\(timeoutId\);/);
    assert.match(script, /return await response\.json\(\);/);
    assert.match(script, /resolveRuntimeSummaryQueryState\(state, \{ kind: "success", payload \}\)/);
    assert.match(script, /resolveRuntimeSummaryQueryState\(state, \{ kind: "error" \}\)/);
    assert.match(script, /getRuntimeStatePresentation\(runtime, telemetryAvailable\)/);
    assert.match(script, /getStageLabel\(runtime\.current_stage\)/);
    assert.match(script, /formatRunTimestamp\(runtime\.updated_at\)/);
    assert.match(script, /presentation\.telemetryLabel/);
    assert.match(script, /presentation\.livenessLabel/);
    assert.equal(script.match(/void loadRuntimeSummary\(\);/g)?.length, 1);
    assert.equal(script.match(/setTimeout\(/g)?.length, 1);
    assert.doesNotMatch(
        script,
        /현재 실행 중|setInterval\(|setTimeout\((?:load|fetch)RuntimeSummary/,
    );
});

test("Dashboard links only completed Runtime items to Run Detail", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");
    const cardSource = script.slice(
        script.indexOf("function createRuntimeSummaryCard"),
        script.indexOf("function renderOverviewState"),
    );

    // Then
    assert.match(
        cardSource,
        /if \(runtime\.status === "completed" && runtime\.run_id\.trim\(\)\) \{/,
    );
    assert.match(cardSource, /link\.href = buildRunDetailViewPath\(runtime\.run_id\);/);
    assert.match(cardSource, /else \{\s+heading\.textContent = runtime\.run_id;/);
    assert.equal(cardSource.match(/buildRunDetailViewPath/g)?.length, 1);
    assert.doesNotMatch(cardSource, /if \(runtime\.run_id\.trim\(\)\) \{/);
});
