// Dashboard UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS,
    buildPipelineStagePresentation,
    canRefreshSelectedAnalysis,
    createSelectedRuntimeTracking,
    findSelectedRuntime,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
    getOverviewQueryMessage,
    getRunTypeLabel,
    getSelectedAnalysisScope,
    getSelectedAnalysisSource,
    getSelectedAnalysisState,
    getSelectedAnalysisTargetHost,
    getSelectedRuntimeOutsideQueryLabel,
    getSelectedRuntimeRecheckMessage,
    getStoppingTraceAvailability,
    isRunSelectionTarget,
    recordSelectedRuntimeRecheck,
    resolveInitialRunSelection,
    resolveOverviewQueryState,
    resolveRunSelectionFocus,
    resolveRunListQueryState,
    resolveRuntimeSummaryQueryState,
    resolveSelectedRuntimeTracking,
    shouldApplySelectedRunResponse,
    shouldRecheckSelectedRuntimeAnalysis,
    shouldRefreshSelectedRunAnalysis,
    shouldUpdateSelectedRunFailureState,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";
import {
    buildFusionEngineApiPath,
} from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";
import {
    getRuntimeStatePresentation,
} from "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs";
import {
    buildRunDetailApiPath,
} from "../../../src/incident_awareness/dashboard/ui/assets/run-detail-contract.mjs";

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
                entity_id: "WIN-B",
                status: "completed",
                current_stage: null,
                updated_at: "2026-10-09T00:02:00.000Z",
                is_stale: false,
            },
            {
                run_id: "RUN-1",
                entity_id: "WIN-A",
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

test("Latest Runtime report uses updated_at without reordering the API response", () => {
    // Given
    const runtimeItems = [
        {
            run_id: "RUN-RUNNING-OLDER",
            status: "running",
            updated_at: "2026-10-10T01:00:00.000Z",
        },
        {
            run_id: "RUN-COMPLETED-NEWER",
            status: "completed",
            updated_at: "2026-10-10T01:05:00.000Z",
        },
    ];
    const originalOrder = runtimeItems.map((runtime) => runtime.run_id);

    // When
    const latest = getLatestRuntimeReport(runtimeItems);

    // Then
    assert.strictEqual(latest, runtimeItems[1]);
    assert.deepEqual(runtimeItems.map((runtime) => runtime.run_id), originalOrder);
    assert.equal(getLatestRuntimeReport([]), null);
});

test("Runtime Summary accepts null current_stage for terminal states", () => {
    // Given
    const payload = {
        items: [
            {
                run_id: "RUN-COMPLETED",
                entity_id: "WIN-COMPLETED",
                status: "completed",
                current_stage: null,
                updated_at: "2026-10-09T00:02:00.000Z",
                is_stale: false,
            },
            {
                run_id: "RUN-FAILED",
                entity_id: "WIN-FAILED",
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
        entity_id: "WIN-A",
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
        entity_id: "WIN-A",
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
        entity_id: "WIN-A",
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
            payload: { items: [{ ...validRuntime, entity_id: null }] },
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

test("Pipeline stages highlight only states justified by persisted Runtime data", () => {
    // Given
    const running = {
        status: "running",
        current_stage: "fusion",
        is_stale: false,
    };
    const stale = { ...running, is_stale: true };
    const failed = {
        status: "failed",
        current_stage: null,
        failed_stage: "hybrid",
        is_stale: false,
    };
    const completed = {
        status: "completed",
        current_stage: null,
        is_stale: false,
    };

    // When
    const runningStages = buildPipelineStagePresentation(running, true);
    const staleStages = buildPipelineStagePresentation(stale, true);
    const unavailableStages = buildPipelineStagePresentation(running, false);
    const failedStages = buildPipelineStagePresentation(failed, true);
    const completedStages = buildPipelineStagePresentation(completed, true);

    // Then
    assert.deepEqual(
        runningStages.map((stage) => stage.state),
        ["unknown", "unknown", "current", "unknown", "unknown", "unknown"],
    );
    assert.equal(staleStages[2].state, "stale");
    assert.equal(unavailableStages[2].state, "unknown");
    assert.equal(failedStages[4].state, "failed");
    assert.equal(failedStages.filter((stage) => stage.state === "completed").length, 0);
    assert.equal(completedStages.every((stage) => stage.state === "completed"), true);
});

test("Pipeline stages remain unknown when the selected Run has no Runtime report", () => {
    // Given
    const runtime = null;

    // When
    const stages = buildPipelineStagePresentation(runtime, true);

    // Then
    assert.equal(stages.length, 6);
    assert.equal(stages.every((stage) => stage.state === "unknown"), true);
    assert.deepEqual(
        stages.map((stage) => stage.stage),
        [
            "artifact_validation",
            "normalization",
            "fusion",
            "fast_handoff",
            "hybrid",
            "persistence",
        ],
    );
});

test("Stopping Trace availability distinguishes missing, empty, and stored points", () => {
    // Given
    const emptyTrace = { points: [] };
    const populatedTrace = { points: [{ score: 0.5 }] };

    // When
    const missing = getStoppingTraceAvailability(null);
    const empty = getStoppingTraceAvailability(emptyTrace);
    const available = getStoppingTraceAvailability(populatedTrace);

    // Then
    assert.equal(missing, "missing");
    assert.equal(empty, "empty");
    assert.equal(available, "available");
    assert.throws(() => getStoppingTraceAvailability({ points: null }), TypeError);
});

test("Selected Run request versions reject a delayed response from an earlier selection", () => {
    // Given
    const firstSelectionVersion = 1;
    const currentSelectionVersion = 2;

    // When
    const applyDelayed = shouldApplySelectedRunResponse(
        firstSelectionVersion,
        currentSelectionVersion,
    );
    const applyCurrent = shouldApplySelectedRunResponse(
        currentSelectionVersion,
        currentSelectionVersion,
    );

    // Then
    assert.equal(applyDelayed, false);
    assert.equal(applyCurrent, true);
});

test("Initial Run selection waits for Runtime and follows status priority", () => {
    // Given
    const runs = [
        { run_id: "RUN-LIST-NEWEST" },
        { run_id: "RUN-LIST-OLDER" },
    ];
    const runtimes = [
        {
            run_id: "RUN-COMPLETED-NEWEST",
            entity_id: "WIN-C",
            status: "completed",
            is_stale: false,
        },
        {
            run_id: "RUN-RUNNING-NEWEST",
            entity_id: "WIN-A",
            status: "running",
            is_stale: false,
        },
        {
            run_id: "RUN-RUNNING-OLDER",
            entity_id: "WIN-B",
            status: "running",
            is_stale: false,
        },
    ];

    // When
    const overviewFirst = resolveInitialRunSelection(null, null, false, false, [], []);
    const runsFirst = resolveInitialRunSelection(null, null, false, false, [], runs);
    const runtimeFirst = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        runtimes,
        [],
    );
    const runsThenRuntime = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        runtimes,
        runs,
    );
    const completedOnly = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        runtimes.filter((runtime) => runtime.status === "completed"),
        runs,
    );
    const runFallback = resolveInitialRunSelection(null, null, true, true, [], runs);

    // Then
    assert.equal(overviewFirst, null);
    assert.equal(runsFirst, null);
    assert.deepEqual(runtimeFirst, {
        runId: "RUN-RUNNING-NEWEST",
        entityId: "WIN-A",
    });
    assert.deepEqual(runsThenRuntime, {
        runId: "RUN-RUNNING-NEWEST",
        entityId: "WIN-A",
    });
    assert.deepEqual(completedOnly, {
        runId: "RUN-COMPLETED-NEWEST",
        entityId: "WIN-C",
    });
    assert.deepEqual(runFallback, { runId: "RUN-LIST-NEWEST", entityId: null });
});

test("Automatic selection never replaces an existing user selection", () => {
    // Given
    const selectedRunId = "RUN-USER-SELECTED";
    const runtimes = [
        {
            run_id: "RUN-NEW-RUNTIME",
            entity_id: "WIN-NEW",
            status: "running",
            is_stale: false,
        },
    ];
    const runs = [{ run_id: "RUN-NEW-LIST", status: "completed" }];

    // When
    const selectionAfterPolling = resolveInitialRunSelection(
        selectedRunId,
        "WIN-USER",
        true,
        true,
        runtimes,
        runs,
    );

    // Then
    assert.deepEqual(selectionAfterPolling, {
        runId: selectedRunId,
        entityId: "WIN-USER",
    });
});

test("Initial Run selection deprioritizes stale Running Runtime", () => {
    // Given
    const currentRunning = {
        run_id: "RUN-CURRENT",
        entity_id: "WIN-CURRENT",
        status: "running",
        is_stale: false,
    };
    const completed = {
        run_id: "RUN-COMPLETED",
        entity_id: "WIN-COMPLETED",
        status: "completed",
        is_stale: false,
    };
    const staleRunning = {
        run_id: "RUN-STALE",
        entity_id: "WIN-STALE",
        status: "running",
        is_stale: true,
    };
    const runs = [{ run_id: "RUN-STORED" }];

    // When
    const currentBeforeCompleted = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        [completed, currentRunning, staleRunning],
        runs,
    );
    const completedBeforeStale = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        [staleRunning, completed],
        runs,
    );
    const staleOnly = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        [staleRunning],
        runs,
    );
    const unavailableTelemetry = resolveInitialRunSelection(
        null,
        null,
        true,
        false,
        [currentRunning],
        runs,
    );

    // Then
    assert.deepEqual(currentBeforeCompleted, {
        runId: "RUN-CURRENT",
        entityId: "WIN-CURRENT",
    });
    assert.deepEqual(completedBeforeStale, {
        runId: "RUN-COMPLETED",
        entityId: "WIN-COMPLETED",
    });
    assert.deepEqual(staleOnly, {
        runId: "RUN-STALE",
        entityId: "WIN-STALE",
    });
    assert.deepEqual(unavailableTelemetry, { runId: "RUN-STORED", entityId: null });
});

test("Run selection focus is restored only within its original table", () => {
    // Given
    const runtimeItems = [
        { run_id: "RUN-RUNTIME", entity_id: "WIN-A", status: "running" },
        { run_id: "RUN-RUNTIME", entity_id: "WIN-B", status: "running" },
    ];
    const updatedRuntimeItems = [
        { run_id: "RUN-RUNTIME", entity_id: "WIN-A", status: "completed" },
        { run_id: "RUN-RUNTIME", entity_id: "WIN-B", status: "running" },
    ];
    const runItems = [{ run_id: "RUN-STORED" }];

    // When
    const afterKeyboardSelection = resolveRunSelectionFocus(
        "RUN-STORED",
        null,
        "runs",
        runtimeItems,
        runItems,
    );
    const afterRuntimePolling = resolveRunSelectionFocus(
        "RUN-RUNTIME",
        "WIN-B",
        "runtime",
        updatedRuntimeItems,
        runItems,
    );
    const outsideTable = resolveRunSelectionFocus(
        null,
        null,
        null,
        updatedRuntimeItems,
        runItems,
    );

    // Then
    assert.deepEqual(afterKeyboardSelection, {
        runId: "RUN-STORED",
        entityId: null,
        table: "runs",
    });
    assert.deepEqual(afterRuntimePolling, {
        runId: "RUN-RUNTIME",
        entityId: "WIN-B",
        table: "runtime",
    });
    assert.equal(outsideTable, null);
});

test("Selected analysis handles completed and failed terminal transitions once", () => {
    // Given
    const selectedRunId = "RUN-SELECTED";
    const selectedEntityId = "WIN-B";
    const running = [
        { run_id: selectedRunId, entity_id: selectedEntityId, status: "running" },
    ];
    const completed = [
        { run_id: selectedRunId, entity_id: selectedEntityId, status: "completed" },
    ];
    const failed = [
        { run_id: selectedRunId, entity_id: selectedEntityId, status: "failed" },
    ];
    const otherCompleted = [
        { run_id: selectedRunId, entity_id: "WIN-A", status: "completed" },
    ];

    // When
    const transition = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        selectedEntityId,
        running,
        completed,
    );
    const repeatedCompletedPoll = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        selectedEntityId,
        completed,
        completed,
    );
    const differentSelection = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        selectedEntityId,
        running,
        otherCompleted,
    );
    const failedDoesNotReload = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        selectedEntityId,
        running,
        failed,
    );
    const failedTransition = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        selectedEntityId,
        running,
        failed,
    );
    const repeatedFailedPoll = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        selectedEntityId,
        failed,
        failed,
    );
    const completedDoesNotUseFailureState = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        selectedEntityId,
        running,
        completed,
    );

    // Then
    assert.equal(transition, true);
    assert.equal(repeatedCompletedPoll, false);
    assert.equal(differentSelection, false);
    assert.equal(failedDoesNotReload, false);
    assert.equal(failedTransition, true);
    assert.equal(repeatedFailedPoll, false);
    assert.equal(completedDoesNotUseFailureState, false);
});

test("Runtime selection keeps same-Run Entities independent", () => {
    // Given
    const runtimeItems = [
        {
            run_id: "RUN-A",
            entity_id: "WIN-A",
            status: "completed",
            current_stage: null,
        },
        {
            run_id: "RUN-A",
            entity_id: "WIN-B",
            status: "running",
            current_stage: "fusion",
        },
    ];

    // When
    const winA = findSelectedRuntime(runtimeItems, "RUN-A", "WIN-A");
    const winB = findSelectedRuntime(runtimeItems, "RUN-A", "WIN-B");
    const runListSelection = findSelectedRuntime(runtimeItems, "RUN-A", null);
    const pressedForWinB = runtimeItems.map(
        (runtime) => isRunSelectionTarget("RUN-A", "WIN-B", runtime.run_id, runtime.entity_id),
    );
    const runRowPressedForWinB = isRunSelectionTarget("RUN-A", "WIN-B", "RUN-A", null);
    const pressedForRunList = runtimeItems.map(
        (runtime) => isRunSelectionTarget("RUN-A", null, runtime.run_id, runtime.entity_id),
    );
    const runRowPressedForRunList = isRunSelectionTarget("RUN-A", null, "RUN-A", null);
    const nothingSelected = isRunSelectionTarget(null, null, "RUN-A", null);

    // Then
    assert.strictEqual(winA, runtimeItems[0]);
    assert.strictEqual(winB, runtimeItems[1]);
    assert.equal(winB.current_stage, "fusion");
    assert.equal(runListSelection, null);
    assert.deepEqual(pressedForWinB, [false, true]);
    assert.equal(runRowPressedForWinB, false);
    assert.deepEqual(pressedForRunList, [false, false]);
    assert.equal(runRowPressedForRunList, true);
    assert.equal(nothingSelected, false);
    assert.throws(() => isRunSelectionTarget("RUN-A", 1, "RUN-A", null), TypeError);
});

test("Initial Runtime selection falls back to the Run list without a Runtime candidate", () => {
    // Given
    const runs = [{ run_id: "RUN-STORED" }];
    const runtimeWithoutEntity = [
        { run_id: "RUN-NO-ENTITY", entity_id: "", status: "running", is_stale: false },
    ];

    // When
    const emptyRuntime = resolveInitialRunSelection(null, null, true, true, [], runs);
    const invalidRuntime = resolveInitialRunSelection(
        null,
        null,
        true,
        true,
        runtimeWithoutEntity,
        runs,
    );
    const nothingAvailable = resolveInitialRunSelection(null, null, true, true, [], []);

    // Then
    assert.deepEqual(emptyRuntime, { runId: "RUN-STORED", entityId: null });
    assert.deepEqual(invalidRuntime, { runId: "RUN-STORED", entityId: null });
    assert.equal(nothingAvailable, null);
    assert.throws(
        () => resolveInitialRunSelection(null, "WIN-A", true, true, [], runs),
        TypeError,
    );
});

test("Selected Runtime tracking keeps the last report separate from the query page", () => {
    // Given
    const selectedRunId = "RUN-A";
    const selectedEntityId = "WIN-B";
    const running = {
        run_id: selectedRunId,
        entity_id: selectedEntityId,
        status: "running",
        current_stage: "fusion",
    };
    const sameRunOtherEntity = { ...running, entity_id: "WIN-A" };
    const tracking = createSelectedRuntimeTracking(running);

    // When
    const stillPresent = resolveSelectedRuntimeTracking(
        tracking,
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [{ ...running, current_stage: "hybrid" }] },
    );
    const missing = resolveSelectedRuntimeTracking(
        tracking,
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [sameRunOtherEntity] },
    );
    const missingAgain = resolveSelectedRuntimeTracking(
        missing,
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [] },
    );
    const queryFailed = resolveSelectedRuntimeTracking(
        missingAgain,
        selectedRunId,
        selectedEntityId,
        { kind: "error" },
    );
    const recovered = resolveSelectedRuntimeTracking(
        queryFailed,
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [] },
    );
    const returnedCompleted = resolveSelectedRuntimeTracking(
        recordSelectedRuntimeRecheck(recovered),
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [{ ...running, status: "completed" }] },
    );
    const missingCompleted = resolveSelectedRuntimeTracking(
        returnedCompleted,
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: [] },
    );
    const runListTracking = resolveSelectedRuntimeTracking(
        createSelectedRuntimeTracking(null),
        selectedRunId,
        null,
        { kind: "success", items: [running] },
    );

    // Then
    assert.equal(stillPresent.report.current_stage, "hybrid");
    assert.equal(stillPresent.outsideQuery, false);
    assert.strictEqual(missing.report, running);
    assert.deepEqual(
        { ...missing, report: null },
        {
            report: null,
            outsideQuery: true,
            queryFailed: false,
            missingPolls: 1,
            recheckAttempts: 0,
        },
    );
    assert.equal(missingAgain.missingPolls, 2);
    assert.equal(queryFailed.queryFailed, true);
    assert.equal(queryFailed.outsideQuery, true);
    assert.equal(queryFailed.missingPolls, 2);
    assert.strictEqual(queryFailed.report, running);
    assert.equal(recovered.queryFailed, false);
    assert.equal(recovered.missingPolls, 3);
    assert.equal(returnedCompleted.report.status, "completed");
    assert.equal(returnedCompleted.outsideQuery, false);
    assert.equal(returnedCompleted.missingPolls, 0);
    assert.equal(returnedCompleted.recheckAttempts, 0);
    assert.equal(missingCompleted.outsideQuery, false);
    assert.equal(missingCompleted.report.status, "completed");
    assert.equal(runListTracking.report, null);
    assert.equal(runListTracking.outsideQuery, false);
    assert.throws(
        () => resolveSelectedRuntimeTracking(tracking, selectedRunId, selectedEntityId, {
            kind: "success",
        }),
        TypeError,
    );
    assert.throws(
        () => resolveSelectedRuntimeTracking(
            { ...tracking, missingPolls: -1 },
            selectedRunId,
            selectedEntityId,
            { kind: "error" },
        ),
        TypeError,
    );
});

test("Missing selected Runtime is never inferred as completed or failed", () => {
    // Given
    const selectedRunId = "RUN-A";
    const selectedEntityId = "WIN-B";
    const running = [
        { run_id: selectedRunId, entity_id: selectedEntityId, status: "running" },
    ];
    const nextPage = [
        { run_id: selectedRunId, entity_id: "WIN-A", status: "completed" },
    ];
    const otherEntityFailed = [
        ...running,
        { run_id: selectedRunId, entity_id: "WIN-A", status: "failed" },
    ];
    const outsideTracking = resolveSelectedRuntimeTracking(
        createSelectedRuntimeTracking(running[0]),
        selectedRunId,
        selectedEntityId,
        { kind: "success", items: nextPage },
    );
    const failedTracking = resolveSelectedRuntimeTracking(
        outsideTracking,
        selectedRunId,
        selectedEntityId,
        { kind: "error" },
    );

    // When
    const inferredCompleted = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        selectedEntityId,
        running,
        nextPage,
    );
    const inferredFailed = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        selectedEntityId,
        running,
        nextPage,
    );
    const otherEntityFailure = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        selectedEntityId,
        running,
        otherEntityFailed,
    );
    const outsideLabel = getSelectedRuntimeOutsideQueryLabel(outsideTracking);
    const failedLabel = getSelectedRuntimeOutsideQueryLabel(failedTracking);
    const insideLabel = getSelectedRuntimeOutsideQueryLabel(
        createSelectedRuntimeTracking(running[0]),
    );
    const stages = buildPipelineStagePresentation(null, true);

    // Then
    assert.equal(inferredCompleted, false);
    assert.equal(inferredFailed, false);
    assert.equal(otherEntityFailure, false);
    assert.equal(
        outsideLabel,
        "최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)",
    );
    assert.equal(
        failedLabel,
        "Runtime API 조회 실패 · 조회 범위 밖 항목의 현재 상태 확인 불가",
    );
    assert.equal(insideLabel, null);
    assert.equal(stages.every((stage) => stage.state === "unknown"), true);
});

test("Missing selected Runtime uses bounded non-overlapping analysis rechecks", () => {
    // Given
    const running = {
        run_id: "RUN-A",
        entity_id: "WIN-B",
        status: "running",
    };
    const outsideAfter = (missingPolls, recheckAttempts) => ({
        ...createSelectedRuntimeTracking(running),
        outsideQuery: true,
        missingPolls,
        recheckAttempts,
    });

    // When
    const insideQuery = shouldRecheckSelectedRuntimeAnalysis(
        createSelectedRuntimeTracking(running),
        false,
        false,
    );
    const firstAttempt = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(1, 0), false, false);
    const beforeSecondBackoff = shouldRecheckSelectedRuntimeAnalysis(
        outsideAfter(2, 1),
        false,
        false,
    );
    const secondAttempt = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(3, 1), false, false);
    const blockedOverlap = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(7, 2), true, false);
    const thirdAttempt = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(7, 2), false, false);
    const lastAttempt = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(31, 4), false, false);
    const bounded = shouldRecheckSelectedRuntimeAnalysis(outsideAfter(1000, 5), false, false);
    const storedResultStopsRetry = shouldRecheckSelectedRuntimeAnalysis(
        outsideAfter(7, 2),
        false,
        true,
    );
    const runtimeQueryFailed = shouldRecheckSelectedRuntimeAnalysis(
        { ...outsideAfter(7, 2), queryFailed: true },
        false,
        false,
    );
    const recorded = recordSelectedRuntimeRecheck(outsideAfter(1, 0));

    // Then
    assert.deepEqual(SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS, [1, 3, 7, 15, 31]);
    assert.equal(Object.isFrozen(SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS), true);
    assert.equal(insideQuery, false);
    assert.equal(firstAttempt, true);
    assert.equal(beforeSecondBackoff, false);
    assert.equal(secondAttempt, true);
    assert.equal(blockedOverlap, false);
    assert.equal(thirdAttempt, true);
    assert.equal(lastAttempt, true);
    assert.equal(bounded, false);
    assert.equal(storedResultStopsRetry, false);
    assert.equal(runtimeQueryFailed, false);
    assert.equal(recorded.recheckAttempts, 1);
    assert.equal(recorded.missingPolls, 1);
    assert.throws(
        () => shouldRecheckSelectedRuntimeAnalysis(outsideAfter(1, 0), "no", false),
        TypeError,
    );
});

test("Recheck messages separate Runtime API failure from leaving the query range", () => {
    // Given
    const running = { run_id: "RUN-A", entity_id: "WIN-B", status: "running" };
    const outside = {
        ...createSelectedRuntimeTracking(running),
        outsideQuery: true,
        missingPolls: 1,
        recheckAttempts: 1,
    };

    // When
    const inside = getSelectedRuntimeRecheckMessage(createSelectedRuntimeTracking(running));
    const rechecking = getSelectedRuntimeRecheckMessage(outside);
    const exhausted = getSelectedRuntimeRecheckMessage({ ...outside, recheckAttempts: 5 });
    const queryFailed = getSelectedRuntimeRecheckMessage({ ...outside, queryFailed: true });

    // Then
    assert.equal(inside, null);
    assert.equal(
        rechecking,
        "선택한 Runtime이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
            + "저장 결과를 제한된 간격으로 다시 확인합니다 (1/5회).",
    );
    assert.match(exhausted, /저장 결과 재확인 5회를 마쳤지만 아직 결과가 없습니다/);
    assert.match(exhausted, /결과 다시 조회 버튼으로 저장 결과를 다시 조회할 수 있습니다/);
    assert.match(queryFailed, /^Runtime API 조회에 실패해/);
    assert.match(queryFailed, /Runtime 조회가 복구되면 이어서 진행합니다/);
    for (const message of [rechecking, exhausted, queryFailed]) {
        assert.doesNotMatch(message, /실행 중입니다|완료되었습니다|실패했습니다\.$/);
    }
});

test("Manual analysis refresh requires a selected Run and no pending request", () => {
    // Given
    const selectedRunId = "RUN-A";

    // When
    const idle = canRefreshSelectedAnalysis(selectedRunId, false);
    const pending = canRefreshSelectedAnalysis(selectedRunId, true);
    const nothingSelected = canRefreshSelectedAnalysis(null, false);

    // Then
    assert.equal(idle, true);
    assert.equal(pending, false);
    assert.equal(nothingSelected, false);
    assert.throws(() => canRefreshSelectedAnalysis(selectedRunId, null), TypeError);
    assert.throws(() => canRefreshSelectedAnalysis(1, false), TypeError);
});

test("Selected analysis scope never presents run-level results as another Entity", () => {
    // Given
    const detail = { run: { run_id: "RUN-A", target_host: "WIN-A" } };
    const fusion = { run: { run_id: "RUN-A", target_host: "WIN-A" } };
    const changedFusion = { run: { run_id: "RUN-A", target_host: "WIN-Z" } };

    // When
    const targetHost = getSelectedAnalysisTargetHost(detail, fusion);
    const detailOnlyHost = getSelectedAnalysisTargetHost(detail, null);
    const inconsistentHost = getSelectedAnalysisTargetHost(detail, changedFusion);
    const missingHost = getSelectedAnalysisTargetHost(null, null);
    const none = getSelectedAnalysisScope(null, null, null);
    const runList = getSelectedAnalysisScope("RUN-A", null, targetHost);
    const mismatch = getSelectedAnalysisScope("RUN-A", "WIN-B", targetHost);
    const match = getSelectedAnalysisScope("RUN-A", "WIN-A", targetHost);
    const unconfirmed = getSelectedAnalysisScope("RUN-A", "WIN-B", null);

    // Then
    assert.equal(targetHost, "WIN-A");
    assert.equal(detailOnlyHost, "WIN-A");
    assert.equal(inconsistentHost, null);
    assert.equal(missingHost, null);
    assert.equal(none.scope, "none");
    assert.equal(runList.scope, "run");
    assert.match(runList.message, /run_id 범위/);
    assert.match(runList.message, /RunMetadata\.target_host WIN-A/);
    assert.equal(mismatch.scope, "runtime_entity_mismatch");
    assert.match(mismatch.message, /RunMetadata\.target_host WIN-A 결과이며 WIN-B 결과가 아닙니다/);
    assert.equal(match.scope, "runtime_entity_match");
    assert.match(match.message, /RunMetadata\.target_host도 WIN-A/);
    assert.equal(unconfirmed.scope, "runtime_entity_unconfirmed");
    assert.match(unconfirmed.message, /WIN-B 결과로 간주하지 않습니다/);
    assert.throws(() => getSelectedAnalysisScope("RUN-A", "WIN-B", 1), TypeError);
});

test("Running 404 waits for persistence and completed results become available", () => {
    // Given
    const initialDetailState = "not_found";
    const initialFusionState = "not_found";
    const refreshedDetailState = "success";
    const refreshedFusionState = "success";

    // When
    const waiting = getSelectedAnalysisState(
        initialDetailState,
        initialFusionState,
        "running",
        false,
        "unavailable",
    );
    const available = getSelectedAnalysisState(
        refreshedDetailState,
        refreshedFusionState,
        "completed",
        true,
        "match",
    );
    const queryError = getSelectedAnalysisState(
        "error",
        initialFusionState,
        "running",
        false,
        "unavailable",
    );

    // Then
    assert.equal(waiting, "waiting");
    assert.equal(available, "available");
    assert.equal(queryError, "error");
});

test("Decision version consistency prevents mixed Run Detail and Fusion results", () => {
    // Given
    const runDetail = {
        current_decision: { decision: { decision_id: "DEC-DETAIL" } },
    };
    const matchingFusion = { current_decision: { decision_id: "DEC-DETAIL" } };
    const mismatchingFusion = { current_decision: { decision_id: "DEC-FUSION" } };
    const fusionWithoutDecision = {
        current_decision: null,
        fusion_result: { fusion_status: "miss" },
        stopping_trace: { points: [{ score: 0.2 }] },
    };
    const runDetailWithoutDecision = { current_decision: null };

    // When
    const matching = getDecisionVersionConsistency(runDetail, matchingFusion);
    const mismatching = getDecisionVersionConsistency(runDetail, mismatchingFusion);
    const unavailable = getDecisionVersionConsistency(runDetail, fusionWithoutDecision);
    const matchingSource = getSelectedAnalysisSource(runDetail, matchingFusion);
    const mismatchingSource = getSelectedAnalysisSource(runDetail, mismatchingFusion);
    const unavailableSource = getSelectedAnalysisSource(runDetail, fusionWithoutDecision);
    const traceWithoutDecisionSource = getSelectedAnalysisSource(
        runDetailWithoutDecision,
        fusionWithoutDecision,
    );
    const detailFailureSource = getSelectedAnalysisSource(null, matchingFusion);
    const fusionFailureSource = getSelectedAnalysisSource(runDetail, null);

    // Then
    assert.equal(matching, "match");
    assert.equal(mismatching, "mismatch");
    assert.equal(unavailable, "unavailable");
    assert.equal(matchingSource, "matched");
    assert.equal(mismatchingSource, "run_detail");
    assert.equal(unavailableSource, "run_detail");
    assert.equal(traceWithoutDecisionSource, "fusion_engine_without_decision");
    assert.equal(detailFailureSource, "fusion_engine");
    assert.equal(fusionFailureSource, "run_detail");
});

test("Dashboard polls Runtime after each completed request without overlap", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");
    const failureRenderer = script.slice(
        script.indexOf("function renderSelectedRunFailureState"),
        script.indexOf("function renderSelectedLinks"),
    );

    // Then
    assert.match(script, /const RUNTIME_ENDPOINT = "\/operations\/runtime\?limit=5";/);
    assert.match(script, /const RUNTIME_POLL_INTERVAL_MS = 5000;/);
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
    assert.match(script, /resolveRuntimeSummaryQueryState\(/);
    assert.match(script, /\{ kind: "success", payload \}/);
    assert.match(script, /\{ kind: "error" \}/);
    assert.match(script, /async function pollRuntimeSummary\(\)/);
    assert.match(script, /const payload = await fetchRuntimeSummary\(\);/);
    assert.match(script, /shouldRefreshSelectedRunAnalysis\(/);
    assert.match(script, /shouldUpdateSelectedRunFailureState\(/);
    assert.match(script, /refreshCompletedSelection/);
    assert.match(script, /updateFailedSelection/);
    assert.match(script, /renderSelectedRunFailureState\(\)/);
    assert.match(script, /상세 결과 자동 재조회는 수행하지 않습니다/);
    assert.doesNotMatch(failureRenderer, /loadSelectedRunAnalysis|fetch/);
    assert.match(script, /void loadSelectedRunAnalysis\(/);
    assert.match(
        script,
        /완료 보고를 확인해 저장된 분석 결과를 다시 불러오는 중입니다/,
    );
    assert.match(script, /runtimePollTimeoutId = setTimeout\(\(\) =>/);
    assert.match(script, /void pollRuntimeSummary\(\);/);
    assert.match(script, /RUNTIME_POLL_INTERVAL_MS/);
    assert.match(script, /getStageLabel\(runtime\.current_stage\)/);
    assert.match(script, /getLatestRuntimeReport\(state\.items\)/);
    assert.match(script, /formatRunTimestamp\(runtime\.updated_at\)/);
    assert.match(script, /presentation\.telemetryLabel/);
    assert.match(script, /window\.addEventListener\("pagehide", stopRuntimePolling\)/);
    assert.match(script, /window\.addEventListener\("pageshow"/);
    assert.doesNotMatch(script, /현재 실행 중|setInterval\(/);
});

test("Dashboard selection loads both detail APIs and discards delayed responses", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");
    const analysisLoader = script.slice(
        script.indexOf("async function loadSelectedRunAnalysis"),
        script.indexOf("async function selectRun"),
    );

    // Then
    assert.match(script, /async function selectRun\(runId, runtimeEntityId = null\)/);
    assert.match(script, /const ANALYSIS_REQUEST_TIMEOUT_MS = 10000;/);
    assert.match(script, /buildRunDetailApiPath\(runId\)/);
    assert.match(script, /buildFusionEngineApiPath\(runId\)/);
    assert.match(script, /async function fetchSelectedAnalysis\(endpoint, failureMessage\)/);
    assert.match(script, /selectedAnalysisAbortControllers\.add\(controller\)/);
    assert.match(script, /signal: controller\.signal/);
    assert.match(script, /payload: await response\.json\(\)/);
    assert.match(script, /cancelSelectedAnalysisRequests\(\)/);
    assert.match(script, /Promise\.all\(\[/);
    assert.match(script, /shouldApplySelectedRunResponse\(/);
    assert.match(script, /resolveInitialRunSelection\(/);
    assert.match(script, /buildRunDetailViewPath\(runId\)/);
    assert.match(script, /buildFusionEngineViewPath\(runId\)/);
    assert.match(script, /selectedRunDetailLink\.hidden = !detailAvailable/);
    assert.match(script, /selectedRunFusionLink\.hidden = !fusionAvailable/);
    assert.match(script, /getDecisionVersionConsistency\(/);
    assert.match(script, /getSelectedAnalysisSource\(/);
    assert.match(script, /analysisState === "version_mismatch"/);
    assert.match(script, /Decision 버전이 달라 결과를 결합하지 않았습니다/);
    assert.match(script, /Decision ID를 비교할 수 없어 Run Detail 출처의 결과만 표시합니다/);
    assert.match(script, /Decision ID를 비교할 수 없어 Fusion Engine 출처의 결과만 표시합니다/);
    assert.match(script, /Fusion Engine Decision ID를 확인할 수 없어 Trace를 결합하지 않았습니다/);
    assert.match(script, /Decision 없는 Fusion Engine 저장 결과를 단일 출처로 표시합니다/);
    assert.equal(analysisLoader.match(/Promise\.all\(\[/g)?.length, 2);
    assert.doesNotMatch(analysisLoader, /while \(|for \(/);
    assert.match(script, /getStoppingTraceAvailability\(stoppingTrace\)/);
    assert.match(script, /buildScoreTrajectoryModel\(/);
    assert.match(script, /createScoreTrajectoryChart\(model\)/);
    assert.match(script, /fusionResult\?\.fusion_status === "not_evaluated"/);
    assert.match(script, /Stopping Trace가 비어 있습니다/);
    assert.match(script, /결과 저장을 기다리는 중입니다/);
});

test("Dashboard restores Run selector focus without moving external focus", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");

    // Then
    assert.match(script, /list\.contains\(document\.activeElement\)/);
    assert.match(script, /button\.dataset\.runId = runId/);
    assert.match(script, /button\.dataset\.entityId = runtimeEntityId/);
    assert.match(script, /resolveRunSelectionFocus\(/);
    assert.match(script, /replacement\?\.focus\(\{ preventScroll: true \}\)/);
    assert.match(
        script,
        /"aria-pressed",\s*String\(isSelectedTarget\(runId, runtimeEntityId\)\)/,
    );
});

test("Dashboard renders dense Runtime and Run tables without exposing Run Type", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.js",
        import.meta.url,
    );
    const htmlPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/dashboard.html",
        import.meta.url,
    );
    const stylesheetPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/dashboard.css",
        import.meta.url,
    );

    // When
    const [script, html, stylesheet] = await Promise.all([
        readFile(scriptPath, "utf8"),
        readFile(htmlPath, "utf8"),
        readFile(stylesheetPath, "utf8"),
    ]);

    // Then
    assert.match(script, /const RUNS_ENDPOINT = "\/runs\?limit=20";/);
    assert.match(script, /state\.items\.map\(\(run\) => createRunRow\(run\)\)/);
    assert.match(script, /displayValue\(run\.scenario_id\)/);
    assert.match(script, /displayValue\(run\.target_host\)/);
    assert.match(script, /formatRunTimestamp\(run\.start_time\)/);
    assert.match(script, /buildRunDetailViewPath\(run\.run_id\)/);
    assert.doesNotMatch(script, /run\.run_type|getRunTypeLabel/);
    assert.match(html, /<table class="dashboard-table runtime-table">/);
    assert.match(html, /<th scope="col">Run ID<\/th>\s*<th scope="col">Entity ID<\/th>/);
    assert.match(html, /Run ID와 Entity ID 조합으로 선택/);
    assert.match(html, /id="selected-run-scope"/);
    assert.match(
        html,
        /<button id="selected-run-refresh" class="dashboard-analysis-refresh" type="button" hidden>결과 다시 조회<\/button>/,
    );
    assert.match(script, /createTableCell\(runtime\.entity_id\)/);
    assert.match(html, /<table class="dashboard-table runs-table">/);
    assert.match(html, /API의 관측 시작 시각 최근순을 그대로 유지하며 최대 20건/);
    assert.match(html, /최근 Runtime 조회 결과는\s+전체 실행 통계가 아닙니다/);
    assert.match(html, /조회 완료 후 약 5초 간격으로 Runtime 상태 갱신/);
    assert.match(html, /조회 범위 내 최신 Runtime 상태/);
    assert.match(html, /조회 범위 내 최신 Runtime 보고/);
    assert.match(html, /<details class="dashboard-time-note">/);
    assert.match(html, /<summary>표시 기준 및 상태 안내<\/summary>/);
    assert.match(html, /class="dashboard-workbench"/);
    assert.match(html, /class="dashboard-stage-scroll"/);
    assert.match(stylesheet, /\.app-page\.dashboard-page\s*{[^}]*width: 100%;/s);
    assert.match(stylesheet, /\.app-page\.dashboard-page\s*{[^}]*max-width: 101rem;/s);
    assert.match(stylesheet, /grid-template-columns: repeat\(6, minmax\(9rem, 1fr\)\)/);
    assert.match(stylesheet, /@media \(max-width: 82rem\)/);
    assert.doesNotMatch(html, />Type<|>Run Type</);
    assert.match(script, /runsStatus\.textContent = state\.message;/);
    assert.equal(script.match(/void loadRuns\(\);/g)?.length, 1);
    assert.doesNotMatch(script, /\.sort\(|\.toSorted\(|\.reverse\(|\.toReversed\(/);
});

// The scenarios below run the real dashboard.js against a minimal DOM, fetch, and timer
// double so selection, polling, and delayed responses are checked end to end.
const DASHBOARD_ASSETS_URL = new URL(
    "../../../src/incident_awareness/dashboard/ui/assets/",
    import.meta.url,
);
const RUNTIME_API_PATH = "/operations/runtime?limit=5";
const RUNTIME_POLL_DELAY_MS = 5000;
const PIPELINE_STAGE_STATES = ["completed", "current", "stale", "failed", "unknown"];
const RUNNING_LABEL = getRuntimeStatePresentation(
    { status: "running", is_stale: false },
    true,
).statusLabel;
const COMPLETED_LABEL = getRuntimeStatePresentation({ status: "completed" }, true).statusLabel;
const WAITING_STATUS = "마지막 Runtime 보고는 실행 중이며 결과 저장을 기다리는 중입니다.";
const STORED_STATUS = "저장된 분석 결과를 불러왔습니다.";
const RECHECK_LOADING_STATUS = (
    "조회 범위를 벗어난 Runtime의 저장 분석 결과를 다시 확인하는 중입니다."
);
let dashboardHarnessCount = 0;

class FakeNode {}

class FakeElement extends FakeNode {
    constructor(ownerDocument) {
        super();
        this.ownerDocument = ownerDocument;
        this.parentNode = null;
        this.childNodes = [];
        this.classNames = new Set();
        this.classList = {
            add: (...names) => names.forEach((name) => this.classNames.add(name)),
            contains: (name) => this.classNames.has(name),
        };
        this.dataset = {};
        this.attributes = new Map();
        this.listeners = new Map();
        this.hidden = false;
        this.href = "";
        this.type = "";
        this.ownText = "";
    }

    get textContent() {
        return this.ownText + this.childNodes.map((child) => child.textContent).join("");
    }

    set textContent(value) {
        this.replaceChildren();
        this.ownText = String(value);
    }

    append(...nodes) {
        for (const node of nodes) {
            assert.ok(node instanceof FakeElement, "Dashboard must append DOM nodes only");
            node.parentNode = this;
            this.childNodes.push(node);
        }
    }

    replaceChildren(...nodes) {
        for (const child of this.childNodes) {
            child.parentNode = null;
        }
        this.childNodes = [];
        this.ownText = "";
        this.append(...nodes);
    }

    setAttribute(name, value) {
        this.attributes.set(name, String(value));
    }

    getAttribute(name) {
        return this.attributes.get(name) ?? null;
    }

    addEventListener(type, listener) {
        this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    click() {
        for (const listener of this.listeners.get("click") ?? []) {
            listener({ type: "click", target: this });
        }
    }

    focus() {
        this.ownerDocument.activeElement = this;
    }

    contains(node) {
        for (let current = node; current !== null && current !== undefined;) {
            if (current === this) {
                return true;
            }
            current = current.parentNode;
        }
        return false;
    }

    querySelectorAll(selector) {
        assert.match(selector, /^\.[\w-]+$/);
        const className = selector.slice(1);
        const matches = [];
        const visit = (element) => {
            for (const child of element.childNodes) {
                if (child.classList.contains(className)) {
                    matches.push(child);
                }
                visit(child);
            }
        };
        visit(this);
        return matches;
    }
}

async function startDashboardHarness() {
    const source = await readFile(new URL("dashboard.js", DASHBOARD_ASSETS_URL), "utf8");
    const document = {
        activeElement: null,
        elements: new Map(),
        createElement: () => new FakeElement(document),
        getElementById: (id) => document.elements.get(id) ?? null,
    };
    for (const [, id] of source.matchAll(/document\.getElementById\("([^"]+)"\)/g)) {
        document.elements.set(id, new FakeElement(document));
    }

    const requests = [];
    const timers = new Map();
    const windowListeners = new Map();
    let nextTimerId = 1;
    const fakeGlobals = {
        document,
        window: {
            addEventListener(type, listener) {
                windowListeners.set(type, [
                    ...(windowListeners.get(type) ?? []),
                    listener,
                ]);
            },
        },
        Node: FakeNode,
        fetch: (url, options = {}) => new Promise((resolve, reject) => {
            const request = {
                url: String(url),
                options,
                resolve,
                reject,
                settled: false,
                jsonReject: null,
            };
            const rejectAborted = () => {
                if (!request.settled) {
                    request.settled = true;
                    reject(new Error("Request aborted"));
                }
                request.jsonReject?.(new Error("Response body aborted"));
            };
            options.signal?.addEventListener("abort", rejectAborted, { once: true });
            if (options.signal?.aborted) {
                rejectAborted();
            }
            requests.push(request);
        }),
        setTimeout: (callback, delay) => {
            const id = nextTimerId;
            nextTimerId += 1;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeout: (id) => {
            timers.delete(id);
        },
    };
    const originalGlobals = new Map(
        Object.keys(fakeGlobals).map(
            (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)],
        ),
    );
    const restore = () => {
        for (const [name, descriptor] of originalGlobals) {
            if (descriptor === undefined) {
                delete globalThis[name];
            } else {
                Object.defineProperty(globalThis, name, descriptor);
            }
        }
    };
    for (const [name, value] of Object.entries(fakeGlobals)) {
        Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
    }

    const flush = async () => {
        for (let index = 0; index < 20; index += 1) {
            await new Promise((resolve) => setImmediate(resolve));
        }
    };
    const respond = async (
        url,
        status,
        body,
        { newest = false, deferJson = false } = {},
    ) => {
        const pending = requests.filter(
            (candidate) => !candidate.settled && candidate.url === url,
        );
        const request = newest ? pending.at(-1) : pending[0];
        assert.ok(request, `Expected a pending request for ${url}`);
        request.settled = true;
        request.resolve({
            ok: status >= 200 && status < 300,
            status,
            json: async () => {
                if (!deferJson) {
                    return body;
                }
                return new Promise((resolve, reject) => {
                    if (request.options.signal?.aborted) {
                        reject(new Error("Response body aborted"));
                        return;
                    }
                    request.jsonReject = reject;
                });
            },
        });
        await flush();
    };
    const triggerTimers = async (delay) => {
        const matchingTimers = [...timers].filter(([, timer]) => timer.delay === delay);
        for (const [timerId, timer] of matchingTimers) {
            timers.delete(timerId);
            timer.callback();
        }
        await flush();
    };
    const dispatchWindowEvent = async (type, event = {}) => {
        for (const listener of windowListeners.get(type) ?? []) {
            listener({ type, ...event });
        }
        await flush();
    };
    const triggerPoll = async () => {
        const pollTimers = [...timers].filter(
            ([, timer]) => timer.delay === RUNTIME_POLL_DELAY_MS,
        );
        assert.equal(pollTimers.length, 1, "Exactly one Runtime poll must be scheduled");
        const [[timerId, timer]] = pollTimers;
        timers.delete(timerId);
        timer.callback();
        await flush();
    };
    const selectorRows = (listId) => document.getElementById(listId).childNodes.map(
        (row) => {
            const [button] = row.querySelectorAll(".dashboard-run-selector");
            return { row, button };
        },
    );

    const moduleSource = source.replaceAll(
        /from "\.\/([^"]+)"/g,
        (_, file) => `from "${new URL(file, DASHBOARD_ASSETS_URL).href}"`,
    );
    dashboardHarnessCount += 1;
    try {
        await import(
            "data:text/javascript;charset=utf-8,"
            + encodeURIComponent(
                `${moduleSource}\n// dashboard harness ${dashboardHarnessCount}\n`,
            )
        );
        await flush();
    } catch (error) {
        restore();
        throw error;
    }

    return {
        document,
        restore,
        flush,
        respond,
        dispatchWindowEvent,
        triggerTimers,
        timerCount: (delay) => [...timers.values()].filter(
            (timer) => timer.delay === delay,
        ).length,
        requestCount: (url) => requests.filter((request) => request.url === url).length,
        pendingCount: (url) => requests.filter(
            (request) => !request.settled && request.url === url,
        ).length,
        async respondAnalysis(runId, detail, fusion, options = {}) {
            await respond(buildRunDetailApiPath(runId), detail.status, detail.body, options);
            await respond(
                buildFusionEngineApiPath(runId),
                fusion.status,
                fusion.body,
                options,
            );
        },
        async poll(items) {
            await triggerPoll();
            await respond(RUNTIME_API_PATH, 200, { items });
        },
        async pollFailure() {
            await triggerPoll();
            await respond(RUNTIME_API_PATH, 503, { detail: "Runtime unavailable" });
        },
        text: (id) => document.getElementById(id).textContent,
        refreshButton: () => document.getElementById("selected-run-refresh"),
        stageStates: () => document.getElementById("pipeline-stage-list").childNodes.map(
            (item) => PIPELINE_STAGE_STATES.find(
                (state) => item.classList.contains(`pipeline-stage--${state}`),
            ),
        ),
        runtimeRows: () => selectorRows("runtime-summary-list").map(({ row, button }) => ({
            runId: button.dataset.runId,
            entityId: button.dataset.entityId ?? null,
            entityCell: row.childNodes[1].textContent,
            label: button.getAttribute("aria-label"),
            pressed: button.getAttribute("aria-pressed"),
            selected: row.classList.contains("dashboard-table__row--selected"),
        })),
        runRows: () => selectorRows("runs-list").map(({ row, button }) => ({
            runId: button.dataset.runId,
            entityId: button.dataset.entityId ?? null,
            pressed: button.getAttribute("aria-pressed"),
            selected: row.classList.contains("dashboard-table__row--selected"),
        })),
        runtimeButton: (runId, entityId) => selectorRows("runtime-summary-list").find(
            ({ button }) => (
                button.dataset.runId === runId && button.dataset.entityId === entityId
            ),
        ).button,
        runButton: (runId) => selectorRows("runs-list").find(
            ({ button }) => button.dataset.runId === runId,
        ).button,
    };
}

function runtimeReport(runId, entityId, status, currentStage) {
    return {
        execution_id: `${runId}-${entityId}`,
        run_id: runId,
        entity_id: entityId,
        status,
        current_stage: currentStage,
        input_total: 10,
        normalization_processed_count: 5,
        remaining_count: 5,
        started_at: "2026-10-09T00:00:00Z",
        stage_started_at: null,
        updated_at: "2026-10-09T00:01:00Z",
        completed_at: status === "completed" ? "2026-10-09T00:02:00Z" : null,
        failed_stage: status === "failed" ? "hybrid" : null,
        has_error: status === "failed",
        is_stale: false,
    };
}

function runListItem(runId, targetHost) {
    return {
        run_id: runId,
        scenario_id: "SCN-1",
        run_type: "attack",
        target_host: targetHost,
        start_time: "2026-10-09T00:00:00Z",
        end_time: null,
    };
}

function notFound() {
    return { status: 404, body: { detail: "Run not found" } };
}

function storedDetail(runId, targetHost, decisionId = null) {
    return {
        status: 200,
        body: {
            run: { run_id: runId, target_host: targetHost },
            current_decision: decisionId === null
                ? null
                : {
                    decision: { decision_id: decisionId },
                    latest_detection_result: null,
                    latest_fusion_result: null,
                    latest_fusion_stopping_trace: null,
                },
            decision_history: [],
        },
    };
}

function storedFusion(runId, targetHost, decisionId = null) {
    return {
        status: 200,
        body: {
            run: { run_id: runId, target_host: targetHost },
            current_decision: decisionId === null ? null : { decision_id: decisionId },
            fusion_result: null,
            stopping_trace: null,
            runtime_config_snapshot: null,
        },
    };
}

function otherRunningReports() {
    return ["RUN-B", "RUN-C", "RUN-D", "RUN-E", "RUN-F"].map(
        (runId, index) => runtimeReport(runId, `WIN-${index + 1}`, "running", "normalization"),
    );
}

async function startDashboardWithRuntime(runtimeItems, runs) {
    const harness = await startDashboardHarness();
    await harness.respond("/overview", 200, { total_runs: runs.length, recent_runs: runs });
    await harness.respond("/runs?limit=20", 200, { runs });
    await harness.respond(RUNTIME_API_PATH, 200, { items: runtimeItems });
    return harness;
}

test("Dashboard pauses and resumes Runtime polling across bfcache lifecycle", async (t) => {
    // Given
    const harness = await startDashboardHarness();
    t.after(harness.restore);
    const initialRequestCount = harness.requestCount(RUNTIME_API_PATH);

    // When
    await harness.dispatchWindowEvent("pageshow", { persisted: false });
    const afterOrdinaryPageShow = harness.requestCount(RUNTIME_API_PATH);
    await harness.dispatchWindowEvent("pagehide");
    await harness.dispatchWindowEvent("pageshow", { persisted: true });
    const whileOriginalRequestIsPending = harness.requestCount(RUNTIME_API_PATH);
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const scheduledAfterRestore = harness.timerCount(RUNTIME_POLL_DELAY_MS);
    await harness.dispatchWindowEvent("pageshow", { persisted: true });
    const duplicateTimerCount = harness.timerCount(RUNTIME_POLL_DELAY_MS);
    await harness.dispatchWindowEvent("pagehide");
    const timersAfterHide = harness.timerCount(RUNTIME_POLL_DELAY_MS);
    await harness.dispatchWindowEvent("pageshow", { persisted: false });
    const afterNonPersistedShowWhilePaused = harness.requestCount(RUNTIME_API_PATH);
    await harness.dispatchWindowEvent("pageshow", { persisted: true });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.poll([]);
    const continuedTimerCount = harness.timerCount(RUNTIME_POLL_DELAY_MS);

    // Then
    assert.equal(initialRequestCount, 1);
    assert.equal(afterOrdinaryPageShow, 1);
    assert.equal(whileOriginalRequestIsPending, 1);
    assert.equal(scheduledAfterRestore, 1);
    assert.equal(duplicateTimerCount, 1);
    assert.equal(timersAfterHide, 0);
    assert.equal(afterNonPersistedShowWhilePaused, 1);
    assert.equal(harness.requestCount(RUNTIME_API_PATH), 3);
    assert.equal(continuedTimerCount, 1);
});

test("Dashboard does not schedule a poll when an in-flight request ends while hidden", async (t) => {
    // Given
    const harness = await startDashboardHarness();
    t.after(harness.restore);

    // When
    await harness.dispatchWindowEvent("pagehide");
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const timersWhileHidden = harness.timerCount(RUNTIME_POLL_DELAY_MS);
    await harness.dispatchWindowEvent("pageshow", { persisted: true });

    // Then
    assert.equal(timersWhileHidden, 0);
    assert.equal(harness.requestCount(RUNTIME_API_PATH), 2);
});

test("Dashboard keeps Runtime transition detection after bfcache restore", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-A", "running", "fusion")],
        [runListItem("RUN-A", "WIN-A")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.dispatchWindowEvent("pagehide");

    // When
    await harness.dispatchWindowEvent("pageshow", { persisted: true });
    await harness.respond(RUNTIME_API_PATH, 200, {
        items: [runtimeReport("RUN-A", "WIN-A", "completed", null)],
    });
    const requestsAfterCompletion = harness.requestCount(detailPath);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-A"),
        storedFusion("RUN-A", "WIN-A", "DEC-A"),
    );

    // Then
    assert.equal(requestsAfterCompletion, 2);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
    assert.equal(harness.timerCount(RUNTIME_POLL_DELAY_MS), 1);
});

test("Dashboard preserves Run Detail when Fusion Engine times out and can retry", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    await harness.respond(
        buildRunDetailApiPath("RUN-A"),
        200,
        storedDetail("RUN-A", "WIN-A", "DEC-A").body,
    );

    // When
    await harness.triggerTimers(10000);
    const timedOut = {
        status: harness.text("selected-run-status"),
        disabled: harness.refreshButton().disabled,
    };
    harness.refreshButton().click();
    const retryPending = harness.refreshButton().disabled;
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-A"),
        storedFusion("RUN-A", "WIN-A", "DEC-A"),
    );

    // Then
    assert.deepEqual(timedOut, {
        status: "Fusion Engine 조회에 실패해 Run Detail 출처의 결과만 표시합니다.",
        disabled: false,
    });
    assert.equal(retryPending, true);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
});

test("Dashboard preserves Fusion Engine when Run Detail response body times out", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    await harness.respond(
        buildRunDetailApiPath("RUN-A"),
        200,
        storedDetail("RUN-A", "WIN-A", "DEC-A").body,
        { deferJson: true },
    );
    await harness.respond(
        buildFusionEngineApiPath("RUN-A"),
        200,
        storedFusion("RUN-A", "WIN-A", "DEC-A").body,
    );

    // When
    await harness.triggerTimers(10000);

    // Then
    assert.equal(
        harness.text("selected-run-status"),
        "Run Detail 조회에 실패해 Fusion Engine 출처의 결과만 표시합니다.",
    );
    assert.equal(harness.refreshButton().disabled, false);
});

test("Dashboard distinguishes analysis timeout from 404 and clears pending state", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);

    // When
    await harness.triggerTimers(10000);
    const afterTimeout = {
        status: harness.text("selected-run-status"),
        disabled: harness.refreshButton().disabled,
    };
    harness.refreshButton().click();
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const afterNotFound = {
        status: harness.text("selected-run-status"),
        disabled: harness.refreshButton().disabled,
    };

    // Then
    assert.deepEqual(afterTimeout, {
        status: "선택한 Run의 상세 결과를 불러오지 못했습니다.",
        disabled: false,
    });
    assert.deepEqual(afterNotFound, {
        status: "선택한 Run에 저장된 상세 결과가 없습니다.",
        disabled: false,
    });
});

test("Dashboard bounds a Decision mismatch retry even when its second read times out", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    const fusionPath = buildFusionEngineApiPath("RUN-A");
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-DETAIL"),
        storedFusion("RUN-A", "WIN-A", "DEC-FUSION"),
    );
    await harness.respond(
        detailPath,
        200,
        storedDetail("RUN-A", "WIN-A", "DEC-DETAIL").body,
    );

    // When
    await harness.triggerTimers(10000);

    // Then
    assert.equal(harness.requestCount(detailPath), 2);
    assert.equal(harness.requestCount(fusionPath), 2);
    assert.equal(
        harness.text("selected-run-status"),
        "Fusion Engine 조회에 실패해 Run Detail 출처의 결과만 표시합니다.",
    );
    assert.equal(harness.refreshButton().disabled, false);
});

test("Dashboard can resume an out-of-query automatic recheck after timeout", async (t) => {
    // Given
    const others = otherRunningReports();
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-A", "running", "fusion"), ...others.slice(0, 4)],
        [runListItem("RUN-A", "WIN-A")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.poll(others);

    // When
    await harness.triggerTimers(10000);
    const afterTimeout = {
        pending: harness.pendingCount(detailPath),
        disabled: harness.refreshButton().disabled,
    };
    await harness.poll(others);
    await harness.poll(others);

    // Then
    assert.deepEqual(afterTimeout, { pending: 0, disabled: false });
    assert.equal(harness.requestCount(detailPath), 3);
    assert.equal(harness.pendingCount(detailPath), 1);
    assert.equal(harness.refreshButton().disabled, true);
});

test("Dashboard Runtime rows select one Run and Entity pair at a time", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [
            runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
            runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
        ],
        [runListItem("RUN-A", "WIN-A")],
    );
    t.after(harness.restore);
    const autoSelection = harness.runtimeRows();
    await harness.respondAnalysis("RUN-A", notFound(), notFound());

    // When
    harness.runtimeButton("RUN-A", "WIN-B").click();
    await harness.flush();
    const scopeBeforeAnalysis = harness.text("selected-run-scope");
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
    );
    const runtimeSelection = {
        runtimeRows: harness.runtimeRows(),
        runRows: harness.runRows(),
        context: harness.text("pipeline-stage-context"),
        stages: harness.stageStates(),
        scope: harness.text("selected-run-scope"),
    };
    harness.runButton("RUN-A").click();
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
    );
    const runListSelection = {
        runtimeRows: harness.runtimeRows(),
        runRows: harness.runRows(),
        context: harness.text("pipeline-stage-context"),
        stages: harness.stageStates(),
        scope: harness.text("selected-run-scope"),
    };

    // Then
    assert.deepEqual(autoSelection.map((row) => row.pressed), ["true", "false"]);
    assert.deepEqual(runtimeSelection.runtimeRows, [
        {
            runId: "RUN-A",
            entityId: "WIN-A",
            entityCell: "WIN-A",
            label: "Run RUN-A, Entity WIN-A",
            pressed: "false",
            selected: false,
        },
        {
            runId: "RUN-A",
            entityId: "WIN-B",
            entityCell: "WIN-B",
            label: "Run RUN-A, Entity WIN-B",
            pressed: "true",
            selected: true,
        },
    ]);
    assert.deepEqual(runtimeSelection.runRows, [
        { runId: "RUN-A", entityId: null, pressed: "false", selected: false },
    ]);
    assert.equal(runtimeSelection.context, `RUN-A · WIN-B · ${RUNNING_LABEL}`);
    assert.deepEqual(
        runtimeSelection.stages,
        ["unknown", "unknown", "unknown", "unknown", "current", "unknown"],
    );
    assert.match(scopeBeforeAnalysis, /WIN-B 결과로 간주하지 않습니다/);
    assert.match(
        runtimeSelection.scope,
        /RunMetadata\.target_host WIN-A 결과이며 WIN-B 결과가 아닙니다/,
    );
    assert.deepEqual(
        runListSelection.runtimeRows.map((row) => [row.pressed, row.selected]),
        [["false", false], ["false", false]],
    );
    assert.deepEqual(runListSelection.runRows, [
        { runId: "RUN-A", entityId: null, pressed: "true", selected: true },
    ]);
    assert.match(runListSelection.context, /Run 목록 선택은 Entity를 지정하지 않아/);
    assert.equal(runListSelection.stages.every((state) => state === "unknown"), true);
    assert.match(runListSelection.scope, /run_id 범위.*RunMetadata\.target_host WIN-A/);
});

test("Dashboard restores focus and status transitions per Runtime Entity", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [
            runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
            runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
        ],
        [runListItem("RUN-A", "WIN-B")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    harness.runtimeButton("RUN-A", "WIN-B").click();
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const focusedButton = harness.runtimeButton("RUN-A", "WIN-B");
    focusedButton.focus();

    // When
    await harness.poll([
        runtimeReport("RUN-A", "WIN-A", "failed", null),
        runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
    ]);
    const restoredFocus = harness.document.activeElement;
    const restoredFocusAttached = harness.document.getElementById(
        "runtime-summary-list",
    ).contains(restoredFocus);
    const afterOtherEntityFailure = {
        status: harness.text("selected-run-status"),
        detailRequests: harness.requestCount(detailPath),
    };
    await harness.poll([
        runtimeReport("RUN-A", "WIN-A", "completed", null),
        runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
    ]);
    const afterOtherEntityCompletion = harness.requestCount(detailPath);
    await harness.poll([
        runtimeReport("RUN-A", "WIN-A", "completed", null),
        runtimeReport("RUN-A", "WIN-B", "completed", null),
    ]);
    const afterSelectedCompletion = harness.requestCount(detailPath);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-B", "DEC-B"),
        storedFusion("RUN-A", "WIN-B", "DEC-B"),
    );
    await harness.poll([
        runtimeReport("RUN-A", "WIN-A", "completed", null),
        runtimeReport("RUN-A", "WIN-B", "completed", null),
    ]);

    // Then
    assert.notStrictEqual(restoredFocus, focusedButton);
    assert.equal(restoredFocus.dataset.runId, "RUN-A");
    assert.equal(restoredFocus.dataset.entityId, "WIN-B");
    assert.equal(restoredFocus.getAttribute("aria-pressed"), "true");
    assert.equal(restoredFocusAttached, true);
    assert.deepEqual(afterOtherEntityFailure, { status: WAITING_STATUS, detailRequests: 2 });
    assert.equal(afterOtherEntityCompletion, 2);
    assert.equal(afterSelectedCompletion, 3);
    assert.equal(harness.requestCount(detailPath), 3);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
    assert.match(harness.text("selected-run-scope"), /RunMetadata\.target_host도 WIN-B/);
    assert.equal(
        harness.text("pipeline-stage-context"),
        `RUN-A · WIN-B · ${COMPLETED_LABEL}`,
    );
});

test("Dashboard keeps the selected Running to Failed notice scoped to its Entity", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [
            runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
            runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
        ],
        [runListItem("RUN-A", "WIN-B")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());

    // When
    await harness.poll([
        runtimeReport("RUN-A", "WIN-B", "failed", null),
        runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
    ]);
    const failedStatus = harness.text("selected-run-status");
    await harness.poll([
        runtimeReport("RUN-A", "WIN-B", "failed", null),
        runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
    ]);

    // Then
    assert.equal(
        failedStatus,
        "마지막 Runtime 보고가 실패했습니다. 상세 결과 자동 재조회는 수행하지 않습니다.",
    );
    assert.equal(harness.text("selected-run-status"), failedStatus);
    assert.equal(harness.requestCount(detailPath), 1);
    assert.deepEqual(
        harness.stageStates(),
        ["unknown", "unknown", "unknown", "unknown", "failed", "unknown"],
    );
});

test("Dashboard rechecks a Running Runtime that leaves the limit=5 query", async (t) => {
    // Given
    const others = otherRunningReports();
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-B", "running", "fusion"), ...others.slice(0, 4)],
        [runListItem("RUN-A", "WIN-B")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const waitingStatus = harness.text("selected-run-status");

    // When
    await harness.poll(others);
    const leftQuery = {
        context: harness.text("pipeline-stage-context"),
        stages: harness.stageStates(),
        status: harness.text("selected-run-status"),
        detailRequests: harness.requestCount(detailPath),
        pendingDetailRequests: harness.pendingCount(detailPath),
        selectedRows: harness.runtimeRows().filter((row) => row.pressed === "true"),
    };
    await harness.poll(others);
    await harness.poll(others);
    const requestsWhileRecheckPending = harness.requestCount(detailPath);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const afterFirstRecheck = harness.text("selected-run-status");
    await harness.poll(others);
    const requestsAfterBackoff = harness.requestCount(detailPath);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-B", "DEC-LATE"),
        storedFusion("RUN-A", "WIN-B", "DEC-LATE"),
    );
    const storedResult = {
        status: harness.text("selected-run-status"),
        scope: harness.text("selected-run-scope"),
        context: harness.text("pipeline-stage-context"),
    };
    for (let poll = 0; poll < 40; poll += 1) {
        await harness.poll(others);
    }

    // Then
    assert.equal(waitingStatus, WAITING_STATUS);
    assert.equal(
        leftQuery.context,
        "RUN-A · WIN-B · 최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)",
    );
    assert.equal(leftQuery.stages.every((state) => state === "unknown"), true);
    assert.equal(leftQuery.status, RECHECK_LOADING_STATUS);
    assert.equal(leftQuery.detailRequests, 2);
    assert.equal(leftQuery.pendingDetailRequests, 1);
    assert.deepEqual(leftQuery.selectedRows, []);
    assert.equal(requestsWhileRecheckPending, 2);
    assert.equal(
        afterFirstRecheck,
        "선택한 Runtime이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
            + "저장 결과를 제한된 간격으로 다시 확인합니다 (1/5회).",
    );
    assert.equal(requestsAfterBackoff, 3);
    assert.equal(storedResult.status, STORED_STATUS);
    assert.match(storedResult.scope, /RunMetadata\.target_host도 WIN-B/);
    assert.equal(storedResult.context, leftQuery.context);
    assert.equal(harness.requestCount(detailPath), 3);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
});

test("Dashboard bounds rechecks and pauses them while the Runtime API fails", async (t) => {
    // Given
    const others = otherRunningReports();
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-B", "running", "fusion"), ...others.slice(0, 4)],
        [runListItem("RUN-A", "WIN-B")],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.poll(others);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.poll(others);

    // When
    await harness.pollFailure();
    const duringFailure = {
        context: harness.text("pipeline-stage-context"),
        status: harness.text("selected-run-status"),
        detailRequests: harness.requestCount(detailPath),
    };
    await harness.poll(others);
    const afterRecovery = harness.requestCount(detailPath);
    for (let poll = 0; poll < 60; poll += 1) {
        if (harness.pendingCount(detailPath) > 0) {
            await harness.respondAnalysis("RUN-A", notFound(), notFound());
        }
        await harness.poll(others);
    }

    // Then
    assert.equal(
        duringFailure.context,
        "RUN-A · WIN-B · Runtime API 조회 실패 · 조회 범위 밖 항목의 현재 상태 확인 불가",
    );
    assert.match(duringFailure.status, /^Runtime API 조회에 실패해/);
    assert.equal(duringFailure.detailRequests, 2);
    assert.equal(afterRecovery, 3);
    assert.equal(harness.requestCount(detailPath), 1 + SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS.length);
    assert.equal(harness.pendingCount(detailPath), 0);
    assert.match(
        harness.text("selected-run-status"),
        /저장 결과 재확인 5회를 마쳤지만 아직 결과가 없습니다/,
    );
    assert.equal(harness.stageStates().every((state) => state === "unknown"), true);
});

test("Dashboard discards a delayed recheck after another Runtime Entity is selected", async (t) => {
    // Given
    const others = otherRunningReports().slice(0, 4);
    const completedOther = runtimeReport("RUN-C", "WIN-C", "completed", null);
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-B", "running", "fusion"), completedOther],
        [runListItem("RUN-A", "WIN-B"), runListItem("RUN-C", "WIN-C")],
    );
    t.after(harness.restore);
    const firstDetailPath = buildRunDetailApiPath("RUN-A");
    const secondDetailPath = buildRunDetailApiPath("RUN-C");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.poll([completedOther, ...others]);
    const pendingRecheck = harness.pendingCount(firstDetailPath);

    // When
    harness.runtimeButton("RUN-C", "WIN-C").click();
    await harness.flush();
    const cancelledRecheck = harness.pendingCount(firstDetailPath);
    const afterDelayedResponse = {
        runId: harness.text("selected-run-id"),
        status: harness.text("selected-run-status"),
        scope: harness.text("selected-run-scope"),
        context: harness.text("pipeline-stage-context"),
    };
    await harness.respondAnalysis(
        "RUN-C",
        storedDetail("RUN-C", "WIN-C", "DEC-C"),
        storedFusion("RUN-C", "WIN-C", "DEC-C"),
    );
    for (let poll = 0; poll < 10; poll += 1) {
        await harness.poll([completedOther, ...others]);
    }

    // Then
    assert.equal(pendingRecheck, 1);
    assert.equal(cancelledRecheck, 0);
    assert.equal(afterDelayedResponse.runId, "RUN-C");
    assert.equal(
        afterDelayedResponse.status,
        "선택한 Run의 저장 분석 결과를 불러오는 중입니다.",
    );
    assert.match(afterDelayedResponse.scope, /Entity WIN-C/);
    assert.doesNotMatch(afterDelayedResponse.scope, /WIN-B/);
    assert.equal(afterDelayedResponse.context, `RUN-C · WIN-C · ${COMPLETED_LABEL}`);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
    assert.match(harness.text("selected-run-scope"), /RunMetadata\.target_host도 WIN-C/);
    assert.deepEqual(
        harness.runtimeRows().filter((row) => row.pressed === "true").map(
            (row) => [row.runId, row.entityId],
        ),
        [["RUN-C", "WIN-C"]],
    );
    assert.equal(harness.requestCount(firstDetailPath), 2);
    assert.equal(harness.requestCount(secondDetailPath), 1);
});

function serverError() {
    return { status: 500, body: { detail: "Read failed" } };
}

test("Dashboard manual refresh recovers a Run missing from both lists after rechecks", async (t) => {
    // Given
    const others = otherRunningReports();
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-B", "running", "fusion"), ...others.slice(0, 4)],
        [],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.poll(others);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    harness.refreshButton().click();
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const statusAfterEarlyManualRefresh = harness.text("selected-run-status");
    for (let poll = 0; poll < 40; poll += 1) {
        await harness.poll(others);
        if (harness.pendingCount(detailPath) > 0) {
            await harness.respondAnalysis("RUN-A", notFound(), notFound());
        }
    }
    const exhausted = {
        status: harness.text("selected-run-status"),
        detailRequests: harness.requestCount(detailPath),
        listedRunIds: [...harness.runtimeRows(), ...harness.runRows()].map((row) => row.runId),
        hidden: harness.refreshButton().hidden,
        disabled: harness.refreshButton().disabled,
    };

    // When
    harness.refreshButton().click();
    const whilePending = {
        disabled: harness.refreshButton().disabled,
        status: harness.text("selected-run-status"),
    };
    harness.refreshButton().click();
    await harness.flush();
    const requestsAfterDuplicateClick = harness.requestCount(detailPath);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-B", "DEC-MANUAL"),
        storedFusion("RUN-A", "WIN-B", "DEC-MANUAL"),
    );
    const refreshed = {
        runId: harness.text("selected-run-id"),
        status: harness.text("selected-run-status"),
        scope: harness.text("selected-run-scope"),
        context: harness.text("pipeline-stage-context"),
        disabled: harness.refreshButton().disabled,
    };
    for (let poll = 0; poll < 5; poll += 1) {
        await harness.poll(others);
    }

    // Then
    assert.equal(
        statusAfterEarlyManualRefresh,
        "선택한 Runtime이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
            + "저장 결과를 제한된 간격으로 다시 확인합니다 (1/5회).",
    );
    assert.match(exhausted.status, /저장 결과 재확인 5회를 마쳤지만 아직 결과가 없습니다/);
    assert.match(exhausted.status, /결과 다시 조회 버튼으로/);
    assert.equal(
        exhausted.detailRequests,
        1 + SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS.length + 1,
    );
    assert.equal(exhausted.listedRunIds.includes("RUN-A"), false);
    assert.deepEqual([exhausted.hidden, exhausted.disabled], [false, false]);
    assert.deepEqual(whilePending, {
        disabled: true,
        status: "선택한 Run의 저장 분석 결과를 다시 조회하는 중입니다.",
    });
    assert.equal(requestsAfterDuplicateClick, exhausted.detailRequests + 1);
    assert.equal(refreshed.runId, "RUN-A");
    assert.equal(refreshed.status, STORED_STATUS);
    assert.match(refreshed.scope, /Entity WIN-B\. 저장 분석 대상 RunMetadata\.target_host도 WIN-B/);
    assert.equal(
        refreshed.context,
        "RUN-A · WIN-B · 최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)",
    );
    assert.equal(refreshed.disabled, false);
    assert.equal(harness.requestCount(detailPath), requestsAfterDuplicateClick);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
});

test("Dashboard manual refresh retries after failure and keeps Decision checks", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const runtimeRowCount = harness.runtimeRows().length;

    // When
    harness.refreshButton().click();
    await harness.respondAnalysis("RUN-A", serverError(), serverError());
    const failed = {
        status: harness.text("selected-run-status"),
        disabled: harness.refreshButton().disabled,
    };
    harness.refreshButton().click();
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-1"),
        storedFusion("RUN-A", "WIN-A", "DEC-2"),
    );
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-1"),
        storedFusion("RUN-A", "WIN-A", "DEC-2"),
    );
    const mismatch = {
        status: harness.text("selected-run-status"),
        chartStatus: harness.text("selected-run-chart-status"),
    };
    harness.refreshButton().click();
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-3"),
        storedFusion("RUN-A", "WIN-A", "DEC-3"),
    );

    // Then
    assert.equal(runtimeRowCount, 0);
    assert.deepEqual(failed, {
        status: "선택한 Run의 상세 결과를 불러오지 못했습니다.",
        disabled: false,
    });
    assert.deepEqual(mismatch, {
        status: "Run Detail과 Fusion Engine의 Decision 버전이 달라 결과를 결합하지 않았습니다.",
        chartStatus: "조회 시점이 일치하지 않아 Fusion Trace를 표시하지 않습니다.",
    });
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
    assert.match(
        harness.text("selected-run-scope"),
        /Run 목록 선택: run_id 범위입니다\. 저장 분석 대상은 RunMetadata\.target_host WIN-A/,
    );
    assert.match(harness.text("pipeline-stage-context"), /Run 목록 선택은 Entity를 지정하지 않아/);
    assert.equal(harness.requestCount(detailPath), 5);
    assert.equal(harness.pendingCount(detailPath), 0);
});

test("Dashboard discards a late manual refresh after another Entity is selected", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [
            runtimeReport("RUN-A", "WIN-B", "running", "hybrid"),
            runtimeReport("RUN-A", "WIN-A", "running", "fusion"),
        ],
        [],
    );
    t.after(harness.restore);
    const detailPath = buildRunDetailApiPath("RUN-A");
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    harness.refreshButton().click();
    const manualPending = harness.pendingCount(detailPath);

    // When
    harness.runtimeButton("RUN-A", "WIN-A").click();
    await harness.flush();
    const switching = {
        disabled: harness.refreshButton().disabled,
        pending: harness.pendingCount(detailPath),
    };
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
        { newest: true },
    );
    const current = {
        status: harness.text("selected-run-status"),
        scope: harness.text("selected-run-scope"),
        context: harness.text("pipeline-stage-context"),
    };
    // Then
    assert.equal(manualPending, 1);
    assert.deepEqual(switching, { disabled: true, pending: 1 });
    assert.equal(current.status, WAITING_STATUS);
    assert.match(current.scope, /Entity WIN-A\. 저장 분석 대상 RunMetadata\.target_host도 WIN-A/);
    assert.equal(current.context, `RUN-A · WIN-A · ${RUNNING_LABEL}`);
    assert.deepEqual(
        {
            status: harness.text("selected-run-status"),
            scope: harness.text("selected-run-scope"),
            context: harness.text("pipeline-stage-context"),
        },
        current,
    );
    assert.deepEqual(
        harness.runtimeRows().filter((row) => row.pressed === "true").map(
            (row) => [row.runId, row.entityId],
        ),
        [["RUN-A", "WIN-A"]],
    );
    assert.equal(harness.refreshButton().disabled, false);
    assert.equal(harness.requestCount(detailPath), 3);
    assert.equal(harness.pendingCount(detailPath), 0);
});
