// Dashboard UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    buildPipelineStagePresentation,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
    getOverviewQueryMessage,
    getRunTypeLabel,
    getSelectedAnalysisSource,
    getSelectedAnalysisState,
    getStoppingTraceAvailability,
    resolveInitialRunSelection,
    resolveOverviewQueryState,
    resolveRunSelectionFocus,
    resolveRunListQueryState,
    resolveRuntimeSummaryQueryState,
    shouldApplySelectedRunResponse,
    shouldRefreshSelectedRunAnalysis,
    shouldUpdateSelectedRunFailureState,
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
        { run_id: "RUN-COMPLETED-NEWEST", status: "completed", is_stale: false },
        { run_id: "RUN-RUNNING-NEWEST", status: "running", is_stale: false },
        { run_id: "RUN-RUNNING-OLDER", status: "running", is_stale: false },
    ];

    // When
    const overviewFirst = resolveInitialRunSelection(null, false, false, [], []);
    const runsFirst = resolveInitialRunSelection(null, false, false, [], runs);
    const runtimeFirst = resolveInitialRunSelection(null, true, true, runtimes, []);
    const runsThenRuntime = resolveInitialRunSelection(null, true, true, runtimes, runs);
    const completedOnly = resolveInitialRunSelection(
        null,
        true,
        true,
        runtimes.filter((runtime) => runtime.status === "completed"),
        runs,
    );
    const runFallback = resolveInitialRunSelection(null, true, true, [], runs);

    // Then
    assert.equal(overviewFirst, null);
    assert.equal(runsFirst, null);
    assert.equal(runtimeFirst, "RUN-RUNNING-NEWEST");
    assert.equal(runsThenRuntime, "RUN-RUNNING-NEWEST");
    assert.equal(completedOnly, "RUN-COMPLETED-NEWEST");
    assert.equal(runFallback, "RUN-LIST-NEWEST");
});

test("Automatic selection never replaces an existing user selection", () => {
    // Given
    const selectedRunId = "RUN-USER-SELECTED";
    const runtimes = [
        { run_id: "RUN-NEW-RUNTIME", status: "running", is_stale: false },
    ];
    const runs = [{ run_id: "RUN-NEW-LIST", status: "completed" }];

    // When
    const selectionAfterPolling = resolveInitialRunSelection(
        selectedRunId,
        true,
        true,
        runtimes,
        runs,
    );

    // Then
    assert.equal(selectionAfterPolling, selectedRunId);
});

test("Initial Run selection deprioritizes stale Running Runtime", () => {
    // Given
    const currentRunning = {
        run_id: "RUN-CURRENT",
        status: "running",
        is_stale: false,
    };
    const completed = {
        run_id: "RUN-COMPLETED",
        status: "completed",
        is_stale: false,
    };
    const staleRunning = {
        run_id: "RUN-STALE",
        status: "running",
        is_stale: true,
    };
    const runs = [{ run_id: "RUN-STORED" }];

    // When
    const currentBeforeCompleted = resolveInitialRunSelection(
        null,
        true,
        true,
        [completed, currentRunning, staleRunning],
        runs,
    );
    const completedBeforeStale = resolveInitialRunSelection(
        null,
        true,
        true,
        [staleRunning, completed],
        runs,
    );
    const staleOnly = resolveInitialRunSelection(
        null,
        true,
        true,
        [staleRunning],
        runs,
    );
    const unavailableTelemetry = resolveInitialRunSelection(
        null,
        true,
        false,
        [currentRunning],
        runs,
    );

    // Then
    assert.equal(currentBeforeCompleted, "RUN-CURRENT");
    assert.equal(completedBeforeStale, "RUN-COMPLETED");
    assert.equal(staleOnly, "RUN-STALE");
    assert.equal(unavailableTelemetry, "RUN-STORED");
});

test("Run selection focus is restored only within its original table", () => {
    // Given
    const runtimeItems = [{ run_id: "RUN-RUNTIME", status: "running" }];
    const updatedRuntimeItems = [{ run_id: "RUN-RUNTIME", status: "completed" }];
    const runItems = [{ run_id: "RUN-STORED" }];

    // When
    const afterKeyboardSelection = resolveRunSelectionFocus(
        "RUN-STORED",
        "runs",
        runtimeItems,
        runItems,
    );
    const afterRuntimePolling = resolveRunSelectionFocus(
        "RUN-RUNTIME",
        "runtime",
        updatedRuntimeItems,
        runItems,
    );
    const outsideTable = resolveRunSelectionFocus(
        null,
        null,
        updatedRuntimeItems,
        runItems,
    );

    // Then
    assert.deepEqual(afterKeyboardSelection, { runId: "RUN-STORED", table: "runs" });
    assert.deepEqual(afterRuntimePolling, { runId: "RUN-RUNTIME", table: "runtime" });
    assert.equal(outsideTable, null);
});

test("Selected analysis handles completed and failed terminal transitions once", () => {
    // Given
    const selectedRunId = "RUN-SELECTED";
    const running = [{ run_id: selectedRunId, status: "running" }];
    const completed = [{ run_id: selectedRunId, status: "completed" }];
    const failed = [{ run_id: selectedRunId, status: "failed" }];
    const otherCompleted = [{ run_id: "RUN-OTHER", status: "completed" }];

    // When
    const transition = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        running,
        completed,
    );
    const repeatedCompletedPoll = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        completed,
        completed,
    );
    const differentSelection = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        running,
        otherCompleted,
    );
    const failedDoesNotReload = shouldRefreshSelectedRunAnalysis(
        selectedRunId,
        running,
        failed,
    );
    const failedTransition = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        running,
        failed,
    );
    const repeatedFailedPoll = shouldUpdateSelectedRunFailureState(
        selectedRunId,
        failed,
        failed,
    );
    const completedDoesNotUseFailureState = shouldUpdateSelectedRunFailureState(
        selectedRunId,
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
    assert.match(script, /runtimePollTimeoutId = setTimeout\(/);
    assert.match(script, /\(\) => void pollRuntimeSummary\(\)/);
    assert.match(script, /RUNTIME_POLL_INTERVAL_MS/);
    assert.match(script, /getStageLabel\(runtime\.current_stage\)/);
    assert.match(script, /getLatestRuntimeReport\(state\.items\)/);
    assert.match(script, /formatRunTimestamp\(runtime\.updated_at\)/);
    assert.match(script, /presentation\.telemetryLabel/);
    assert.equal(script.match(/void pollRuntimeSummary\(\)/g)?.length, 2);
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
    assert.match(script, /async function selectRun\(runId\)/);
    assert.match(script, /buildRunDetailApiPath\(runId\)/);
    assert.match(script, /buildFusionEngineApiPath\(runId\)/);
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
    assert.match(script, /resolveRunSelectionFocus\(/);
    assert.match(script, /replacement\?\.focus\(\{ preventScroll: true \}\)/);
    assert.match(script, /button\.setAttribute\("aria-pressed", String\(runId === selectedRunId\)\)/);
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
