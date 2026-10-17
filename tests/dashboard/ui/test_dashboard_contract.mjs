// Dashboard UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    PIPELINE_STAGE_ORDER,
    RUN_SEARCH_FIELDS,
    SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS,
    buildPipelineStagePresentation,
    canRefreshSelectedAnalysis,
    createSelectedRuntimeTracking,
    filterRunsBySearch,
    findSelectedRuntime,
    formatRunTimestamp,
    getDecisionVersionConsistency,
    getLatestRuntimeReport,
    getOverviewQueryMessage,
    getRunListVisibilityMessage,
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
    resolveRunListVisibility,
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
    buildEventTimelineApiPath,
} from "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs";
import {
    getRuntimeStatePresentation,
} from "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs";
import {
    buildRunDetailApiPath,
    buildRunDetailViewPath,
} from "../../../src/incident_awareness/dashboard/ui/assets/run-detail-contract.mjs";
import {
    buildStageTimingModel,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-stage-timing-contract.mjs";
import { timingPayload } from "./stage-timing-fixture.mjs";
import { evidenceItem, evidencePayload } from "./evidence-fixture.mjs";

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

test("Run row focus is not moved to another Run when the focused Run left the query", () => {
    // Given
    const runItems = [{ run_id: "RUN-REMAINING" }];
    const runtimeItems = [{ run_id: "RUN-REMAINING", entity_id: "WIN-A", status: "running" }];

    // When
    const missingRun = resolveRunSelectionFocus("RUN-GONE", null, "runs", runtimeItems, runItems);
    const missingEntity = resolveRunSelectionFocus(
        "RUN-REMAINING",
        "WIN-GONE",
        "runtime",
        runtimeItems,
        runItems,
    );

    // Then
    assert.equal(missingRun, null);
    assert.equal(missingEntity, null);
});

function searchRun(runId, targetHost, scenarioId) {
    return {
        run_id: runId,
        scenario_id: scenarioId,
        run_type: "attack",
        target_host: targetHost,
        start_time: "2026-10-08T00:00:00Z",
        end_time: null,
    };
}

const SEARCH_RUNS = [
    searchRun("RUN-20261008-920", "R1-TGTA", "R1"),
    searchRun("RUN-20261008-919", "WIN-DC-01", "S0"),
    searchRun("RUN-20261005-913", "R1-TGTB", "R2"),
    searchRun("RUN-20261005-908", "WIN-DC-02", "S0-BASELINE"),
];

const searchIds = (runs) => runs.map((run) => run.run_id);

test("Run search matches an exact Run ID and a partial Run ID in server order", () => {
    // When
    const exact = filterRunsBySearch(SEARCH_RUNS, "RUN-20261008-919");
    const partial = filterRunsBySearch(SEARCH_RUNS, "20261005");
    const digits = filterRunsBySearch(SEARCH_RUNS, "9");

    // Then
    assert.deepEqual(RUN_SEARCH_FIELDS, ["run_id", "target_host", "scenario_id"]);
    assert.deepEqual(searchIds(exact), ["RUN-20261008-919"]);
    assert.deepEqual(searchIds(partial), ["RUN-20261005-913", "RUN-20261005-908"]);
    assert.deepEqual(
        searchIds(digits),
        ["RUN-20261008-920", "RUN-20261008-919", "RUN-20261005-913", "RUN-20261005-908"],
    );
});

test("Run search matches target host and Scenario ID substrings", () => {
    // When
    const host = filterRunsBySearch(SEARCH_RUNS, "TGTB");
    const hostFamily = filterRunsBySearch(SEARCH_RUNS, "WIN-DC");
    const scenario = filterRunsBySearch(SEARCH_RUNS, "S0");
    const scenarioPartial = filterRunsBySearch(SEARCH_RUNS, "BASELINE");

    // Then
    assert.deepEqual(searchIds(host), ["RUN-20261005-913"]);
    assert.deepEqual(searchIds(hostFamily), ["RUN-20261008-919", "RUN-20261005-908"]);
    assert.deepEqual(searchIds(scenario), ["RUN-20261008-919", "RUN-20261005-908"]);
    assert.deepEqual(searchIds(scenarioPartial), ["RUN-20261005-908"]);
});

test("Run search ignores letter case and surrounding whitespace", () => {
    // When
    const lowerRunId = filterRunsBySearch(SEARCH_RUNS, "run-20261008-919");
    const mixedHost = filterRunsBySearch(SEARCH_RUNS, "r1-TgTa");
    const padded = filterRunsBySearch(SEARCH_RUNS, "  \t913 \n");
    const paddedScenario = filterRunsBySearch(SEARCH_RUNS, "  s0-baseline  ");

    // Then
    assert.deepEqual(searchIds(lowerRunId), ["RUN-20261008-919"]);
    assert.deepEqual(searchIds(mixedHost), ["RUN-20261008-920"]);
    assert.deepEqual(searchIds(padded), ["RUN-20261005-913"]);
    assert.deepEqual(searchIds(paddedScenario), ["RUN-20261005-908"]);
});

test("Run search returns no rows for a miss and every row for an empty query", () => {
    // When
    const miss = filterRunsBySearch(SEARCH_RUNS, "RUN-20991231");
    const empty = filterRunsBySearch(SEARCH_RUNS, "");
    const blank = filterRunsBySearch(SEARCH_RUNS, "   ");
    const middleSpace = filterRunsBySearch(SEARCH_RUNS, "RUN 2026");

    // Then
    assert.deepEqual(miss, []);
    assert.deepEqual(searchIds(empty), searchIds(SEARCH_RUNS));
    assert.deepEqual(searchIds(blank), searchIds(SEARCH_RUNS));
    assert.deepEqual(middleSpace, []);
});

test("Run search treats pattern characters literally and skips missing fields", () => {
    // Given
    const runs = [
        searchRun("RUN-A.B", "HOST-1", "S0"),
        searchRun("RUN-AXB", "HOST-2", "S0"),
        { run_id: "RUN-NO-HOST", target_host: null, scenario_id: null },
    ];

    // When / Then
    assert.deepEqual(searchIds(filterRunsBySearch(runs, "A.B")), ["RUN-A.B"]);
    assert.deepEqual(filterRunsBySearch(runs, ".*"), []);
    assert.deepEqual(filterRunsBySearch(runs, "[A]"), []);
    assert.deepEqual(searchIds(filterRunsBySearch(runs, "no-host")), ["RUN-NO-HOST"]);
    assert.deepEqual(filterRunsBySearch(runs, "null"), []);
    assert.throws(() => filterRunsBySearch(runs, null), TypeError);
    assert.throws(() => filterRunsBySearch(null, "RUN"), TypeError);
});

test("Run search covers all twenty fetched Runs without changing the fetched list", () => {
    // Given
    const fetched = Object.freeze(Array.from({ length: 20 }, (_, index) => Object.freeze(
        searchRun(`RUN-${String(index).padStart(2, "0")}`, `HOST-${index}`, "S0"),
    )));
    const snapshot = JSON.stringify(fetched);

    // When
    const last = filterRunsBySearch(fetched, "run-19");
    const hiddenByDefault = filterRunsBySearch(fetched, "HOST-1");
    const all = filterRunsBySearch(fetched, "");

    // Then
    assert.deepEqual(searchIds(last), ["RUN-19"]);
    assert.deepEqual(
        searchIds(hiddenByDefault),
        ["RUN-01", "RUN-10", "RUN-11", "RUN-12", "RUN-13", "RUN-14", "RUN-15", "RUN-16", "RUN-17", "RUN-18", "RUN-19"],
    );
    assert.equal(all.length, 20);
    assert.notStrictEqual(all, fetched);
    assert.strictEqual(last[0], fetched[19]);
    assert.equal(JSON.stringify(fetched), snapshot);
});

test("Run list visibility shows every match while searching and keeps the expansion choice", () => {
    // Given
    const runs = Array.from({ length: 10 }, (_, index) => searchRun(`RUN-${index}`, "R1-TGTA", "R1"));

    // When
    const collapsed = resolveRunListVisibility(runs, "", false, 5, "RUN-7");
    const expanded = resolveRunListVisibility(runs, "", true, 5, "RUN-7");
    const searching = resolveRunListVisibility(runs, " run-7 ", false, 5, "RUN-2");
    const searchingWhileExpanded = resolveRunListVisibility(runs, "tgta", true, 5, "RUN-2");
    const noMatch = resolveRunListVisibility(runs, "zz", false, 5, "RUN-2");
    const empty = resolveRunListVisibility([], "RUN", false, 5, null);

    // Then
    assert.deepEqual(collapsed.visible, [true, true, true, true, true, false, false, false, false, false]);
    assert.deepEqual(
        { searchActive: collapsed.searchActive, toggleHidden: collapsed.toggleHidden, selectedHidden: collapsed.selectedHidden },
        { searchActive: false, toggleHidden: false, selectedHidden: true },
    );
    assert.equal(expanded.visible.every(Boolean), true);
    assert.equal(expanded.selectedHidden, false);
    assert.deepEqual(searching.visible, runs.map((run) => run.run_id === "RUN-7"));
    assert.deepEqual(
        { searchActive: searching.searchActive, toggleHidden: searching.toggleHidden, visibleCount: searching.visibleCount, selectedHidden: searching.selectedHidden },
        { searchActive: true, toggleHidden: true, visibleCount: 1, selectedHidden: true },
    );
    assert.equal(searchingWhileExpanded.visibleCount, 10);
    assert.equal(noMatch.visibleCount, 0);
    assert.deepEqual({ total: empty.totalCount, visible: empty.visibleCount }, { total: 0, visible: 0 });
});

test("Run list visibility messages separate matches, misses, and the unchanged default", () => {
    // Given
    const runs = Array.from({ length: 10 }, (_, index) => searchRun(`RUN-${index}`, "R1-TGTA", "R1"));
    const message = (query, expanded, selectedRunId) => getRunListVisibilityMessage(
        resolveRunListVisibility(runs, query, expanded, 5, selectedRunId),
        selectedRunId,
    );

    // When / Then
    assert.equal(message("", false, "RUN-0"), "10개 중 5개 표시");
    assert.equal(message("", false, "RUN-7"), "10개 중 5개 표시 · 선택 유지: RUN-7 (접힌 목록)");
    assert.equal(message("", true, "RUN-7"), "10개 중 10개 표시");
    assert.equal(message("RUN-7", false, "RUN-7"), "검색 결과 1건 / 조회된 Run 10건");
    assert.equal(
        message("RUN-7", false, "RUN-2"),
        "검색 결과 1건 / 조회된 Run 10건 · 선택 유지: RUN-2 (검색 결과 밖)",
    );
    assert.equal(
        message("RUN-99", false, "RUN-2"),
        "현재 조회된 Run에서 일치하는 결과가 없습니다. · 선택 유지: RUN-2 (검색 결과 밖)",
    );
    assert.equal(message("RUN-99", false, null), "현재 조회된 Run에서 일치하는 결과가 없습니다.");
    assert.equal(
        getRunListVisibilityMessage(resolveRunListVisibility([], "RUN", false, 5, null), null),
        "",
    );
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
    assert.match(script, /window\.addEventListener\("pagehide", \(\) => \{/);
    assert.match(script, /stopRuntimePolling\(\);/);
    assert.match(script, /telemetryController\.stop\(\);/);
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
    assert.match(script, /createDashboardReplayChart\(/);
    assert.match(script, /decision\?\.t_e \?\? null/);
    assert.match(script, /저장된 Stopping Trace가 없습니다/);
    assert.match(script, /fusionResult\?\.fusion_status === "not_evaluated"/);
    assert.match(script, /Fusion이 평가되지 않아 저장된 Trace point가 없습니다/);
    assert.match(script, /Stopping Trace가 비어 있습니다/);
    assert.match(script, /fusionState\.queryState !== "success"/);
    assert.match(script, /Runtime Config Snapshot이 없어 threshold 기준선을 표시할 수 없습니다/);
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
    assert.match(script, /createRunTimestamp\(run\.start_time\)/);
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
    assert.match(html, /관측 시작 시각 최근순 최대 20건/);
    assert.match(html, /최근 Runtime 조회 결과는\s+전체 실행 통계가 아닙니다/);
    assert.match(html, /조회 완료 후 약 5초 간격으로 Runtime 상태 갱신/);
    assert.match(html, /조회 범위 내 최신 Runtime 상태/);
    assert.match(html, /조회 범위 내 최신 Runtime 보고/);
    assert.match(html, /<details class="dashboard-time-note">/);
    assert.match(html, /<summary>표시 기준 및 상태 안내<\/summary>/);
    assert.match(html, /class="dashboard-monitor-grid"/);
    assert.match(html, /id="selected-run-summary"/);
    assert.match(html, /id="selected-run-settings"/);
    assert.match(html, /class="dashboard-stage-scroll"/);
    assert.match(stylesheet, /\.app-page\.dashboard-page\s*{[^}]*width: 100%;/s);
    assert.match(stylesheet, /\.app-page\.dashboard-page\s*{[^}]*max-width: 116rem;/s);
    assert.match(stylesheet, /grid-template-columns: repeat\(6, minmax\(0, 1fr\)\)/);
    assert.match(
        stylesheet,
        /\.dashboard-monitor-grid\s*{[^}]*grid-template-columns: minmax\(0, 906fr\) minmax\(0, 548fr\);/s,
    );
    assert.match(stylesheet, /\.dashboard-event-types li\s*{[^}]*grid-template-columns: minmax\(0, 1fr\) auto;/s);
    assert.match(stylesheet, /\.dashboard-event-types li strong\s*{[^}]*text-align: center;/s);
    assert.match(
        stylesheet,
        /\.dashboard-analysis-summary\s*{[^}]*grid-template-columns: repeat\(4,/s,
    );
    assert.match(stylesheet, /#selected-run-chart:empty\s*{[^}]*display: none;/s);
    assert.doesNotMatch(stylesheet, /minmax\(36rem, 0\.9fr\)/);
    assert.ok(
        html.indexOf('id="runtime-summary-heading"')
        < html.indexOf('id="selected-run-heading"'),
    );
    assert.ok(
        html.indexOf('id="selected-run-heading"')
        < html.indexOf("Fusion Score Trajectory"),
    );
    assert.ok(html.indexOf('id="runs-heading"') < html.indexOf('id="selected-run-heading"'));
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
            toggle: (name, force) => {
                if (force) {
                    this.classNames.add(name);
                } else {
                    this.classNames.delete(name);
                }
                return force;
            },
        };
        this.dataset = {};
        this.attributes = new Map();
        this.listeners = new Map();
        this.hidden = false;
        this.href = "";
        this.type = "";
        this.value = "";
        this.ownText = "";
        this.textContentWrites = 0;
    }

    get children() {
        return this.childNodes;
    }

    get textContent() {
        return this.ownText + this.childNodes.map((child) => child.textContent).join("");
    }

    set textContent(value) {
        this.textContentWrites += 1;
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

    keyDown(key) {
        const event = {
            type: "keydown",
            key,
            target: this,
            defaultPrevented: false,
            preventDefault() {
                this.defaultPrevented = true;
            },
        };
        for (const listener of this.listeners.get("keydown") ?? []) {
            listener(event);
        }
        return event.defaultPrevented;
    }

    focus(options = {}) {
        this.focusOptions = { ...options };
        this.ownerDocument.activeElement = this;
        for (const listener of this.listeners.get("focus") ?? []) {
            listener({ type: "focus", target: this });
        }
    }

    scrollIntoView(options) {
        this.scrollIntoViewCalls ??= [];
        this.scrollIntoViewCalls.push({ ...options });
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

// extraElementIds adds DOM owned by imported modules (e.g. the Stage Timing card), which the
// dashboard.js id scan below cannot see; without them those modules stay inert.
async function startDashboardHarness({ extraElementIds = [] } = {}) {
    const source = await readFile(new URL("dashboard.js", DASHBOARD_ASSETS_URL), "utf8");
    const document = {
        activeElement: null,
        elements: new Map(),
        createElement: () => new FakeElement(document),
        createElementNS: () => new FakeElement(document),
        getElementById: (id) => document.elements.get(id) ?? null,
    };
    for (const [, id] of source.matchAll(/document\.getElementById\("([^"]+)"\)/g)) {
        document.elements.set(id, new FakeElement(document));
    }
    for (const id of extraElementIds) {
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

    // Keep the existing Run/Runtime harness independent of Telemetry DOM and timers.
    // The actual Telemetry controller is covered by its dedicated tests.
    const isolatedSource = source.replace(
        'import { createDashboardTelemetryController } from "./dashboard-telemetry-controller.mjs";',
        "const createDashboardTelemetryController = () => ({ start() {}, stop() {} });",
    );
    assert.notEqual(isolatedSource, source, "Expected Dashboard Telemetry import");
    const moduleSource = isolatedSource.replaceAll(
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
        requestsFor: (url) => requests.filter((request) => request.url === url),
        totalRequests: () => requests.length,
        // Types into the header Run search the way a browser reports it: value, then "input".
        typeSearch(value) {
            const input = document.getElementById("dashboard-run-search");
            input.value = value;
            for (const listener of input.listeners.get("input") ?? []) {
                listener({ type: "input", target: input });
            }
        },
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
        analysisFields: (id) => document.getElementById(id).childNodes.map(
            (field) => ({
                label: field.childNodes[0].textContent,
                value: field.childNodes[1].textContent,
                primary: field.classList.contains("dashboard-analysis-field--primary"),
                setting: field.classList.contains("dashboard-analysis-field--setting"),
            }),
        ),
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

async function startDashboardWithRuntime(runtimeItems, runs, options = {}) {
    const harness = await startDashboardHarness(options);
    await harness.respond("/overview", 200, { total_runs: runs.length, recent_runs: runs });
    await harness.respond("/runs?limit=20", 200, { runs });
    await harness.respond(RUNTIME_API_PATH, 200, { items: runtimeItems });
    return harness;
}

// The real dashboard.js wired to the real Evidence tab controller.
const EVIDENCE_ELEMENT_IDS = ["status", "archive", "region", "list"].map((key) => `evidence-${key}`);
const evidencePath = (runId) => `/runs/${encodeURIComponent(runId)}/evidences?limit=100`;

test("Evidence tab reads the selected Run lazily, once per Run, and never on Runtime polls", async (t) => {
    // Given
    const runtime = [
        runtimeReport("RUN-A", "WIN-A", "completed", null),
        runtimeReport("RUN-A", "WIN-C", "completed", null),
    ];
    const harness = await startDashboardWithRuntime(
        runtime,
        [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")],
        { extraElementIds: EVIDENCE_ELEMENT_IDS },
    );
    t.after(harness.restore);
    const list = harness.document.getElementById("evidence-list");
    const status = harness.document.getElementById("evidence-status");
    const tab = harness.document.getElementById("dashboard-tab-evidence");
    const beforeTab = harness.requestCount(evidencePath("RUN-A"));

    // When: the tab opens for the default Run.
    tab.focus();
    tab.click();
    await harness.flush();
    await harness.respond(evidencePath("RUN-A"), 200, evidencePayload({
        runId: "RUN-A", items: [evidenceItem({ entity_id: "WIN-A" })],
    }));
    const shown = { rows: list.children.length, status: status.textContent, focused: harness.document.activeElement === tab };
    // When: Runtime polls, another Entity of the same Run, and a tab round trip.
    for (let index = 0; index < 3; index += 1) await harness.poll(runtime);
    harness.runtimeButton("RUN-A", "WIN-C").click();
    await harness.flush();
    harness.document.getElementById("dashboard-tab-replay").click();
    tab.click();
    await harness.flush();
    const readsForRunA = harness.requestCount(evidencePath("RUN-A"));
    // When: another Run is selected while the tab is open.
    harness.runButton("RUN-B").click();
    await harness.flush();
    const clearedOnRunChange = list.children.length;
    await harness.respond(evidencePath("RUN-B"), 200, evidencePayload({ runId: "RUN-B", availability: "no_archive" }));
    await harness.respondAnalysis("RUN-B", notFound(), notFound());
    harness.document.getElementById("selected-run-refresh").click();
    await harness.flush();

    // Then
    assert.equal(beforeTab, 0);
    assert.equal(shown.rows, 1);
    assert.match(shown.status, /^Evidence 조회 완료 · 검증된 1건/);
    assert.equal(shown.focused, true);
    assert.equal(readsForRunA, 1);
    assert.equal(clearedOnRunChange, 0);
    assert.equal(status.textContent, "선택한 Run의 Evidence 아카이브를 조회하는 중입니다.");
    assert.equal(harness.requestCount(evidencePath("RUN-B")), 2);
    assert.equal(harness.timerCount(RUNTIME_POLL_DELAY_MS), 1);
});

// The real dashboard.js wired to the real Stage Timing controller through Runtime polling.
const STAGE_TIMING_ELEMENT_IDS = ["state", "caption", "scope", "records", "refresh", "detail"]
    .map((key) => `insight-bottleneck-${key}`);
const stageTimingPath = (executionId) => (
    `/operations/stage-timings?execution_id=${encodeURIComponent(executionId)}`
);
const stageTarget = (runId, entityId) => ({
    runId, entityId, executionId: `${runId}-${entityId}`, status: "completed", currentStage: null,
});

test("Runtime polling re-reads Stage Timing only on the selected Execution's reported transitions", async (t) => {
    // Given: the default selection is the running Runtime Execution.
    const running = runtimeReport("RUN-A", "WIN-A", "running", "normalization");
    const harness = await startDashboardWithRuntime([running], [runListItem("RUN-A", "WIN-A")], {
        extraElementIds: STAGE_TIMING_ELEMENT_IDS,
    });
    t.after(harness.restore);
    const target = stageTarget("RUN-A", "WIN-A");
    const path = stageTimingPath(target.executionId);
    const state = harness.document.getElementById("insight-bottleneck-state");
    const payload = timingPayload({ scope: target, selectedStages: ["artifact_validation", "normalization"], active: "fusion" });
    await harness.respond(path, 200, payload);
    const firstLabel = state.textContent;
    const writes = state.textContentWrites;

    // When: three heartbeats change only updated_at.
    for (const second of ["05", "10", "15"]) {
        await harness.poll([{ ...running, updated_at: `2026-10-09T00:01:${second}Z` }]);
    }
    const afterHeartbeats = { requests: harness.requestCount(path), writes: state.textContentWrites - writes };
    // When: the reported stage advances, then the Execution completes and stays completed.
    await harness.poll([{ ...running, current_stage: "fusion" }]);
    const afterStageChange = harness.requestCount(path);
    await harness.respond(path, 200, payload);
    const completed = runtimeReport("RUN-A", "WIN-A", "completed", null);
    await harness.poll([completed]);
    await harness.respond(path, 200, timingPayload({ scope: target }));
    await harness.poll([completed]);
    await harness.poll([completed]);

    // Then
    assert.equal(firstLabel, buildStageTimingModel(payload, { ...target, status: "running", currentStage: "normalization" }).label);
    assert.deepEqual(afterHeartbeats, { requests: 1, writes: 0 });
    assert.equal(afterStageChange, 2);
    assert.equal(harness.requestCount(path), 3);
    assert.equal(state.textContent, buildStageTimingModel(timingPayload({ scope: target }), target).label);
    assert.match(harness.document.getElementById("insight-bottleneck-caption").textContent, /부분 비교 · Execution RUN-A-WIN-A/);
    assert.equal(harness.timerCount(RUNTIME_POLL_DELAY_MS), 1);
});

test("Stage Timing follows Run, Entity and Run-only selection without mixing or reusing responses", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [
            runtimeReport("RUN-A", "WIN-A", "completed", null),
            runtimeReport("RUN-A", "WIN-B", "completed", null),
            runtimeReport("RUN-B", "WIN-C", "completed", null),
        ],
        [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-C"), runListItem("RUN-C", "WIN-D")],
        { extraElementIds: STAGE_TIMING_ELEMENT_IDS },
    );
    t.after(harness.restore);
    const state = harness.document.getElementById("insight-bottleneck-state");
    const scope = harness.document.getElementById("insight-bottleneck-scope");
    const caption = harness.document.getElementById("insight-bottleneck-caption");
    const records = harness.document.getElementById("insight-bottleneck-records");
    const winA = stageTarget("RUN-A", "WIN-A");
    const winB = stageTarget("RUN-A", "WIN-B");

    // When: select WIN-A, then switch to WIN-B of the same Run before WIN-A answers.
    harness.runtimeButton("RUN-A", "WIN-A").click();
    await harness.flush();
    const [pendingWinA] = harness.requestsFor(stageTimingPath(winA.executionId)).filter((request) => !request.settled);
    harness.runtimeButton("RUN-A", "WIN-B").click();
    await harness.flush();
    await harness.respond(stageTimingPath(winB.executionId), 200, timingPayload({ scope: winB }));
    const afterEntityChange = { label: state.textContent, scope: scope.textContent, rows: records.children.length };
    // When: a Run-only selection, a Run without Runtime, then a Runtime query failure.
    harness.runButton("RUN-B").click();
    await harness.flush();
    const runOnlyWithRuntime = { label: state.textContent, caption: caption.textContent, rows: records.children.length };
    harness.runButton("RUN-C").click();
    await harness.flush();
    const runOnlyWithoutRuntime = caption.textContent;
    harness.runtimeButton("RUN-B", "WIN-C").click();
    await harness.flush();
    await harness.pollFailure();
    const afterRuntimeFailure = { label: state.textContent, caption: caption.textContent };

    // Then
    assert.equal(pendingWinA.options.signal.aborted, true);
    assert.equal(afterEntityChange.label, buildStageTimingModel(timingPayload({ scope: winB }), winB).label);
    assert.match(afterEntityChange.scope, /Entity WIN-B · Execution RUN-A-WIN-B/);
    assert.doesNotMatch(afterEntityChange.scope, /WIN-A/);
    assert.equal(afterEntityChange.rows, 6);
    assert.deepEqual(runOnlyWithRuntime, { label: "비교 대상 없음", caption: "Runtime 선택 필요", rows: 0 });
    assert.equal(runOnlyWithoutRuntime, "Runtime 보고 없음");
    assert.deepEqual(afterRuntimeFailure, { label: "비교 대상 없음", caption: "Runtime 조회 실패" });
    assert.equal(harness.requestCount(stageTimingPath("RUN-C-WIN-D")), 0);
    assert.equal(harness.requestCount(stageTimingPath(winA.executionId)), 1);
});

test("Pipeline context keeps the same element across status, Entity, query-error and range changes", async (t) => {
    // Given
    const first = runtimeReport("RUN-A", "WIN-A", "running", "fusion");
    const second = runtimeReport("RUN-A", "WIN-B", "running", "hybrid");
    const harness = await startDashboardWithRuntime([first, second], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const context = harness.document.getElementById("pipeline-stage-context");
    assert.equal(context.textContent, `RUN-A · WIN-A · ${RUNNING_LABEL}`);

    // When / Then
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null), second]);
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `RUN-A · WIN-A · ${COMPLETED_LABEL}`);
    assert.deepEqual(harness.stageStates(), Array(6).fill("completed"));
    harness.runtimeButton("RUN-A", "WIN-B").click();
    await harness.flush();
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `RUN-A · WIN-B · ${RUNNING_LABEL}`);
    assert.deepEqual(harness.stageStates(), ["unknown", "unknown", "unknown", "unknown", "current", "unknown"]);
    await harness.pollFailure();
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `RUN-A · WIN-B · ${RUNNING_LABEL}`);
    assert.match(harness.text("runtime-top-status"), /불러오지 못했습니다/);
    await harness.poll(otherRunningReports());
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.match(context.textContent, /RUN-A · WIN-B · 최근 5건 조회 범위 밖/);
    assert.equal(context.hidden, false);
    assert.equal(harness.stageStates().length, 6);
    assert.equal(harness.text("pipeline-status-note"), "단계 완료 미확인");
});

test("Recent Runs defaults to five rows and explicitly expands all twenty without refetching", async (t) => {
    // Given
    const runs = Array.from({ length: 20 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    const list = harness.document.getElementById("runs-list");
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    const visibleIds = () => list.children.filter((row) => !row.hidden).map(
        (row) => row.querySelectorAll(".dashboard-run-selector")[0].dataset.runId,
    );

    // When / Then
    assert.equal(list.children.length, 20);
    assert.deepEqual(visibleIds(), runs.slice(0, 5).map((run) => run.run_id));
    assert.equal(toggle.hidden, false);
    assert.equal(toggle.getAttribute("aria-expanded"), "false");
    toggle.focus();
    toggle.click(); // Native button activation also handles Enter and Space in a browser.
    assert.deepEqual(visibleIds(), runs.map((run) => run.run_id));
    assert.equal(toggle.getAttribute("aria-expanded"), "true");
    await harness.poll([]);
    assert.deepEqual(visibleIds(), runs.map((run) => run.run_id));
    assert.equal(toggle.getAttribute("aria-expanded"), "true");
    assert.equal(harness.document.activeElement, toggle);
    toggle.click();
    assert.equal(visibleIds().length, 5);
    assert.equal(toggle.getAttribute("aria-expanded"), "false");
    assert.equal(harness.requestCount("/runs?limit=20"), 1);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
});

test("Collapsing and Runtime polling preserve a hidden Run selection, links and navigation", async (t) => {
    // Given
    const runs = Array.from({ length: 8 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    toggle.click();
    harness.runButton("RUN-6").focus();
    harness.runButton("RUN-6").click();
    await harness.respondAnalysis("RUN-6", storedDetail("RUN-6", "WIN-A"), notFound());
    const detailLink = harness.document.getElementById("selected-run-detail-link");

    // When
    toggle.click();
    await harness.poll([]);

    // Then
    assert.equal(harness.text("selected-run-id"), "RUN-6");
    assert.equal(harness.runButton("RUN-6").getAttribute("aria-pressed"), "true");
    assert.equal(harness.document.getElementById("runs-list").children[6].hidden, true);
    assert.equal(harness.document.activeElement, toggle);
    assert.match(harness.text("runs-visibility-status"), /선택 유지: RUN-6 \(접힌 목록\)/);
    assert.equal(detailLink.hidden, false);
    assert.equal(detailLink.href, buildRunDetailViewPath("RUN-6"));
    const requestsBeforeToggle = harness.requestCount(buildRunDetailApiPath("RUN-6"));
    toggle.click();
    assert.equal(harness.runButton("RUN-6").getAttribute("aria-pressed"), "true");
    assert.equal(harness.requestCount(buildRunDetailApiPath("RUN-6")), requestsBeforeToggle);
    toggle.click();
    harness.document.getElementById("dashboard-prev-run").click();
    assert.equal(harness.text("selected-run-id"), "RUN-7");
    assert.equal(harness.document.getElementById("dashboard-prev-run").disabled, true);
    harness.document.getElementById("dashboard-next-run").click();
    assert.equal(harness.text("selected-run-id"), "RUN-6");
    assert.equal(harness.document.getElementById("runs-list").children.filter((row) => !row.hidden).length, 5);
});

test("A Runtime selection outside the first five Runs survives collapse and polling with its Entity", async (t) => {
    // Given
    const runs = Array.from({ length: 8 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const runtime = runtimeReport("RUN-7", "WIN-A", "running", "normalization");
    const harness = await startDashboardWithRuntime([runtime], runs);
    t.after(harness.restore);
    const toggle = harness.document.getElementById("dashboard-runs-toggle");

    // When
    toggle.click();
    toggle.click();
    await harness.poll([runtime]);

    // Then
    assert.equal(harness.text("selected-run-id"), "RUN-7");
    assert.equal(harness.runtimeButton("RUN-7", "WIN-A").getAttribute("aria-pressed"), "true");
    assert.equal(harness.runButton("RUN-7").getAttribute("aria-pressed"), "false");
    assert.match(harness.text("runs-visibility-status"), /선택 유지: RUN-7/);
    assert.equal(harness.stageStates()[1], "current");
});

test("Recent Runs disclosure is hidden for an empty list and exposes its controlled rows", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], []);
    t.after(harness.restore);
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    const html = await readFile(new URL("../dashboard.html", DASHBOARD_ASSETS_URL), "utf8");

    // When / Then
    assert.equal(toggle.hidden, true);
    assert.equal(harness.text("runs-visibility-status"), "");
    assert.match(html, /id="dashboard-runs-toggle"[^>]*type="button"[^>]*aria-expanded="false"\s+aria-controls="runs-list"/);
    assert.match(html, /id="runs-visibility-status" role="status" aria-live="polite"/);
});

test("Recent Runs never hides any rows when there are at most five Runs", async (t) => {
    // Given
    const runs = Array.from({ length: 5 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);

    // When / Then
    assert.equal(harness.document.getElementById("dashboard-runs-toggle").hidden, true);
    assert.equal(harness.document.getElementById("runs-list").children.every((row) => !row.hidden), true);
    assert.equal(harness.text("runs-visibility-status"), "5개 중 5개 표시");
});

test("Runtime polling never rewrites an unchanged Run visibility live region", async (t) => {
    // Given
    const runs = Array.from({ length: 20 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const runtime = runtimeReport("RUN-7", "WIN-A", "running", "normalization");
    const harness = await startDashboardWithRuntime([runtime], runs);
    t.after(harness.restore);
    const status = harness.document.getElementById("runs-visibility-status");
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    let writes = status.textContentWrites;

    // When / Then: collapsed selection, expanded list, and collapsed list remain stable on polls.
    for (let index = 0; index < 3; index += 1) {
        await harness.poll([runtime]);
    }
    assert.equal(status.textContentWrites, writes);
    assert.match(status.textContent, /선택 유지: RUN-7/);
    toggle.click();
    assert.equal(status.textContentWrites, ++writes);
    await harness.poll([runtime]);
    assert.equal(status.textContentWrites, writes);
    toggle.click();
    assert.equal(status.textContentWrites, ++writes);
    await harness.poll([runtime]);
    assert.equal(status.textContentWrites, writes);
    harness.document.getElementById("dashboard-prev-run").click();
    assert.equal(status.textContentWrites, ++writes);
    assert.match(status.textContent, /선택 유지: RUN-8/);
    assert.equal(harness.text("selected-run-id"), "RUN-8");
    assert.equal(harness.timerCount(RUNTIME_POLL_DELAY_MS), 1);
});

test("Pipeline SVG icons preserve six stage identities independently of reported status badges", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const icons = () => harness.document.getElementById("pipeline-stage-list").children.map(
        (stage) => stage.children[0].children[0].children[0].getAttribute("href"),
    );
    const expectedIcons = PIPELINE_STAGE_ORDER.map((stage) => `/dashboard-assets/dashboard-icons.svg#${stage}`);
    assert.deepEqual(icons(), expectedIcons);
    assert.deepEqual(harness.stageStates(), Array(6).fill("unknown"));

    // When / Then
    const running = runtimeReport("RUN-A", "WIN-A", "running", "normalization");
    await harness.poll([running]);
    harness.runtimeButton("RUN-A", "WIN-A").click();
    assert.equal(harness.stageStates()[1], "current");
    assert.equal(harness.stageStates().includes("completed"), false);
    assert.deepEqual(icons(), expectedIcons);
    await harness.poll([{ ...running, is_stale: true }]);
    assert.equal(harness.stageStates()[1], "stale");
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "failed", "hybrid")]);
    assert.equal(harness.stageStates()[4], "failed");
    assert.equal(harness.stageStates().includes("completed"), false);
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null)]);
    assert.deepEqual(harness.stageStates(), Array(6).fill("completed"));
    assert.deepEqual(icons(), expectedIcons);
    assert.equal(new Set(icons()).size, 6);
    assert.match(harness.text("pipeline-stage-list"), /완료/);
});

test("Dashboard opens the Replay panel and switches detail tabs without changing the selection", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const tabNames = ["summary", "replay", "evidence", "decision", "workflow"];
    const tabStates = () => tabNames.map((name) => ({
        tab: harness.document.getElementById(`dashboard-tab-${name}`).getAttribute("aria-selected"),
        hidden: harness.document.getElementById(`dashboard-panel-${name}`).hidden,
    }));
    const selectedRun = harness.text("selected-run-id");

    // When
    const defaultStates = tabStates();
    harness.document.getElementById("dashboard-tab-decision").click();
    const decisionStates = tabStates();
    harness.document.getElementById("dashboard-tab-replay").click();
    const replayTab = harness.document.getElementById("dashboard-tab-replay");
    const arrowHandled = replayTab.keyDown("ArrowRight");
    const evidenceTab = harness.document.getElementById("dashboard-tab-evidence");
    const evidenceFocused = harness.document.activeElement === evidenceTab;
    const endHandled = evidenceTab.keyDown("End");
    const workflowTab = harness.document.getElementById("dashboard-tab-workflow");
    const workflowFocused = harness.document.activeElement === workflowTab;
    const homeHandled = workflowTab.keyDown("Home");

    // Then
    assert.deepEqual(defaultStates, [
        { tab: "false", hidden: true },
        { tab: "true", hidden: false },
        { tab: "false", hidden: true },
        { tab: "false", hidden: true },
        { tab: "false", hidden: true },
    ]);
    assert.deepEqual(decisionStates, [
        { tab: "false", hidden: true },
        { tab: "false", hidden: true },
        { tab: "false", hidden: true },
        { tab: "true", hidden: false },
        { tab: "false", hidden: true },
    ]);
    assert.equal(arrowHandled, true);
    assert.equal(evidenceFocused, true);
    assert.equal(endHandled, true);
    assert.equal(workflowFocused, true);
    assert.equal(homeHandled, true);
    for (const name of ["evidence", "workflow", "summary"]) {
        assert.deepEqual(harness.document.getElementById(`dashboard-tab-${name}`).scrollIntoViewCalls, [
            { block: "nearest", inline: "nearest" },
        ]);
    }
    assert.equal(harness.document.getElementById("dashboard-tab-summary").getAttribute("aria-selected"), "true");
    assert.equal(harness.document.activeElement, harness.document.getElementById("dashboard-tab-summary"));
    assert.equal(harness.document.getElementById("dashboard-panel-summary").hidden, false);
    assert.equal(harness.text("selected-run-id"), selectedRun);
});

test("Recent Runs reveals the focused detail link without selecting or refetching a Run", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const row = harness.document.getElementById("runs-list").children[0];
    const link = row.children[6].children[0];
    const selected = harness.text("selected-run-id");
    const reads = harness.requestCount("/runs?limit=20");

    // When
    link.focus();

    // Then
    assert.strictEqual(harness.document.activeElement, link);
    assert.equal(link.href, buildRunDetailViewPath("RUN-A"));
    assert.deepEqual(link.scrollIntoViewCalls, [{ block: "nearest", inline: "nearest" }]);
    assert.equal(harness.text("selected-run-id"), selected);
    assert.equal(harness.requestCount("/runs?limit=20"), reads);
});

function recentRunRow(harness, runId) {
    return harness.document.getElementById("runs-list").children.find(
        (row) => row.querySelectorAll(".dashboard-run-selector")[0].dataset.runId === runId,
    );
}

function recentRunDetailLink(harness, runId) {
    return recentRunRow(harness, runId).children[6].children[0];
}

test("Runtime polling restores Run Detail link focus to the same Run without scrolling", async (t) => {
    // Given
    const runs = Array.from({ length: 8 }, (_, index) => runListItem(`RUN-${index}`, "WIN-A"));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    const list = harness.document.getElementById("runs-list");
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    toggle.click();
    const original = recentRunDetailLink(harness, "RUN-6");
    original.focus();
    const detailRequests = harness.requestCount(buildRunDetailApiPath("RUN-0"));

    // When
    await harness.poll([]);
    const firstRestore = harness.document.activeElement;
    await harness.poll([]);
    const secondRestore = harness.document.activeElement;

    // Then
    assert.notStrictEqual(firstRestore, original);
    assert.equal(list.contains(original), false);
    assert.notStrictEqual(secondRestore, firstRestore);
    assert.strictEqual(secondRestore, recentRunDetailLink(harness, "RUN-6"));
    for (const restored of [firstRestore, secondRestore]) {
        assert.equal(restored.href, buildRunDetailViewPath("RUN-6"));
        assert.equal(restored.textContent, "Run Detail");
        assert.deepEqual(restored.focusOptions, { preventScroll: true });
        assert.equal(restored.scrollIntoViewCalls, undefined);
    }
    assert.equal(list.contains(secondRestore), true);
    assert.equal(recentRunRow(harness, "RUN-6").hidden, false);
    assert.deepEqual(original.scrollIntoViewCalls, [{ block: "nearest", inline: "nearest" }]);
    assert.equal(toggle.getAttribute("aria-expanded"), "true");
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    assert.equal(harness.runButton("RUN-0").getAttribute("aria-pressed"), "true");
    assert.equal(harness.requestCount(buildRunDetailApiPath("RUN-0")), detailRequests);
    assert.equal(harness.requestCount(buildRunDetailApiPath("RUN-6")), 0);
});

test("Runtime polling keeps Run selector focus restoration next to Run Detail links", async (t) => {
    // Given
    const runs = ["RUN-A", "RUN-B", "RUN-C"].map((runId) => runListItem(runId, "WIN-A"));
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-B", "WIN-A", "running", "fusion")],
        runs,
    );
    t.after(harness.restore);
    const originalSelector = harness.runButton("RUN-C");
    originalSelector.focus();

    // When
    await harness.poll([runtimeReport("RUN-B", "WIN-A", "completed", null)]);
    const restoredSelector = harness.document.activeElement;
    const renderedSelector = harness.runButton("RUN-C");
    recentRunDetailLink(harness, "RUN-B").focus();
    await harness.poll([runtimeReport("RUN-B", "WIN-A", "completed", null)]);
    const restoredLink = harness.document.activeElement;

    // Then
    assert.notStrictEqual(restoredSelector, originalSelector);
    assert.strictEqual(restoredSelector, renderedSelector);
    assert.equal(restoredSelector.dataset.entityId, undefined);
    assert.strictEqual(restoredLink, recentRunDetailLink(harness, "RUN-B"));
    assert.equal(restoredLink.href, buildRunDetailViewPath("RUN-B"));
});

test("Runtime polling does not pull focus back to a Run row after the user moved away", async (t) => {
    // Given
    const runs = ["RUN-A", "RUN-B", "RUN-C"].map((runId) => runListItem(runId, "WIN-A"));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    const decisionTab = harness.document.getElementById("dashboard-tab-decision");

    // When
    recentRunDetailLink(harness, "RUN-B").focus();
    await harness.triggerTimers(RUNTIME_POLL_DELAY_MS);
    decisionTab.focus();
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const afterTabMove = harness.document.activeElement;
    recentRunDetailLink(harness, "RUN-B").focus();
    await harness.triggerTimers(RUNTIME_POLL_DELAY_MS);
    harness.document.activeElement = null;
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const afterBlur = harness.document.activeElement;
    recentRunDetailLink(harness, "RUN-B").focus();
    await harness.triggerTimers(RUNTIME_POLL_DELAY_MS);
    harness.runButton("RUN-C").focus();
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const afterRowMove = harness.document.activeElement;

    // Then
    assert.strictEqual(afterTabMove, decisionTab);
    assert.equal(afterBlur, null);
    assert.strictEqual(afterRowMove, harness.runButton("RUN-C"));
    assert.notEqual(afterRowMove.textContent, "Run Detail");
});

function visibleRunIds(harness) {
    return harness.document.getElementById("runs-list").children
        .filter((row) => !row.hidden)
        .map((row) => row.querySelectorAll(".dashboard-run-selector")[0].dataset.runId);
}

function tenSearchRuns() {
    return Array.from(
        { length: 10 },
        (_, index) => runListItem(`RUN-${index}`, index < 5 ? "WIN-A" : "WIN-B"),
    );
}

function setRunType(harness, value) {
    const filter = harness.document.getElementById("dashboard-run-type");
    filter.value = value;
    for (const listener of filter.listeners.get("change") ?? []) {
        listener({ type: "change", target: filter });
    }
}

test("Run type filter uses persisted run_type and combines with the unchanged search", () => {
    // Given
    const runs = Object.freeze([
        Object.freeze({ ...searchRun("RUN-A", "WIN-1", "normal"), run_type: "attack" }),
        Object.freeze({ ...searchRun("RUN-B", "WIN-1", "attack"), run_type: "normal" }),
        Object.freeze({ ...searchRun("RUN-C", "WIN-2", "attack"), run_type: "attack" }),
        Object.freeze({ ...searchRun("RUN-D", "WIN-1", "attack"), run_type: "unknown" }),
    ]);
    const snapshot = JSON.stringify(runs);

    // When
    const attack = resolveRunListVisibility(runs, "", false, 5, "RUN-B", "attack");
    const combined = resolveRunListVisibility(runs, " win-1 ", true, 5, "RUN-C", "normal");
    const cleared = resolveRunListVisibility(runs, "", false, 5, null);

    // Then
    assert.deepEqual(attack.visible, [true, false, true, false]);
    assert.deepEqual(combined.visible, [false, true, false, false]);
    assert.equal(attack.toggleHidden, true);
    assert.equal(attack.selectedHidden, true);
    assert.match(getRunListVisibilityMessage(attack, "RUN-B"), /필터 결과 2건.*조회된 Run 4건.*유형 attack.*최대 20건.*선택 유지/);
    assert.equal(cleared.visibleCount, 4);
    assert.equal(JSON.stringify(runs), snapshot);
    assert.throws(() => resolveRunListVisibility(runs, "", false, 5, null, "att"), RangeError);
});

test("Run filter reset preserves selection, original rows, request count and expansion", async (t) => {
    // Given
    const runs = tenSearchRuns().map((run, index) => ({ ...run, run_type: index % 2 ? "attack" : "normal" }));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    const rows = [...harness.document.getElementById("runs-list").children];
    const requests = harness.totalRequests();
    const filter = harness.document.getElementById("dashboard-run-type");
    const reset = harness.document.getElementById("dashboard-run-filter-reset");

    // When
    filter.focus();
    setRunType(harness, "attack");
    assert.deepEqual(visibleRunIds(harness), ["RUN-1", "RUN-3", "RUN-5", "RUN-7", "RUN-9"]);
    harness.typeSearch("win-b");
    assert.deepEqual(visibleRunIds(harness), ["RUN-5", "RUN-7", "RUN-9"]);
    assert.equal(harness.document.activeElement, filter);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    harness.typeSearch("RUN-2");
    assert.deepEqual(visibleRunIds(harness), []);
    assert.match(harness.text("runs-visibility-status"), /일치하는 결과가 없습니다.*유형 attack/);
    reset.focus();
    reset.click();

    // Then
    assert.deepEqual(visibleRunIds(harness), runs.slice(0, 5).map((run) => run.run_id));
    assert.equal(harness.document.getElementById("dashboard-run-search").value, "");
    assert.equal(filter.value, "all");
    assert.equal(harness.document.activeElement, reset);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    assert.deepEqual([...harness.document.getElementById("runs-list").children], rows);
    assert.equal(harness.totalRequests(), requests);
    harness.document.getElementById("dashboard-runs-toggle").click();
    setRunType(harness, "normal");
    harness.typeSearch("RUN-9");
    reset.click();
    assert.equal(visibleRunIds(harness).length, 10);
    assert.equal(harness.document.getElementById("dashboard-runs-toggle").getAttribute("aria-expanded"), "true");
});

test("Run type and combined search survive Runtime polling without focus or live status changes", async (t) => {
    // Given
    const runs = tenSearchRuns().map((run, index) => ({ ...run, run_type: index % 2 ? "attack" : "normal" }));
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    setRunType(harness, "attack");
    harness.typeSearch("WIN-B");
    const filter = harness.document.getElementById("dashboard-run-type");
    filter.focus();
    const writes = harness.document.getElementById("runs-visibility-status").textContentWrites;

    // When
    await harness.triggerTimers(RUNTIME_POLL_DELAY_MS);
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });

    // Then
    assert.equal(filter.value, "attack");
    assert.strictEqual(harness.document.activeElement, filter);
    assert.deepEqual(visibleRunIds(harness), ["RUN-5", "RUN-7", "RUN-9"]);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    assert.equal(harness.document.getElementById("runs-visibility-status").textContentWrites, writes);
});

test("Run search moves focus and scroll only on explicit Enter or result button", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    const input = harness.document.getElementById("dashboard-run-search");
    const results = harness.document.getElementById("dashboard-run-search-results");
    input.focus();

    // When
    harness.typeSearch("RUN-7");

    // Then
    assert.equal(harness.document.activeElement, input);
    assert.equal(harness.runButton("RUN-7").scrollIntoViewCalls, undefined);
    for (const listener of input.listeners.get("keydown")) {
        listener({ key: "Enter", isComposing: true, preventDefault() { assert.fail("IME Enter was intercepted"); } });
    }
    assert.equal(harness.document.activeElement, input);
    assert.equal(input.keyDown("ArrowDown"), false);
    assert.equal(input.keyDown("Enter"), true);
    assert.equal(harness.document.activeElement, harness.runButton("RUN-7"));
    assert.deepEqual(harness.runButton("RUN-7").focusOptions, { preventScroll: true });
    assert.deepEqual(harness.runButton("RUN-7").scrollIntoViewCalls, [{ block: "center", inline: "nearest" }]);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    harness.typeSearch("no-result");
    results.click();
    assert.equal(harness.document.activeElement, harness.document.getElementById("runs-visibility-status"));
    assert.equal(harness.text("selected-run-id"), "RUN-0");
});

test("Run search filters fetched rows in place without selecting, fetching, or rerendering", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    const list = harness.document.getElementById("runs-list");
    const toggle = harness.document.getElementById("dashboard-runs-toggle");
    const rowsBefore = [...list.children];
    const requestsBefore = harness.totalRequests();

    // When
    harness.typeSearch("run-7");
    const exact = { ids: visibleRunIds(harness), toggleHidden: toggle.hidden, status: harness.text("runs-visibility-status") };
    harness.typeSearch("WIN-b");
    const hiddenRows = visibleRunIds(harness);
    harness.typeSearch("   ");
    const cleared = { ids: visibleRunIds(harness), toggleHidden: toggle.hidden, status: harness.text("runs-visibility-status") };

    // Then
    assert.deepEqual(exact, {
        ids: ["RUN-7"],
        toggleHidden: true,
        status: "검색 결과 1건 / 조회된 Run 10건 · 선택 유지: RUN-0 (검색 결과 밖)",
    });
    assert.deepEqual(hiddenRows, ["RUN-5", "RUN-6", "RUN-7", "RUN-8", "RUN-9"]);
    assert.deepEqual(cleared, {
        ids: ["RUN-0", "RUN-1", "RUN-2", "RUN-3", "RUN-4"],
        toggleHidden: false,
        status: "10개 중 5개 표시",
    });
    assert.deepEqual([...list.children], rowsBefore);
    assert.equal(harness.totalRequests(), requestsBefore);
    assert.equal(harness.text("selected-run-id"), "RUN-0");
    assert.equal(harness.runButton("RUN-0").getAttribute("aria-pressed"), "true");
});

test("Run search keeps the selected Run, opens filtered Runs, and moves in full-list order", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    harness.document.getElementById("dashboard-runs-toggle").click();
    harness.runButton("RUN-7").click();
    await harness.respondAnalysis("RUN-7", storedDetail("RUN-7", "WIN-B"), notFound());
    const detailLink = harness.document.getElementById("selected-run-detail-link");
    const requestsBefore = harness.totalRequests();

    // When: the selected Run falls outside the search result.
    harness.typeSearch("RUN-2");
    const outside = {
        selected: harness.text("selected-run-id"),
        pressed: harness.runButton("RUN-7").getAttribute("aria-pressed"),
        detailHref: detailLink.href,
        detailHidden: detailLink.hidden,
        status: harness.text("runs-visibility-status"),
        requests: harness.totalRequests() - requestsBefore,
    };
    // When: previous/next follow the fetched list, not the filtered rows.
    harness.document.getElementById("dashboard-prev-run").click();
    await harness.flush();
    const afterPrevious = { selected: harness.text("selected-run-id"), ids: visibleRunIds(harness) };
    harness.document.getElementById("dashboard-next-run").click();
    await harness.flush();
    const afterNext = harness.text("selected-run-id");
    // When: a Run shown by the filter is opened.
    harness.runButton("RUN-2").click();
    await harness.flush();

    // Then
    assert.deepEqual(outside, {
        selected: "RUN-7",
        pressed: "true",
        detailHref: buildRunDetailViewPath("RUN-7"),
        detailHidden: false,
        status: "검색 결과 1건 / 조회된 Run 10건 · 선택 유지: RUN-7 (검색 결과 밖)",
        requests: 0,
    });
    assert.deepEqual(afterPrevious, { selected: "RUN-8", ids: ["RUN-2"] });
    assert.equal(afterNext, "RUN-7");
    assert.equal(harness.text("selected-run-id"), "RUN-2");
    assert.equal(harness.runButton("RUN-2").getAttribute("aria-pressed"), "true");
    assert.equal(harness.requestCount(buildRunDetailApiPath("RUN-2")), 1);
    assert.deepEqual(visibleRunIds(harness), ["RUN-2"]);
    assert.equal(harness.text("runs-visibility-status"), "검색 결과 1건 / 조회된 Run 10건");
});

test("Clearing the Run search restores the collapsed or expanded list chosen before", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(harness.restore);
    const toggle = harness.document.getElementById("dashboard-runs-toggle");

    // When: collapsed before searching.
    harness.typeSearch("run");
    const searchingCollapsed = { ids: visibleRunIds(harness).length, toggleHidden: toggle.hidden };
    harness.typeSearch("");
    const restoredCollapsed = {
        ids: visibleRunIds(harness).length,
        toggleHidden: toggle.hidden,
        expanded: toggle.getAttribute("aria-expanded"),
        label: toggle.textContent,
    };
    // When: expanded before searching.
    toggle.click();
    harness.typeSearch("RUN-3");
    const searchingExpanded = {
        ids: visibleRunIds(harness),
        toggleHidden: toggle.hidden,
        expanded: toggle.getAttribute("aria-expanded"),
    };
    harness.typeSearch("");
    const restoredExpanded = {
        ids: visibleRunIds(harness).length,
        toggleHidden: toggle.hidden,
        expanded: toggle.getAttribute("aria-expanded"),
        label: toggle.textContent,
    };

    // Then
    assert.deepEqual(searchingCollapsed, { ids: 10, toggleHidden: true });
    assert.deepEqual(restoredCollapsed, {
        ids: 5,
        toggleHidden: false,
        expanded: "false",
        label: "전체 10개 Run 펼치기",
    });
    assert.deepEqual(searchingExpanded, { ids: ["RUN-3"], toggleHidden: true, expanded: "true" });
    assert.deepEqual(restoredExpanded, {
        ids: 10,
        toggleHidden: false,
        expanded: "true",
        label: "최근 5개만 보기",
    });
});

test("Runtime polling during a Run search keeps the input, filter, selection, and link focus", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-0", storedDetail("RUN-0", "WIN-A"), notFound());
    const input = harness.document.getElementById("dashboard-run-search");
    const status = harness.document.getElementById("runs-visibility-status");
    input.focus();
    harness.typeSearch("RUN-6");
    input.selectionStart = 3;
    input.selectionEnd = 3;
    let valueWrites = 0;
    let value = input.value;
    Object.defineProperty(input, "value", {
        get: () => value,
        set: (next) => {
            valueWrites += 1;
            value = next;
        },
    });
    const statusWrites = status.textContentWrites;
    const running = runtimeReport("RUN-6", "WIN-B", "running", "fusion");

    // When
    await harness.poll([running]);
    await harness.poll([running]);
    const afterPolls = {
        focused: harness.document.activeElement === input,
        value: input.value,
        caret: [input.selectionStart, input.selectionEnd],
        valueWrites,
        ids: visibleRunIds(harness),
        statusWrites: status.textContentWrites - statusWrites,
        selected: harness.text("selected-run-id"),
        scrolled: input.scrollIntoViewCalls,
        runtimeStatusUpdated: harness.runButton("RUN-6").parentNode.parentNode.parentNode
            .children[2].textContent.startsWith(RUNNING_LABEL),
    };
    const link = recentRunDetailLink(harness, "RUN-6");
    link.focus();
    await harness.poll([running]);
    const restoredLink = harness.document.activeElement;

    // Then
    assert.deepEqual(afterPolls, {
        focused: true,
        value: "RUN-6",
        caret: [3, 3],
        valueWrites: 0,
        ids: ["RUN-6"],
        statusWrites: 0,
        selected: "RUN-0",
        scrolled: undefined,
        runtimeStatusUpdated: true,
    });
    assert.notStrictEqual(restoredLink, link);
    assert.strictEqual(restoredLink, recentRunDetailLink(harness, "RUN-6"));
    assert.equal(recentRunRow(harness, "RUN-6").hidden, false);
    assert.deepEqual(restoredLink.focusOptions, { preventScroll: true });
    assert.deepEqual(visibleRunIds(harness), ["RUN-6"]);
});

test("Run search distinguishes no matching fetched Run from a failed Run list query", async (t) => {
    // Given / When: each harness owns the page globals, so the two pages run one after another.
    const fetched = await startDashboardWithRuntime([], tenSearchRuns());
    t.after(fetched.restore);
    fetched.typeSearch("RUN-99");
    const noMatch = {
        status: fetched.text("runs-visibility-status"),
        queryStatusHidden: fetched.document.getElementById("runs-status").hidden,
        ids: visibleRunIds(fetched),
    };
    fetched.restore();
    const failed = await startDashboardHarness();
    t.after(failed.restore);
    await failed.respond("/overview", 200, { total_runs: 10, recent_runs: [] });
    await failed.respond("/runs?limit=20", 503, { detail: "unavailable" });
    await failed.respond(RUNTIME_API_PATH, 200, { items: [] });
    failed.typeSearch("RUN-99");

    // Then
    assert.deepEqual(noMatch, {
        status: "현재 조회된 Run에서 일치하는 결과가 없습니다. · 선택 유지: RUN-0 (검색 결과 밖)",
        queryStatusHidden: true,
        ids: [],
    });
    assert.equal(failed.text("runs-visibility-status"), "");
    assert.equal(failed.document.getElementById("runs-status").hidden, false);
    assert.match(failed.text("runs-status"), /Run 목록을 불러오지 못했습니다/);
});

test("Dashboard requests the selected Run timeline once and labels fetched Event counts", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const timelinePath = buildEventTimelineApiPath("RUN-A", 50, 0);

    // When
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
    );
    const initialRequests = harness.requestCount(timelinePath);
    await harness.respond(timelinePath, 200, {
        items: [
            { event_id: "EVT-1", timestamp: "2026-10-09T00:00:01Z", host_id: "WIN-A", event_type: "Process" },
            { event_id: "EVT-2", timestamp: "2026-10-09T00:00:02Z", host_id: "WIN-A", event_type: "Network" },
        ],
        total: 75,
        limit: 50,
        offset: 0,
    });
    const summary = harness.text("event-type-summary");
    const status = harness.text("event-type-summary-status");
    const rows = harness.document.getElementById("event-type-summary").childNodes;

    // Then
    assert.equal(initialRequests, 1);
    assert.match(summary, /Process/);
    assert.match(summary, /Network/);
    assert.deepEqual(rows.map((row) => row.childNodes.map((node) => node.textContent)), [
        ["Process", "1"],
        ["Network", "1"],
    ]);
    assert.equal(
        status,
        "조회된 Event 2건 / 전체 75건 · Run 범위",
    );
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    assert.match(html, /<summary aria-label="연관 Event 집계 기준">집계<\/summary>\s*<p>조회된 Event에 포함된 유형만 집계합니다\. Run 단위 조회이며 선택 Runtime Entity로 한정되지 않습니다\./);
    assert.match(html, /Event 시각과 기술적 판정 시각은 별도 의미입니다/);
    assert.equal(harness.requestCount(timelinePath), 1);
});

test("Dashboard shows stored Decision history without deriving a causal Event timeline", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A", "WIN-A", "DEC-2");
    detail.body.decision_history = [
        { decision_id: "DEC-2", decision_path: "fusion", t_e: "2026-10-09T00:02:00Z" },
        { decision_id: "DEC-1", decision_path: "fast", t_e: "2026-10-09T00:01:00Z" },
    ];

    // When
    await harness.respondAnalysis("RUN-A", detail, storedFusion("RUN-A", "WIN-A", "DEC-2"));
    const history = harness.text("decision-history-list");
    const replayTimeline = harness.text("decision-timeline-list");
    const entries = harness.document.getElementById("decision-timeline-list").childNodes;

    // Then
    assert.equal(harness.text("decision-history-status"), "최신 Decision부터 저장된 순서로 표시합니다.");
    assert.ok(history.indexOf("DEC-2") < history.indexOf("DEC-1"));
    assert.match(replayTimeline, /DEC-2/);
    assert.match(replayTimeline, /DEC-1/);
    assert.deepEqual(entries.map((item) => [
        item.childNodes[0].textContent,
        ...item.childNodes[1].childNodes.map((detail) => detail.textContent),
    ]), [
        ["DEC-2", `t_e · ${formatRunTimestamp("2026-10-09T00:02:00Z")}`, "판단 경로 · Fusion"],
        ["DEC-1", `t_e · ${formatRunTimestamp("2026-10-09T00:01:00Z")}`, "판단 경로 · Fast"],
    ]);
    assert.doesNotMatch(history, /Alert Sent|Analyst Ack|24h/);
});

test("Dashboard keeps a single stored Decision readable as a distinct timeline entry", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A", "WIN-A", "DEC-1");
    detail.body.decision_history = [
        { decision_id: "DEC-1", decision_path: "fast_and_fusion", t_e: "2026-10-09T00:02:00Z" },
    ];

    // When
    await harness.respondAnalysis("RUN-A", detail, storedFusion("RUN-A", "WIN-A", "DEC-1"));
    const entries = harness.document.getElementById("decision-timeline-list").childNodes;

    // Then
    assert.equal(entries.length, 1);
    assert.equal(entries[0].childNodes[0].textContent, "DEC-1");
    assert.deepEqual(entries[0].childNodes[1].childNodes.map((detailItem) => detailItem.textContent), [
        `t_e · ${formatRunTimestamp("2026-10-09T00:02:00Z")}`,
        "판단 경로 · Fast + Fusion",
    ]);
});

test("Dashboard distinguishes empty and failed Event category reads", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const timelinePath = buildEventTimelineApiPath("RUN-A", 50, 0);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
    );

    // When
    await harness.respond(timelinePath, 200, { items: [], total: 0, limit: 50, offset: 0 });
    const emptyStatus = harness.text("event-type-summary-status");
    const emptyItems = harness.text("event-type-summary");
    harness.runButton("RUN-A").click();
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A"),
        storedFusion("RUN-A", "WIN-A"),
    );
    await harness.respond(timelinePath, 503, { detail: "Unavailable" });

    // Then
    assert.match(emptyStatus, /저장된 Event가 없습니다/);
    assert.equal(emptyItems, "");
    assert.match(harness.text("event-type-summary-status"), /불러오지 못했습니다/);
    assert.equal(harness.text("event-type-summary"), "");
});

test("Dashboard refreshes Event categories once when a selected Running Run completes", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-A", "running", "fusion")],
        [runListItem("RUN-A", "WIN-A")],
    );
    t.after(harness.restore);
    const timelinePath = buildEventTimelineApiPath("RUN-A", 50, 0);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.respond(timelinePath, 200, { items: [], total: 0, limit: 50, offset: 0 });
    const initialStatus = harness.text("event-type-summary-status");

    // When
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null)]);
    await harness.respondAnalysis(
        "RUN-A",
        storedDetail("RUN-A", "WIN-A", "DEC-A"),
        storedFusion("RUN-A", "WIN-A", "DEC-A"),
    );
    const requestsAfterCompletion = harness.requestCount(timelinePath);
    await harness.respond(timelinePath, 200, {
        items: [
            { event_id: "EVT-1", timestamp: "2026-10-09T00:02:00Z", host_id: "WIN-A", event_type: "Process" },
        ],
        total: 1,
        limit: 50,
        offset: 0,
    });
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null)]);

    // Then
    assert.match(initialStatus, /저장된 Event가 없습니다/);
    assert.equal(requestsAfterCompletion, 2);
    assert.equal(harness.requestCount(timelinePath), 2);
    assert.match(harness.text("event-type-summary"), /Process1/);
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
});

test("Recent Runs uses Runtime status and progress only for the exact Run and Entity scope", async (t) => {
    // Given
    const otherEntity = runtimeReport("RUN-A", "WIN-B", "running", "normalization");
    otherEntity.normalization_processed_count = 9;
    otherEntity.remaining_count = 1;
    const matchingEntity = runtimeReport("RUN-A", "WIN-A", "running", "normalization");
    matchingEntity.normalization_processed_count = 7;
    matchingEntity.remaining_count = 3;
    const harness = await startDashboardWithRuntime(
        [otherEntity],
        [runListItem("RUN-A", "WIN-A")],
    );
    t.after(harness.restore);
    const timelinePath = buildEventTimelineApiPath("RUN-A", 50, 0);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.respond(timelinePath, 200, { items: [], total: 0, limit: 50, offset: 0 });
    const runCells = () => harness.document.getElementById("runs-list").childNodes[0].childNodes;
    const initial = {
        target: runCells()[1].textContent,
        status: runCells()[2].textContent,
        progress: runCells()[4].textContent,
    };

    // When
    await harness.poll([otherEntity, matchingEntity]);
    const matched = {
        status: runCells()[2].textContent,
        progress: runCells()[4].textContent,
    };
    await harness.poll([otherEntity, { ...matchingEntity, is_stale: true }]);
    const staleStatus = runCells()[2].textContent;
    await harness.pollFailure();
    const failedQueryStatus = runCells()[2].textContent;

    // Then
    assert.match(initial.target, /분석 대상 WIN-A/);
    assert.equal(initial.status, "최근 5건 미포함");
    assert.equal(initial.progress, "-");
    assert.match(matched.status, /최근 갱신/);
    assert.equal(matched.progress, "7 / 10 처리");
    assert.match(staleStatus, /오래됨/);
    assert.match(failedQueryStatus, /확인 불가 \(조회 실패\)/);
    assert.doesNotMatch(failedQueryStatus, /최근 갱신/);
});

test("Dashboard keeps empty Runtime explicit in the KPI without a duplicate status row", async (t) => {
    // Given
    const harness = await startDashboardHarness();
    t.after(harness.restore);
    const loading = {
        top: harness.text("runtime-top-status"),
        summary: harness.text("runtime-summary-status"),
    };

    // When
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    const empty = {
        top: harness.text("runtime-top-status"),
        summary: harness.text("runtime-summary-status"),
    };
    const emptyKpi = harness.text("system-status-value");
    const emptyStages = harness.stageStates();
    const topStatus = harness.document.getElementById("runtime-top-status");
    const emptyAccessible = !topStatus.hidden
        && topStatus.classList.contains("dashboard-visually-hidden");
    const writes = topStatus.textContentWrites;
    await harness.poll([]);
    assert.equal(topStatus.textContentWrites, writes);
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null)]);
    const success = {
        top: harness.text("runtime-top-status"),
        summary: harness.text("runtime-summary-status"),
    };
    await harness.pollFailure();
    const error = {
        top: harness.text("runtime-top-status"),
        summary: harness.text("runtime-summary-status"),
    };

    // Then
    assert.deepEqual(loading, {
        top: "Runtime 정보를 불러오는 중입니다.",
        summary: "Runtime 정보를 불러오는 중입니다.",
    });
    assert.deepEqual(empty, {
        top: "표시할 Runtime 정보가 없습니다.",
        summary: "표시할 Runtime 정보가 없습니다.",
    });
    assert.equal(emptyKpi, "최근 Runtime 보고 없음");
    assert.equal(emptyAccessible, true);
    assert.deepEqual(emptyStages, Array(6).fill("unknown"));
    assert.deepEqual(success, {
        top: "",
        summary: "Runtime 1건을 불러왔습니다.",
    });
    assert.deepEqual(error, {
        top: "Runtime 정보를 불러오지 못했습니다.",
        summary: "Runtime 정보를 불러오지 못했습니다.",
    });
    assert.equal(topStatus.classList.contains("dashboard-visually-hidden"), false);
});

test("Compact Run timestamps retain local seconds, timezone and the original instant", async (t) => {
    // Given
    const run = { ...runListItem("RUN-20261008-920", "R1-TGTA"), start_time: "2026-10-08T18:49:53.429Z" };
    const harness = await startDashboardWithRuntime([], [run]);
    t.after(harness.restore);

    // When
    const cells = harness.document.getElementById("runs-list").children[0].children;
    const time = cells[0].children[0];
    const instant = new Date(run.start_time);

    // Then
    assert.equal(time.getAttribute("datetime"), run.start_time);
    assert.equal(time.getAttribute("title"), formatRunTimestamp(run.start_time));
    assert.equal(time.getAttribute("aria-label"), formatRunTimestamp(run.start_time));
    assert.equal(time.children[0].textContent, [instant.getFullYear(), instant.getMonth() + 1, instant.getDate()]
        .map((part, index) => index === 0 ? String(part) : String(part).padStart(2, "0")).join("-"));
    assert.equal(time.children[1].textContent, instant.toLocaleTimeString("en-GB", {
        hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short",
    }));
    assert.match(time.children[1].textContent, /:53/);
    assert.match(cells[1].textContent, /RUN-20261008-920/);
    assert.match(cells[1].textContent, /분석 대상 R1-TGTA/);
});

test("Dashboard separates primary decision results from threshold settings", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A", "WIN-A", "DEC-A");
    detail.body.current_decision.decision = {
        decision_id: "DEC-A",
        fast_status: "detected",
        fusion_status: "miss",
        decision_path: "fast",
        t_e: "2026-10-09T00:02:00Z",
    };
    const fusion = storedFusion("RUN-A", "WIN-A", "DEC-A");
    fusion.body.runtime_config_snapshot = {
        stopping: { threshold_on: 0.8, threshold_off: 0.4 },
    };

    // When
    await harness.respondAnalysis("RUN-A", detail, fusion);

    // Then
    assert.deepEqual(harness.analysisFields("selected-run-summary"), [
        { label: "Fast 상태", value: "탐지", primary: true, setting: false },
        { label: "Fusion 상태", value: "미탐", primary: true, setting: false },
        { label: "최종 판단 경로", value: "Fast", primary: true, setting: false },
        {
            label: "기술적 판정 시각 (t_e)",
            value: formatRunTimestamp("2026-10-09T00:02:00Z"),
            primary: true,
            setting: false,
        },
    ]);
    assert.deepEqual(harness.analysisFields("selected-run-settings"), [
        { label: "Threshold On", value: "0.8", primary: false, setting: true },
        { label: "Threshold Off", value: "0.4", primary: false, setting: true },
    ]);
    assert.equal(harness.text("selected-run-detail-status"), "");
    assert.equal(harness.text("selected-run-chart-status"), "저장된 Stopping Trace가 없습니다.");
});

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
    assert.match(runListSelection.context, /Run 목록 선택 · Entity 미지정/);
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
    assert.match(harness.text("pipeline-stage-context"), /Run 목록 선택 · Entity 미지정/);
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
