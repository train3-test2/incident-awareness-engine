// Dashboard UI contract tests use Node's built-in test runner only.
// 분석 with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    PIPELINE_STAGE_ORDER,
    RUN_SEARCH_FIELDS,
    SELECTED_RUNTIME_RECHECK_POLL_THRESHOLDS,
    buildPipelineStagePresentation,
    buildStoredFusionContext,
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
    shouldRefreshStoredRunIndex,
    shouldUpdateSelectedRunFailureState,
    summarizePipelineStages,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";

test("Stored Fusion context separates observed zero, missing Trace, decision score and provenance scopes", () => {
    const fusion = { run_id: "R", entity_id: "H", scoring_config_version: "C", score_at_decision: null,
        fusion_episodes: [], contributing_evidence_ids: [] };
    const trace = { run_id: "R", entity_id: "H", scoring_config_version: "C", points: [{ score: 0 }, { score: 0.5 }] };
    const before = JSON.stringify([fusion, trace]);
    assert.deepEqual(buildStoredFusionContext(fusion, trace), {
        traceMax: 0.5, decisionScore: null, episodeCount: 0, evidenceIds: [],
    });
    assert.equal(buildStoredFusionContext(fusion, { ...trace, points: [{ score: 0 }] }).traceMax, 0);
    for (const altered of [null, { ...trace, run_id: "OTHER" }, { ...trace, entity_id: "OTHER" },
        { ...trace, scoring_config_version: "OTHER" }, { ...trace, points: [] },
        { ...trace, points: [{ score: null }] }]) {
        assert.equal(buildStoredFusionContext(fusion, altered).traceMax, null);
    }
    assert.equal(buildStoredFusionContext(null, trace), null);
    assert.equal(JSON.stringify([fusion, trace]), before);
});
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

test("분석 Type presentation maps the persisted vocabulary with a safe fallback", () => {
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
        totalMessage: "전체 분석을 불러오는 중입니다.",
        message: "최근 분석을 불러오는 중입니다.",
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
    assert.equal(state.totalMessage, "전체 분석을 불러왔습니다.");
    assert.equal(state.message, "최근 분석을 불러왔습니다.");
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
        totalMessage: "전체 분석을 불러왔습니다.",
        message: "최근 분석이 없습니다.",
    });
    assert.equal(nonzeroTotal.queryState, "empty");
    assert.equal(nonzeroTotal.totalRuns, 7);
    assert.strictEqual(nonzeroTotal.recentRuns, nonzeroTotalPayload.recent_runs);
});

test("Overview error is a query failure without Pipeline or 분석 failure semantics", () => {
    // Given
    const previousState = resolveOverviewQueryState(null, { kind: "loading" });

    // When
    const state = resolveOverviewQueryState(previousState, { kind: "error" });

    // Then
    assert.deepEqual(state, {
        queryState: "error",
        totalRuns: null,
        recentRuns: [],
        totalMessage: "전체 분석을 불러오지 못했습니다.",
        message: "최근 분석을 불러오지 못했습니다.",
    });
    assert.doesNotMatch(state.message, /Pipeline failed|분석 failed/i);
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

test("분석 List loading has no items and a loading message", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveRunListQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        items: [],
        message: "분석 목록을 불러오는 중입니다.",
    });
});

test("분석 List success preserves API order and reports the item count", () => {
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
    assert.equal(state.message, "분석 2건을 불러왔습니다.");
    assert.deepEqual(payload, payloadSnapshot);
});

test("분석 List empty returns no items and an empty message", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });
    const payload = { runs: [] };

    // When
    const state = resolveRunListQueryState(previousState, { kind: "success", payload });

    // Then
    assert.deepEqual(state, {
        queryState: "empty",
        items: [],
        message: "표시할 분석이 없습니다.",
    });
    assert.strictEqual(state.items, payload.runs);
});

test("분석 List error is a generalized query failure", () => {
    // Given
    const previousState = resolveRunListQueryState(null, { kind: "loading" });

    // When
    const state = resolveRunListQueryState(previousState, { kind: "error" });

    // Then
    assert.deepEqual(state, {
        queryState: "error",
        items: [],
        message: "분석 목록을 불러오지 못했습니다.",
    });
    assert.doesNotMatch(state.message, /Pipeline failed|분석 failed/i);
});

test("Overview success is preserved when 분석 List fails", () => {
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

test("분석 List success is preserved when Overview fails", () => {
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

test("분석 List query state rejects malformed results and payloads", () => {
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

test("실행 보고 Summary loading is independent and exposes no inferred 실행 보고 data", () => {
    // Given
    const previousState = null;

    // When
    const state = resolveRuntimeSummaryQueryState(previousState, { kind: "loading" });

    // Then
    assert.deepEqual(state, {
        queryState: "loading",
        items: [],
        telemetryAvailable: false,
        message: "실행 보고 정보를 불러오는 중입니다.",
    });
});

test("실행 보고 Summary success preserves API order and empty state", () => {
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
    assert.equal(success.message, "실행 보고 2건을 불러왔습니다.");
    assert.deepEqual(empty, {
        queryState: "empty",
        items: [],
        telemetryAvailable: true,
        message: "표시할 실행 보고 정보가 없습니다.",
    });
    assert.deepEqual(payload, payloadSnapshot);
});

test("Latest 실행 보고 report uses updated_at without reordering the API response", () => {
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

test("실행 보고 Summary accepts null current_stage for terminal states", () => {
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

test("실행 보고 Summary stale Running success preserves the Operations display contract", () => {
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

test("실행 보고 Summary error retains only its own last data without claiming liveness", () => {
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
    assert.equal(failedQuery.message, "실행 보고 정보를 불러오지 못했습니다.");
    assert.equal(failedQuery.telemetryAvailable, false);
    assert.equal(presentation.statusLabel, "실행 중(마지막 보고)");
    assert.equal(presentation.telemetryLabel, "확인 불가 (조회 실패)");
    assert.equal(presentation.livenessLabel, "확인 불가");
    assert.doesNotMatch(JSON.stringify(presentation), /현재 실행 중/);
});

test("실행 보고 Summary state rejects malformed results and payloads", () => {
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

test("Pipeline stages highlight only states justified by persisted 실행 보고 data", () => {
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
    assert.equal(completedStages.every((stage) => stage.state === "unknown"), true);
    // Overall completion cannot establish a path's stage history (Standalone has no Fast stage).
    const measuredStages = buildPipelineStagePresentation(completed, true, [
        { stage: "normalization", outcome: "completed" },
        { stage: "fusion", outcome: "completed" },
    ]);
    assert.equal(measuredStages[1].state, "completed");
    assert.equal(measuredStages[2].state, "completed");
    assert.equal(measuredStages[3].state, "unknown");
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

test("Stage summary separates no report, unconfirmed reports and query failures without inventing completion", () => {
    // Given
    const none = buildPipelineStagePresentation(null, true);
    const running = buildPipelineStagePresentation(
        { status: "running", current_stage: "fusion", is_stale: false, execution_id: "EX-1" }, true,
        [{ stage: "artifact_validation", outcome: "completed" }, { stage: "normalization", outcome: "completed" }],
    );
    const stale = buildPipelineStagePresentation({ status: "running", current_stage: "fusion", is_stale: true }, true);
    const failed = buildPipelineStagePresentation({ status: "failed", failed_stage: "hybrid" }, true);

    // When / Then
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: false }), { text: "처리 단계 기록 없음", tone: "none" });
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: false, unconfirmed: true }), { text: "단계 보고 확인 불가", tone: "none" });
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: false, queryState: "loading" }), { text: "확인 중", tone: "neutral" });
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: false, queryState: "error" }), { text: "조회 실패", tone: "error" });
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: false, queryState: "not_ready" }), { text: "조회 미지원", tone: "none" });
    assert.deepEqual(summarizePipelineStages(running, { hasRuntime: true, readFailed: true }), { text: "단계 계측 조회 실패", tone: "error" });
    assert.deepEqual(summarizePipelineStages(running, { hasRuntime: true }),
        { text: "완료 보고 2단계 · 진행 단계 보고 · 일부 단계 보고 없음", tone: "reported" });
    assert.deepEqual(summarizePipelineStages(stale, { hasRuntime: true }), { text: "마지막 보고 오래됨 · 일부 단계 보고 없음", tone: "warning" });
    assert.deepEqual(summarizePipelineStages(failed, { hasRuntime: true }), { text: "실패 보고 1단계 · 일부 단계 보고 없음", tone: "error" });
    // A report whose stages are all unmeasured is not described as complete or failed.
    assert.deepEqual(summarizePipelineStages(none, { hasRuntime: true }), { text: "완료 보고 없음", tone: "none" });
    assert.doesNotMatch(summarizePipelineStages(running, { hasRuntime: true }).text, /\/\s*6|정상|중단/);
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
    assert.equal(message("RUN-7", false, "RUN-7"), "검색 결과 1건 / 조회된 분석 10건");
    assert.equal(
        message("RUN-7", false, "RUN-2"),
        "검색 결과 1건 / 조회된 분석 10건 · 선택 유지: RUN-2 (검색 결과 밖)",
    );
    assert.equal(
        message("RUN-99", false, "RUN-2"),
        "현재 조회된 분석에서 일치하는 결과가 없습니다. · 선택 유지: RUN-2 (검색 결과 밖)",
    );
    assert.equal(message("RUN-99", false, null), "현재 조회된 분석에서 일치하는 결과가 없습니다.");
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
        "실행 보고 API 조회 실패 · 조회 범위 밖 항목의 현재 상태 확인 불가",
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
        "선택한 실행 보고이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
            + "저장 결과를 제한된 간격으로 다시 확인합니다 (1/5회).",
    );
    assert.match(exhausted, /저장 결과 재확인 5회를 마쳤지만 아직 결과가 없습니다/);
    assert.match(exhausted, /결과 다시 조회 버튼으로 저장 결과를 다시 조회할 수 있습니다/);
    assert.match(queryFailed, /^실행 보고 API 조회에 실패해/);
    assert.match(queryFailed, /실행 보고 조회가 복구되면 이어서 진행합니다/);
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
    assert.match(script, /분석 결정 버전이 달라 결과를 결합하지 않았습니다/);
    assert.match(script, /결정 ID를 비교할 수 없어 분석 상세 출처의 결과만 표시합니다/);
    assert.match(script, /결정 ID를 비교할 수 없어 Fusion Engine 출처의 결과만 표시합니다/);
    assert.match(script, /Fusion Engine 결정 ID를 확인할 수 없어 Trace를 결합하지 않았습니다/);
    assert.match(script, /분석 결정 없는 Fusion Engine 저장 결과를 단일 출처로 표시합니다/);
    assert.equal(analysisLoader.match(/Promise\.all\(\[/g)?.length, 2);
    assert.doesNotMatch(analysisLoader, /while \(|for \(/);
    assert.match(script, /getStoppingTraceAvailability\(stoppingTrace\)/);
    assert.match(script, /buildScoreTrajectoryModel\(/);
    assert.match(script, /createDashboardReplayChart\(/);
    assert.match(script, /const chartDecisionTime = decision === null \? undefined : decision\.t_e \?\? null;/);
    assert.match(script, /저장된 점수 기록 없음/);
    assert.match(script, /fusionResult\?\.fusion_status === "not_evaluated"/);
    assert.match(script, /증거 누적 분석 미평가 · 점수 기록 없음/);
    assert.match(script, /저장된 점수 0건/);
    assert.match(script, /fusionState\.queryState !== "success"/);
    assert.match(script, /판정 기준 미확인 · 저장 설정 없음/);
    assert.match(script, /createDashboardReplayRecords\(fusionResult, chartDecisionTime, presentation\.summary\)/);
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

test("Dashboard keeps dense Run tables while explaining Metadata separately", async () => {
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
    assert.match(script, /\["시나리오 ID", displayValue\(runMetadata\?\.scenario_id\)\]/);
    assert.match(script, /displayValue\(run\.target_host\)/);
    assert.match(script, /createRunTimestamp\(run\.start_time\)/);
    assert.match(script, /buildRunDetailViewPath\(run\.run_id\)/);
    const rowSource = script.slice(script.indexOf("function createRunRow("), script.indexOf("function createRunTimestamp("));
    assert.doesNotMatch(rowSource, /run\.run_type|getRunTypeLabel/);
    assert.match(html, /입력 유형/);
    // The list scope disclosure was removed on request; the filter no longer points at it.
    assert.doesNotMatch(html, /dashboard-runs-context|aria-describedby="dashboard-run-filter-scope"/);
    assert.match(html, /<table class="dashboard-table runtime-table">/);
    assert.match(html, /<th scope="col">분석 ID<\/th>\s*<th scope="col">Entity ID<\/th>/);
    assert.doesNotMatch(html, /분석 ID와 Entity ID 조합으로 선택/, "The API-order explanation was removed on request");
    assert.match(html, /id="selected-run-scope"/);
    assert.match(
        html,
        /<button id="selected-run-refresh" class="dashboard-analysis-refresh" type="button" hidden>결과 다시 조회<\/button>/,
    );
    assert.match(script, /createTableCell\(runtime\.entity_id\)/);
    assert.match(html, /<table class="dashboard-table runs-table">/);
    assert.doesNotMatch(html, /입력 이벤트 시작 시각 최근순 최대 20건/, "The list scope disclosure was removed on request");
    assert.match(html, /최근 실행 보고 조회 결과는\s+전체 실행 통계가 아닙니다/);
    assert.match(html, /조회 완료 후 약 5초 간격으로 실행 보고 상태 갱신/);
    assert.match(html, /<p class="dashboard-kpi__label">실행 보고<\/p>/);
    assert.match(html, /저장 분석 · 전체 <strong id="total-runs-value">/);
    assert.doesNotMatch(html, /최근 분석 상태|최근 처리 업데이트|가동 시간<\/p>/);
    assert.match(html, /<details class="dashboard-time-note">/);
    assert.match(html, /<summary>표시 기준 및 상태 안내<\/summary>/);
    assert.match(html, /class="dashboard-monitor-grid"/);
    assert.match(html, /id="selected-run-summary"/);
    // The Threshold settings list was removed on request.
    assert.doesNotMatch(html, /id="selected-run-settings"|Threshold 설정/);
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
    // Task 7-S: the run table lives in the system status disclosure above the list.
    assert.ok(
        html.indexOf('id="runtime-summary-heading"')
        < html.indexOf('id="runs-heading"'),
    );
    assert.ok(
        html.indexOf('id="selected-run-heading"')
        < html.indexOf("증거 누적 점수"),
    );
    assert.ok(html.indexOf('id="runs-heading"') < html.indexOf('id="selected-run-heading"'));
    assert.doesNotMatch(html, />Type<|>Run Type</);
    assert.match(script, /runsStatus\.textContent = state\.message;/);
    // Startup plus terminal-Runtime reconciliation; no separate Run polling loop.
    assert.equal(script.match(/void loadRuns\(\);/g)?.length, 2);
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
const WAITING_STATUS = "마지막 실행 보고는 실행 중이며 결과 저장을 기다리는 중입니다.";
const STORED_STATUS = "저장된 분석 결과를 불러왔습니다.";
const RECHECK_LOADING_STATUS = (
    "조회 범위를 벗어난 실행 보고의 저장 분석 결과를 다시 확인하는 중입니다."
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
        if (name === "class") this.classList.add(...String(value).split(" "));
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

    before(sibling) {
        const index = this.parentNode.childNodes.indexOf(this);
        sibling.parentNode = this.parentNode;
        this.parentNode.childNodes.splice(index, 0, sibling);
    }

    querySelector(selector) {
        return this.querySelectorAll(selector)[0] ?? null;
    }

    querySelectorAll(selector) {
        assert.match(selector, /^\.?[\w-]+$/);
        const className = selector.slice(1);
        const matches = [];
        const visit = (element) => {
            for (const child of element.childNodes) {
                if (selector.startsWith(".") ? child.classList.contains(className) : child.tagName === selector) {
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
async function startDashboardHarness({ extraElementIds = [], autoFollow = false } = {}) {
    const source = await readFile(new URL("dashboard.js", DASHBOARD_ASSETS_URL), "utf8");
    const document = {
        activeElement: null,
        elements: new Map(),
        createElement: (tagName) => Object.assign(new FakeElement(document), { tagName }),
        createElementNS: (_namespace, tagName) => Object.assign(new FakeElement(document), { tagName }),
        getElementById: (id) => document.elements.get(id) ?? null,
    };
    for (const [, id] of source.matchAll(/document\.getElementById\("([^"]+)"\)/g)) {
        document.elements.set(id, new FakeElement(document));
    }
    for (const id of extraElementIds) {
        document.elements.set(id, new FakeElement(document));
    }
    // Existing selection scenarios exercise explicit Auto Off. New follow scenarios use On.
    document.getElementById("pipeline-auto-follow").checked = autoFollow;

    const requests = [];
    const persistedRuntime = new Map();
    let runtimeReady = false, runtimeError = false;
    const settleContexts = () => {
        for (const request of requests.filter(r => !r.settled && r.url.startsWith("/operations/runtime-context?"))) {
            const query = new URL(request.url, "http://test.invalid").searchParams;
            const all = [...persistedRuntime.values()].sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
            const pipeline = all.find(r => r.status === "running") ?? all[0] ?? null;
            request.settled = true;
            request.resolve({ ok: !runtimeError, status: runtimeError ? 503 : 200, json: async () => ({
                schema_version: "dashboard_runtime_context_v1", generated_at: "2026-10-09T00:03:00Z", pipeline,
                scopes: query.getAll("run_id").map((run_id, index) => {
                    const entity_id = query.getAll("entity_id")[index];
                    return { run_id, entity_id, runtime: persistedRuntime.get(JSON.stringify([run_id, entity_id])) ?? null };
                }),
            }) });
        }
    };
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
            if (runtimeReady && request.url.startsWith("/operations/runtime-context?")) {
                queueMicrotask(() => {
                    if (!requests.some(r => !r.settled && r.url === RUNTIME_API_PATH)) settleContexts();
                });
            }
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
        delete globalThis.__dashboardWorkflowOptions;
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
        { newest = false, deferJson = false, ignoreBodyAbort = false } = {},
    ) => {
        const pending = requests.filter(
            (candidate) => !candidate.settled && candidate.url === url,
        );
        const request = newest ? pending.at(-1) : pending[0];
        assert.ok(request, `Expected a pending request for ${url}`);
        request.settled = true;
        if (url === RUNTIME_API_PATH) {
            runtimeReady = true; runtimeError = status !== 200;
            if (status === 200) for (const item of body.items) persistedRuntime.set(JSON.stringify([item.run_id, item.entity_id]), item);
            settleContexts();
        }
        request.resolve({
            ok: status >= 200 && status < 300,
            status,
            json: async () => {
                if (!deferJson) {
                    return body;
                }
                return new Promise((resolve, reject) => {
                    request.jsonResolve = resolve;
                    // ignoreBodyAbort models a body that still arrives after abort().
                    if (ignoreBodyAbort) {
                        return;
                    }
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
        "const createDashboardTelemetryController = () => ({ start() {}, stop() {}, async poll() { return true; } });",
    ).replace(
        'import { createHumanWorkflowController } from "./dashboard-workflow-controller.mjs";',
        // Task 6: the stub keeps its callbacks so a test can publish already-loaded alerts.
        "const createHumanWorkflowController = (_document, options) => { globalThis.__dashboardWorkflowOptions = options; return ({ async select() {}, savedSelection() { return null; } }); };",
    ).replace(
        'import { createKisaFormController } from "./dashboard-kisa-controller.mjs";',
        "const createKisaFormController = () => ({ async setDraft() {} });",
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
        allRequests: () => requests.map((request) => ({ url: request.url, method: request.options.method ?? "GET" })),
        workflowOptions: () => globalThis.__dashboardWorkflowOptions,
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

test("Auto On follows latest Pipeline independently of past incident selection and observed failure", async (t) => {
    // Given
    const latest = runtimeReport("RUN-NEW", "WIN-N", "running", "persistence");
    const previous = runtimeReport("RUN-OLD", "WIN-O", "completed", null);
    previous.updated_at = "2026-10-09T00:00:00Z";
    const harness = await startDashboardWithRuntime([latest, previous],
        [runListItem("RUN-NEW", "WIN-N"), runListItem("RUN-OLD", "WIN-O")], {autoFollow:true});
    t.after(harness.restore);
    // When
    harness.runButton("RUN-OLD").click();await harness.flush();
    // Then
    assert.match(harness.text("pipeline-stage-context"), /분석 RUN-NEW · Entity WIN-N/);
    assert.equal(harness.text("selected-run-id"), "RUN-OLD");
    assert.equal(harness.stageStates()[5], "current");
    assert.ok(harness.stageStates().slice(0,5).every(s=>s==="unknown"));
    // When / Then: terminal failure is actual saved Runtime, not synthesized transitions.
    await harness.poll([{...latest,status:"failed",current_stage:null,failed_stage:"persistence",has_error:true},previous]);
    assert.match(harness.text("pipeline-stage-context"), /RUN-NEW.*실패/);
    assert.equal(harness.stageStates()[5], "failed");
    assert.equal(harness.text("selected-run-id"), "RUN-OLD");
});

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

test("Stored Run index reconciles first-seen completion without guessing missing/failed executions", () => {
    // Given
    const completed = runtimeReport("RUN-A", "WIN-A", "completed", null);
    const anotherExecution = { ...completed, execution_id: "another-execution" };
    // When / Then
    assert.equal(shouldRefreshStoredRunIndex([], [completed]), true);
    assert.equal(shouldRefreshStoredRunIndex([completed], [completed]), false);
    assert.equal(shouldRefreshStoredRunIndex([completed], [anotherExecution]), true);
    assert.equal(shouldRefreshStoredRunIndex([completed], []), false);
    assert.equal(shouldRefreshStoredRunIndex([], [runtimeReport("RUN-B", "WIN-B", "failed", null)]), false);
});

test("A fast new completed Run refreshes the list once without replacing the selected Run", async (t) => {
    // Given
    const old = runListItem("RUN-A", "WIN-A");
    const added = runListItem("RUN-B", "WIN-B");
    const harness = await startDashboardWithRuntime([], [old]);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-A", storedDetail("RUN-A", "WIN-A"), storedFusion("RUN-A", "WIN-A"));
    const focus = harness.document.getElementById("dashboard-run-search");
    focus.focus();
    // When: RUN-B started and finished entirely between two 5-second polls.
    const completed = runtimeReport("RUN-B", "WIN-B", "completed", null);
    await harness.poll([completed]);
    assert.equal(harness.requestCount("/runs?limit=20"), 2);
    assert.equal(harness.requestCount("/overview"), 2);
    await harness.respond("/runs?limit=20", 200, { runs: [added, old] });
    await harness.respond("/overview", 200, { total_runs: 2, recent_runs: [added, old] });
    await harness.poll([completed]);
    // Then
    assert.equal(harness.text("selected-run-id"), "RUN-A");
    assert.equal(harness.requestCount("/runs?limit=20"), 2);
    assert.deepEqual(harness.runRows().map(row => row.runId), ["RUN-B", "RUN-A"]);
    assert.equal(harness.document.activeElement, focus);
});

test("Completion queues a fresh Run index after an older in-flight list snapshot", async (t) => {
    // Given
    const harness = await startDashboardHarness();
    t.after(harness.restore);
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    // When: the first list/overview reads still represent the pre-commit state.
    await harness.poll([runtimeReport("RUN-NEW", "WIN-A", "completed", null)]);
    assert.equal(harness.requestCount("/runs?limit=20"), 1);
    await harness.respond("/overview", 200, { total_runs: 0, recent_runs: [] });
    await harness.respond("/runs?limit=20", 200, { runs: [] });
    // Then: one post-completion read must replace that old snapshot.
    assert.equal(harness.requestCount("/runs?limit=20"), 2);
    assert.equal(harness.requestCount("/overview"), 2);
    const added = runListItem("RUN-NEW", "WIN-A");
    await harness.respond("/overview", 200, { total_runs: 1, recent_runs: [added] });
    await harness.respond("/runs?limit=20", 200, { runs: [added] });
    assert.equal(harness.runRows()[0].runId, "RUN-NEW");
});

test("Selected completion invalidates the open Evidence cache but keeps its tab and focus", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime(
        [runtimeReport("RUN-A", "WIN-A", "running", "normalization")], [],
        { extraElementIds: EVIDENCE_ELEMENT_IDS },
    );
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const tab = harness.document.getElementById("dashboard-tab-evidence");
    tab.click(); tab.focus();
    await harness.flush();
    const path = evidencePath("RUN-A");
    await harness.respond(path, 200, evidencePayload({ runId: "RUN-A", availability: "no_archive" }));
    // When
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null)]);
    // Then
    assert.equal(harness.requestCount(path), 2);
    assert.equal(tab.getAttribute("aria-selected"), "true");
    assert.equal(harness.document.activeElement, tab);
    await harness.respond(path, 200, evidencePayload({ runId: "RUN-A", availability: "no_archive" }));
    assert.equal(harness.text("evidence-status"), "", "no_archive has no status sentence");
});

test("Main refresh joins startup reads and ignores repeated activation without moving focus", async (t) => {
    // Given: the first three API reads are still pending.
    const harness = await startDashboardHarness();
    t.after(harness.restore);
    const button = harness.document.getElementById("dashboard-refresh");
    button.focus();
    // When
    button.click();
    button.click();
    await harness.flush();
    // Then: startup reads are shared, not duplicated.
    for (const path of ["/overview", "/runs?limit=20", RUNTIME_API_PATH]) {
        assert.equal(harness.requestCount(path), 1);
    }
    assert.equal(button.getAttribute("aria-disabled"), "true");
    await harness.respond("/overview", 200, { total_runs: 0, recent_runs: [] });
    await harness.respond("/runs?limit=20", 200, { runs: [] });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.flush();
    assert.equal(button.getAttribute("aria-busy"), "false");
    assert.match(harness.text("dashboard-refresh-status"), /화면 재조회 완료/);
    assert.equal(harness.document.activeElement, button);
    assert.equal(harness.timerCount(5000), 1);
});

test("Empty Run overview keeps its accessible announcement without a duplicate layout row", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], []);
    t.after(harness.restore);
    const status = harness.document.getElementById("overview-status");
    // When / Then
    assert.equal(harness.text("total-runs-value"), "0");
    assert.equal(status.classList.contains("dashboard-visually-hidden"), true);
    assert.ok(status.textContent.length > 0);
    harness.document.getElementById("dashboard-refresh").click();
    await harness.respond("/overview", 503, {});
    await harness.respond("/runs?limit=20", 200, { runs: [] });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.flush();
    assert.equal(status.classList.contains("dashboard-visually-hidden"), false);
});

test("Main refresh rereads fetched scope while retaining query, type, selection and closed Evidence", async (t) => {
    // Given
    const runs = [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")];
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    harness.typeSearch("RUN-A");
    const type = harness.document.getElementById("dashboard-run-type");
    type.value = "attack";
    type.listeners.get("change")[0]();
    const button = harness.document.getElementById("dashboard-refresh");
    // When: repeat activation and the scheduled poll must join the same Runtime read.
    button.click();
    button.click();
    await harness.triggerTimers(5000);
    await harness.respond("/overview", 200, { total_runs: 2, recent_runs: runs });
    await harness.respond("/runs?limit=20", 200, { runs });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    await harness.respond(buildEventTimelineApiPath("RUN-A", 50, 0), 200, { items: [], total: 0, limit: 50, offset: 0 });
    await harness.flush();
    // Then
    assert.equal(harness.requestCount(RUNTIME_API_PATH), 2);
    assert.equal(harness.requestCount("/runs?limit=20"), 2);
    assert.equal(harness.text("selected-run-id"), "RUN-A");
    assert.equal(harness.document.getElementById("dashboard-run-search").value, "RUN-A");
    assert.equal(type.value, "attack");
    assert.equal(harness.requestCount(evidencePath("RUN-A")), 0);
    assert.equal(button.getAttribute("aria-busy"), "false");
});

test("Main refresh reports API failure, releases its guard and can retry without a reload", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], []);
    t.after(harness.restore);
    const button = harness.document.getElementById("dashboard-refresh");
    // When
    button.click();
    await harness.respond("/overview", 503, {});
    await harness.respond("/runs?limit=20", 503, {});
    await harness.respond(RUNTIME_API_PATH, 503, {});
    await harness.flush();
    // Then
    assert.match(harness.text("dashboard-refresh-status"), /일부 조회 실패/);
    assert.equal(button.getAttribute("aria-disabled"), "false");
    // When / Then: explicit recovery.
    button.click();
    await harness.respond("/overview", 200, { total_runs: 0, recent_runs: [] });
    await harness.respond("/runs?limit=20", 200, { runs: [] });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.flush();
    assert.match(harness.text("dashboard-refresh-status"), /화면 재조회 완료/);
    assert.equal(harness.requestCount("/overview"), 3);
});

test("Pipeline copy names the missing completion proof and stale last report, not live execution", () => {
    // Given
    const stale = runtimeReport("RUN-A", "WIN-A", "running", "normalization");
    stale.is_stale = true;
    // When
    const missing = buildPipelineStagePresentation(null, true);
    const stages = buildPipelineStagePresentation(stale, true);
    // Then
    assert.ok(missing.every(stage => stage.stateLabel === "완료 보고 없음"));
    assert.equal(stages.find(stage => stage.stage === "normalization").stateLabel, "마지막 보고 · 오래됨");
});

test("Main refresh does not start secondary reads after pagehide", async (t) => {
    // Given
    const runs = [runListItem("RUN-A", "WIN-A")];
    const harness = await startDashboardWithRuntime([], runs);
    t.after(harness.restore);
    await harness.respondAnalysis("RUN-A", notFound(), notFound());
    const detailPath = buildRunDetailApiPath("RUN-A");
    const before = harness.requestCount(detailPath);
    // When
    harness.document.getElementById("dashboard-refresh").click();
    await harness.dispatchWindowEvent("pagehide");
    await harness.respond("/overview", 200, { total_runs: 1, recent_runs: runs });
    await harness.respond("/runs?limit=20", 200, { runs });
    await harness.respond(RUNTIME_API_PATH, 200, { items: [] });
    await harness.flush();
    // Then
    assert.equal(harness.requestCount(detailPath), before);
    assert.equal(harness.document.getElementById("dashboard-refresh").getAttribute("aria-busy"), "false");
});

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
    assert.equal(harness.document.getElementById("dashboard-tab-summary").getAttribute("aria-selected"), "true");
    tab.click();
    await harness.flush();
    await harness.respond(evidencePath("RUN-B"), 200, evidencePayload({ runId: "RUN-B", availability: "no_archive" }));
    await harness.respondAnalysis("RUN-B", notFound(), notFound());
    harness.document.getElementById("selected-run-refresh").click();
    await harness.flush();

    // Then
    assert.equal(beforeTab, 0);
    assert.equal(shown.rows, 1);
    assert.match(shown.status, /^증거 조회 완료 · 검증된 1건/);
    assert.equal(shown.focused, true);
    assert.equal(readsForRunA, 1);
    assert.equal(clearedOnRunChange, 0);
    assert.equal(status.textContent, "선택한 분석의 증거 아카이브를 조회하는 중입니다.");
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
    assert.deepEqual(runOnlyWithRuntime, { label: "비교 대상 없음", caption: "실행 보고 선택 필요", rows: 0 });
    assert.equal(runOnlyWithoutRuntime, "실행 보고 없음");
    assert.deepEqual(afterRuntimeFailure, { label: "비교 대상 없음", caption: "실행 보고 조회 실패" });
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
    assert.equal(context.textContent, `선택 항목 · RUN-A · WIN-A · ${RUNNING_LABEL}`);

    // When / Then
    await harness.poll([runtimeReport("RUN-A", "WIN-A", "completed", null), second]);
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `선택 항목 · RUN-A · WIN-A · ${COMPLETED_LABEL}`);
    assert.deepEqual(harness.stageStates(), Array(6).fill("unknown"));
    harness.runtimeButton("RUN-A", "WIN-B").click();
    await harness.flush();
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `선택 항목 · RUN-A · WIN-B · ${RUNNING_LABEL}`);
    assert.deepEqual(harness.stageStates(), ["unknown", "unknown", "unknown", "unknown", "current", "unknown"]);
    await harness.pollFailure();
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.equal(context.textContent, `선택 항목 · RUN-A · WIN-B · ${RUNNING_LABEL}`);
    assert.match(harness.text("runtime-top-status"), /불러오지 못했습니다/);
    await harness.poll(otherRunningReports());
    assert.strictEqual(harness.document.getElementById("pipeline-stage-context"), context);
    assert.match(context.textContent, /^선택 항목 · RUN-A · WIN-B · 최근 5건 조회 범위 밖/);
    assert.equal(context.hidden, false);
    assert.equal(harness.stageStates().length, 6);
    // Outside the query range the report may still exist, so the summary never says "no report".
    assert.equal(harness.text("pipeline-status-note"), "단계 보고 확인 불가");
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
    assert.deepEqual(harness.stageStates(), Array(6).fill("unknown"));
    assert.deepEqual(icons(), expectedIcons);
    assert.equal(new Set(icons()).size, 6);
    assert.match(harness.text("pipeline-stage-list"), /완료/);
});

test("Dashboard opens the case summary and switches detail tabs without changing the selection", async (t) => {
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
        { tab: "true", hidden: false },
        { tab: "false", hidden: true },
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
    const link = row.querySelectorAll(".dashboard-run-detail-link")[0];
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
    return recentRunRow(harness, runId).querySelectorAll(".dashboard-run-detail-link")[0];
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
        assert.equal(restored.textContent, "기술 상세");
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
    assert.notEqual(afterRowMove.textContent, "분석 상세");
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
    assert.match(getRunListVisibilityMessage(attack, "RUN-B"), /필터 결과 2건.*조회된 분석 4건.*유형 attack.*최대 20건.*선택 유지/);
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
        status: "검색 결과 1건 / 조회된 분석 10건 · 선택 유지: RUN-0 (검색 결과 밖)",
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

test("Run search preserves selection and limits previous/next to the filtered list", async (t) => {
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
        status: "검색 결과 1건 / 조회된 분석 10건 · 선택 유지: RUN-7 (검색 결과 밖)",
        requests: 0,
    });
    assert.deepEqual(afterPrevious, { selected: "RUN-7", ids: ["RUN-2"] });
    assert.equal(afterNext, "RUN-7");
    assert.equal(harness.text("selected-run-id"), "RUN-2");
    assert.equal(harness.runButton("RUN-2").getAttribute("aria-pressed"), "true");
    assert.equal(harness.requestCount(buildRunDetailApiPath("RUN-2")), 1);
    assert.deepEqual(visibleRunIds(harness), ["RUN-2"]);
    assert.equal(harness.text("runs-visibility-status"), "검색 결과 1건 / 조회된 분석 10건");
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
        label: "전체 10개 분석 펼치기",
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
        runtimeStatusUpdated: recentRunRow(harness, "RUN-6").children[3].textContent.includes(RUNNING_LABEL),
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
        status: "현재 조회된 분석에서 일치하는 결과가 없습니다. · 선택 유지: RUN-0 (검색 결과 밖)",
        queryStatusHidden: true,
        ids: [],
    });
    assert.equal(failed.text("runs-visibility-status"), "");
    assert.equal(failed.document.getElementById("runs-status").hidden, false);
    assert.match(failed.text("runs-status"), /분석 목록을 불러오지 못했습니다/);
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
        "조회 이벤트 2건 / 전체 75건",
    );
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    assert.doesNotMatch(html, /aria-label="연관 Event 집계 기준"/);
    assert.match(html, /id="event-type-summary"/);
    assert.doesNotMatch(html, /Event 시각과 기술적 판정 시각은 별도 의미입니다/);
    assert.equal(harness.requestCount(timelinePath), 1);
});

// Task 6: one stored Decision record as label -> value, read from its own field list.
function decisionRecordFieldMap(item) {
    const fields = [item.querySelector(".dashboard-decision-record__fields"), item.querySelector(".dashboard-decision-record__technical-fields")];
    const values = fields.flatMap((list) => list.childNodes.map((field) => [field.childNodes[0].textContent, field.childNodes[1].textContent]));
    const reason = item.querySelector(".dashboard-decision-record__reason");
    if (reason) values.push(["판단 사유", reason.childNodes[1].textContent]);
    return Object.fromEntries(values);
}

test("Task 6 stored 분석 결정 history lives only in the 기록 tab, newest first, without a storage time", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A", "WIN-A", "DEC-2");
    detail.body.decision_history = [
        { decision_id: "DEC-2", decision_path: "fusion", t_e: "2026-10-09T00:02:00Z", supersedes_decision_id: "DEC-1" },
        { decision_id: "DEC-1", decision_path: "fast", t_e: "2026-10-09T00:01:00Z" },
    ];

    // When
    await harness.respondAnalysis("RUN-A", detail, storedFusion("RUN-A", "WIN-A", "DEC-2"));
    const history = harness.text("decision-history-list");
    const entries = harness.document.getElementById("decision-history-list").childNodes;

    // Then
    assert.equal(harness.document.getElementById("decision-timeline-list"), null, "The score tab repeats no Decision list");
    assert.doesNotMatch(harness.text("selected-run-chart"), /DEC-2|DEC-1/);
    assert.equal(harness.text("decision-history-status"), "", "The record labels carry the order; no status sentence");
    assert.ok(history.indexOf("DEC-2") < history.indexOf("DEC-1"));
    assert.deepEqual(entries.map((item) => item.querySelector(".dashboard-decision-record__header").textContent), [
        "현재 결정종합 판단 상태 확인 필요", "이전 결정 1종합 판단 상태 확인 필요"]);
    assert.ok(entries[0].classList.contains("dashboard-decision-record--current"));
    assert.equal(entries[1].classList.contains("dashboard-decision-record--current"), false);
    const [current, previous] = entries.map(decisionRecordFieldMap);
    assert.equal(current["종합 판단 시각"], "확정 · 2026.10.09 09:02:00 KST");
    assert.equal(current["종합 판단 경로"], "확정 · 증거 누적 분석");
    assert.equal(current["이전 결정 연결"], "DEC-1를 대체한 결정");
    assert.equal(previous["이전 결정 연결"], "연결된 이전 결정 없음");
    assert.equal(previous["종합 판단 경로"], "확정 · 즉시 규칙 분석");
    assert.equal(Object.keys(current).some((label) => /저장 ?시각|기록 ?시각/.test(label)), false);
    assert.doesNotMatch(history, /Alert Sent|Analyst Ack|24h/);
});

test("Task 6 a single stored Decision is the current record with its identity and raw JSON", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A", "WIN-A", "DEC-1");
    detail.body.decision_history = [
        { decision_id: "DEC-1", decision_path: "fast_and_fusion", t_e: "2026-10-09T00:02:00Z" },
    ];

    // When
    await harness.respondAnalysis("RUN-A", detail, storedFusion("RUN-A", "WIN-A", "DEC-1"));
    const entries = harness.document.getElementById("decision-history-list").childNodes;

    // Then
    assert.equal(entries.length, 1);
    assert.equal(entries[0].querySelector(".dashboard-decision-id").textContent, "DEC-1");
    const fields = decisionRecordFieldMap(entries[0]);
    assert.equal(fields["종합 판단 시각"], "확정 · 2026.10.09 09:02:00 KST");
    assert.equal(fields["종합 판단 경로"], "확정 · 즉시 규칙·증거 누적 분석");
    assert.match(fields["결정 ID"], /DEC-1/);
    const contents = entries[0].textContent;
    assert.match(contents, /판단 식별 정보·버전·원문/);
    assert.match(contents, /"decision_id": "DEC-1"/);
});

test("Task 6 no stored 분석 결정 and a failed 분석 상세 read stay distinct in the 기록 tab", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
    t.after(harness.restore);
    // When
    await harness.respondAnalysis("RUN-A", storedDetail("RUN-A", "WIN-A"), storedFusion("RUN-A", "WIN-A"));
    const empty = harness.text("decision-history-status");
    harness.runButton("RUN-B").click();
    await harness.respondAnalysis("RUN-B", { status: 503, body: { detail: "unavailable" } }, storedFusion("RUN-B", "WIN-B"));
    // Then
    assert.equal(empty, "저장된 분석 결정 이력이 없습니다.");
    assert.notEqual(harness.text("decision-history-status"), empty);
    assert.equal(harness.document.getElementById("decision-history-list").childNodes.length, 0);
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

test("Observation list shows execution progress only for the exact Run and Entity report", async t => {
    const other = runtimeReport("RUN-A", "WIN-B", "running", "normalization");
    const matching = { ...runtimeReport("RUN-A", "WIN-A", "running", "normalization"),
        normalization_processed_count: 7, remaining_count: 3 };
    const harness = await startDashboardWithRuntime([other], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const cells = () => harness.document.getElementById("runs-list").children[0].children;
    assert.match(cells()[1].textContent, /WIN-A/);
    assert.doesNotMatch(cells()[3].textContent, /실행 보고 ·|7 \/ 10/);
    await harness.poll([other, matching]);
    assert.match(cells()[3].textContent, /실행 보고 ·.*7 \/ 10 처리/);
    await harness.poll([other, { ...matching, is_stale: true }]);
    assert.match(cells()[3].textContent, /오래됨/);
    await harness.pollFailure();
    assert.doesNotMatch(cells()[3].textContent, /최근 갱신/);
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
    const emptyReportLine = harness.document.getElementById("latest-runtime-line").hidden;
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
        top: "실행 보고 정보를 불러오는 중입니다.",
        summary: "실행 보고 정보를 불러오는 중입니다.",
    });
    // No report is stated once, by the KPI; no extra status sentence.
    assert.deepEqual(empty, { top: "", summary: "" });
    assert.equal(emptyKpi, "");
    assert.equal(emptyReportLine, true);
    assert.equal(emptyAccessible, true);
    assert.deepEqual(emptyStages, Array(6).fill("unknown"));
    assert.deepEqual(success, {
        top: "",
        summary: "실행 보고 1건을 불러왔습니다.",
    });
    assert.deepEqual(error, {
        top: "실행 보고 정보를 불러오지 못했습니다.",
        summary: "실행 보고 정보를 불러오지 못했습니다.",
    });
    assert.equal(topStatus.classList.contains("dashboard-visually-hidden"), false);
});

test("Compact Run timestamps retain KST seconds, timezone and the original instant", async (t) => {
    // Given
    const run = { ...runListItem("RUN-20261008-920", "R1-TGTA"), start_time: "2026-10-08T18:49:53.429Z" };
    const harness = await startDashboardWithRuntime([], [run]);
    t.after(harness.restore);

    // When
    const cells = harness.document.getElementById("runs-list").children[0].children;
    const time = cells[0].querySelectorAll(".dashboard-run-time")[0];
    const instant = new Date(run.start_time);

    // Then
    assert.equal(time.getAttribute("datetime"), run.start_time);
    assert.equal(time.getAttribute("title"), formatRunTimestamp(run.start_time));
    assert.equal(time.getAttribute("aria-label"), formatRunTimestamp(run.start_time));
    // 18:49:53Z is the next KST day; the literals hold in any test-process time zone.
    assert.equal(instant.toISOString(), run.start_time);
    assert.equal(time.textContent, "2026.10.09 03:49:53.429 ");
    assert.match(cells[0].textContent, /KST/);
    assert.match(cells[0].querySelectorAll(".dashboard-run-range")[0].title, /시작 원본 2026-10-08T18:49:53\.429Z/);
    assert.match(cells[5].textContent, /RUN-20261008-920/);
    assert.match(cells[1].textContent, /R1-TGTA/);
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
        { label: "탐지 시각", value: "즉시 규칙 분석 · 탐지 시각 미확인 · 종합 판단 시각: 2026.10.09 09:02:00 KST", primary: true, setting: false },
        { label: "기여 증거", value: "미확인", primary: true, setting: false },
        { label: "원본 검증", value: "검증 상태 미조회", primary: true, setting: false },
    ]);
    assert.deepEqual(harness.analysisFields("selected-run-paths").map(row => [row.label, row.value]), [
        ["즉시 규칙 분석", "의심 행위 탐지"], ["증거 누적 분석", "탐지 기준 미충족"],
    ]);
    assert.equal(harness.text("selected-run-judgment"), "종합 판단 완료 · 의심 행위 탐지");
    assert.equal(selectedResultValues(harness)["종합 판단 경로"], "즉시 규칙 분석");
    assert.equal(selectedResultValues(harness)["실행 보고"], "실행 보고 없음");
    assert.deepEqual(harness.analysisFields("selected-run-settings"), [
        { label: "Threshold On", value: "0.8", primary: false, setting: true },
        { label: "Threshold Off", value: "0.4", primary: false, setting: true },
    ]);
    assert.equal(harness.text("selected-run-detail-status"), "");
    assert.equal(harness.text("selected-run-chart-status"), "저장된 점수 기록 없음");
});

for (const [name, score, decisionScore, episodes, ids] of [
    ["miss", 0.5, null, [], []],
    ["detected", 1, 1, [{ start_time: "2026-10-09T00:00:10Z", end_time: null }], ["E-A", "E-B"]],
]) {
    test(`Dashboard ${name} context explains stored Hybrid state and clears on another selection`, async (t) => {
        const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
        t.after(harness.restore);
        const detail = storedDetail("RUN-A", "WIN-A", "DEC-A");
        detail.body.run.run_type = "attack";
        detail.body.current_decision.decision = { decision_id: "DEC-A", fast_status: "not_evaluated",
            fusion_status: name, t_e: null, decision_path: null, winning_path: null, config_version: "parallel-v0.2",
            decision_reason: "Required parallel evaluation was not completed" };
        const fusion = storedFusion("RUN-A", "WIN-A", "DEC-A");
        fusion.body.fusion_result = { run_id: "RUN-A", entity_id: "WIN-A", scoring_config_version: "C",
            score_at_decision: decisionScore, fusion_episodes: episodes, contributing_evidence_ids: ids };
        fusion.body.stopping_trace = { run_id: "RUN-A", entity_id: "WIN-A", scoring_config_version: "C",
            points: [{ timestamp: "2026-10-09T00:00:00Z", score: 0, policy_state: "off", persistence_count: null },
                { timestamp: "2026-10-09T00:00:10Z", score, policy_state: "off", persistence_count: null }] };
        await harness.respondAnalysis("RUN-A", detail, fusion);
        assert.match(harness.text("selected-run-metadata-note"), /run_type: attack.*원본 수집 라벨과 별도/);
        assert.equal(harness.text("selected-run-hybrid-note"), "종합 판단 미완료 · 즉시 규칙 분석 미평가");
        assert.match(harness.text("selected-run-fusion-summary"), new RegExp(`Trace 최대 ${score}`));
        assert.match(harness.text("selected-run-fusion-summary"), new RegExp(`판단 시 score ${decisionScore ?? "미확정"}`));
        assert.equal(harness.document.getElementById("selected-run-contributing-ids").children.length, ids.length);
        assert.equal(harness.document.getElementById("selected-run-event-provenance-link").href, "/dashboard/runs/RUN-A/timeline");
        assert.equal(detail.body.current_decision.decision.t_e, null);
        assert.equal(detail.body.current_decision.decision.decision_path, null);
        harness.runButton("RUN-B").click();
        await harness.flush();
        assert.equal(harness.document.getElementById("selected-run-explanation").hidden, true);
        assert.equal(harness.text("selected-run-hybrid-note"), "");
        assert.equal(harness.document.getElementById("selected-run-contributing-ids").children.length, 0);
    });
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
        status: "Fusion Engine 조회에 실패해 분석 상세 출처의 결과만 표시합니다.",
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
        "분석 상세 조회에 실패해 Fusion Engine 출처의 결과만 표시합니다.",
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
        status: "선택한 분석의 상세 결과를 불러오지 못했습니다.",
        disabled: false,
    });
    assert.deepEqual(afterNotFound, {
        status: "선택한 분석에 저장된 상세 결과가 없습니다.",
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
        "Fusion Engine 조회에 실패해 분석 상세 출처의 결과만 표시합니다.",
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
            label: "분석 RUN-A, Entity WIN-A",
            pressed: "false",
            selected: false,
        },
        {
            runId: "RUN-A",
            entityId: "WIN-B",
            entityCell: "WIN-B",
            label: "분석 RUN-A, Entity WIN-B",
            pressed: "true",
            selected: true,
        },
    ]);
    assert.deepEqual(runtimeSelection.runRows, [
        { runId: "RUN-A", entityId: null, pressed: "false", selected: false },
    ]);
    assert.equal(runtimeSelection.context, `선택 항목 · RUN-A · WIN-B · ${RUNNING_LABEL}`);
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
    assert.match(runListSelection.context, /^선택 항목 · Entity 미지정/);
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
        `선택 항목 · RUN-A · WIN-B · ${COMPLETED_LABEL}`,
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
        "마지막 실행 보고가 실패했습니다. 상세 결과 자동 재조회는 수행하지 않습니다.",
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
        "선택 항목 · RUN-A · WIN-B · 최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)",
    );
    assert.equal(leftQuery.stages.every((state) => state === "unknown"), true);
    assert.equal(leftQuery.status, RECHECK_LOADING_STATUS);
    assert.equal(leftQuery.detailRequests, 2);
    assert.equal(leftQuery.pendingDetailRequests, 1);
    assert.deepEqual(leftQuery.selectedRows, []);
    assert.equal(requestsWhileRecheckPending, 2);
    assert.equal(
        afterFirstRecheck,
        "선택한 실행 보고이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
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
        "선택 항목 · RUN-A · WIN-B · 실행 보고 API 조회 실패 · 조회 범위 밖 항목의 현재 상태 확인 불가",
    );
    assert.match(duringFailure.status, /^실행 보고 API 조회에 실패해/);
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
        "선택한 분석의 저장 분석 결과를 불러오는 중입니다.",
    );
    assert.match(afterDelayedResponse.scope, /Entity WIN-C/);
    assert.doesNotMatch(afterDelayedResponse.scope, /WIN-B/);
    assert.equal(afterDelayedResponse.context, `선택 항목 · RUN-C · WIN-C · ${COMPLETED_LABEL}`);
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
        "선택한 실행 보고이 최근 5건 조회 범위를 벗어나 현재 상태를 확인할 수 없습니다. "
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
        status: "선택한 분석의 저장 분석 결과를 다시 조회하는 중입니다.",
    });
    assert.equal(requestsAfterDuplicateClick, exhausted.detailRequests + 1);
    assert.equal(refreshed.runId, "RUN-A");
    assert.equal(refreshed.status, STORED_STATUS);
    assert.match(refreshed.scope, /Entity WIN-B\. 저장 분석 대상 RunMetadata\.target_host도 WIN-B/);
    assert.equal(
        refreshed.context,
        "선택 항목 · RUN-A · WIN-B · 최근 5건 조회 범위 밖 · 현재 상태 확인 불가 (완료/실패로 추정하지 않음)",
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
        status: "선택한 분석의 상세 결과를 불러오지 못했습니다.",
        disabled: false,
    });
    assert.deepEqual(mismatch, {
        status: "분석 상세과 Fusion Engine의 분석 결정 버전이 달라 결과를 결합하지 않았습니다.",
        chartStatus: "조회 시점이 일치하지 않아 Fusion Trace를 표시하지 않습니다.",
    });
    assert.equal(harness.text("selected-run-status"), STORED_STATUS);
    assert.match(
        harness.text("selected-run-scope"),
        /분석 목록 선택: run_id 범위입니다\. 저장 분석 대상은 RunMetadata\.target_host WIN-A/,
    );
    assert.match(harness.text("pipeline-stage-context"), /^선택 항목 · Entity 미지정/);
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
    assert.equal(current.context, `선택 항목 · RUN-A · WIN-A · ${RUNNING_LABEL}`);
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


test("Missing Fast execution and unknown timing outcomes never become completed analysis", () => {
    // Given
    const runtime = { status: "completed", current_stage: null, is_stale: false };
    const records = [
        { stage: "fusion", outcome: "completed" },
        { stage: "normalization", outcome: "unknown" },
        { stage: "persistence", outcome: "failed" },
    ];
    // When
    const stages = buildPipelineStagePresentation(runtime, true, records);
    // Then
    assert.equal(stages.find(stage => stage.stage === "fusion").state, "completed");
    assert.equal(stages.find(stage => stage.stage === "fast_handoff").state, "unknown");
    assert.equal(stages.find(stage => stage.stage === "normalization").state, "unknown");
    assert.equal(stages.find(stage => stage.stage === "persistence").state, "failed");
    assert.equal(stages.some(stage => stage.state === "current"), false);
});


function selectedResultValues(harness) {
    const fields = ["selected-run-summary", "selected-run-paths", "selected-run-identity"]
        .flatMap(id => harness.analysisFields(id));
    return { ...Object.fromEntries(fields.map(row => [row.label, row.value])),
        "종합 판단": harness.text("selected-run-judgment") };
}

function task1Decision(overrides = {}) {
    return {run_id:"RUN-20261021-901",entity_id:"WIN-01",decision_id:"DEC-RUN-20261021-901",
        fast_status:"not_evaluated",fusion_status:"detected",detector_time:null,
        fusion_time:"2026-10-03T00:00:20.000Z",t_e:null,decision_path:null,winning_path:null,
        config_version:"parallel-v0.2",decision_reason:"Required parallel evaluation was not completed",
        supersedes_decision_id:"DEC-PREVIOUS",...overrides};
}

test("Task 1 renders the persisted incomplete Decision, both clocks and accessible provenance", async (t) => {
    // Given
    const runId = "RUN-20261021-901", decision = task1Decision();
    const harness = await startDashboardWithRuntime([], [runListItem(runId,"WIN-01")]);
    t.after(harness.restore);
    const detail = storedDetail(runId,"WIN-01",decision.decision_id);
    detail.body.current_decision.decision = decision;
    detail.body.decision_history = [decision];
    const fusion = storedFusion(runId,"WIN-01",decision.decision_id);
    fusion.body.fusion_result = {fusion_status:"detected",fusion_time:decision.fusion_time,contributing_evidence_ids:["E-A","E-B"]};
    const before = JSON.stringify({detail,fusion});
    // When
    await harness.respondAnalysis(runId,detail,fusion);
    // Then
    assert.equal(harness.text("selected-decision-summary-heading"), "증거 누적 분석에서 의심 행위 탐지");
    const fields = selectedResultValues(harness);
    assert.equal(fields["종합 판단"], "종합 판단 미완료 · 즉시 규칙 분석 미평가");
    assert.equal(fields["종합 판단 경로"], "미확정");
    assert.equal(fields["탐지 시각"], "증거 누적 분석 · 2026.10.03 09:00:20 KST · 종합 판단 시각: 미확정");
    assert.equal(fields["기여 증거"], "2건");
    assert.equal(fields["원본 검증"], "검증 상태 미조회");
    const history = harness.text("decision-history-list");
    assert.match(history, /종합 판단 미완료 · 즉시 규칙 분석 미평가/);
    // Task 6: the stored incomplete Decision is shown as a stored record, never as a missing one.
    const record = decisionRecordFieldMap(harness.document.getElementById("decision-history-list").childNodes[0]);
    assert.equal(record["판단 사유"], "필수 병렬 평가 미완료");
    assert.equal(record["즉시 규칙 분석"], "미평가");
    assert.equal(record["증거 누적 분석"], "의심 행위 탐지");
    assert.equal(record["종합 판단 시각"], "미확정");
    assert.equal(record["종합 판단 경로"], "미확정 · 저장값 없음");
    assert.equal(record["이전 결정 연결"], "DEC-PREVIOUS를 대체한 결정");
    assert.equal(record["설정·정책 버전"], "config parallel-v0.2");
    assert.equal(record["판단 사유 원문"], "Required parallel evaluation was not completed");
    assert.match(record["결정 ID"], /DEC-RUN-20261021-901/);
    assert.doesNotMatch(history, /저장된 종합 판단 결과 없음|저장된 종합 판단 없음/);
    assert.equal(harness.document.getElementById("decision-history-list").childNodes.length,1);
    assert.equal(JSON.stringify({detail,fusion}),before);
    assert.equal(harness.requestCount(`/human-workflow/runs/${runId}/sync`),0);
});

for (const scenario of [
    {name:"both evaluated detections",change:{fast_status:"detected",detector_time:"2026-10-03T00:00:10Z",
        t_e:"2026-10-03T00:00:10Z",decision_path:"fast_and_fusion",winning_path:"fast"},
        summary:"종합 판단 완료 · 의심 행위 탐지",path:"즉시 규칙·증거 누적 분석"},
    {name:"both misses",change:{fast_status:"miss",fusion_status:"miss",fusion_time:null,
        decision_path:"none",winning_path:"none",decision_reason:"Both evaluated paths missed"},
        summary:"종합 판단 완료 · 탐지 기준 미충족",path:"탐지 경로 없음"},
    {name:"unknown unevaluated reason",change:{decision_reason:"future input exclusion reason"},
        summary:"종합 판단 미완료 · 즉시 규칙 분석 미평가 · 사유 미확인",path:"미확정"},
]) {
    test(`Task 1 renders ${scenario.name} without guessing a missing result`, async (t) => {
        // Given
        const harness = await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A")]);
        t.after(harness.restore);
        const decision = task1Decision({run_id:"RUN-A",entity_id:"WIN-A",decision_id:"DEC-A",...scenario.change});
        const detail = storedDetail("RUN-A","WIN-A","DEC-A");
        detail.body.current_decision.decision = decision;
        detail.body.decision_history = [decision];
        // When
        await harness.respondAnalysis("RUN-A",detail,storedFusion("RUN-A","WIN-A","DEC-A"));
        // Then
        const fields = selectedResultValues(harness);
        assert.equal(fields["종합 판단"],scenario.summary);
        assert.equal(fields["종합 판단 경로"],scenario.path);
        assert.match(harness.text("decision-history-list"),new RegExp(scenario.summary.replaceAll("·","\\u00b7")));
        assert.equal(decision.t_e,scenario.change.t_e ?? null);
    });
}

for (const [status,expected] of [[200,"저장된 종합 판단 결과 없음"],[503,"종합 판단 조회 실패"]]) {
    test(`Task 1 keeps Fusion-only detection distinct from Decision read status ${status}`, async (t) => {
        // Given
        const harness = await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A")]);
        t.after(harness.restore);
        const detail = status === 200 ? storedDetail("RUN-A","WIN-A") : {status,body:{detail:"unavailable"}};
        const fusion = storedFusion("RUN-A","WIN-A");
        fusion.body.fusion_result = {fusion_status:"detected",fusion_time:"2026-10-03T00:00:20.000Z"};
        // When
        await harness.respondAnalysis("RUN-A",detail,fusion);
        // Then
        const fields = selectedResultValues(harness);
        assert.equal(fields["종합 판단"],expected);
        assert.match(fields["탐지 시각"],/증거 누적 분석 · 2026.10.03 09:00:20 KST/);
        assert.match(harness.text("selected-decision-summary-heading"),/증거 누적 분석에서 의심 행위 탐지/);
        assert.equal(harness.document.getElementById("decision-history-list").childNodes.length,0);
    });
}

test("Task 1 withholds a combined judgment after both mismatch reads", async (t) => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A")]);
    t.after(harness.restore);
    const detail = storedDetail("RUN-A","WIN-A","DEC-A");
    detail.body.current_decision.decision = task1Decision({decision_id:"DEC-A"});
    const fusion = storedFusion("RUN-A","WIN-A","DEC-B");
    fusion.body.fusion_result = {fusion_status:"detected",fusion_time:"2026-10-03T00:09:00Z"};
    // When
    await harness.respondAnalysis("RUN-A",detail,fusion);
    await harness.respondAnalysis("RUN-A",detail,fusion);
    // Then
    const fields = selectedResultValues(harness);
    assert.equal(fields["종합 판단"],"종합 판단 확인 보류 · 조회 버전 불일치");
    assert.equal(fields["종합 판단 경로"],"표시 보류");
    assert.doesNotMatch(fields["탐지 시각"],/09:00:20|09:09:00/);
    assert.match(harness.text("selected-run-status"),/분석 결정 버전이 달라 결과를 결합하지 않았습니다/);
    assert.equal(harness.document.getElementById("selected-run-chart").childNodes.length,0);
});

test("Task 1 ignores an old Run body that arrives after the current decision is rendered", async (t) => {
    // Given: the old response body deliberately ignores AbortSignal.
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A"),runListItem("RUN-B","WIN-B")]);
    t.after(harness.restore);
    const old = storedDetail("RUN-A","WIN-A","DEC-A");
    old.body.current_decision.decision = task1Decision({decision_id:"DEC-A"});
    const [request] = harness.requestsFor(buildRunDetailApiPath("RUN-A")).filter(item=>!item.settled);
    let deliver;
    request.settled = true;
    request.resolve({ok:true,status:200,json:()=>new Promise(resolve=>{deliver=resolve;})});
    await harness.flush();
    await harness.respond(buildFusionEngineApiPath("RUN-A"),200,storedFusion("RUN-A","WIN-A","DEC-A").body);
    // When
    harness.runButton("RUN-B").click();
    await harness.flush();
    const current = storedDetail("RUN-B","WIN-B","DEC-B");
    current.body.current_decision.decision = task1Decision({decision_id:"DEC-B",fast_status:"miss",fusion_status:"miss",
        fusion_time:null,decision_path:"none",winning_path:"none",decision_reason:"Both evaluated paths missed"});
    await harness.respondAnalysis("RUN-B",current,storedFusion("RUN-B","WIN-B","DEC-B"));
    const before = JSON.stringify(selectedResultValues(harness));
    deliver(old.body);
    await harness.flush();
    // Then
    assert.equal(harness.text("selected-run-id"),"RUN-B");
    assert.equal(JSON.stringify(selectedResultValues(harness)),before);
    assert.match(before,/종합 판단 완료 · 탐지 기준 미충족/);
    assert.doesNotMatch(before,/09:00:20|종합 판단 미완료/);
});


const PROVENANCE_ELEMENT_IDS=["provenance-status","provenance-list","provenance-retention"];
const provenancePath=run=>`/runs/${run}/evidence-provenance`;
function task2Provenance(run="RUN-A",entity="WIN-A",ids=["E-1","E-2"],levels=[]) {
    return {schema_version:"evidence_provenance_v1",scope:"fusion_contributing_ids_only",run_id:run,
        raw_retention:{available:true,status:"storage_verified",byte_size:42,content_sha256:"a".repeat(64),manifest_identity:"fixture-manifest"},
        items:ids.map((id,i)=>({run_id:run,entity_id:entity,evidence_id:id,evidence_type:"fixture",event_ids:[`evt-${id}`],
            resolution_status:levels[i]??"raw_verified",unresolved_reason:levels[i]==="event_verified"?"run_manifest_unavailable":null,
            observed_behavior:[],validation_details:{}})),
        source_events:ids.map(id=>({event_id:`evt-${id}`,run_id:run,host_id:entity,source_event_id:id,
            timestamp:"2026-10-03T00:00:00Z",source:"sysmon",source_layer:"raw_telemetry",raw_ref:{}}))};
}
function task2Analysis(run="RUN-A",entity="WIN-A",decisionId="DEC-A",ids=["E-1","E-2"]){
    const decision=task1Decision({run_id:run,entity_id:entity,decision_id:decisionId});
    const detail=storedDetail(run,entity,decisionId);detail.body.current_decision.decision=decision;
    const fusion=storedFusion(run,entity,decisionId);
    fusion.body.fusion_result={run_id:run,entity_id:entity,fusion_status:"detected",fusion_time:decision.fusion_time,contributing_evidence_ids:ids};
    return {detail,fusion};
}
const rawSummary=h=>h.analysisFields("selected-run-summary").find(row=>row.label==="원본 검증")?.value;

test("Task 2 summary shares lazy verification and keeps no_archive separate",async(t)=>{
    // Given
    const h=await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A")],
        {extraElementIds:[...PROVENANCE_ELEMENT_IDS,...EVIDENCE_ELEMENT_IDS]});t.after(h.restore);
    const {detail,fusion}=task2Analysis();await h.respondAnalysis("RUN-A",detail,fusion);
    assert.equal(rawSummary(h),"검증 상태 미조회");assert.equal(h.requestCount(provenancePath("RUN-A")),0);
    // When
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    assert.equal(rawSummary(h),"원본 검증 확인 중");
    await h.respond(evidencePath("RUN-A"),200,evidencePayload({runId:"RUN-A",availability:"no_archive"}));
    await h.respond(provenancePath("RUN-A"),200,task2Provenance());
    // Then
    assert.equal(rawSummary(h),"원본 대조 통과 · 2/2건");
    assert.equal(h.text("evidence-status"), "", "no_archive has no status sentence");
    h.document.getElementById("dashboard-tab-summary").click();await h.flush();
    assert.equal(rawSummary(h),"원본 대조 통과 · 2/2건");assert.equal(h.requestCount(provenancePath("RUN-A")),1);
    assert.match(h.text("selected-run-judgment"),/종합 판단 미완료 · 즉시 규칙 분석 미평가/);
});

test("Task 2 same-Run Decision and Evidence changes invalidate a verified summary before any new read",async(t)=>{
    // Given
    const h=await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A")],{extraElementIds:PROVENANCE_ELEMENT_IDS});t.after(h.restore);
    let analysis=task2Analysis();await h.respondAnalysis("RUN-A",analysis.detail,analysis.fusion);
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    await h.respond(provenancePath("RUN-A"),200,task2Provenance());assert.match(rawSummary(h),/대조 통과/);
    h.document.getElementById("dashboard-tab-summary").click();await h.flush();
    // When: explicit result refresh, new Decision, same Evidence.
    h.refreshButton().click();await h.flush();assert.equal(rawSummary(h),undefined);
    analysis=task2Analysis("RUN-A","WIN-A","DEC-NEXT");await h.respondAnalysis("RUN-A",analysis.detail,analysis.fusion);
    assert.equal(rawSummary(h),"검증 상태 미조회");assert.equal(h.requestCount(provenancePath("RUN-A")),1);
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    await h.respond(provenancePath("RUN-A"),503,{detail:"unavailable"});assert.equal(rawSummary(h),"조회 실패");
    // When: same Decision, new contributing set.
    h.document.getElementById("dashboard-tab-summary").click();h.refreshButton().click();await h.flush();
    analysis=task2Analysis("RUN-A","WIN-A","DEC-NEXT",["E-NEW"]);await h.respondAnalysis("RUN-A",analysis.detail,analysis.fusion);
    // Then
    assert.equal(rawSummary(h),"검증 상태 미조회");
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    await h.respond(provenancePath("RUN-A"),200,task2Provenance("RUN-A","WIN-A",["E-NEW"]));
    assert.equal(rawSummary(h),"원본 대조 통과 · 1/1건");
});

test("Task 2 discards a late provenance body after Run selection changes",async(t)=>{
    // Given
    const h=await startDashboardWithRuntime([], [runListItem("RUN-A","WIN-A"),runListItem("RUN-B","WIN-B")],
        {extraElementIds:PROVENANCE_ELEMENT_IDS});t.after(h.restore);
    let analysis=task2Analysis();await h.respondAnalysis("RUN-A",analysis.detail,analysis.fusion);
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    const [request]=h.requestsFor(provenancePath("RUN-A")).filter(value=>!value.settled);let deliver;
    request.settled=true;request.resolve({ok:true,status:200,json:()=>new Promise(resolve=>{deliver=resolve;})});await h.flush();
    // When
    h.runButton("RUN-B").click();await h.flush();
    analysis=task2Analysis("RUN-B","WIN-B","DEC-B");await h.respondAnalysis("RUN-B",analysis.detail,analysis.fusion);
    h.document.getElementById("dashboard-tab-evidence").click();await h.flush();
    await h.respond(provenancePath("RUN-B"),200,task2Provenance("RUN-B","WIN-B",["E-1","E-2"],["event_verified","event_verified"]));
    const current=rawSummary(h);deliver(task2Provenance());await h.flush();
    // Then
    assert.equal(rawSummary(h),current);assert.match(current,/원본 대조 미완료/);
    assert.equal(h.text("selected-run-id"),"RUN-B");assert.doesNotMatch(h.text("provenance-list"),/RUN-A/);
});

function task3Analysis(runId = "RUN-A", decisionId = "DEC-A", shift = 0) {
    const detail = storedDetail(runId, "WIN-A", decisionId);
    const fusion = storedFusion(runId, "WIN-A", decisionId);
    const decision = { run_id: runId, entity_id: "WIN-A", decision_id: decisionId,
        fast_status: "not_evaluated", fusion_status: "detected", t_e: null,
        fusion_time: new Date(Date.UTC(2026, 9, 3, shift, 0, 20)).toISOString(),
        decision_path: null, winning_path: null, config_version: "parallel-v0.2",
        decision_reason: "Required parallel evaluation was not completed" };
    detail.body.current_decision.decision = decision;
    detail.body.decision_history = [decision];
    fusion.body.current_decision = { ...decision };
    fusion.body.fusion_result = { run_id: runId, entity_id: "WIN-A", fusion_status: "detected",
        fusion_time: decision.fusion_time, scoring_config_version: "F-C1",
        contributing_evidence_ids: ["E-A", "E-B"], score_at_decision: 1,
        fusion_episodes: [{ episode_id: `${runId}-EP`, start_time: decision.fusion_time,
            end_time: new Date(Date.UTC(2026, 9, 3, shift, 5, 20)).toISOString(), end_reason: "released" }] };
    fusion.body.stopping_trace = { run_id: runId, entity_id: "WIN-A", scoring_config_version: "F-C1",
        points: Array.from({ length: 67 }, (_, index) => ({
            timestamp: new Date(Date.UTC(2026, 9, 3, shift, 0, index * 10)).toISOString(),
            score: index === 0 ? 0.5 : index < 32 ? 1 : 0,
            policy_state: index >= 2 && index < 32 ? "on" : "off",
            persistence_count: index === 1 ? 1 : index === 2 ? 2 : null,
        })) };
    fusion.body.runtime_config_snapshot = { stopping: { threshold_on: 0.8, threshold_off: 0.4, persistence_k: 2 } };
    return { detail, fusion };
}

test("Task 3 actual Dashboard module renders exact transitions and preserves Task 1/2 meanings", async t => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const { detail, fusion } = task3Analysis();
    const before = JSON.stringify([detail, fusion]);
    // When
    await harness.respondAnalysis("RUN-A", detail, fusion);
    // Then
    const chart = harness.document.getElementById("selected-run-chart");
    assert.ok(chart.querySelector(".dashboard-replay-chart"), harness.text("selected-run-chart-status"));
    assert.equal(chart.querySelectorAll(".fusion-score-chart__point").length, 67);
    assert.match(chart.textContent, /점수 기록 67개/);
    assert.match(chart.textContent, /진입 기준 0\.80 이상 · 2회 연속/);
    const records = chart.querySelector(".dashboard-replay-chart__records").textContent;
    assert.match(records, /09:00:20\.000 KST — 탐지 구간 시작/);
    assert.match(records, /09:05:20\.000 KST — 탐지 구간 해제/);
    assert.match(records, /종합 판단 시각: 미확정/);
    assert.doesNotMatch(records, /KST — 종합 판단 시각/);
    assert.equal(chart.querySelector(".fusion-score-chart__clock").textContent, "2026-10-03 · KST");
    assert.equal(harness.text("selected-run-hybrid-note"), "종합 판단 미완료 · 즉시 규칙 분석 미평가");
    const callouts = chart.querySelectorAll(".dashboard-replay-chart__callout").map(label => label.ownText);
    assert.deepEqual(callouts, ["09:00:20 탐지 구간 시작", "09:05:20 탐지 구간 해제"]);
    assert.ok(chart.querySelectorAll(".fusion-score-chart__axis-label--x").some(label => label.ownText === "09:05:30"));
    assert.match(harness.text("selected-run-summary"), /검증 상태 미조회/);
    assert.match(harness.text("decision-history-list"), /DEC-A/);
    assert.equal(JSON.stringify([detail, fusion]), before);
    const marker = chart.querySelectorAll(".fusion-score-chart__point")[2];
    marker.focus();
    assert.match(chart.querySelector(".fusion-score-chart__point-detail").textContent, /09:00:20\.000 KST.*탐지 구간 활성/);
});

for (const kind of ["missing", "empty", "invalid"]) {
    test(`Task 3 Dashboard ${kind} trajectory retains known Episode records without a fabricated curve`, async t => {
        // Given
        const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
        t.after(harness.restore);
        const { detail, fusion } = task3Analysis();
        fusion.body.stopping_trace = kind === "missing" ? null : kind === "empty" ? { points: [] }
            : { points: [{ timestamp: "invalid", score: 1 }] };
        // When
        await harness.respondAnalysis("RUN-A", detail, fusion);
        // Then
        const chart = harness.document.getElementById("selected-run-chart");
        assert.equal(chart.querySelectorAll(".fusion-score-chart__trajectory").length, 0);
        assert.match(chart.textContent, /09:00:20\.000 KST — 탐지 구간 시작/);
        assert.match(chart.textContent, /09:05:20\.000 KST — 탐지 구간 해제/);
        assert.equal(harness.document.getElementById("selected-run-chart-status").hidden, false);
    });
}

test("Task 3 Dashboard ignores a late non-abortable Fusion response after selecting another Run", async t => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-A")]);
    t.after(harness.restore);
    const old = task3Analysis();
    await harness.respond(buildRunDetailApiPath("RUN-A"), 200, old.detail.body);
    await harness.respond(buildFusionEngineApiPath("RUN-A"), 200, old.fusion.body,
        { deferJson: true, ignoreBodyAbort: true });
    const late = harness.requestsFor(buildFusionEngineApiPath("RUN-A"))[0];
    assert.equal(typeof late.jsonResolve, "function");
    // When
    harness.runButton("RUN-B").click();
    await harness.flush();
    assert.equal(harness.text("selected-run-chart"), "");
    const current = task3Analysis("RUN-B", "DEC-B", 1);
    await harness.respondAnalysis("RUN-B", current.detail, current.fusion);
    const beforeLateResponse = harness.text("selected-run-chart");
    late.jsonResolve(old.fusion.body);
    await harness.flush();
    // Then
    assert.equal(harness.text("selected-run-id"), "RUN-B");
    assert.equal(harness.text("selected-run-chart"), beforeLateResponse);
    const records = harness.document.getElementById("selected-run-chart").querySelector(".dashboard-replay-chart__records").textContent;
    assert.match(records, /10:00:20\.000 KST — 탐지 구간 시작/);
    assert.match(records, /RUN-B-EP/);
    assert.doesNotMatch(records, /09:00:20|RUN-A-EP/);
});

test("Task 3 Dashboard shows a stored t_e as its own Decision clock, never as a Fusion transition", async t => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const { detail, fusion } = task3Analysis();
    const decision = { ...detail.body.current_decision.decision, t_e: "2026-10-03T00:00:30Z" };
    detail.body.current_decision.decision = decision;
    detail.body.decision_history = [decision];
    fusion.body.current_decision = { ...decision };
    // When
    await harness.respondAnalysis("RUN-A", detail, fusion);
    // Then
    const records = harness.document.getElementById("selected-run-chart")
        .querySelector(".dashboard-replay-chart__records").textContent;
    assert.match(records, /09:00:20\.000 KST — 탐지 구간 시작/);
    assert.match(records, /09:00:30\.000 KST — 종합 판단 시각 \(t_e\)/);
    assert.match(records, /원천 Decision\.t_e/);
    assert.match(records, /원천 fusion_episodes\.start_time/);
    assert.equal(fusion.body.fusion_result.fusion_time, "2026-10-03T00:00:20.000Z");
});

test("Task 3 Dashboard without any stored Decision says nothing about t_e", async t => {
    // Given: Fusion artifacts exist but neither API returns a Decision.
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const { detail, fusion } = task3Analysis();
    detail.body.current_decision = null;
    detail.body.decision_history = [];
    fusion.body.current_decision = null;
    // When
    await harness.respondAnalysis("RUN-A", detail, fusion);
    // Then
    const records = harness.document.getElementById("selected-run-chart")
        .querySelector(".dashboard-replay-chart__records").textContent;
    assert.match(records, /09:00:20\.000 KST — 탐지 구간 시작/);
    assert.doesNotMatch(records, /종합 판단 시각/);
});

test("Task 3 Dashboard keeps mismatched Decision artifacts out of the chart", async t => {
    // Given
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(harness.restore);
    const { detail, fusion } = task3Analysis();
    fusion.body.current_decision.decision_id = "DEC-OTHER";
    // When: the Dashboard retries a mismatch once before withholding the combined view.
    await harness.respondAnalysis("RUN-A", detail, fusion);
    await harness.respondAnalysis("RUN-A", detail, fusion);
    // Then
    assert.equal(harness.text("selected-run-chart"), "");
    assert.equal(harness.text("selected-run-chart-status"), "조회 시점이 일치하지 않아 Fusion Trace를 표시하지 않습니다.");
    assert.match(harness.text("selected-run-judgment"), /종합 판단 확인 보류 · 조회 버전 불일치/);
    assert.doesNotMatch(harness.text("selected-run-summary"), /09:00:20/);
});

test("Task 4 KPIs state one run-report condition and keep stored analysis separate from running state", async t => {
    // Given: a stored analysis exists while no execution report was saved.
    const harness = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")], { autoFollow: true });
    t.after(harness.restore);
    const line = id => harness.document.getElementById(id);
    // When / Then: no report is not "no analysis" and not "service down".
    assert.equal(harness.text("system-status-value"), "");
    assert.equal(line("system-status-value").hidden, true);
    assert.equal(line("runtime-report-cell").hidden, true);
    assert.equal(line("latest-runtime-line").hidden, true);
    assert.equal(line("active-runtime-line").hidden, true);
    assert.equal(harness.text("total-runs-value"), "1");
    assert.equal(harness.text("pipeline-stage-context"), "");
    assert.equal(line("pipeline-stage-context").hidden, true);
    assert.match(line("pipeline-stage-context").title, /서비스 가동·중단 여부를 뜻하지 않습니다/);
    // When: an actual fresh running report arrives.
    await harness.poll([runtimeReport("RUN-B", "WIN-B", "running", "normalization")]);
    // Then
    assert.equal(harness.text("system-status-value"), "실행 중 보고 있음");
    assert.equal(line("runtime-report-cell").hidden, false);
    assert.equal(line("active-runtime-line").hidden, false);
    assert.equal(harness.text("active-runtime-run"), "RUN-B · WIN-B");
    assert.equal(line("latest-runtime-line").hidden, false);
    assert.match(harness.text("latest-runtime-updated"), /KST/);
    assert.match(harness.text("pipeline-stage-context"), /^최신 실행 · 분석 RUN-B · Entity WIN-B · /);
    // When: the report query fails, the failure is stated instead of an empty or healthy state.
    await harness.pollFailure();
    // Then
    assert.equal(harness.text("system-status-value"), "실행 보고 조회 실패");
    assert.equal(line("runtime-report-cell").hidden, false);
    assert.equal(line("active-runtime-line").hidden, true);
    assert.doesNotMatch(harness.text("system-status-value"), /없음|정상/);
});

test("Task 4 overview shell names the environment and actor once and keeps unmeasured metrics out of KPIs", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    const command = html.split('aria-labelledby="command-heading"')[1].split("</section>")[0];
    // Then
    assert.match(html, /<span id="operator-demo-badge" class="operator-demo-badge" hidden\s+title="[^"]+">실험 환경<\/span>/);
    assert.match(html, /<span class="dashboard-header-user" title="[^"]*실제 인증 계정이 아닙니다\.">[\s\S]*?<span>로컬 담당자<\/span><\/span>/);
    assert.doesNotMatch(html, />로컬 데모 Actor<|>로컬 데모<|dashboard-header-updated|분석 구조 안내입니다/);
    assert.equal((command.match(/class="dashboard-kpi(?: dashboard-kpi--system)?"/g) ?? []).length, 1);
    assert.doesNotMatch(command, /미계측|가동 시간|SLA|큐/);
    assert.match(html, /<p class="dashboard-measurement-gaps">/);
    assert.match(html, /<label><input id="pipeline-auto-follow"[^>]*> 범위: 최신 실행 \(끄면 선택 항목\)<\/label>/);
    // The explanatory structure diagram was removed on request.
    assert.doesNotMatch(html, /operator-analysis-logic|분석 구조 보기/);
});

test("Task 5 promotes the list and selected item while preserving the system and technical records", async () => {
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    // Task 7-S order: page title, system status, list, selected item, analysis detail.
    assert.ok(html.indexOf('class="page-title"') < html.indexOf('id="system-heading"'));
    assert.ok(html.indexOf('id="system-heading"') < html.indexOf('id="runs-heading"'));
    assert.ok(html.indexOf('id="runs-heading"') < html.indexOf('id="selected-item-heading"'));
    assert.ok(html.indexOf('id="selected-item-heading"') < html.indexOf('id="selected-run-heading"'));
    assert.match(html, /관측·분석 목록/);
    assert.match(html, /id="selected-run-paths"/);
    assert.match(html, /<summary>식별 정보<\/summary>/);
    assert.match(html, /id="pipeline-stage-list"/);
    assert.match(html, /id="workflow-next"/);
    assert.match(html, /id="selected-run-observations"/);
    assert.doesNotMatch(html, /Incident ID|T1059|T1071/);
});

test("Task 5 actual Dashboard list batches summaries without changing selection or requesting row details", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
    t.after(h.restore);
    const selection = h.text("selected-run-id");
    const analysisPath = "/analysis-summaries?run_id=RUN-A&run_id=RUN-B";
    const workflowPath = "/human-workflow/alert-summaries?run_id=RUN-A&run_id=RUN-B";
    assert.equal(h.requestCount(analysisPath), 1);
    assert.equal(h.requestCount(workflowPath), 1);
    const before = h.requestCount(buildRunDetailApiPath("RUN-B"));
    const items = ["RUN-A", "RUN-B"].map((run_id, index) => ({ run_id, entity_id: index ? "WIN-B" : "WIN-A", status: "available",
        decision: task1Decision({ run_id, entity_id: index ? "WIN-B" : "WIN-A" }), fusion_result: null }));
    await h.respond(analysisPath, 200, { schema_version: "dashboard_analysis_summaries_v1", items });
    await h.respond(workflowPath, 200, { schema_version: "human_workflow_alert_summaries_v1", items: items.map(item => ({ run_id: item.run_id, alerts: [] })) });
    assert.equal(h.text("selected-run-id"), selection);
    assert.equal(h.requestCount(buildRunDetailApiPath("RUN-B")), before);
    assert.match(recentRunRow(h, "RUN-B").textContent, /미완료/);
    assert.doesNotMatch(recentRunRow(h, "RUN-B").textContent, /즉시 규칙 분석 미평가/, "The list shows completion only");
    assert.match(recentRunRow(h, "RUN-B").textContent, /처리 기록 없음/);
    assert.doesNotMatch(recentRunRow(h, "RUN-A").textContent, /입력 출처 미확인/, "The input-source label was removed on request");
});

test("Task 5 summary actions focus the selected detail tab without refetching analysis", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(h.restore);
    const data = task2Analysis(); await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    const count = h.requestCount(buildRunDetailApiPath("RUN-A"));
    assert.equal(h.document.getElementById("selected-item-body").hidden, false);
    h.document.getElementById("selected-item-open").click();
    assert.equal(h.document.activeElement, h.document.getElementById("dashboard-tab-summary"));
    h.document.getElementById("selected-run-workflow-open").click();
    assert.equal(h.document.getElementById("dashboard-tab-workflow").getAttribute("aria-selected"), "true");
    assert.equal(h.document.activeElement, h.document.getElementById("dashboard-tab-workflow"));
    assert.equal(h.requestCount(buildRunDetailApiPath("RUN-A")), count);
    assert.equal(h.requestCount("/human-workflow/runs/RUN-A/sync"), 0);
});

test("Task 5 observations reuse only raw-verified prose and disappear on selection change", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")],
        { extraElementIds: PROVENANCE_ELEMENT_IDS });
    t.after(h.restore);
    const data = task2Analysis(); await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    assert.doesNotMatch(h.text("selected-run-observations"), /확인한 PowerShell/);
    h.document.getElementById("selected-run-evidence-open").click(); await h.flush();
    const provenance = task2Provenance("RUN-A", "WIN-A", ["E-1", "E-2"], ["raw_verified", "event_verified"]);
    provenance.items[0].observed_behavior = [{ behavior_summary: "확인한 PowerShell 실행 옵션", observed_at: "2026-10-03T00:00:10Z" }];
    provenance.items[1].observed_behavior = [{ behavior_summary: "미검증 활동을 표시하면 안 됨" }];
    await h.respond(provenancePath("RUN-A"), 200, provenance);
    assert.equal(h.text("selected-run-observations"), "2026.10.03 09:00:10 KST — 확인한 PowerShell 실행 옵션");
    assert.match(h.text("selected-item-observation"), /확인한 PowerShell 실행 옵션/);
    assert.doesNotMatch(h.text("selected-item-observation"), /미검증 활동/);
    h.runButton("RUN-B").click(); await h.flush();
    assert.equal(h.text("selected-run-observations"), "");
    assert.doesNotMatch(h.text("selected-item-observation"), /PowerShell/);
});

test("Task 5 same-ID Live entries cannot enter the formal Run list or start workflow writes", async t => {
    const h = await startDashboardHarness(); t.after(h.restore);
    const formal = { ...runListItem("SAME", "HOST"), kind: "formal_run" };
    const live = { ...runListItem("SAME", "LIVE"), kind: "live_observation", data_class: "demo_only", canonical_result: null };
    await h.respond("/overview", 200, { total_runs: 1, recent_runs: [formal] });
    await h.respond("/runs?limit=20", 200, { runs: [live, formal] });
    await h.respond(RUNTIME_API_PATH, 200, { items: [] });
    assert.equal(h.runRows().length, 1);
    assert.equal(h.runButton("SAME").dataset.kind, "formal_run");
    assert.match(recentRunRow(h, "SAME").textContent, /HOST/);
    assert.doesNotMatch(recentRunRow(h, "SAME").textContent, /LIVE/);
    assert.equal(h.requestCount("/human-workflow/runs/SAME/sync"), 0);
});

test("Task 5 an empty analysis list has no phantom selection or list-summary traffic", async t => {
    const h = await startDashboardWithRuntime([], []); t.after(h.restore);
    assert.equal(h.runRows().length, 0);
    assert.equal(h.document.getElementById("selected-item-body").hidden, true);
    assert.equal(h.requestsFor("/analysis-summaries?").length, 0);
    assert.equal(h.text("selected-run-id"), "");
});

test("Task 5 review row, selected summary and header share the same formal case scope", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
    t.after(h.restore);
    const data = task2Analysis(); await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    const header = h.document.getElementById("selected-run-heading");
    const panel = h.document.getElementById("selected-item-body");
    assert.equal(h.text("selected-run-target"), "WIN-A");
    assert.equal(h.text("selected-item-target"), "WIN-A");
    assert.deepEqual(header.dataset, { kind: "formal_run", runId: "RUN-A", entityId: "WIN-A" });
    assert.deepEqual(header.dataset, panel.dataset);
    assert.deepEqual(header.dataset, recentRunRow(h, "RUN-A").dataset);
    h.runButton("RUN-B").click(); await h.flush();
    assert.equal(h.text("selected-run-target"), "WIN-B");
    assert.equal(h.text("selected-item-target"), "WIN-B");
    assert.equal(h.text("selected-run-id"), "RUN-B");
    assert.equal(header.dataset.entityId, "WIN-B");
    assert.doesNotMatch(h.text("selected-item-headline"), /RUN-A/);
});

test("Task 5 review an unselected header never retains an old Run identifier", async t => {
    const h = await startDashboardWithRuntime([], []); t.after(h.restore);
    assert.equal(h.text("selected-run-target"), "선택 항목 없음");
    assert.equal(h.text("selected-run-id"), "");
    assert.equal(h.document.getElementById("selected-run-id-note").hidden, true);
    assert.deepEqual(h.document.getElementById("selected-run-heading").dataset, { kind: "", runId: "", entityId: "" });
});

test("Task 5 review new selections open summary while refresh and same-case selection preserve the manual tab", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
    t.after(h.restore);
    let data = task2Analysis(); await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    const summary = h.document.getElementById("dashboard-tab-summary");
    const workflow = h.document.getElementById("dashboard-tab-workflow");
    assert.equal(summary.getAttribute("aria-selected"), "true");
    workflow.click(); h.refreshButton().click(); await h.flush();
    await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    assert.equal(workflow.getAttribute("aria-selected"), "true");
    h.runButton("RUN-A").click(); await h.flush();
    await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    assert.equal(workflow.getAttribute("aria-selected"), "true");
    h.runButton("RUN-B").click(); await h.flush();
    assert.equal(summary.getAttribute("aria-selected"), "true");
    workflow.click();
    data = task2Analysis("RUN-B", "WIN-B", "DEC-B"); await h.respondAnalysis("RUN-B", data.detail, data.fusion);
    assert.equal(workflow.getAttribute("aria-selected"), "true", "A user's tab change during loading is retained");
});

test("Task 5 review a late old body cannot replace the new header, quick view or detail scope", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A"), runListItem("RUN-B", "WIN-B")]);
    t.after(h.restore);
    const first = task2Analysis();
    const request = h.requestsFor(buildRunDetailApiPath("RUN-A")).find(item => !item.settled);
    let deliver; request.settled = true;
    request.resolve({ ok: true, status: 200, json: () => new Promise(resolve => { deliver = resolve; }) });
    await h.flush(); await h.respond(buildFusionEngineApiPath("RUN-A"), 200, first.fusion.body);
    h.runButton("RUN-B").click(); await h.flush();
    const second = task2Analysis("RUN-B", "WIN-B", "DEC-B"); await h.respondAnalysis("RUN-B", second.detail, second.fusion);
    const before = [h.text("selected-run-target"), h.text("selected-item-target"), h.text("selected-run-id"), h.text("selected-run-judgment")];
    deliver(first.detail.body); await h.flush();
    assert.deepEqual([h.text("selected-run-target"), h.text("selected-item-target"), h.text("selected-run-id"), h.text("selected-run-judgment")], before);
    assert.deepEqual(before.slice(0, 3), ["WIN-B", "WIN-B", "RUN-B"]);
});

test("Task 5 review a wrong-분석 response is rejected rather than shown under the selected title", async t => {
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]); t.after(h.restore);
    const data = task2Analysis("OTHER", "OTHER-HOST", "D");
    await h.respondAnalysis("RUN-A", data.detail, data.fusion);
    assert.equal(h.text("selected-run-target"), "WIN-A");
    assert.doesNotMatch(h.text("selected-item-target"), /OTHER/);
    assert.match(h.text("selected-run-status"), /불러오지 못했습니다/);
    assert.doesNotMatch(h.text("selected-item-headline"), /의심 행위 탐지/);
});

test("Task 5 review short lists use a compact strip and Workflow controls live only in the detailed tab", async () => {
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    const css = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/assets/dashboard-operator.css", import.meta.url), "utf8");
    const sidebar = html.slice(html.indexOf('aria-labelledby="selected-item-heading"'), html.indexOf('aria-labelledby="selected-run-heading"'));
    assert.doesNotMatch(sidebar, /id="workflow-next"|id="workflow-current"|id="workflow-alerts"|workflow-awareness-form/);
    assert.match(sidebar, /id="selected-item-workflow-open"/);
    const detailed = html.slice(html.indexOf('id="dashboard-panel-workflow"'));
    for (const id of ["workflow-next", "workflow-current", "workflow-alerts", "workflow-awareness-form", "workflow-report-form", "kisa-panel"]) {
        assert.ok(detailed.includes(`id="${id}"`), `${id} remains in detail`);
    }
    assert.match(css, /data-short-list="true"/);
});

// Task 6: evidence, score, records and Workflow areas wired through the real dashboard module.
const TASK6_EVIDENCE_IDS = [...PROVENANCE_ELEMENT_IDS, "provenance-count", "provenance-retention-state", "provenance-region",
    ...EVIDENCE_ELEMENT_IDS, "evidence-archive-state"];
const task6Tab = (h) => ["summary", "replay", "evidence", "decision", "workflow"].find(
    (name) => h.document.getElementById(`dashboard-tab-${name}`).getAttribute("aria-selected") === "true");
function task6Alert(entityId = "WIN-A") {
    const before = { version: 0, analyst_ack_time: null, evidence_reviewed_at: null, t_h: null, t_h_recorded_at: null,
        report_choice: null, report_decided_at: null, report_reason: null };
    const after = { ...before, version: 1, analyst_ack_time: "2026-10-21T01:00:00.000Z" };
    return { alert_id: `ALERT-${entityId}`, run_id: "RUN-A", entity_id: entityId, decision_id: "DEC-A", detection_kind: "fusion",
        issued_at: "2026-10-21T00:30:00.000Z", state: after, audit: [{ action_id: "ACT-1", alert_id: `ALERT-${entityId}`, version: 1,
            idempotency_key: "key-1", actor_id: "local-demo-analyst", actor_kind: "unauthenticated_local_demo", action: "acknowledge",
            recorded_at: "2026-10-21T01:00:00.000Z", command: { action: "acknowledge", expected_version: 0 },
            previous_state: before, resulting_state: after }] };
}

test("Task 6 evidence overview shows stored retention, raw comparison and R1 no_archive side by side", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")], { extraElementIds: TASK6_EVIDENCE_IDS });
    t.after(h.restore);
    const { detail, fusion } = task2Analysis();
    await h.respondAnalysis("RUN-A", detail, fusion);
    // When
    h.document.getElementById("dashboard-tab-evidence").click();
    await h.flush();
    await h.respond(evidencePath("RUN-A"), 200, evidencePayload({ runId: "RUN-A", availability: "no_archive" }));
    await h.respond(provenancePath("RUN-A"), 200, task2Provenance());
    // Then
    const overview = ["provenance-count", "provenance-status", "provenance-retention-state", "evidence-archive-state"].map((id) => h.text(id));
    assert.deepEqual(overview, ["2건", "원본 대조 통과 · 2/2건", "보관 원본 검증됨", "게시 아카이브 없음 · 원본 보관과 별개"]);
    assert.doesNotMatch(overview.join(" "), /원본 없음|원본 전체/);
    assert.equal(h.text("evidence-status"), "", "no_archive has no status sentence");
    assert.equal(h.document.getElementById("provenance-region").hidden, false);
    assert.equal(h.document.getElementById("evidence-region").hidden, true);
    assert.equal(h.document.getElementById("provenance-list").childNodes.length, 2);
    assert.equal(rawSummary(h), "원본 대조 통과 · 2/2건", "The analysis summary shares the same scoped state");
});

test("Task 6 the 기록 tab keeps analysis Decisions and human audit records apart and reuses loaded alerts", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(h.restore);
    const { detail, fusion } = task3Analysis();
    await h.respondAnalysis("RUN-A", detail, fusion);
    const before = h.allRequests().length;
    const pending = h.text("workflow-records-status");
    // When
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert(), task6Alert("WIN-OTHER")], status: "", step: "", next: "" });
    // Then
    const decisions = h.text("decision-history-list");
    const audits = h.text("workflow-records-list");
    assert.match(decisions, /DEC-A/);
    assert.doesNotMatch(decisions, /local-demo-analyst|담당자 확인 시각/);
    // Review: one table row per stored action (time, action, actor, changed values); details on request.
    const [row] = h.document.getElementById("workflow-records-list").childNodes[0].querySelectorAll(".dashboard-audit-row");
    assert.deepEqual(row.childNodes.map((cell) => cell.textContent).slice(1, 3),
        ["담당자 확인", "로컬 담당자로컬 실험 담당자 · 인증 계정 아님"]);
    assert.match(row.childNodes[0].textContent, /KST기록 버전 v1$/);
    assert.match(audits, /담당자 확인 시각: 미기록 → .*KST/);
    assert.doesNotMatch(audits, /원본 기록/, "Raw records stay in the row detail");
    assert.doesNotMatch(audits, /DEC-A|종합 판단/);
    assert.equal(h.document.getElementById("workflow-records-list").childNodes.length, 1, "Only the selected target's alerts");
    // Records shown: no count/order sentence above the table; the status line is used only for loading, empty and errors.
    assert.equal(h.text("workflow-records-status"), "");
    assert.notEqual(pending, h.text("workflow-records-status"));
    assert.equal(h.allRequests().length, before, "The records tab starts no request of its own");
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [], status: "" });
    assert.equal(h.text("workflow-records-status"), "담당자 처리 기록 없음");
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: null, alerts: null, status: "서버 오류: 같은 입력으로 재시도할 수 있습니다." });
    assert.equal(h.text("workflow-records-status"), "서버 오류: 같은 입력으로 재시도할 수 있습니다.");
    assert.equal(h.document.getElementById("workflow-records-list").childNodes.length, 0);
});

test("Task 6 cross-tab links and every new area read nothing extra and never write or send", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")], { extraElementIds: TASK6_EVIDENCE_IDS });
    t.after(h.restore);
    const { detail, fusion } = task3Analysis();
    await h.respondAnalysis("RUN-A", detail, fusion);
    const before = h.allRequests().length;
    // When
    h.document.getElementById("dashboard-tab-replay").click();
    h.document.getElementById("replay-records-open").click();
    const fromReplay = [task6Tab(h), h.document.activeElement === h.document.getElementById("dashboard-tab-decision")];
    h.document.getElementById("records-workflow-open").click();
    const fromRecords = task6Tab(h);
    h.document.getElementById("workflow-records-open").click();
    const fromWorkflow = task6Tab(h);
    const afterLinks = h.allRequests().length;
    for (const name of ["evidence", "decision", "workflow", "replay", "summary"]) {
        h.document.getElementById(`dashboard-tab-${name}`).click();
        await h.flush();
    }
    // Then
    assert.deepEqual(fromReplay, ["decision", true]);
    assert.equal(fromRecords, "workflow");
    assert.equal(fromWorkflow, "decision");
    assert.equal(afterLinks, before);
    const all = h.allRequests();
    assert.ok(all.every((request) => request.method === "GET"), JSON.stringify(all.filter((request) => request.method !== "GET")));
    assert.equal(all.some((request) => /\/sync|report-drafts|report-snapshot|ai-report|kisa-forms|docx|\/actions|\/review/.test(request.url)), false);
    assert.deepEqual(all.slice(before).map((request) => request.url).sort(), [evidencePath("RUN-A"), provenancePath("RUN-A")].sort());
});

test("Task 6 a Runtime poll keeps the 기록 tab, its rendered records and keyboard focus", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(h.restore);
    const { detail, fusion } = task3Analysis();
    await h.respondAnalysis("RUN-A", detail, fusion);
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert()], status: "" });
    h.document.getElementById("dashboard-tab-decision").click();
    const decisionNode = h.document.getElementById("decision-history-list").childNodes[0];
    const auditNode = h.document.getElementById("workflow-records-list").childNodes[0];
    const focused = decisionNode.querySelector(".dashboard-decision-id");
    focused.focus();
    // When: a poll, then the same stored alerts published again.
    await h.poll([]);
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert()], status: "" });
    // Then
    assert.equal(task6Tab(h), "decision");
    assert.strictEqual(h.document.getElementById("decision-history-list").childNodes[0], decisionNode);
    assert.strictEqual(h.document.getElementById("workflow-records-list").childNodes[0], auditNode);
    assert.strictEqual(h.document.activeElement, focused);
});

test("Review an opened audit row and its toggle focus survive a poll and an identical re-publication", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(h.restore);
    const { detail, fusion } = task3Analysis();
    await h.respondAnalysis("RUN-A", detail, fusion);
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert()], status: "" });
    h.document.getElementById("dashboard-tab-decision").click();
    const toggle = () => h.document.getElementById("workflow-records-list").querySelector(".dashboard-evidence-expand");
    const detailRows = () => h.document.getElementById("workflow-records-list").querySelectorAll(".dashboard-evidence-detail-row");
    const auditRegion = () => h.document.getElementById("workflow-records-list").querySelector(".dashboard-audit-region");
    auditRegion().scrollLeft = 300;
    // When
    toggle().click();
    const opened = toggle();
    await h.poll([]);
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert()], status: "" });
    // Then
    assert.equal(opened.getAttribute("aria-expanded"), "true");
    assert.strictEqual(h.document.activeElement, opened, "The re-rendered toggle keeps focus after opening");
    assert.strictEqual(toggle(), opened, "Unchanged records are not rebuilt");
    assert.equal(auditRegion().scrollLeft, 300, "Opening details and polling keep the audit table's horizontal position");
    assert.equal(detailRows().length, 1);
    assert.match(detailRows()[0].textContent, /원본 기록/);
    toggle().click();
    assert.equal(auditRegion().scrollLeft, 300, "Closing details keeps the same position");
    h.runButton("RUN-A").click();
    await h.flush();
    h.workflowOptions().onProgress({ runId: "RUN-A", entityId: "WIN-A", alerts: [task6Alert()], status: "" });
    assert.equal(detailRows().length, 0, "A new selection starts with every row closed");
});

test("Task 6 the score tab keeps stored transitions before the full score table and repeats no Decision", async (t) => {
    // Given
    const h = await startDashboardWithRuntime([], [runListItem("RUN-A", "WIN-A")]);
    t.after(h.restore);
    const { detail, fusion } = task3Analysis();
    // When
    await h.respondAnalysis("RUN-A", detail, fusion);
    await h.respond(buildEventTimelineApiPath("RUN-A", 50, 0), 200, { items: [
        { event_id: "EVT-1", timestamp: "2026-10-03T00:00:01Z", host_id: "WIN-A", event_type: "process_create" },
        { event_id: "EVT-2", timestamp: "2026-10-03T00:00:02Z", host_id: "WIN-A", event_type: "network_connection" },
        { event_id: "EVT-3", timestamp: "2026-10-03T00:00:03Z", host_id: "WIN-A", event_type: "network_connection" },
    ], total: 3, limit: 50, offset: 0 });
    // Then
    const chart = h.document.getElementById("selected-run-chart").childNodes[0];
    const order = chart.childNodes.map((node) => [...node.classNames].find((name) => /__svg|__records|__technical/.test(name))).filter(Boolean);
    assert.deepEqual(order, ["fusion-score-chart__svg", "dashboard-replay-chart__records", "fusion-score-chart__technical"]);
    assert.equal(chart.querySelector(".fusion-score-chart__svg").getAttribute("viewBox"), "0 0 960 180");
    assert.match(chart.querySelector(".dashboard-replay-chart__records").textContent, /09:00:20\.000 KST — 탐지 구간 시작/);
    assert.doesNotMatch(chart.textContent, /DEC-A/);
    assert.match(chart.querySelector(".dashboard-replay-chart__judgment").textContent, /저장된 판단: 종합 판단 미완료/);
    const kinds = h.document.getElementById("event-type-summary").childNodes.map((item) => [item.childNodes[0].textContent, item.childNodes[0].title, item.childNodes[1].textContent]);
    assert.deepEqual(kinds, [["프로세스 생성", "process_create", "1"], ["네트워크 연결", "network_connection", "2"]]);
});


test("ISO prose clock display preserves precision and does not rewrite URLs, identifiers or quoted originals", async () => {
    const {formatOperatorProse} = await import("../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs");
    const value = "관측 2026-10-03T00:00:00.123001Z · 다음 2026-10-03T00:00:00.123002+00:00";
    assert.equal(formatOperatorProse(value),"관측 2026.10.03 09:00:00.123001 KST · 다음 2026.10.03 09:00:00.123002 KST");
    assert.equal(formatOperatorProse("2026-10-03T15:00:00Z"),"2026.10.04 00:00:00 KST");
    for (const raw of ['https://example.test/2026-10-03T00:00:00Z', 'ID-2026-10-03T00:00:00Z',
        '{"timestamp":"2026-10-03T00:00:00Z"}', '2026-02-30T00:00:00Z', '2026-10-03T00:00:00', 'UNKNOWN']) {
        assert.equal(formatOperatorProse(raw),raw);
    }
});

test("Operators read 내부 인지시각, never the internal t_h name, while stored text and JSON keys stay intact", async () => {
    const {formatOperatorProse, operatorAwarenessTerm} = await import("../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs");
    // Labels and prose stored before the wording change.
    assert.equal(operatorAwarenessTerm("사고인지시점 (담당자 기록 t_h)"), "사고인지시점 (담당자 기록 내부 인지시각)");
    assert.equal(operatorAwarenessTerm("담당자가 기록한 조직 내부 인지시각 t_h"), "담당자가 기록한 조직 내부 인지시각");
    assert.equal(operatorAwarenessTerm("내부 인지시각 (t_h)"), "내부 인지시각");
    assert.equal(operatorAwarenessTerm("t_h 시스템 기록시각"), "내부 인지시각 시스템 기록시각");
    assert.equal(operatorAwarenessTerm("t_h는 미래 시각일 수 없습니다."), "내부 인지시각은 미래 시각일 수 없습니다.");
    assert.equal(operatorAwarenessTerm("t_e는 조직 인지 시각 t_h가 아닙니다."), "t_e는 조직 인지시각이 아닙니다.");
    // Identifiers and quoted keys are not prose.
    for (const raw of ["t_h_recorded_at", "previous_t_h", '{"t_h":"2026-10-03T00:00:00Z"}', "path#/analysis/times/t_h_x"]) {
        assert.equal(operatorAwarenessTerm(raw), raw);
    }
    assert.equal(formatOperatorProse("추가 확인: 담당자가 기록한 조직 내부 인지시각 t_h, 피해 규모"), "추가 확인: 담당자가 기록한 조직 내부 인지시각, 피해 규모");
    assert.equal(operatorAwarenessTerm(null), null);
});
