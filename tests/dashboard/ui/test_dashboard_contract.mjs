// Dashboard UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_dashboard_contract.mjs
import assert from "node:assert/strict";
import test from "node:test";

import {
    NOT_APPLICABLE,
    formatRunTimestamp,
    getOverviewQueryMessage,
    getRunTypeLabel,
    resolveOverviewQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";

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
        message: "Overview 정보를 불러오는 중입니다.",
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
    assert.equal(state.message, "Overview 정보를 불러왔습니다.");
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
        message: "Overview 정보를 불러오지 못했습니다.",
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
