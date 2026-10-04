// Operations View UI contract: runs the real presentation module under Node's built-in test runner.
// Run with: node --test tests/dashboard/ui/test_operations_contract.mjs
import assert from "node:assert/strict";
import test from "node:test";

import {
    NOT_APPLICABLE,
    getRuntimeProgressPresentation,
    getRuntimeQueryMessage,
    getRuntimeStatePresentation,
    getStageLabel,
    resolveRuntimeQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs";

const RUNNING_STATUS_LABEL = "실행 중(마지막 보고)";
const PIPELINE_FAILURE_WORDING = /실패|중단|종료|failed|stopped|dead|timeout/i;

function runtime(overrides) {
    return {
        status: "running",
        is_stale: false,
        has_error: false,
        current_stage: "normalization",
        failed_stage: null,
        normalization_processed_count: 137,
        input_total: 250,
        remaining_count: 113,
        ...overrides,
    };
}

function presentationText(presentation) {
    return [presentation.statusLabel, presentation.telemetryLabel, presentation.livenessLabel]
        .filter((label) => label !== null)
        .join(" ");
}

test("fresh running reports recent telemetry without claiming liveness", () => {
    // Given
    const freshRunning = runtime({ status: "running", is_stale: false });

    // When
    const presentation = getRuntimeStatePresentation(freshRunning, true);

    // Then
    assert.deepEqual(presentation, {
        modifiers: ["running"],
        statusLabel: RUNNING_STATUS_LABEL,
        telemetryLabel: "최근 갱신",
        livenessLabel: null,
    });
});

test("stale running keeps the running status but cannot confirm current execution", () => {
    // Given
    const staleRunning = runtime({ status: "running", is_stale: true });

    // When
    const presentation = getRuntimeStatePresentation(staleRunning, true);

    // Then
    assert.deepEqual(presentation, {
        modifiers: ["running", "stale"],
        statusLabel: RUNNING_STATUS_LABEL,
        telemetryLabel: "오래됨",
        livenessLabel: "확인 불가",
    });
    assert.doesNotMatch(presentationText(presentation), PIPELINE_FAILURE_WORDING);
    assert.doesNotMatch(presentationText(presentation), /현재 실행 중/);
});

test("retained running shows unavailable telemetry while the query is failing", () => {
    // Given
    const retained = [
        runtime({ status: "running", is_stale: false }),
        runtime({ status: "running", is_stale: true }),
    ];

    // When
    const presentations = retained.map((item) => getRuntimeStatePresentation(item, false));

    // Then
    for (const presentation of presentations) {
        assert.deepEqual(presentation, {
            modifiers: ["running", "telemetry-unavailable"],
            statusLabel: RUNNING_STATUS_LABEL,
            telemetryLabel: "확인 불가 (조회 실패)",
            livenessLabel: "확인 불가",
        });
        assert.notEqual(presentation.telemetryLabel, "최근 갱신");
        assert.notEqual(presentation.telemetryLabel, "오래됨");
        assert.notEqual(presentation.statusLabel, "실패");
        assert.ok(!presentation.modifiers.includes("failed"));
    }
});

test("completed is presented as completed regardless of query availability", () => {
    // Given
    const completed = runtime({ status: "completed", current_stage: null, remaining_count: 0 });

    // When
    const available = getRuntimeStatePresentation(completed, true);
    const unavailable = getRuntimeStatePresentation(completed, false);

    // Then
    assert.equal(available.statusLabel, "완료");
    assert.deepEqual(available.modifiers, ["completed"]);
    assert.equal(available.telemetryLabel, NOT_APPLICABLE);
    assert.deepEqual(unavailable, available);
});

test("failed is presented as failed regardless of query availability", () => {
    // Given
    const failed = runtime({
        status: "failed",
        has_error: true,
        current_stage: null,
        failed_stage: "hybrid",
    });

    // When
    const available = getRuntimeStatePresentation(failed, true);
    const unavailable = getRuntimeStatePresentation(failed, false);

    // Then
    assert.equal(available.statusLabel, "실패");
    assert.deepEqual(available.modifiers, ["failed"]);
    assert.equal(available.telemetryLabel, NOT_APPLICABLE);
    assert.deepEqual(unavailable, available);
});

test("persisted status, not has_error, decides the presented state", () => {
    // Given
    const runningWithErrorFlag = runtime({ status: "running", has_error: true });

    // When
    const presentation = getRuntimeStatePresentation(runningWithErrorFlag, true);

    // Then
    assert.equal(presentation.statusLabel, RUNNING_STATUS_LABEL);
    assert.deepEqual(presentation.modifiers, ["running"]);
});

test("stage vocabulary maps to readable labels with safe fallbacks", () => {
    // Given
    const expectedLabels = [
        ["artifact_validation", "입력 검증"],
        ["normalization", "이벤트 처리"],
        ["fusion", "증거 누적 판단"],
        ["fast_handoff", "즉시 판단 연계"],
        ["hybrid", "통합 판단"],
        ["persistence", "결과 저장"],
    ];

    // When
    const labels = expectedLabels.map(([stage]) => getStageLabel(stage));

    // Then
    assert.deepEqual(labels, expectedLabels.map(([, label]) => label));
    assert.equal(getStageLabel(null), "-");
    assert.equal(getStageLabel(undefined), "-");
    assert.equal(getStageLabel("future_stage_x"), "future_stage_x");
});

test("progress shows processed, total, and remaining counts as reported", () => {
    // Given
    const inProgress = {
        normalization_processed_count: 137,
        input_total: 250,
        remaining_count: 113,
    };
    const finished = { normalization_processed_count: 250, input_total: 250, remaining_count: 0 };

    // When
    const inProgressPresentation = getRuntimeProgressPresentation(inProgress);
    const finishedPresentation = getRuntimeProgressPresentation(finished);

    // Then
    assert.deepEqual(inProgressPresentation, { processed: "137 / 250 처리", remaining: "113" });
    assert.deepEqual(finishedPresentation, { processed: "250 / 250 처리", remaining: "0" });
    assert.doesNotMatch(JSON.stringify(inProgressPresentation), /%|대기열|backlog|queue/i);
});

test("query messages cover loading, success, empty, and error states", () => {
    // Given
    const states = [["loading"], ["success", 3], ["success", 0], ["error"]];

    // When
    const messages = states.map(([state, count]) => getRuntimeQueryMessage(state, count));

    // Then
    assert.deepEqual(messages, [
        "Runtime 정보를 불러오는 중입니다.",
        "Runtime 3건을 불러왔습니다.",
        "표시할 Runtime 정보가 없습니다.",
        "Runtime 정보를 불러오지 못했습니다.",
    ]);
});

test("query messages reject unknown states and invalid counts", () => {
    // Given
    const invalidCalls = [
        () => getRuntimeQueryMessage("refreshing"),
        () => getRuntimeQueryMessage("success"),
        () => getRuntimeQueryMessage("success", -1),
        () => getRuntimeQueryMessage("success", 1.5),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall, RangeError);
    }
});

test("empty query success clears the visible Runtime items", () => {
    // Given
    const previousItems = [{ status: "running" }];
    const previousSnapshot = structuredClone(previousItems);

    // When
    const result = resolveRuntimeQueryState(
        previousItems,
        { kind: "success", items: [] },
    );

    // Then
    assert.deepEqual(result.items, []);
    assert.equal(result.telemetryAvailable, true);
    assert.equal(result.message, "표시할 Runtime 정보가 없습니다.");
    assert.deepEqual(previousItems, previousSnapshot);
});

test("query error retains the last successful Runtime items", () => {
    // Given
    const previousItems = [{ run_id: "RUN-1", status: "running" }];
    const previousSnapshot = structuredClone(previousItems);

    // When
    const result = resolveRuntimeQueryState(previousItems, { kind: "error" });

    // Then
    assert.strictEqual(result.items, previousItems);
    assert.equal(result.telemetryAvailable, false);
    assert.equal(result.message, "Runtime 정보를 불러오지 못했습니다.");
    assert.deepEqual(previousItems, previousSnapshot);
});

test("query state rejects invalid previous items, success items, and result kinds", () => {
    // Given
    const invalidCalls = [
        () => resolveRuntimeQueryState(null, { kind: "error" }),
        () => resolveRuntimeQueryState([], { kind: "success", items: null }),
        () => resolveRuntimeQueryState([], { kind: "unknown" }),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
});
