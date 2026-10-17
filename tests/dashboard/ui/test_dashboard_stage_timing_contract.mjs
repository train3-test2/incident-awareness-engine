import assert from "node:assert/strict";
import test from "node:test";
import { buildStageTimingModel, classifyStageTimingFailure, formatStageDuration, resolveStageTimingTarget } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-stage-timing-contract.mjs";
import { stages, target, timingPayload } from "./stage-timing-fixture.mjs";

test("Six ended First Cycle records compare stored durations without declaring complete coverage", () => {
    // Given
    const payload = timingPayload();
    // When
    const model = buildStageTimingModel(payload, target);
    // Then
    assert.equal(model.records.length, 6);
    assert.deepEqual(model.longest.map((r) => r.stage), ["persistence"]);
    assert.equal(model.label, "결과 저장 · 6 ms");
    assert.equal(model.comparison, "부분 비교");
    assert.match(model.scope, /전체 실행의 확정 병목이 아닙니다/);
});

test("Standalone five operations do not invent or require an independent Fast handoff", () => {
    // Given / When
    const model = buildStageTimingModel(timingPayload({ selectedStages: stages.filter((s) => s !== "fast_handoff") }), target);
    // Then
    assert.equal(model.records.length, 5);
    assert.equal(model.records.some((r) => r.stage === "fast_handoff"), false);
    assert.match(model.scope, /응답으로 실행 경로를 식별하지 않습니다/);
    assert.equal(model.comparison, "부분 비교");
});

test("Exact BigInt comparison retains all ties in invocation order without summing retries", () => {
    // Given
    const payload = timingPayload({ selectedStages: ["normalization", "normalization", "fusion"],
        durations: ["9007199254740993", "9007199254740993", "9007199254740992"] });
    // When
    const model = buildStageTimingModel(payload, target);
    // Then
    assert.deepEqual(model.longest.map((r) => r.invocation_index), ["1", "2"]);
    assert.equal(model.label, "동률 2회 · 9007199254.740993 ms");
    assert.equal(formatStageDuration("0"), "0 ms");
    assert.equal(formatStageDuration("1"), "0.000001 ms");
    assert.equal(formatStageDuration("354226"), "0.354226 ms");
});

for (const kind of ["no-records", "known-no-snapshot", "partial", "failed", "active", "missing-duration", "missing-utc"]) {
    test(`Read state ${kind} never invents duration or terminal success`, () => {
        // Given
        const payload = timingPayload({ selectedStages: kind.startsWith("no-") || kind === "known-no-snapshot" ? [] : stages.slice(0, 2),
            failed: kind === "failed" ? "normalization" : null,
            active: kind === "active" ? "fusion" : null,
            issues: kind === "partial" ? ["observer_error"] : [], nullDuration: kind === "missing-duration" });
        if (kind === "known-no-snapshot") payload.snapshot = null;
        if (kind === "missing-utc") {
            payload.snapshot.records[0].started_at = null;
            payload.snapshot.records[0].issues = ["utc_clock_error"];
            payload.snapshot.quality_status = "partial";
        }
        // When
        const model = buildStageTimingModel(payload, target);
        // Then
        assert.match(model.comparison, /부분 비교/);
        if (kind === "failed") assert.match(model.comparison, /실패 단계 포함/);
        if (kind === "active") { assert.match(model.comparison, /실행 중/); assert.equal(model.records.length, 2); }
        if (kind === "partial" || kind === "missing-utc") assert.match(model.comparison, /계측 불완전/);
        if (["no-records", "known-no-snapshot"].includes(kind)) {
            assert.equal(model.label, "측정 기록 없음");
            assert.equal(model.caption, `Execution ${target.executionId}`);
        }
        if (kind === "missing-duration") {
            assert.equal(model.label, "소요시간 미관측");
            assert.equal(model.longest.length, 0);
            assert.equal(model.records.length, 2);
            assert.equal(model.caption, `계측 불완전 · Execution ${target.executionId}`);
        }
    });
}

test("Tied longest invocations are all named in the accessible scope, not reduced to one stage", () => {
    // Given
    const payload = timingPayload({ selectedStages: ["normalization", "fusion", "hybrid"],
        durations: ["5000000", "5000000", "1000000"] });
    // When
    const model = buildStageTimingModel(payload, target);
    // Then
    assert.equal(model.label, "동률 2회 · 5 ms");
    assert.match(model.scope, /최장 동률: #1 [^,]+, #2 [^·]+ · 5 ms/);
    assert.deepEqual(model.longest.map((r) => r.stage), ["normalization", "fusion"]);
});

test("Only documented Read API error details name a cause; other failures stay generic", () => {
    // When
    const routeMissing = classifyStageTimingFailure(404, "Not Found", "exec-1");
    const notStored = classifyStageTimingFailure(404, "Execution is not present in stored observation records", "exec-1");
    const otherNotFound = classifyStageTimingFailure(404, "Something else", "exec-1");
    const unavailable = classifyStageTimingFailure(503, "Stage timing database is unavailable", "exec-1");
    const readFailed = classifyStageTimingFailure(500, "Stage timing read failed", "exec-1");
    const network = classifyStageTimingFailure(0, null, "exec-1");
    // Then
    assert.deepEqual([routeMissing.label, routeMissing.caption, routeMissing.tone], ["계측 저장 미준비", "조회 API 미제공", "neutral"]);
    assert.match(routeMissing.scope, /0ms나 미실행으로 해석하지 않습니다/);
    assert.deepEqual([notStored.label, notStored.tone], ["측정 기록 없음", "neutral"]);
    for (const failure of [otherNotFound, unavailable, readFailed, network]) {
        assert.equal(failure.label, "계측 조회 실패");
        assert.equal(failure.tone, "error");
        assert.match(failure.scope, /저장 미준비 여부는 구분할 수 없습니다/);
    }
    assert.equal(unavailable.caption, "HTTP 503 · 계측 DB 연결 불가");
    assert.equal(readFailed.caption, "HTTP 500 · 원인 구분 불가");
    assert.equal(network.caption, "응답 확인 실패");
});

const corruptions = {
    "negative duration": (p) => { p.snapshot.records[0].duration_ns = "-1"; },
    "float duration": (p) => { p.snapshot.records[0].duration_ns = "1.2"; },
    "numeric duration": (p) => { p.snapshot.records[0].duration_ns = 1; },
    "missing duration": (p) => { p.snapshot.records[0].duration_ns = null; },
    "duplicate ordinal": (p) => { p.snapshot.records[1].invocation_index = "1"; },
    "unordered ordinal": (p) => { p.snapshot.records.reverse(); },
    "active ordinal collision": (p) => { p.snapshot.active_stage = "fusion"; p.snapshot.active_invocation_index = "1"; },
    "UTC offset": (p) => { p.snapshot.records[0].ended_at = "2026-10-18T01:02:03.001+00:00"; },
    "invalid calendar UTC": (p) => { p.snapshot.records[0].ended_at = "2026-02-30T01:02:03.001Z"; },
    "UTC regression": (p) => { p.snapshot.records[0].ended_at = "2026-10-17T01:02:03.001Z"; },
    "mixed Run": (p) => { p.snapshot.run_id = "other"; },
    "mixed Entity": (p) => { p.snapshot.entity_id = "other"; },
    "mixed Execution": (p) => { p.snapshot.execution_id = "other"; },
    "mismatched response Execution": (p) => { p.execution_id = "other"; },
    "wrong coverage": (p) => { p.coverage_status = "complete"; },
    "wrong failure summary": (p) => { p.operation_failure_recorded = true; },
    "wrong missing summary": (p) => { p.unmeasured_stages = ["fusion"]; },
    "wrong quality": (p) => { p.snapshot.quality_status = "partial"; },
    "wrong availability": (p) => { p.availability = "no_stage_timings"; },
    "wrong schema": (p) => { p.schema_version = "v0"; },
};
for (const [name, corrupt] of Object.entries(corruptions)) {
    test(`Reject ${name} before showing any measurement`, () => {
        // Given
        const payload = timingPayload(); corrupt(payload);
        // When / Then
        assert.throws(() => buildStageTimingModel(payload, target), TypeError);
    });
}

test("Target resolution requires exact selected scope in the current query, never retained or ambiguous reports", () => {
    // Given
    const report = { run_id: target.runId, entity_id: target.entityId, execution_id: target.executionId,
        status: "completed", current_stage: null };
    const input = { runId: target.runId, entityId: target.entityId, items: [report] };
    // When / Then
    assert.deepEqual(resolveStageTimingTarget(input).target, target);
    for (const overrides of [{ entityId: null }, { runId: null }, { queryFailed: true }, { outsideQuery: true },
        { items: [] }, { entityId: "other" }, { items: [{ ...report, execution_id: null }] },
        { items: [report, { ...report, execution_id: "other-execution" }] }]) {
        assert.equal(resolveStageTimingTarget({ ...input, ...overrides }).target, null);
    }
    assert.deepEqual(resolveStageTimingTarget({ ...input, items: [report, { ...report, entity_id: "other" }] }).target, target);
});

test("Each unresolved selection state has its own short card caption", () => {
    // Given
    const report = { run_id: target.runId, entity_id: target.entityId, execution_id: target.executionId,
        status: "completed", current_stage: null };
    const input = { runId: target.runId, entityId: target.entityId, items: [report] };
    const caption = (overrides) => resolveStageTimingTarget({ ...input, ...overrides }).caption;
    // When / Then
    assert.equal(caption({ runId: null, entityId: null }), "Runtime 선택 필요");
    assert.equal(caption({ entityId: null }), "Runtime 선택 필요");
    assert.equal(caption({ entityId: null, items: [] }), "Runtime 보고 없음");
    assert.equal(caption({ items: [] }), "Runtime 보고 없음");
    assert.equal(caption({ outsideQuery: true }), "조회 범위 밖");
    assert.equal(caption({ queryFailed: true }), "Runtime 조회 실패");
    assert.equal(caption({ items: [report, { ...report, execution_id: "other" }] }), "복수 Execution");
    assert.equal(caption({ items: [{ ...report, execution_id: " padded" }] }), "Execution 확인 불가");
    assert.equal(resolveStageTimingTarget(input).caption, "");
});
