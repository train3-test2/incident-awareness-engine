// Evaluation View UI contract: exercises the pure presentation module under Node.
// Run with: node --test tests/dashboard/ui/test_evaluation_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    formatNullable,
    formatPercentage,
    formatSeconds,
    getEvaluationErrorMessage,
    getEvaluationStatusPresentations,
    getPurposePresentation,
    projectEvaluationSections,
    projectExclusions,
    projectSnapshotSummary,
    resolveEvaluationQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/evaluation-contract.mjs";

function evaluationPayload(overrides = {}) {
    return {
        snapshot_id: "snapshot-1",
        plan: {
            scenario_id: "S0",
            purpose: "smoke",
            decision_ids: { "RUN-1": "DEC-1" },
            decision_config_version: "decision-v1",
            scoring_config_version: "scoring-v1",
            scoring_profile_id: "profile-v1",
            scoring_method: "weighted-sum",
            scorer_version: "scorer-v1",
            model_version: null,
            detector_set_version: "detectors-v1",
            fast_episode_policy_version: "fast-policy-v1",
            evaluation_horizon_sec: 120,
            parallel_required: true,
        },
        exclusions: [],
        evaluated_run_ids: {
            Fast: ["RUN-1"],
            Fusion: ["RUN-1"],
            Hybrid: ["RUN-1"],
        },
        comparison_ready: true,
        metrics: {
            Fast: { run_recall: 0.75 },
            Fusion: { run_recall: 0.5 },
            Hybrid: { run_recall: 1.0 },
        },
        normal_alert_burden: {
            comparison_ready: true,
            metrics: { Fast: {}, Fusion: {} },
        },
        paired_timing: {
            paired_coverage_complete: true,
            per_run: [],
        },
        ...overrides,
    };
}

test("snapshot summary projects only stored Snapshot and Plan fields", () => {
    // Given
    const payload = evaluationPayload();

    // When
    const summary = projectSnapshotSummary(payload);

    // Then
    assert.deepEqual(summary, [
        { label: "Snapshot ID", value: "snapshot-1" },
        { label: "Scenario ID", value: "S0" },
        { label: "Purpose", value: "smoke" },
        { label: "Evaluation Horizon", value: "120 sec" },
        { label: "Decision Config Version", value: "decision-v1" },
        { label: "Scoring Config Version", value: "scoring-v1" },
        { label: "Scoring Profile ID", value: "profile-v1" },
        { label: "Scoring Method", value: "weighted-sum" },
        { label: "Scorer Version", value: "scorer-v1" },
        { label: "Model Version", value: "N/A" },
        { label: "Detector Set Version", value: "detectors-v1" },
        { label: "Fast Episode Policy Version", value: "fast-policy-v1" },
    ]);
});

test("smoke purpose warns against performance claims", () => {
    // Given
    const purpose = "smoke";

    // When
    const presentation = getPurposePresentation(purpose);

    // Then
    assert.equal(presentation.title, "Smoke Evaluation");
    assert.equal(presentation.modifier, "smoke");
    assert.match(presentation.description, /파이프라인 및 평가 계약 검증/);
    assert.match(presentation.description, /성능 우위 주장에 사용하는 결과가 아닙니다/);
});

test("performance purpose remains descriptive without readiness claims", () => {
    // Given
    const purpose = "performance";

    // When
    const presentation = getPurposePresentation(purpose);

    // Then
    assert.deepEqual(presentation, {
        label: "performance",
        title: "Performance Evaluation",
        description: "성능 평가 목적으로 저장된 Evaluation Snapshot 결과입니다.",
        modifier: "performance",
    });
    assert.doesNotMatch(presentation.description, /production ready|validated|superior/i);
});

test("percentage and seconds format only API-provided values", () => {
    // Given
    const recall = 0.75;
    const horizon = 120;

    // When
    const percentage = formatPercentage(recall);
    const seconds = formatSeconds(horizon);

    // Then
    assert.equal(percentage, "75.0%");
    assert.equal(seconds, "120 sec");
});

test("nullable presentation consistently uses N/A", () => {
    // Given
    const nullableValues = [null, undefined];

    // When
    const values = nullableValues.flatMap((value) => [
        formatNullable(value),
        formatPercentage(value),
        formatSeconds(value),
    ]);

    // Then
    assert.ok(values.every((value) => value === NOT_APPLICABLE));
});

test("three comparison states remain independent", () => {
    // Given
    const payload = evaluationPayload({
        comparison_ready: false,
        normal_alert_burden: { comparison_ready: true, metrics: { Fast: {}, Fusion: {} } },
        paired_timing: { paired_coverage_complete: false, per_run: [] },
    });

    // When
    const statuses = getEvaluationStatusPresentations(payload);

    // Then
    assert.deepEqual(statuses.map(({ label, statusLabel }) => [label, statusLabel]), [
        ["Method Comparison", "Incomplete"],
        ["Normal Alert Burden", "Ready"],
        ["Paired Timing", "Incomplete"],
    ]);
});

test("exclusions preserve API order and not_evaluated semantics", () => {
    // Given
    const payload = evaluationPayload({
        exclusions: [
            { run_id: "RUN-2", method: "Fusion", reason: "not_evaluated" },
            { run_id: "RUN-1", method: "Fast", reason: "not_evaluated" },
        ],
    });

    // When
    const exclusions = projectExclusions(payload);

    // Then
    assert.deepEqual(exclusions, [
        { runId: "RUN-2", method: "Fusion", reason: "not_evaluated" },
        { runId: "RUN-1", method: "Fast", reason: "not_evaluated" },
    ]);
    assert.doesNotMatch(JSON.stringify(exclusions), /miss|failed/);
});

test("future section contract preserves evaluator-owned report references", () => {
    // Given
    const payload = evaluationPayload();

    // When
    const sections = projectEvaluationSections(payload);

    // Then
    assert.strictEqual(sections.methodComparison.metrics, payload.metrics);
    assert.strictEqual(
        sections.methodComparison.evaluatedRunIds,
        payload.evaluated_run_ids,
    );
    assert.strictEqual(sections.normalAlertBurden, payload.normal_alert_burden);
    assert.strictEqual(sections.pairedTiming, payload.paired_timing);
    assert.strictEqual(sections.runLevelPairedTiming, payload.paired_timing.per_run);
    assert.deepEqual(Object.keys(sections.normalAlertBurden.metrics), ["Fast", "Fusion"]);
});

test("query states distinguish loading, success, and sanitized errors", () => {
    // Given
    const payload = evaluationPayload();

    // When
    const loading = resolveEvaluationQueryState(null, { kind: "loading" });
    const success = resolveEvaluationQueryState(loading, { kind: "success", payload });
    const unavailable = resolveEvaluationQueryState(success, {
        kind: "error",
        status: 503,
        detail: "Evaluation snapshot is unavailable",
    });
    const invalid = resolveEvaluationQueryState(success, {
        kind: "error",
        status: 500,
        detail: "Stored evaluation snapshot is invalid",
    });
    const generic = getEvaluationErrorMessage(502, "upstream detail");

    // Then
    assert.equal(loading.message, "평가 정보를 불러오는 중입니다.");
    assert.strictEqual(success.payload, payload);
    assert.equal(unavailable.message, "Evaluation Snapshot을 사용할 수 없습니다.");
    assert.equal(invalid.message, "저장된 Evaluation Snapshot이 유효하지 않습니다.");
    assert.equal(generic, "평가 정보를 불러오지 못했습니다.");
});

test("presentation helpers do not mutate the API payload", () => {
    // Given
    const payload = evaluationPayload({
        exclusions: [{ run_id: "RUN-1", method: "Hybrid", reason: "not_evaluated" }],
    });
    const original = structuredClone(payload);

    // When
    projectSnapshotSummary(payload);
    getEvaluationStatusPresentations(payload);
    projectExclusions(payload);
    projectEvaluationSections(payload);
    resolveEvaluationQueryState(null, { kind: "success", payload });

    // Then
    assert.deepEqual(payload, original);
});

test("contract rejects malformed payloads without deriving fallback metrics", () => {
    // Given
    const invalidCalls = [
        () => resolveEvaluationQueryState(null, { kind: "success", payload: null }),
        () => projectSnapshotSummary(evaluationPayload({ plan: null })),
        () => resolveEvaluationQueryState(null, {
            kind: "success",
            payload: evaluationPayload({
                plan: { ...evaluationPayload().plan, purpose: "production" },
            }),
        }),
        () => resolveEvaluationQueryState(null, {
            kind: "success",
            payload: evaluationPayload({
                plan: { ...evaluationPayload().plan, evaluation_horizon_sec: "120" },
            }),
        }),
        () => getEvaluationStatusPresentations(evaluationPayload({ comparison_ready: 1 })),
        () => projectExclusions(evaluationPayload({ exclusions: [null] })),
        () => projectExclusions(evaluationPayload({
            exclusions: [{ run_id: "RUN-1", method: "Fast", reason: null }],
        })),
        () => projectEvaluationSections(evaluationPayload({
            paired_timing: { paired_coverage_complete: true, per_run: null },
        })),
        () => formatPercentage(Number.NaN),
        () => formatSeconds(Number.POSITIVE_INFINITY),
        () => getPurposePresentation("production"),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
});

test("Evaluation contract is pure and contains no evaluation formulas", async () => {
    // Given
    const source = await readFile(
        new URL(
            "../../../src/incident_awareness/dashboard/ui/assets/evaluation-contract.mjs",
            import.meta.url,
        ),
        "utf8",
    );

    // When
    const forbiddenFragments = [
        "document",
        "window",
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "WebSocket",
        "EventSource",
        "detected_runs",
        "false_positive_runs",
        "false_alert_episodes",
        "eligible_time",
        "reference_time",
        "fusion_minus_fast_sec",
        "Math.min(",
    ];

    // Then
    for (const fragment of forbiddenFragments) {
        assert.equal(source.includes(fragment), false);
    }
});
