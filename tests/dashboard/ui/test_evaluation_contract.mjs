// Evaluation View UI contract: exercises the pure presentation module under Node.
// Run with: node --test tests/dashboard/ui/test_evaluation_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    buildAlertBurden,
    buildMethodComparison,
    buildPairedTimingRows,
    buildPairedTimingSummary,
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

function methodMetric(method, overrides = {}) {
    return {
        method,
        total_attack_runs: 4,
        detected_runs: 3,
        run_recall: 0.75,
        median_ttsd_sec: 40,
        total_normal_runs: 2,
        false_positive_runs: 1,
        benign_run_fpr: 0.5,
        ttsd_iqr_sec: 10,
        ...overrides,
    };
}

function burdenMetric(method, overrides = {}) {
    return {
        evaluated_run_ids: [`RUN-${method}-2`, `RUN-${method}-1`],
        false_alert_episodes: 3,
        benign_run_hours: 2,
        false_alerts_per_benign_run_hour: 1.5,
        per_run: [
            {
                run_id: `RUN-${method}-2`,
                entity_id: "host-2",
                family_id: null,
                variation_id: null,
                repetition: null,
                false_alert_episodes: 2,
                observation_seconds: 3600,
            },
            {
                run_id: `RUN-${method}-1`,
                entity_id: "host-1",
                family_id: "family-a",
                variation_id: "variant-b",
                repetition: 2,
                false_alert_episodes: 1,
                observation_seconds: 3600,
            },
        ],
        ...overrides,
    };
}

function pairedRow(runId, overrides = {}) {
    return {
        run_id: runId,
        entity_id: "host-attack",
        family_id: "family-a",
        variation_id: "variant-a",
        repetition: 1,
        decision_id: `DEC-${runId}`,
        reference_time: "2026-09-20T00:00:00.000Z",
        paths: {
            Fast: {
                eligible_status: "detected",
                eligible_time: "2026-09-20T00:00:10.000Z",
                ttsd_sec: 10,
            },
            Fusion: {
                eligible_status: "detected",
                eligible_time: "2026-09-20T00:00:20.000Z",
                ttsd_sec: 20,
            },
        },
        outcome: "both_detected",
        fusion_minus_fast_sec: 10,
        earlier_eligible_path: "Fast",
        ...overrides,
    };
}

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
            Fast: methodMetric("Fast"),
            Fusion: methodMetric("Fusion", { run_recall: 0.5, median_ttsd_sec: null }),
            Hybrid: methodMetric("Hybrid", { run_recall: 1, benign_run_fpr: null }),
        },
        normal_alert_burden: {
            normal_run_ids: ["RUN-Fast-2", "RUN-Fast-1"],
            comparison_ready: true,
            metrics: {
                Fast: burdenMetric("Fast"),
                Fusion: burdenMetric("Fusion"),
            },
        },
        paired_timing: {
            paired_coverage_complete: true,
            counts: {
                both_detected: 1,
                fast_only: 2,
                fusion_only: 3,
                both_miss: 4,
                not_evaluated: 5,
            },
            both_detected_summary: {
                run_count: 1,
                fast_earlier: 1,
                fusion_earlier: 0,
                ties: 0,
                median_fusion_minus_fast_sec: 10,
            },
            per_run: [pairedRow("RUN-2"), pairedRow("RUN-1")],
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
    const payload = evaluationPayload({ comparison_ready: false });
    payload.normal_alert_burden.comparison_ready = true;
    payload.paired_timing.paired_coverage_complete = false;

    // When
    const statuses = getEvaluationStatusPresentations(payload);

    // Then
    assert.deepEqual(statuses.map(({ label, statusLabel }) => [label, statusLabel]), [
        ["Method Comparison", "Incomplete"],
        ["Normal Alert Burden", "Ready"],
        ["Paired Timing", "Incomplete"],
    ]);
});

test("method comparison uses API metrics without recomputing recall or FPR", () => {
    // Given
    const payload = evaluationPayload();
    payload.metrics.Fast = methodMetric("Fast", {
        detected_runs: 1,
        total_attack_runs: 2,
        run_recall: 0.9,
        false_positive_runs: 1,
        total_normal_runs: 2,
        benign_run_fpr: 0.9,
        median_ttsd_sec: 12,
        ttsd_iqr_sec: 7,
    });

    // When
    const methods = buildMethodComparison(payload);

    // Then
    assert.deepEqual(methods.map((method) => method.method), ["Fast", "Fusion", "Hybrid"]);
    assert.deepEqual(methods[0].fields, [
        { label: "Run Recall", value: "90.0%", progressValue: 0.9 },
        { label: "Detected / Total Attack Runs", value: "1 / 2" },
        { label: "Median TTSD", value: "12 sec" },
        { label: "TTSD IQR", value: "7 sec" },
        { label: "Benign Run FPR", value: "90.0%", progressValue: 0.9 },
        { label: "False Positive / Total Normal Runs", value: "1 / 2" },
    ]);
});

test("method comparison keeps null metrics and nullable values explicit", () => {
    // Given
    const payload = evaluationPayload();
    payload.metrics.Fast = null;

    // When
    const methods = buildMethodComparison(payload);

    // Then
    assert.deepEqual(methods[0], {
        method: "Fast",
        available: false,
        emptyMessage: "평가 데이터 없음",
    });
    assert.equal(methods[1].fields[2].value, "N/A");
    assert.equal(methods[2].fields[4].value, "N/A");
    assert.equal(methods[2].fields[4].progressValue, null);
});

test("bounded indicators use only API recall and FPR values", () => {
    // Given
    const payload = evaluationPayload();
    payload.metrics.Fast.run_recall = 0.25;
    payload.metrics.Fast.benign_run_fpr = 0.8;

    // When
    const [fast] = buildMethodComparison(payload);

    // Then
    assert.equal(fast.fields[0].progressValue, 0.25);
    assert.equal(fast.fields[4].progressValue, 0.8);
    assert.ok(fast.fields.slice(1, 4).every((field) => !("progressValue" in field)));
    assert.equal("progressValue" in fast.fields[5], false);
});

test("alert burden includes only Fast and Fusion and trusts the API FA/BH", () => {
    // Given
    const payload = evaluationPayload();
    payload.normal_alert_burden.metrics.Fast = burdenMetric("Fast", {
        false_alert_episodes: 10,
        benign_run_hours: 2,
        false_alerts_per_benign_run_hour: 123,
    });
    payload.normal_alert_burden.metrics.Fusion = burdenMetric("Fusion", {
        false_alerts_per_benign_run_hour: null,
    });

    // When
    const burden = buildAlertBurden(payload);

    // Then
    assert.deepEqual(burden.map((method) => method.method), ["Fast", "Fusion"]);
    assert.deepEqual(burden[0].fields, [
        { label: "Evaluated Normal Runs", value: "2" },
        { label: "False Alert Episodes", value: "10" },
        { label: "Benign Run Hours", value: "2" },
        { label: "FA/BH", value: "123" },
    ]);
    assert.equal(burden[1].fields[3].value, "N/A");
});

test("alert burden preserves per-run order and nullable provenance", () => {
    // Given
    const payload = evaluationPayload();

    // When
    const [fast] = buildAlertBurden(payload);

    // Then
    assert.deepEqual(fast.rows.map((row) => row.runId), ["RUN-Fast-2", "RUN-Fast-1"]);
    assert.deepEqual(fast.rows[0], {
        runId: "RUN-Fast-2",
        entityId: "host-2",
        familyId: "N/A",
        variationId: "N/A",
        repetition: "N/A",
        falseAlertEpisodes: "2",
        observationSeconds: "3600 sec",
    });
});

test("paired timing summary uses API counts and API median delta", () => {
    // Given
    const payload = evaluationPayload();
    payload.paired_timing.both_detected_summary.median_fusion_minus_fast_sec = 999;

    // When
    const summary = buildPairedTimingSummary(payload);

    // Then
    assert.deepEqual(summary.counts.map((item) => item.value), ["1", "2", "3", "4", "5"]);
    assert.deepEqual(summary.bothDetected, [
        { label: "Run Count", value: "1" },
        { label: "Fast Earlier", value: "1" },
        { label: "Fusion Earlier", value: "0" },
        { label: "Ties", value: "0" },
        { label: "Median Fusion - Fast", value: "999 sec" },
    ]);
    assert.match(summary.deltaExplanation, /양수이면 Fast/);
    assert.match(summary.deltaExplanation, /음수이면 Fusion/);
    assert.match(summary.deltaExplanation, /0이면 tie/);
});

test("run-level paired timing preserves API rows, statuses, and delta", () => {
    // Given
    const payload = evaluationPayload();
    payload.paired_timing.per_run[0].fusion_minus_fast_sec = 999;
    payload.paired_timing.per_run[1] = pairedRow("RUN-1", {
        paths: {
            Fast: { eligible_status: "miss", eligible_time: null, ttsd_sec: null },
            Fusion: {
                eligible_status: "not_evaluated",
                eligible_time: null,
                ttsd_sec: null,
            },
        },
        outcome: "not_evaluated",
        fusion_minus_fast_sec: null,
        earlier_eligible_path: null,
    });

    // When
    const rows = buildPairedTimingRows(payload);

    // Then
    assert.deepEqual(rows.map((row) => row.runId), ["RUN-2", "RUN-1"]);
    assert.equal(rows[0].fastTtsd, "10 sec");
    assert.equal(rows[0].fusionTtsd, "20 sec");
    assert.equal(rows[0].fusionMinusFast, "999 sec");
    assert.equal(rows[0].earlierEligiblePath, "Fast");
    assert.equal(rows[1].fastStatus, "Miss");
    assert.equal(rows[1].fusionStatus, "Not Evaluated");
    assert.equal(rows[1].outcome, "Not Evaluated");
    assert.equal(rows[1].fusionMinusFast, "N/A");
    assert.equal(rows[1].earlierEligiblePath, "N/A");
});

test("empty evaluated row collections remain empty without synthetic metrics", () => {
    // Given
    const payload = evaluationPayload();
    payload.normal_alert_burden.normal_run_ids = [];
    payload.normal_alert_burden.metrics.Fast.evaluated_run_ids = [];
    payload.normal_alert_burden.metrics.Fast.per_run = [];
    payload.paired_timing.per_run = [];

    // When
    const burden = buildAlertBurden(payload);
    const pairedRows = buildPairedTimingRows(payload);

    // Then
    assert.equal(burden[0].fields[0].value, "0");
    assert.deepEqual(burden[0].rows, []);
    assert.deepEqual(pairedRows, []);
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
    assert.deepEqual(exclusions.map((item) => item.runId), ["RUN-2", "RUN-1"]);
    assert.doesNotMatch(JSON.stringify(exclusions), /miss|failed/);
});

test("section projection exposes presentation-only Stage 2 data", () => {
    // Given
    const payload = evaluationPayload();

    // When
    const sections = projectEvaluationSections(payload);

    // Then
    assert.deepEqual(sections.methodComparison, buildMethodComparison(payload));
    assert.deepEqual(sections.normalAlertBurden, buildAlertBurden(payload));
    assert.deepEqual(sections.pairedTiming, buildPairedTimingSummary(payload));
    assert.deepEqual(sections.runLevelPairedTiming, buildPairedTimingRows(payload));
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

test("contract rejects malformed Stage 2 fields before rendering", () => {
    // Given
    const invalidPayloads = [
        (() => {
            const payload = evaluationPayload();
            payload.metrics.Fast.run_recall = "0.5";
            return payload;
        })(),
        (() => {
            const payload = evaluationPayload();
            payload.paired_timing.counts.both_detected = "1";
            return payload;
        })(),
        (() => {
            const payload = evaluationPayload();
            delete payload.paired_timing.per_run[0].paths;
            return payload;
        })(),
        (() => {
            const payload = evaluationPayload();
            payload.normal_alert_burden.metrics.Fast.per_run[0].observation_seconds = "3600";
            return payload;
        })(),
        (() => {
            const payload = evaluationPayload();
            payload.metrics.Fast.run_recall = 1.1;
            return payload;
        })(),
    ];

    // When / Then
    for (const payload of invalidPayloads) {
        assert.throws(() => resolveEvaluationQueryState(null, { kind: "success", payload }));
    }
});

test("contract rejects unsupported purpose and malformed evaluation horizon", () => {
    // Given
    const unsupportedPurpose = evaluationPayload();
    unsupportedPurpose.plan.purpose = "production";
    const malformedHorizon = evaluationPayload();
    malformedHorizon.plan.evaluation_horizon_sec = "120";

    // When / Then
    assert.throws(() => resolveEvaluationQueryState(null, {
        kind: "success",
        payload: unsupportedPurpose,
    }));
    assert.throws(() => resolveEvaluationQueryState(null, {
        kind: "success",
        payload: malformedHorizon,
    }));
});

test("contract rejects malformed base fields and non-finite presentation values", () => {
    // Given
    const invalidCalls = [
        () => resolveEvaluationQueryState(null, { kind: "success", payload: null }),
        () => projectSnapshotSummary(evaluationPayload({ plan: null })),
        () => getEvaluationStatusPresentations(evaluationPayload({ comparison_ready: 1 })),
        () => projectExclusions(evaluationPayload({ exclusions: [null] })),
        () => formatPercentage(Number.NaN),
        () => formatSeconds(Number.POSITIVE_INFINITY),
        () => getPurposePresentation("production"),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
});

test("Evaluation presentation is pure, order-preserving, and contains no metric formulas", async () => {
    // Given
    const contractSource = await readFile(
        new URL(
            "../../../src/incident_awareness/dashboard/ui/assets/evaluation-contract.mjs",
            import.meta.url,
        ),
        "utf8",
    );
    const rendererSource = await readFile(
        new URL(
            "../../../src/incident_awareness/dashboard/ui/assets/evaluation.js",
            import.meta.url,
        ),
        "utf8",
    );

    // When
    const pureContractForbidden = [
        "document",
        "window",
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "WebSocket",
        "EventSource",
    ];
    const formulaAndOrderingForbidden = [
        "metric.detected_runs / metric.total_attack_runs",
        "metric.false_positive_runs / metric.total_normal_runs",
        "metric.false_alert_episodes / metric.benign_run_hours",
        "row.paths.Fusion.ttsd_sec - row.paths.Fast.ttsd_sec",
        "eligible_time - reference_time",
        "Math.min(",
        "runtime t_e",
        "winning_path",
        ".sort(",
        ".toSorted(",
        ".reverse(",
        ".toReversed(",
    ];

    // Then
    for (const fragment of pureContractForbidden) {
        assert.equal(contractSource.includes(fragment), false);
    }
    for (const source of [contractSource, rendererSource]) {
        for (const fragment of formulaAndOrderingForbidden) {
            assert.equal(source.includes(fragment), false);
        }
    }
});
