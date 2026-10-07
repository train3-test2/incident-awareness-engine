// Pure Evaluation View presentation contract: no DOM, network, or timer access.

export const NOT_APPLICABLE = "N/A";

const LOADING_MESSAGE = "평가 정보를 불러오는 중입니다.";
const SUCCESS_MESSAGE = "평가 정보를 불러왔습니다.";
const UNAVAILABLE_MESSAGE = "Evaluation Snapshot을 사용할 수 없습니다.";
const INVALID_MESSAGE = "저장된 Evaluation Snapshot이 유효하지 않습니다.";
const ERROR_MESSAGE = "평가 정보를 불러오지 못했습니다.";
const METHOD_NAMES = ["Fast", "Fusion", "Hybrid"];
const BURDEN_METHOD_NAMES = ["Fast", "Fusion"];
const ELIGIBLE_STATUS_LABELS = {
    detected: "Detected",
    miss: "Miss",
    not_evaluated: "Not Evaluated",
};
const OUTCOME_LABELS = {
    both_detected: "Both Detected",
    fast_only: "Fast Only",
    fusion_only: "Fusion Only",
    both_miss: "Both Miss",
    not_evaluated: "Not Evaluated",
};

function requireRecord(value, name) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${name} must be an object`);
    }
    return value;
}

function requireBoolean(value, name) {
    if (typeof value !== "boolean") {
        throw new TypeError(`${name} must be a boolean`);
    }
    return value;
}

function requireString(value, name) {
    if (typeof value !== "string") {
        throw new TypeError(`${name} must be a string`);
    }
    return value;
}

function requireNullableString(value, name) {
    if (value !== null) {
        requireString(value, name);
    }
    return value;
}

function requireFiniteNumber(value, name) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new TypeError(`${name} must be a finite number`);
    }
    return value;
}

function requireNullableFiniteNumber(value, name) {
    if (value !== null) {
        requireFiniteNumber(value, name);
    }
    return value;
}

function requireInteger(value, name) {
    if (!Number.isInteger(value)) {
        throw new TypeError(`${name} must be an integer`);
    }
    return value;
}

function requireArray(value, name) {
    if (!Array.isArray(value)) {
        throw new TypeError(`${name} must be an array`);
    }
    return value;
}

function validateMethodMetric(metric, expectedMethod) {
    if (metric === null) {
        return;
    }
    const value = requireRecord(metric, `Evaluation ${expectedMethod} metric`);
    if (value.method !== expectedMethod) {
        throw new TypeError(`Evaluation ${expectedMethod} metric method must match`);
    }
    for (const field of [
        "total_attack_runs",
        "detected_runs",
        "total_normal_runs",
        "false_positive_runs",
    ]) {
        requireInteger(value[field], `Evaluation ${expectedMethod} metric ${field}`);
    }
    for (const field of [
        "run_recall",
        "median_ttsd_sec",
        "benign_run_fpr",
        "ttsd_iqr_sec",
    ]) {
        requireNullableFiniteNumber(value[field], `Evaluation ${expectedMethod} metric ${field}`);
    }
}

function validateBurdenPerRun(row, method) {
    const value = requireRecord(row, `Normal Alert Burden ${method} per_run item`);
    requireString(value.run_id, `Normal Alert Burden ${method} run_id`);
    requireString(value.entity_id, `Normal Alert Burden ${method} entity_id`);
    requireNullableString(value.family_id, `Normal Alert Burden ${method} family_id`);
    requireNullableString(value.variation_id, `Normal Alert Burden ${method} variation_id`);
    if (value.repetition !== null) {
        requireInteger(value.repetition, `Normal Alert Burden ${method} repetition`);
    }
    requireInteger(
        value.false_alert_episodes,
        `Normal Alert Burden ${method} false_alert_episodes`,
    );
    requireFiniteNumber(
        value.observation_seconds,
        `Normal Alert Burden ${method} observation_seconds`,
    );
}

function validateBurdenMetric(metric, method) {
    const value = requireRecord(metric, `Normal Alert Burden ${method} metric`);
    requireArray(
        value.evaluated_run_ids,
        `Normal Alert Burden ${method} evaluated_run_ids`,
    );
    requireInteger(
        value.false_alert_episodes,
        `Normal Alert Burden ${method} false_alert_episodes`,
    );
    requireFiniteNumber(value.benign_run_hours, `Normal Alert Burden ${method} benign_run_hours`);
    requireNullableFiniteNumber(
        value.false_alerts_per_benign_run_hour,
        `Normal Alert Burden ${method} false_alerts_per_benign_run_hour`,
    );
    const rows = requireArray(value.per_run, `Normal Alert Burden ${method} per_run`);
    for (const row of rows) {
        validateBurdenPerRun(row, method);
    }
}

function validatePairedPath(path, method) {
    const value = requireRecord(path, `Paired Timing ${method} path`);
    if (!Object.hasOwn(ELIGIBLE_STATUS_LABELS, value.eligible_status)) {
        throw new TypeError(`Paired Timing ${method} eligible_status is invalid`);
    }
    requireNullableString(value.eligible_time, `Paired Timing ${method} eligible_time`);
    requireNullableFiniteNumber(value.ttsd_sec, `Paired Timing ${method} ttsd_sec`);
}

function validatePairedRow(row) {
    const value = requireRecord(row, "Paired Timing per_run item");
    requireString(value.run_id, "Paired Timing run_id");
    const paths = requireRecord(value.paths, "Paired Timing paths");
    validatePairedPath(paths.Fast, "Fast");
    validatePairedPath(paths.Fusion, "Fusion");
    if (!Object.hasOwn(OUTCOME_LABELS, value.outcome)) {
        throw new TypeError("Paired Timing outcome is invalid");
    }
    requireNullableFiniteNumber(value.fusion_minus_fast_sec, "Paired Timing delta");
    if (
        value.earlier_eligible_path !== null
        && !["Fast", "Fusion", "tie"].includes(value.earlier_eligible_path)
    ) {
        throw new TypeError("Paired Timing earlier_eligible_path is invalid");
    }
}

function validateEvaluationPayload(payload) {
    const value = requireRecord(payload, "Evaluation payload");
    const plan = requireRecord(value.plan, "Evaluation plan");
    const evaluatedRunIds = requireRecord(
        value.evaluated_run_ids,
        "Evaluation evaluated_run_ids",
    );
    const metrics = requireRecord(value.metrics, "Evaluation metrics");
    const normalAlertBurden = requireRecord(
        value.normal_alert_burden,
        "Normal Alert Burden",
    );
    const burdenMetrics = requireRecord(
        normalAlertBurden.metrics,
        "Normal Alert Burden metrics",
    );
    const pairedTiming = requireRecord(value.paired_timing, "Paired Timing");
    requireBoolean(value.comparison_ready, "Evaluation comparison_ready");
    requireBoolean(normalAlertBurden.comparison_ready, "Normal Alert Burden comparison_ready");
    requireBoolean(pairedTiming.paired_coverage_complete, "Paired Timing coverage");
    getPurposePresentation(plan.purpose);
    formatSeconds(plan.evaluation_horizon_sec);
    requireArray(value.exclusions, "Evaluation exclusions");
    for (const method of METHOD_NAMES) {
        requireArray(evaluatedRunIds[method], `Evaluation ${method} evaluated_run_ids`);
        validateMethodMetric(metrics[method], method);
    }
    requireArray(normalAlertBurden.normal_run_ids, "Normal Alert Burden normal_run_ids");
    for (const method of BURDEN_METHOD_NAMES) {
        validateBurdenMetric(burdenMetrics[method], method);
    }
    for (const exclusion of value.exclusions) {
        requireRecord(exclusion, "Evaluation exclusion");
        for (const field of ["run_id", "method", "reason"]) {
            requireString(exclusion[field], `Evaluation exclusion ${field}`);
        }
    }
    const counts = requireRecord(pairedTiming.counts, "Paired Timing counts");
    for (const field of [
        "both_detected",
        "fast_only",
        "fusion_only",
        "both_miss",
        "not_evaluated",
    ]) {
        requireInteger(counts[field], `Paired Timing counts ${field}`);
    }
    const bothDetected = requireRecord(
        pairedTiming.both_detected_summary,
        "Paired Timing both_detected_summary",
    );
    for (const field of ["run_count", "fast_earlier", "fusion_earlier", "ties"]) {
        requireInteger(bothDetected[field], `Paired Timing summary ${field}`);
    }
    requireNullableFiniteNumber(
        bothDetected.median_fusion_minus_fast_sec,
        "Paired Timing summary median_fusion_minus_fast_sec",
    );
    const pairedRows = requireArray(pairedTiming.per_run, "Paired Timing per_run");
    for (const row of pairedRows) {
        validatePairedRow(row);
    }
    return { payload: value, plan, normalAlertBurden, pairedTiming };
}

export function formatNullable(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }
    return String(value);
}

export function formatPercentage(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new TypeError("Percentage value must be a finite number or null");
    }
    return `${(value * 100).toFixed(1)}%`;
}

export function formatSeconds(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new TypeError("Seconds value must be a finite number or null");
    }
    return `${value} sec`;
}

export function getPurposePresentation(purpose) {
    if (purpose === "smoke") {
        return {
            label: "smoke",
            title: "Smoke Evaluation",
            description: "파이프라인 및 평가 계약 검증용 결과입니다. 성능 우위 주장에 사용하는 결과가 아닙니다.",
            modifier: "smoke",
        };
    }
    if (purpose === "performance") {
        return {
            label: "performance",
            title: "Performance Evaluation",
            description: "성능 평가 목적으로 저장된 Evaluation Snapshot 결과입니다.",
            modifier: "performance",
        };
    }
    throw new RangeError(`Unknown Evaluation purpose: ${purpose}`);
}

export function projectSnapshotSummary(payload) {
    const { plan } = validateEvaluationPayload(payload);
    return [
        { label: "Snapshot ID", value: formatNullable(payload.snapshot_id) },
        { label: "Scenario ID", value: formatNullable(plan.scenario_id) },
        { label: "Purpose", value: formatNullable(plan.purpose) },
        { label: "Evaluation Horizon", value: formatSeconds(plan.evaluation_horizon_sec) },
        { label: "Decision Config Version", value: formatNullable(plan.decision_config_version) },
        { label: "Scoring Config Version", value: formatNullable(plan.scoring_config_version) },
        { label: "Scoring Profile ID", value: formatNullable(plan.scoring_profile_id) },
        { label: "Scoring Method", value: formatNullable(plan.scoring_method) },
        { label: "Scorer Version", value: formatNullable(plan.scorer_version) },
        { label: "Model Version", value: formatNullable(plan.model_version) },
        { label: "Detector Set Version", value: formatNullable(plan.detector_set_version) },
        {
            label: "Fast Episode Policy Version",
            value: formatNullable(plan.fast_episode_policy_version),
        },
    ];
}

export function getEvaluationStatusPresentations(payload) {
    const { normalAlertBurden, pairedTiming } = validateEvaluationPayload(payload);
    return [
        {
            key: "method-comparison",
            label: "Method Comparison",
            complete: payload.comparison_ready,
            statusLabel: payload.comparison_ready ? "Ready" : "Incomplete",
        },
        {
            key: "normal-alert-burden",
            label: "Normal Alert Burden",
            complete: normalAlertBurden.comparison_ready,
            statusLabel: normalAlertBurden.comparison_ready ? "Ready" : "Incomplete",
        },
        {
            key: "paired-timing",
            label: "Paired Timing",
            complete: pairedTiming.paired_coverage_complete,
            statusLabel: pairedTiming.paired_coverage_complete ? "Complete" : "Incomplete",
        },
    ];
}

export function projectExclusions(payload) {
    validateEvaluationPayload(payload);
    return payload.exclusions.map((exclusion) => ({
        runId: formatNullable(exclusion.run_id),
        method: formatNullable(exclusion.method),
        reason: formatNullable(exclusion.reason),
    }));
}

export function buildMethodComparison(payload) {
    validateEvaluationPayload(payload);
    return METHOD_NAMES.map((method) => {
        const metric = payload.metrics[method];
        if (metric === null) {
            return { method, available: false, emptyMessage: "평가 데이터 없음" };
        }
        return {
            method,
            available: true,
            fields: [
                { label: "Run Recall", value: formatPercentage(metric.run_recall) },
                {
                    label: "Detected / Total Attack Runs",
                    value: `${metric.detected_runs} / ${metric.total_attack_runs}`,
                },
                { label: "Median TTSD", value: formatSeconds(metric.median_ttsd_sec) },
                { label: "TTSD IQR", value: formatSeconds(metric.ttsd_iqr_sec) },
                { label: "Benign Run FPR", value: formatPercentage(metric.benign_run_fpr) },
                {
                    label: "False Positive / Total Normal Runs",
                    value: `${metric.false_positive_runs} / ${metric.total_normal_runs}`,
                },
            ],
        };
    });
}

export function buildAlertBurden(payload) {
    const { normalAlertBurden } = validateEvaluationPayload(payload);
    return BURDEN_METHOD_NAMES.map((method) => {
        const metric = normalAlertBurden.metrics[method];
        return {
            method,
            fields: [
                { label: "Evaluated Normal Runs", value: String(metric.evaluated_run_ids.length) },
                { label: "False Alert Episodes", value: String(metric.false_alert_episodes) },
                { label: "Benign Run Hours", value: String(metric.benign_run_hours) },
                {
                    label: "FA/BH",
                    value: formatNullable(metric.false_alerts_per_benign_run_hour),
                },
            ],
            rows: metric.per_run.map((row) => ({
                runId: row.run_id,
                entityId: row.entity_id,
                familyId: formatNullable(row.family_id),
                variationId: formatNullable(row.variation_id),
                repetition: formatNullable(row.repetition),
                falseAlertEpisodes: String(row.false_alert_episodes),
                observationSeconds: formatSeconds(row.observation_seconds),
            })),
        };
    });
}

export function buildPairedTimingSummary(payload) {
    const { pairedTiming } = validateEvaluationPayload(payload);
    const counts = pairedTiming.counts;
    const summary = pairedTiming.both_detected_summary;
    return {
        counts: [
            { label: "Both Detected", value: String(counts.both_detected) },
            { label: "Fast Only", value: String(counts.fast_only) },
            { label: "Fusion Only", value: String(counts.fusion_only) },
            { label: "Both Miss", value: String(counts.both_miss) },
            { label: "Not Evaluated", value: String(counts.not_evaluated) },
        ],
        bothDetected: [
            { label: "Run Count", value: String(summary.run_count) },
            { label: "Fast Earlier", value: String(summary.fast_earlier) },
            { label: "Fusion Earlier", value: String(summary.fusion_earlier) },
            { label: "Ties", value: String(summary.ties) },
            {
                label: "Median Fusion - Fast",
                value: formatSeconds(summary.median_fusion_minus_fast_sec),
            },
        ],
        deltaExplanation: "Fusion - Fast가 양수이면 Fast가 더 빠르고, 음수이면 Fusion이 더 빠르며, 0이면 tie입니다.",
    };
}

export function buildPairedTimingRows(payload) {
    const { pairedTiming } = validateEvaluationPayload(payload);
    return pairedTiming.per_run.map((row) => ({
        runId: row.run_id,
        fastStatus: ELIGIBLE_STATUS_LABELS[row.paths.Fast.eligible_status],
        fastEligibleTime: formatNullable(row.paths.Fast.eligible_time),
        fastTtsd: formatSeconds(row.paths.Fast.ttsd_sec),
        fusionStatus: ELIGIBLE_STATUS_LABELS[row.paths.Fusion.eligible_status],
        fusionEligibleTime: formatNullable(row.paths.Fusion.eligible_time),
        fusionTtsd: formatSeconds(row.paths.Fusion.ttsd_sec),
        outcome: OUTCOME_LABELS[row.outcome],
        fusionMinusFast: formatSeconds(row.fusion_minus_fast_sec),
        earlierEligiblePath: formatNullable(row.earlier_eligible_path),
    }));
}

export function projectEvaluationSections(payload) {
    return {
        methodComparison: buildMethodComparison(payload),
        normalAlertBurden: buildAlertBurden(payload),
        pairedTiming: buildPairedTimingSummary(payload),
        runLevelPairedTiming: buildPairedTimingRows(payload),
    };
}

export function getEvaluationErrorMessage(status, detail) {
    if (status === 503 && detail === "Evaluation snapshot is unavailable") {
        return UNAVAILABLE_MESSAGE;
    }
    if (status === 500 && detail === "Stored evaluation snapshot is invalid") {
        return INVALID_MESSAGE;
    }
    return ERROR_MESSAGE;
}

export function resolveEvaluationQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Evaluation state must be an object or null");
    }
    const value = requireRecord(result, "Evaluation query result");
    if (value.kind === "loading") {
        return { queryState: "loading", payload: null, message: LOADING_MESSAGE };
    }
    if (value.kind === "success") {
        validateEvaluationPayload(value.payload);
        return { queryState: "success", payload: value.payload, message: SUCCESS_MESSAGE };
    }
    if (value.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getEvaluationErrorMessage(value.status, value.detail),
        };
    }
    throw new RangeError(`Unknown Evaluation query result kind: ${value.kind}`);
}
