// Pure Evaluation View presentation contract: no DOM, network, or timer access.

export const NOT_APPLICABLE = "N/A";

const LOADING_MESSAGE = "평가 정보를 불러오는 중입니다.";
const SUCCESS_MESSAGE = "평가 정보를 불러왔습니다.";
const UNAVAILABLE_MESSAGE = "Evaluation Snapshot을 사용할 수 없습니다.";
const INVALID_MESSAGE = "저장된 Evaluation Snapshot이 유효하지 않습니다.";
const ERROR_MESSAGE = "평가 정보를 불러오지 못했습니다.";

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

function validateEvaluationPayload(payload) {
    const value = requireRecord(payload, "Evaluation payload");
    const plan = requireRecord(value.plan, "Evaluation plan");
    const normalAlertBurden = requireRecord(
        value.normal_alert_burden,
        "Normal Alert Burden",
    );
    const pairedTiming = requireRecord(value.paired_timing, "Paired Timing");
    requireRecord(value.evaluated_run_ids, "Evaluation evaluated_run_ids");
    requireRecord(value.metrics, "Evaluation metrics");
    requireBoolean(value.comparison_ready, "Evaluation comparison_ready");
    requireBoolean(normalAlertBurden.comparison_ready, "Normal Alert Burden comparison_ready");
    requireBoolean(pairedTiming.paired_coverage_complete, "Paired Timing coverage");
    getPurposePresentation(plan.purpose);
    formatSeconds(plan.evaluation_horizon_sec);
    if (!Array.isArray(value.exclusions)) {
        throw new TypeError("Evaluation exclusions must be an array");
    }
    if (!Array.isArray(pairedTiming.per_run)) {
        throw new TypeError("Paired Timing per_run must be an array");
    }
    for (const exclusion of value.exclusions) {
        requireRecord(exclusion, "Evaluation exclusion");
        for (const field of ["run_id", "method", "reason"]) {
            if (typeof exclusion[field] !== "string") {
                throw new TypeError(`Evaluation exclusion ${field} must be a string`);
            }
        }
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

export function projectEvaluationSections(payload) {
    const { normalAlertBurden, pairedTiming } = validateEvaluationPayload(payload);
    return {
        methodComparison: {
            evaluatedRunIds: payload.evaluated_run_ids,
            metrics: payload.metrics,
        },
        normalAlertBurden,
        pairedTiming,
        runLevelPairedTiming: pairedTiming.per_run,
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
