// Pure Operations View presentation contract: no DOM, network, or timer access.
// operations.js renders these values; tests/dashboard/ui verifies them under Node.

export const NOT_APPLICABLE = "-";

const RUNNING_STATUS_LABEL = "실행 중(마지막 보고)";
const STAGE_LABELS = new Map([
    ["artifact_validation", "입력 검증"],
    ["normalization", "이벤트 처리"],
    ["fusion", "증거 누적 판단"],
    ["fast_handoff", "즉시 판단 연계"],
    ["hybrid", "통합 판단"],
    ["persistence", "결과 저장"],
]);
const LOADING_MESSAGE = "Runtime 정보를 불러오는 중입니다.";
const EMPTY_MESSAGE = "표시할 Runtime 정보가 없습니다.";
const ERROR_MESSAGE = "Runtime 정보를 불러오지 못했습니다.";

export function displayValue(value) {
    if (value === null || value === undefined) {
        return NOT_APPLICABLE;
    }
    return String(value);
}

export function getStageLabel(stage) {
    if (stage === null || stage === undefined) {
        return NOT_APPLICABLE;
    }
    return STAGE_LABELS.get(stage) ?? String(stage);
}

// Presentation only: the persisted status stays authoritative. A stale snapshot keeps its
// last reported running status but lacks recent telemetry, so current execution is unknown.
// When the latest query failed, retained items cannot vouch for current telemetry freshness.
export function getRuntimeStatePresentation(runtime, telemetryAvailable) {
    if (runtime.status === "running") {
        if (!telemetryAvailable) {
            return {
                modifiers: ["running", "telemetry-unavailable"],
                statusLabel: RUNNING_STATUS_LABEL,
                telemetryLabel: "확인 불가 (조회 실패)",
                livenessLabel: "확인 불가",
            };
        }
        if (runtime.is_stale === true) {
            return {
                modifiers: ["running", "stale"],
                statusLabel: RUNNING_STATUS_LABEL,
                telemetryLabel: "오래됨",
                livenessLabel: "확인 불가",
            };
        }
        return {
            modifiers: ["running"],
            statusLabel: RUNNING_STATUS_LABEL,
            telemetryLabel: "최근 갱신",
            livenessLabel: null,
        };
    }
    if (runtime.status === "completed") {
        return {
            modifiers: ["completed"],
            statusLabel: "완료",
            telemetryLabel: NOT_APPLICABLE,
            livenessLabel: null,
        };
    }
    if (runtime.status === "failed") {
        return {
            modifiers: ["failed"],
            statusLabel: "실패",
            telemetryLabel: NOT_APPLICABLE,
            livenessLabel: null,
        };
    }
    return {
        modifiers: [],
        statusLabel: displayValue(runtime.status),
        telemetryLabel: NOT_APPLICABLE,
        livenessLabel: null,
    };
}

// First Cycle batch progress as reported by the API; no derived percentage.
export function getRuntimeProgressPresentation(runtime) {
    return {
        processed: `${displayValue(runtime.normalization_processed_count)} / `
            + `${displayValue(runtime.input_total)} 처리`,
        remaining: displayValue(runtime.remaining_count),
    };
}

export function getRuntimeQueryMessage(state, count) {
    if (state === "loading") {
        return LOADING_MESSAGE;
    }
    if (state === "error") {
        return ERROR_MESSAGE;
    }
    if (state === "success") {
        if (!Number.isInteger(count) || count < 0) {
            throw new RangeError(`Runtime item count must be a non-negative integer: ${count}`);
        }
        return count === 0 ? EMPTY_MESSAGE : `Runtime ${count}건을 불러왔습니다.`;
    }
    throw new RangeError(`Unknown Runtime query state: ${state}`);
}

export function resolveRuntimeQueryState(previousItems, result) {
    if (!Array.isArray(previousItems)) {
        throw new TypeError("Previous Runtime items must be an array");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Runtime query result must be an object");
    }
    if (result.kind === "success") {
        if (!Array.isArray(result.items)) {
            throw new TypeError("Successful Runtime query items must be an array");
        }
        return {
            items: result.items,
            telemetryAvailable: true,
            message: getRuntimeQueryMessage("success", result.items.length),
        };
    }
    if (result.kind === "error") {
        return {
            items: previousItems,
            telemetryAvailable: false,
            message: getRuntimeQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Runtime query result kind: ${result.kind}`);
}
