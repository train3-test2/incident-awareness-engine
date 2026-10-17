// Stored ended invocations only. Read v1 cannot establish path coverage or a global bottleneck.
import { getStageLabel } from "./operations-contract.mjs";

export const TIMING_STAGES = Object.freeze([
    "artifact_validation", "normalization", "fusion", "fast_handoff", "hybrid", "persistence",
]);
const ISSUES = new Set([
    "utc_clock_error", "monotonic_clock_error", "invalid_duration", "wall_clock_regression",
    "internal_error", "observer_error", "buffer_limit",
]);
const requireValue = (condition) => {
    if (!condition) throw new TypeError("Invalid or mismatched Stage Timing response");
};
const identity = (value) => typeof value === "string" && value.length > 0 && value.trim() === value;
const integer = (value, minimum = 0n) => {
    requireValue(typeof value === "string" && /^(0|[1-9]\d*)$/.test(value));
    const result = BigInt(value);
    requireValue(result >= minimum);
    return result;
};
const issuesValid = (value) => Array.isArray(value) && value.every((issue) => ISSUES.has(issue));
const utc = (value) => typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

// `caption` is the short card text; `reason` is the full accessible explanation.
const noTarget = (caption, reason) => ({ target: null, caption, reason });

export function resolveStageTimingTarget({ runId, entityId, items, queryFailed = false, outsideQuery = false }) {
    if (queryFailed) return noTarget("Runtime 조회 실패", "Runtime 조회 실패 · 비교 대상 확인 불가");
    if (outsideQuery) return noTarget("조회 범위 밖", "선택 Runtime이 최근 5건 조회 범위 밖입니다.");
    if (!identity(runId)) return noTarget("Runtime 선택 필요", "Run·Entity의 Runtime을 선택하세요.");
    if (!identity(entityId)) {
        return items.some((item) => item.run_id === runId)
            ? noTarget("Runtime 선택 필요", "Run만 선택되어 Execution을 알 수 없습니다. Runtime 표에서 Entity를 선택하세요. Run만으로 Execution을 추정하지 않습니다.")
            : noTarget("Runtime 보고 없음", "Run만 선택되어 Execution을 알 수 없고, 이 Run의 Runtime 보고가 최근 5건에 없습니다. Run만으로 Execution을 추정하지 않습니다.");
    }
    const matches = items.filter((item) => item.run_id === runId && item.entity_id === entityId);
    if (matches.length !== 1) {
        return matches.length
            ? noTarget("복수 Execution", "복수 Execution · 단일 비교 대상 확인 불가. 서로 다른 Execution을 합치지 않습니다.")
            : noTarget("Runtime 보고 없음", "일치하는 Runtime Execution이 최근 5건에 없습니다.");
    }
    const report = matches[0];
    if (!identity(report.execution_id) || report.execution_id.length > 512
        || !["running", "completed", "failed"].includes(report.status)) {
        return noTarget("Execution 확인 불가", "Runtime Execution 식별 정보 확인 불가");
    }
    return { target: { runId, entityId, executionId: report.execution_id,
        status: report.status, currentStage: report.current_stage }, caption: "", reason: "" };
}

// Read API v1 error details that identify a cause exactly; every other failure stays generic.
const ROUTE_NOT_FOUND_DETAIL = "Not Found";
const EXECUTION_NOT_STORED_DETAIL = "Execution is not present in stored observation records";

export function classifyStageTimingFailure(status, detail, executionId) {
    if (status === 404 && detail === ROUTE_NOT_FOUND_DETAIL) {
        return { label: "계측 저장 미준비", caption: "조회 API 미제공", tone: "neutral",
            scope: `이 서버는 Stage Timing 조회 API를 제공하지 않습니다(HTTP 404). Execution ${executionId}의 계측 저장 여부를 확인할 수 없으며 0ms나 미실행으로 해석하지 않습니다.` };
    }
    if (status === 404 && detail === EXECUTION_NOT_STORED_DETAIL) {
        return { label: "측정 기록 없음", caption: "저장 관측 기록 없음", tone: "neutral",
            scope: `저장된 관측 기록에 Execution ${executionId}가 없습니다(HTTP 404). 미실행이나 0ms라는 뜻이 아닙니다.` };
    }
    const cause = status === 503 ? "HTTP 503 · 계측 DB 연결 불가"
        : status ? `HTTP ${status} · 원인 구분 불가` : "응답 확인 실패";
    return { label: "계측 조회 실패", caption: cause, tone: "error",
        scope: `Execution ${executionId} · ${cause}. 저장 미준비 여부는 구분할 수 없습니다. 다시 조회할 수 있습니다.` };
}

export function formatStageDuration(value) {
    const ns = integer(value);
    const fraction = (ns % 1000000n).toString().padStart(6, "0").replace(/0+$/, "");
    return `${ns / 1000000n}${fraction ? `.${fraction}` : ""} ms`;
}

export function buildStageTimingModel(payload, target) {
    requireValue(payload?.schema_version === "pipeline_stage_timing_read_v1"
        && payload.execution_id === target.executionId && payload.duration_unit === "ns"
        && payload.integer_encoding === "decimal_string" && payload.coverage_status === "not_evaluable"
        && payload.execution_outcome === "unknown"
        && payload.missing_stage_meaning === "not_observed_not_proof_of_not_run"
        && ["recorded", "no_stage_timings"].includes(payload.availability)
        && (payload.persisted_at === null || utc(payload.persisted_at))
        && Number.isSafeInteger(payload.ended_invocation_count)
        && typeof payload.operation_failure_recorded === "boolean"
        && Array.isArray(payload.unmeasured_stages));
    const snapshot = payload.snapshot;
    if (snapshot !== null) {
        requireValue(snapshot?.schema_version === "pipeline_stage_timing_v1" && identity(snapshot.attempt_id)
            && snapshot.execution_id === target.executionId && snapshot.run_id === target.runId
            && snapshot.entity_id === target.entityId && Array.isArray(snapshot.records)
            && issuesValid(snapshot.issues));
        integer(snapshot.revision);
        requireValue((snapshot.active_stage === null) === (snapshot.active_invocation_index === null));
        if (snapshot.active_stage !== null) {
            requireValue(TIMING_STAGES.includes(snapshot.active_stage));
            integer(snapshot.active_invocation_index, 1n);
        }
    }
    const records = snapshot?.records ?? [];
    let previous = 0n;
    for (const record of records) {
        const index = integer(record.invocation_index, 1n);
        requireValue(index > previous && TIMING_STAGES.includes(record.stage)
            && ["completed", "failed"].includes(record.outcome) && issuesValid(record.issues)
            && (record.started_at === null || utc(record.started_at))
            && (record.ended_at === null || utc(record.ended_at)));
        previous = index;
        if (record.duration_ns !== null) integer(record.duration_ns);
        else requireValue(record.issues.some((issue) => ["monotonic_clock_error", "invalid_duration", "internal_error"].includes(issue)));
        if (record.started_at === null || record.ended_at === null) requireValue(record.issues.includes("utc_clock_error"));
        if (record.started_at !== null && record.ended_at !== null && record.ended_at < record.started_at) {
            requireValue(record.issues.includes("wall_clock_regression"));
        }
    }
    if (snapshot?.active_invocation_index !== null && snapshot?.active_invocation_index !== undefined) {
        requireValue(integer(snapshot.active_invocation_index, 1n) > previous);
    }
    const quality = records.length === 0 ? "unavailable"
        : snapshot.issues.length || records.some((record) => record.issues.length) ? "partial" : "observed";
    requireValue((snapshot === null || snapshot.quality_status === quality)
        && payload.ended_invocation_count === records.length
        && (payload.availability === "recorded") === (records.length > 0)
        && payload.operation_failure_recorded === records.some((record) => record.outcome === "failed")
        && JSON.stringify(payload.unmeasured_stages) === JSON.stringify(TIMING_STAGES.filter((stage) => !records.some((record) => record.stage === stage))));
    const measured = records.filter((record) => record.duration_ns !== null);
    const max = measured.reduce((value, record) => BigInt(record.duration_ns) > value ? BigInt(record.duration_ns) : value, -1n);
    const longest = measured.filter((record) => BigInt(record.duration_ns) === max);
    const active = snapshot?.active_stage ?? null;
    const failure = payload.operation_failure_recorded;
    const comparison = (active ? "실행 중 · 부분 비교" : "부분 비교")
        + (failure ? " · 실패 단계 포함" : "") + (quality === "partial" ? " · 계측 불완전" : "");
    // Ended records without a measured duration are not "no record"; they are unmeasured.
    const label = longest.length === 0 ? records.length ? "소요시간 미관측" : "측정 기록 없음"
        : longest.length === 1 ? `${getStageLabel(longest[0].stage)} · ${formatStageDuration(longest[0].duration_ns)}`
            : `동률 ${longest.length}회 · ${formatStageDuration(longest[0].duration_ns)}`;
    const longestNames = longest.map((record) => `#${record.invocation_index} ${getStageLabel(record.stage)}`).join(", ");
    return { label, comparison, records, longest, active, quality,
        // Without a measured value nothing was compared, so the card does not claim a comparison.
        caption: longest.length
            ? `${comparison} · Execution ${target.executionId}`
            : `${active ? "실행 중 · " : ""}${quality === "partial" ? "계측 불완전 · " : ""}Execution ${target.executionId}`,
        scope: `Run ${target.runId} · Entity ${target.entityId} · Execution ${target.executionId}. `
            + (longest.length ? `${longest.length > 1 ? "최장 동률" : "최장 소요"}: ${longestNames} · ${formatStageDuration(longest[0].duration_ns)}. ` : "")
            + "관측된 종료 invocation 중 최장 소요이며 전체 실행의 확정 병목이 아닙니다. 경로·완전성·전체 종료는 확인 불가. "
            + "First Cycle은 6개 operation, Standalone은 독립 fast_handoff 없이 5개 operation이지만 이 응답으로 실행 경로를 식별하지 않습니다. "
            + "미관측은 미실행 또는 0ns가 아니며, 재시도는 invocation별 비교하고 합산하지 않습니다. "
            + `Runtime 마지막 보고: ${target.status}. ${comparison}. 저장 시각: ${payload.persisted_at ?? "없음"}. `
            + `Attempt ${snapshot?.attempt_id ?? "없음"}, revision ${snapshot?.revision ?? "없음"}. `
            + `진행 단계: ${active ? getStageLabel(active) : "미보고"}, 진행 중 duration 없음. `
            + `계측 이슈: ${snapshot?.issues.join(", ") || "없음"}. `
            + `종료 기록 없는 단계: ${payload.unmeasured_stages.map(getStageLabel).join(", ") || "없음 (완전성 보장 아님)"}.`,
    };
}
