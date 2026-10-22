// Observation/analysis list: one bounded read per data kind for the rows already listed.
// Presentation only; stored results are shown as they are and never merged into a new state.
import { analysisDecisionPresentation, analysisTimestampLabel, workflowRowLabel } from "./dashboard-operator-contract.mjs";

export const MAX_LIST_SUMMARY_RUNS = 20;
export const ANALYSIS_SUMMARIES_PATH = "/analysis-summaries";
export const ALERT_SUMMARIES_PATH = "/human-workflow/alert-summaries";

export function buildListSummaryPath(path, runIds) {
    const params = new URLSearchParams();
    for (const runId of runIds) params.append("run_id", runId);
    return `${path}?${params}`;
}

// First and last input Event times. Never a processing time, collection window or attack duration.
export function runInputRange(run) {
    const start = Date.parse(run?.start_time);
    const end = run?.end_time == null ? NaN : Date.parse(run.end_time);
    const startLabel = Number.isFinite(start) ? analysisTimestampLabel(run.start_time).replace(" KST", "") : "시작 시각 미확인";
    let endLabel = run?.end_time == null ? "종료 미기록" : "종료 시각 확인 필요", span = null;
    if (Number.isFinite(start) && Number.isFinite(end) && end >= start) {
        const full = analysisTimestampLabel(run.end_time).replace(" KST", "");
        endLabel = full.slice(0, 10) === startLabel.slice(0, 10) ? full.slice(11) : full;
        span = `${Math.floor((end - start) / 60000)}분 ${Math.floor((end - start) % 60000 / 1000)}초`;
    }
    return { start: startLabel, end: endLabel, span,
        title: "첫 입력 Event와 마지막 입력 Event의 시각(KST)입니다. 분석 처리 시간, 수집 완전성, 공격 지속 시간이 아닙니다." };
}

const sameInstant = (left, right) => left == null ? right == null : right != null && Date.parse(left) === Date.parse(right);

export function runRowAnalysis(state, runId, entityId = null) {
    const unavailable = { loading: ["분석 요약 조회 중", "조회 중"],
        unsupported: ["목록 요약 조회 미지원", "선택하면 상세에서 확인"],
        error: ["분석 요약 조회 실패", "선택하면 상세에서 확인"] }[state?.queryState];
    if (unavailable) return { headline: unavailable[0], status: unavailable[1], evidence: null, known: false };
    const item = state?.items?.get(runId);
    if (!item) return { headline: "분석 요약 없음", status: "선택하면 상세에서 확인", evidence: null, known: false };
    if (item.status === "run_not_found") return { headline: "저장 분석 없음", status: "분석 조회 불가", evidence: null, known: false };
    if (item.status === "integrity_error") return { headline: "저장 판단 기록 확인 필요", status: "판단 이력 무결성 오류", evidence: null, known: false };
    if (entityId !== null && item.entity_id !== entityId) return { headline: "요약 대상 시스템 확인 필요", status: "조회 범위 불일치", evidence: null, known: false };
    const { decision, fusion_result: fusion } = item;
    if (!decision && !fusion) return { headline: "저장된 분석 결과 없음", status: "미완료", evidence: null, known: true };
    // The same check the alert source uses: a Decision and Fusion row that disagree are not combined.
    if (decision && fusion && (decision.fusion_status !== fusion.fusion_status || !sameInstant(decision.fusion_time, fusion.fusion_time))) {
        return { headline: "결과 확인 보류 · 저장 시점 불일치", status: "상세에서 확인", evidence: null, known: false };
    }
    const presentation = analysisDecisionPresentation(decision, fusion, "success");
    const ids = fusion?.contributing_evidence_ids;
    // The list shows judgment completion only; the detail keeps the full summary.
    return { headline: presentation.headline, status: presentation.completion ?? presentation.summary,
        evidence: Array.isArray(ids) ? `기여 증거 ${ids.length}건` : null, known: true };
}

// Exact stored Event taxonomy counts. This is separate from raw validation and detection.
// Stored Event type names; an unknown type keeps its stored name.
export const EVENT_TYPE_NAMES = Object.freeze({ process_create: "프로세스 생성", network_connection: "네트워크 연결",
    file_create: "파일 생성", dns_query: "DNS 조회" });

export function runRowObservation(state, runId, entityId) {
    if (state?.queryState !== "success") return null;
    const item = state.items.get(runId);
    const value = item?.observations;
    if (item?.status !== "available" || item.entity_id !== entityId || value?.source !== "stored_events"
        || value.entity_id !== entityId) return null;
    if (value.event_count === 0) return "이 대상에 저장된 관측 Event 없음";
    return Object.entries(value.event_type_counts).map(([type, count]) => `${EVENT_TYPE_NAMES[type] ?? type} ${count}건`).join(" · ");
}

export function runRowWorkflow(state, runId, entityId = null) {
    const unavailable = { loading: "조회 중", unsupported: "선택하면 확인", forbidden: "확인 불가 · 로컬 담당자 아님",
        error: "조회 실패" }[state?.queryState];
    if (unavailable) return unavailable;
    const entry = state?.items?.get(runId);
    return entry ? workflowRowLabel(entityId === null ? entry.alerts : entry.alerts.filter(alert => alert.entity_id === entityId)) : "확인 불가";
}

function validateAnalysis(payload, runIds) {
    if (payload?.schema_version !== "dashboard_analysis_summaries_v1" || !Array.isArray(payload.items)
        || payload.items.length !== runIds.length) throw new TypeError("Invalid analysis summaries");
    const items = new Map();
    for (const item of payload.items) {
        if (!runIds.includes(item?.run_id) || items.has(item.run_id)
            || !["available", "run_not_found", "integrity_error"].includes(item.status)) throw new TypeError("Unexpected summary");
        if (item.observations != null) {
            const value = item.observations;
            if (value.source !== "stored_events" || value.entity_id !== item.entity_id
                || !Number.isInteger(value.event_count) || value.event_count < 0
                || !value.event_type_counts || Array.isArray(value.event_type_counts)
                || Object.values(value.event_type_counts).some(count => !Number.isInteger(count) || count <= 0)
                || Object.values(value.event_type_counts).reduce((sum, count) => sum + count, 0) !== value.event_count) {
                throw new TypeError("Invalid stored observation summary");
            }
        }
        for (const result of [item.decision, item.fusion_result]) {
            if (result != null && (result.run_id !== item.run_id || result.entity_id !== item.entity_id)) throw new TypeError("Analysis scope mismatch");
        }
        if (item.decision != null && !["detected", "miss", "not_evaluated"].includes(item.decision.fast_status)) throw new TypeError("Invalid Fast status");
        for (const result of [item.decision, item.fusion_result]) {
            if (result != null && !["detected", "miss", "not_evaluated"].includes(result.fusion_status)) throw new TypeError("Invalid Fusion status");
        }
        items.set(item.run_id, item);
    }
    return items;
}

function validateAlerts(payload, runIds) {
    if (payload?.schema_version !== "human_workflow_alert_summaries_v1" || !Array.isArray(payload.items)
        || payload.items.length !== runIds.length) throw new TypeError("Invalid alert summaries");
    const items = new Map();
    for (const item of payload.items) {
        if (!runIds.includes(item?.run_id) || items.has(item.run_id) || !Array.isArray(item.alerts)
            || item.alerts.length > 100 || item.alerts.some(alert => alert?.run_id !== item.run_id
                || typeof alert.entity_id !== "string" || !alert.state || typeof alert.state !== "object")) throw new TypeError("Unexpected alert summary");
        items.set(item.run_id, item);
    }
    return items;
}

// Two reads per list refresh, never one per row. Older answers are discarded by version.
export function createListSummaryController({ onChange, fetchImpl = (...args) => fetch(...args),
    setTimeoutImpl = globalThis.setTimeout, clearTimeoutImpl = globalThis.clearTimeout } = {}) {
    let version = 0, aborts = [], enabled = true;
    const state = { analysis: { queryState: "loading", items: new Map() }, workflow: { queryState: "loading", items: new Map() } };
    async function read(path, runIds, validate, current, slot) {
        const abort = new AbortController();
        aborts.push(abort);
        const timeout = setTimeoutImpl(() => abort.abort(), 10000);
        try {
            const response = await fetchImpl(buildListSummaryPath(path, runIds),
                { signal: abort.signal, cache: "no-store", headers: { Accept: "application/json" } });
            if (!response.ok) {
                let detail = null;
                try { detail = (await response.json())?.detail; } catch {}
                const queryState = response.status === 404 && detail === "Not Found" ? "unsupported"
                    : response.status === 403 && slot === "workflow" ? "forbidden" : "error";
                if (enabled && current === version) { state[slot] = { queryState, items: new Map() }; onChange(state); }
                return;
            }
            const items = validate(await response.json(), runIds);
            if (abort.signal.aborted) throw new Error("Summary request timed out");
            if (enabled && current === version) { state[slot] = { queryState: "success", items }; onChange(state); }
        } catch {
            if (enabled && current === version) { state[slot] = { queryState: "error", items: new Map() }; onChange(state); }
        } finally { clearTimeoutImpl(timeout); }
    }
    return {
        state,
        refresh(runIds) {
            if (!enabled) return Promise.resolve();
            const ids = [...new Set(runIds)].slice(0, MAX_LIST_SUMMARY_RUNS);
            for (const abort of aborts) abort.abort();
            aborts = [];
            const current = ++version;
            // A fresh read clears the old result, including when the IDs stay the same.
            {
                state.analysis = { queryState: ids.length ? "loading" : "success", items: new Map() };
                state.workflow = { queryState: ids.length ? "loading" : "success", items: new Map() };
                onChange(state);
            }
            if (!ids.length) return Promise.resolve();
            return Promise.all([read(ANALYSIS_SUMMARIES_PATH, ids, validateAnalysis, current, "analysis"),
                read(ALERT_SUMMARIES_PATH, ids, validateAlerts, current, "workflow")]);
        },
        stop() { enabled = false; version += 1; for (const abort of aborts) abort.abort(); aborts = []; },
        start() { enabled = true; },
    };
}
