// Selection-driven reads; no polling timer and no dependency on Telemetry requests.
import {
    buildStageTimingModel,
    classifyStageTimingFailure,
    formatStageDuration,
} from "./dashboard-stage-timing-contract.mjs";
import { getStageLabel } from "./operations-contract.mjs";

const updateText = (element, text) => {
    if (element.textContent !== text) element.textContent = text;
};

export function createDashboardStageTimingController(doc, {
    fetchImpl = globalThis.fetch, setTimeoutImpl = globalThis.setTimeout,
    clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
    const nodes = Object.fromEntries(["state", "caption", "scope", "records", "refresh"].map((key) => (
        [key, doc.getElementById(`insight-bottleneck-${key}`)]
    )));
    if (Object.values(nodes).some((node) => node === null)) {
        return { select() {}, refresh() {}, stop() {}, start() {} };
    }
    let enabled = true;
    let selection = { target: null, reason: "Runtime Execution을 선택하세요." };
    let key = null;
    let version = 0;
    let request = null;
    let cancelRequest = null;
    let pending = null;
    const render = (label, caption, scope, tone = "neutral") => {
        updateText(nodes.state, label);
        updateText(nodes.caption, caption);
        nodes.caption.title = caption;
        updateText(nodes.scope, scope);
        const detail = doc.getElementById("insight-bottleneck-detail");
        if (detail) updateText(detail, scope);
        nodes.state.title = label;
        nodes.state.dataset.timingTone = tone;
    };
    function cancel() {
        version += 1;
        request?.abort();
        cancelRequest?.();
        request = null;
        cancelRequest = null;
        pending = null;
    }
    function clear(label, caption, scope, tone) {
        render(label, caption, scope, tone);
        nodes.records.replaceChildren();
    }
    const clearUnselected = (next) => clear("비교 대상 없음", next.caption ?? next.reason, next.reason, "neutral");
    function refresh() {
        if (!enabled || !selection.target) return Promise.resolve();
        if (pending !== null) return pending;
        const target = { ...selection.target };
        const current = ++version;
        const abort = new AbortController();
        request = abort;
        clear("계측 조회 중", `Execution ${target.executionId}`, `Execution ${target.executionId}의 단계 계측을 조회하고 있습니다.`, "neutral");
        nodes.refresh.disabled = false; // Repeated activation coalesces; keyboard focus stays here.
        let timeout;
        const cancelled = new Promise((_, reject) => {
            cancelRequest = () => reject(new Error("Stage Timing cancelled"));
        });
        const expired = new Promise((_, reject) => {
            timeout = setTimeoutImpl(() => { abort.abort(); reject(new Error("Stage Timing timeout")); }, 10000);
        });
        const task = (async () => {
            try {
                const response = await Promise.race([
                    Promise.resolve().then(() => {
                        if (abort.signal.aborted) throw new Error("Stage Timing cancelled");
                        return fetchImpl(`/operations/stage-timings?execution_id=${encodeURIComponent(target.executionId)}`, { signal: abort.signal });
                    }),
                    expired, cancelled,
                ]);
                if (!response.ok) {
                    // Only the documented error detail distinguishes a cause; an unreadable body stays generic.
                    let detail = null;
                    try {
                        detail = (await Promise.race([response.json(), expired, cancelled]))?.detail ?? null;
                    } catch {
                        detail = null;
                    }
                    if (!enabled || current !== version) return;
                    const failure = classifyStageTimingFailure(
                        response.status, typeof detail === "string" ? detail : null, target.executionId,
                    );
                    clear(failure.label, failure.caption, failure.scope, failure.tone);
                    return;
                }
                const payload = await Promise.race([response.json(), expired, cancelled]);
                const model = buildStageTimingModel(payload, target);
                if (!enabled || current !== version) return;
                render(model.label, model.caption, model.scope, model.longest.length ? "observed" : "neutral");
                const rows = model.records.map((record) => {
                    const row = doc.createElement("li");
                    row.textContent = `#${record.invocation_index} ${getStageLabel(record.stage)} · `
                        + `${record.outcome === "failed" ? "실패 operation" : "operation 반환"} · `
                        + `${record.duration_ns === null ? "경과시간 미관측" : `${formatStageDuration(record.duration_ns)} (${record.duration_ns} ns)`} · `
                        + `${record.started_at ?? "시작 시각 없음"} → ${record.ended_at ?? "종료 시각 없음"} · UTC · `
                        + `이슈: ${record.issues.join(", ") || "없음"}`;
                    return row;
                });
                nodes.records.replaceChildren(...rows);
            } catch {
                if (enabled && current === version) {
                    const failure = classifyStageTimingFailure(0, null, target.executionId);
                    clear(failure.label, failure.caption, failure.scope, failure.tone);
                }
            } finally {
                clearTimeoutImpl(timeout);
                if (current === version) { request = null; cancelRequest = null; pending = null; }
            }
        })();
        pending = task;
        return task;
    }
    function select(next) {
        selection = next;
        // updated_at heartbeats do not invalidate a measurement. Reported stage/status transitions do.
        const nextKey = next.target ? JSON.stringify(next.target) : null;
        if (nextKey === key) {
            if (!next.target && enabled) clearUnselected(next);
            return pending ?? Promise.resolve();
        }
        key = nextKey;
        cancel();
        nodes.refresh.disabled = !next.target;
        if (!enabled) return Promise.resolve();
        if (!next.target) {
            clearUnselected(next);
            return Promise.resolve();
        }
        return refresh();
    }
    nodes.refresh.addEventListener("click", () => { void refresh(); });
    return {
        select, refresh,
        stop() { enabled = false; cancel(); clear("조회 중지", "화면 이탈", "화면 이탈 · 다시 표시할 때 재조회합니다.", "neutral"); },
        start() { if (enabled) return pending ?? Promise.resolve(); enabled = true; const next = selection; key = null; return select(next); },
    };
}
