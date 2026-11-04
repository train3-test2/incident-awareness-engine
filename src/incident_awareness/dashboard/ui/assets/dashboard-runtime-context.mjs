// One bounded read coupled to the existing Runtime poll. No new timer loop.
import { resolveRuntimeSummaryQueryState } from "./dashboard-contract.mjs";
import { buildStageTimingModel } from "./dashboard-stage-timing-contract.mjs";

export const scopeKey = (runId, entityId) => JSON.stringify([runId, entityId]);
const identity = value => typeof value === "string" && value.trim() === value && value.length > 0;
function validateRuntime(value, scope = null) {
    if (value === null) return null;
    resolveRuntimeSummaryQueryState(null, { kind: "success", payload: { items: [value] } });
    if (![value.run_id, value.entity_id, value.execution_id].every(identity)
        || !Number.isFinite(Date.parse(value.updated_at))
        || !Number.isSafeInteger(value.input_total) || value.input_total < 1
        || !Number.isSafeInteger(value.normalization_processed_count) || value.normalization_processed_count < 0
        || value.normalization_processed_count > value.input_total
        || value.remaining_count !== value.input_total - value.normalization_processed_count
        || (scope && (value.run_id !== scope.run_id || value.entity_id !== scope.entity_id))) {
        throw new TypeError("Runtime identity mismatch");
    }
    return value;
}

export function buildRuntimeContext(payload, scopes) {
    if (payload?.schema_version !== "dashboard_runtime_context_v1" || !Array.isArray(payload.scopes)
        || payload.scopes.length !== scopes.length || !Number.isFinite(Date.parse(payload.generated_at))) {
        throw new TypeError("Invalid Runtime context");
    }
    const indexed = new Map();
    for (const item of payload.scopes) {
        const key = scopeKey(item.run_id, item.entity_id);
        if (indexed.has(key) || !scopes.some(scope => scopeKey(scope.run_id, scope.entity_id) === key)) {
            throw new TypeError("Unexpected Runtime scope");
        }
        indexed.set(key, validateRuntime(item.runtime, item));
    }
    return { queryState: "success", pipeline: validateRuntime(payload.pipeline), scopes: indexed };
}

export function resolvePipelineTarget(context, autoFollow, pinned) {
    if (context.queryState !== "success") return null;
    return autoFollow ? context.pipeline : pinned === null ? null
        : context.scopes.get(scopeKey(pinned.run_id, pinned.entity_id)) ?? null;
}

export function createRuntimeContextController({ onChange, fetchImpl = (...args) => fetch(...args),
    origin = globalThis.location?.origin, setTimeoutImpl = globalThis.setTimeout,
    clearTimeoutImpl = globalThis.clearTimeout } = {}) {
    let base = "", discovered = false, version = 0, request = null, pending = null, key = null;
    let enabled = true;
    async function endpoint(signal) {
        if (discovered) return;
        discovered = true;
        if (!origin || !/^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(origin)) return;
        try {
            const response = await fetchImpl("/dashboard-assets/dashboard-local-qa.json", { signal, cache: "no-store" });
            if (!response.ok) return;
            const config = await response.json();
            if (config.schema_version === "local_runtime_companion_v1" && config.dashboard_origin === origin
                && /^http:\/\/127\.0\.0\.1:\d+$/.test(config.origin)) base = config.origin;
        } catch { /* Optional local discovery is not required by a deployed same-origin API. */ }
    }
    function refresh(scopes) {
        if (!enabled) return Promise.resolve();
        const nextKey = JSON.stringify(scopes);
        if (pending !== null && nextKey === key) return pending;
        request?.abort();
        const current = ++version, abort = new AbortController();
        const changed = key !== nextKey;
        key = nextKey; request = abort;
        if (changed) onChange({ queryState: "loading", pipeline: null, scopes: new Map() });
        const params = new URLSearchParams();
        for (const scope of scopes) { params.append("run_id", scope.run_id); params.append("entity_id", scope.entity_id); }
        const timeout = setTimeoutImpl(() => abort.abort(), 10000);
        const operation = (async () => {
            try {
                await endpoint(abort.signal);
                const response = await fetchImpl(`${base}/operations/runtime-context?${params}`, { signal: abort.signal, cache: "no-store" });
                if (!response.ok) throw new Error(response.status === 404 ? "not_ready" : "error");
                const model = buildRuntimeContext(await response.json(), scopes);
                if (enabled && current === version) onChange(model);
            } catch (error) {
                if (enabled && current === version) onChange({ queryState: error.message === "not_ready" ? "not_ready" : "error", pipeline: null, scopes: new Map() });
            } finally { clearTimeoutImpl(timeout); }
        })();
        pending = operation;
        void operation.finally(() => { if (pending === operation) pending = null; });
        return operation;
    }
    return { refresh, stop() { enabled = false; version += 1; request?.abort(); pending = null; }, start() { enabled = true; key = null; } };
}

// Independent from the selected incident's Insight controller; only actual same-Execution records.
export function createPipelineStageReader({ onChange, fetchImpl = (...args) => fetch(...args),
    setTimeoutImpl = globalThis.setTimeout, clearTimeoutImpl = globalThis.clearTimeout } = {}) {
    let key = null, version = 0, request = null, failed = false;
    return {
        select(runtime) {
            const next = runtime === null ? null : JSON.stringify([runtime.run_id, runtime.entity_id,
                runtime.execution_id, runtime.status, runtime.current_stage]);
            if (next === key) return;
            key = next; failed = false; request?.abort(); const current = ++version;
            onChange(null, runtime === null ? "unavailable" : "loading");
            if (runtime === null) return;
            const abort = new AbortController(); request = abort;
            const timeout = setTimeoutImpl(() => abort.abort(), 10000);
            void (async () => {
                try {
                    const response = await fetchImpl(`/operations/stage-timings?execution_id=${encodeURIComponent(runtime.execution_id)}`, { signal: abort.signal, cache: "no-store" });
                    if (!response.ok) throw new Error("Stage read failed");
                    const model = buildStageTimingModel(await response.json(), { runId: runtime.run_id,
                        entityId: runtime.entity_id, executionId: runtime.execution_id });
                    if (current === version) onChange({ executionId: runtime.execution_id, records: model.records }, "success");
                } catch {
                    if (current === version) { failed = true; onChange(null, "error"); }
                } finally { clearTimeoutImpl(timeout); }
            })();
        },
        stop() { version += 1; request?.abort(); key = null; },
        retry() { if (failed) { key = null; failed = false; } },
    };
}
