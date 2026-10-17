// Local-only synthetic observations. Never imported by the production Dashboard.
import { TELEMETRY_ENDPOINT } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-contract.mjs";

export const SCENARIOS = Object.freeze([
    "continuous", "sparse", "no_samples", "observed_zero", "stale", "partial", "unknown",
    "api_500", "api_503", "single", "historical",
]);
const ORIGIN = Date.parse("2026-10-16T00:05:00.000Z");
const iso = (milliseconds) => new Date(milliseconds).toISOString();
const modulo = (value, divisor) => ((value % divisor) + divisor) % divisor;

/** Complete pipeline_telemetry_read_v1 payload, with no invented empty buckets. */
export function buildPreviewPayload(elapsedSeconds = 0, scenario = "continuous") {
    if (!Number.isSafeInteger(elapsedSeconds) || elapsedSeconds < 0 || !SCENARIOS.includes(scenario)) {
        throw new RangeError("Invalid Preview time or scenario");
    }
    const end = ORIGIN + elapsedSeconds * 1000;
    const points = [];
    const singleExample = scenario === "single" || scenario === "historical";
    const exampleSecond = scenario === "historical" ? -91 : -1;
    for (let second = elapsedSeconds - 300; second < elapsedSeconds; second += 1) {
        if (singleExample && second !== exampleSecond) continue;
        if (scenario === "no_samples" || (scenario === "stale" && second >= 0)) continue;
        if (["sparse", "partial"].includes(scenario) && modulo(second, 17) >= 6) continue;
        const batchAdmission = modulo(second, 20) === 0;
        // Synthetic reconstruction of user-reported counts, not an AWS response fixture.
        const input = singleExample ? 7 : batchAdmission ? 50 + modulo(second, 37) : 0;
        const completed = singleExample ? 7 : scenario === "observed_zero" && batchAdmission ? 0
            : 2 + modulo(Math.floor(second / 7) * 3, 19) + modulo(second, 3);
        // Batch admission alone has no latency sample; observed 0ms is distinct from null.
        const latencyNs = scenario === "observed_zero" && modulo(second, 3) === 0
            ? 0 : 250000 + modulo(Math.floor(second / 11) * 7, 71) * 50000 + modulo(second, 5) * 25000;
        const sumNs = singleExample ? 2479588 : completed * latencyNs;
        const start = ORIGIN + second * 1000;
        points.push({
            bucket_start: iso(start), bucket_end: iso(start + 1000), observed_at: iso(start + 500),
            executions_count: 1, input_accepted_count: input,
            processing_completed_count: completed, processing_failed_count: 0,
            processing_latency_sample_count: completed, processing_latency_sum_ns: sumNs,
            processing_latency_mean_ms: completed ? sumNs / completed / 1000000 : null,
        });
    }
    const recent = points.filter((point) => Date.parse(point.bucket_start) >= end - 60000);
    const sum = (key) => recent.length ? recent.reduce((total, point) => total + point[key], 0) : null;
    const samples = sum("processing_latency_sample_count");
    const sumNs = sum("processing_latency_sum_ns");
    const last = scenario === "unknown" || scenario === "no_samples" ? null
        : singleExample ? iso(ORIGIN + exampleSecond * 1000 + 500)
            : scenario === "stale" ? iso(ORIGIN - 500) : points.at(-1)?.observed_at ?? null;
    const age = last === null ? null : (end - Date.parse(last)) / 1000;
    const partial = scenario === "partial";
    const hasObservations = points.length > 0;
    return {
        schema_version: "pipeline_telemetry_read_v1", scope: "reported",
        execution_id: null, run_id: null, entity_id: null,
        aggregation_basis: "execution_attempt", input_scope: "validated_batch_admission",
        processing_scope: "normalization_and_evidence", count_unit: "records_per_1s_bucket",
        latency_unit: "ms", range_start: iso(end - 300000), range_end: iso(end),
        resolution_seconds: 1, executions_count: hasObservations ? 1 : 0, points,
        recent_60s_summary: {
            range_start: iso(end - 60000), range_end: iso(end),
            observed_bucket_count: recent.length, missing_bucket_count: 60 - recent.length,
            continuous_coverage: false, input_accepted_count: sum("input_accepted_count"),
            processing_completed_count: sum("processing_completed_count"),
            processing_failed_count: sum("processing_failed_count"),
            processing_latency_sample_count: samples, processing_latency_sum_ns: sumNs,
            processing_latency_mean_ms: samples ? sumNs / samples / 1000000 : null,
        },
        last_observed_at: last, persisted_at: last, response_generated_at: iso(end),
        observation_quality: {
            status: partial ? "partial" : hasObservations ? "observed" : "no_samples",
            basis: "latest_persisted_execution_snapshot", observed_executions: hasObservations ? 1 : 0,
            partial_executions: partial ? 1 : 0, unavailable_executions: 0, disabled_executions: 0,
            observation_issues: [], continuous_coverage: false, unreported_executions_included: false,
        },
        freshness: {
            status: age === null ? "unknown" : age > 15 ? "stale" : "recent",
            reference_at: iso(end), threshold_seconds: 15, age_seconds: age, process_liveness: "unknown",
        },
    };
}

/** Virtual observation time pauses independently of the injected real/fake clock. */
export function createPreviewSource({ nowImpl = () => performance.now(), onResponse = () => {} } = {}) {
    let accumulated = 0;
    let startedAt = null;
    let scenario = "continuous";
    const elapsed = () => Math.floor((accumulated + (startedAt === null ? 0 : nowImpl() - startedAt)) / 1000);
    return {
        start() { if (startedAt === null) startedAt = nowImpl(); },
        pause() {
            if (startedAt !== null) accumulated += nowImpl() - startedAt;
            startedAt = null;
        },
        reset(nextScenario = scenario) {
            if (!SCENARIOS.includes(nextScenario)) throw new RangeError("Unknown Preview scenario");
            accumulated = 0;
            startedAt = null;
            scenario = nextScenario;
        },
        get elapsedSeconds() { return elapsed(); },
        async fetchImpl(url, options = {}) {
            if (url !== TELEMETRY_ENDPOINT) throw new Error("Preview accepts only the Telemetry contract URL");
            if (options.signal?.aborted) throw new DOMException("Preview stopped", "AbortError");
            const status = scenario === "api_500" ? 500 : scenario === "api_503" ? 503 : 200;
            const payload = status === 200 ? buildPreviewPayload(elapsed(), scenario) : null;
            onResponse({ payload, status, elapsedSeconds: elapsed(), scenario });
            return { ok: status === 200, status, json: async () => payload };
        },
    };
}
