// Pure, read-only chart data conversion for Pipeline Telemetry V1.

export const TELEMETRY_ENDPOINT = "/operations/telemetry?scope=reported&window_seconds=300&resolution_seconds=1";

const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const QUALITY_STATUSES = new Set(["no_samples", "observed", "partial"]);
const FRESHNESS_STATUSES = new Set(["unknown", "recent", "stale"]);

function requireObject(value, label) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError(`${label} must be an object`);
    }
    return value;
}

function requireUtcTimestamp(value, label) {
    if (typeof value !== "string" || !UTC_MILLISECONDS.test(value)) {
        throw new TypeError(`${label} must be a UTC millisecond timestamp`);
    }
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
        throw new TypeError(`${label} must be a valid UTC timestamp`);
    }
    return parsed;
}

function nullableUtcTimestamp(value, label) {
    if (value === null) {
        return null;
    }
    requireUtcTimestamp(value, label);
    return value;
}

function requireCount(value, label, { nullable = false } = {}) {
    if (nullable && value === null) {
        return null;
    }
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(`${label} must be a nonnegative safe integer`);
    }
    return value;
}

function requireLatency(value, sampleCount, label) {
    if (sampleCount === 0 || sampleCount === null) {
        if (value !== null) {
            throw new TypeError(`${label} must be null without samples`);
        }
        return null;
    }
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
        throw new TypeError(`${label} must be a nonnegative finite number`);
    }
    return value;
}

function requireStatus(value, values, label) {
    if (!values.has(value)) {
        throw new TypeError(`${label} is unsupported`);
    }
    return value;
}

export function buildTelemetryChartModel(payload) {
    const response = requireObject(payload, "Telemetry response");
    if (
        response.schema_version !== "pipeline_telemetry_read_v1"
        || response.scope !== "reported"
        || response.resolution_seconds !== 1
        || !Array.isArray(response.points)
    ) {
        throw new TypeError("Unsupported reported Telemetry V1 response");
    }

    const rangeStart = requireUtcTimestamp(response.range_start, "range_start");
    const rangeEnd = requireUtcTimestamp(response.range_end, "range_end");
    const windowSeconds = (rangeEnd - rangeStart) / 1000;
    if (!Number.isInteger(windowSeconds) || windowSeconds < 60 || windowSeconds > 300) {
        throw new RangeError("Telemetry range must contain 60 to 300 complete seconds");
    }
    if (response.points.length > windowSeconds) {
        throw new RangeError("Too many Telemetry points for the requested range");
    }

    // Null means "not observed", never "observed zero".
    const seconds = Array.from({ length: windowSeconds }, (_, index) => ({
        timestamp: new Date(rangeStart + index * 1000).toISOString(),
        observed: false,
        inputAcceptedCount: null,
        processingCompletedCount: null,
        processingFailedCount: null,
        processingLatencySampleCount: null,
        processingLatencyMeanMs: null,
    }));

    let previousIndex = -1;
    for (const [pointIndex, item] of response.points.entries()) {
        const point = requireObject(item, `points[${pointIndex}]`);
        const start = requireUtcTimestamp(point.bucket_start, "bucket_start");
        const end = requireUtcTimestamp(point.bucket_end, "bucket_end");
        const index = (start - rangeStart) / 1000;
        if (
            !Number.isInteger(index)
            || index < 0
            || index >= windowSeconds
            || index <= previousIndex
            || end !== start + 1000
        ) {
            throw new RangeError("Telemetry points must be unique, ordered one-second buckets");
        }
        previousIndex = index;
        const inputAcceptedCount = requireCount(point.input_accepted_count, "input_accepted_count");
        const processingCompletedCount = requireCount(point.processing_completed_count, "processing_completed_count");
        const processingFailedCount = requireCount(point.processing_failed_count, "processing_failed_count");
        const processingLatencySampleCount = requireCount(
            point.processing_latency_sample_count,
            "processing_latency_sample_count",
        );
        if (processingLatencySampleCount > processingCompletedCount) {
            throw new RangeError("Latency sample count exceeds completed records");
        }
        if (inputAcceptedCount + processingCompletedCount + processingFailedCount === 0) {
            throw new RangeError("A stored bucket must contain a recorded activity");
        }
        seconds[index] = {
            timestamp: point.bucket_start,
            observed: true,
            inputAcceptedCount,
            processingCompletedCount,
            processingFailedCount,
            processingLatencySampleCount,
            processingLatencyMeanMs: requireLatency(
                point.processing_latency_mean_ms,
                processingLatencySampleCount,
                "processing_latency_mean_ms",
            ),
        };
    }

    const summary = requireObject(response.recent_60s_summary, "recent_60s_summary");
    const observedBucketCount = requireCount(summary.observed_bucket_count, "observed_bucket_count");
    const missingBucketCount = requireCount(summary.missing_bucket_count, "missing_bucket_count");
    if (observedBucketCount + missingBucketCount !== 60) {
        throw new RangeError("Recent Telemetry coverage must describe 60 seconds");
    }
    const summarySamples = requireCount(
        summary.processing_latency_sample_count,
        "summary.processing_latency_sample_count",
        { nullable: true },
    );
    const quality = requireObject(response.observation_quality, "observation_quality");
    const freshness = requireObject(response.freshness, "freshness");

    return {
        rangeStart: response.range_start,
        rangeEnd: response.range_end,
        seconds,
        observedBucketCount,
        missingBucketCount,
        recent60s: {
            inputAcceptedCount: requireCount(summary.input_accepted_count, "summary.input_accepted_count", { nullable: true }),
            processingCompletedCount: requireCount(summary.processing_completed_count, "summary.processing_completed_count", { nullable: true }),
            processingFailedCount: requireCount(summary.processing_failed_count, "summary.processing_failed_count", { nullable: true }),
            processingLatencySampleCount: summarySamples,
            processingLatencyMeanMs: requireLatency(
                summary.processing_latency_mean_ms,
                summarySamples,
                "summary.processing_latency_mean_ms",
            ),
        },
        qualityStatus: requireStatus(quality.status, QUALITY_STATUSES, "observation_quality.status"),
        freshnessStatus: requireStatus(freshness.status, FRESHNESS_STATUSES, "freshness.status"),
        lastObservedAt: nullableUtcTimestamp(response.last_observed_at, "last_observed_at"),
    };
}
