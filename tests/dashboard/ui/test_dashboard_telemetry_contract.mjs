import assert from "node:assert/strict";
import test from "node:test";

import {
    TELEMETRY_ENDPOINT,
    buildTelemetryChartModel,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-contract.mjs";

function makeResponse() {
    return {
        schema_version: "pipeline_telemetry_read_v1",
        scope: "reported",
        range_start: "2026-10-15T05:22:20.000Z",
        range_end: "2026-10-15T05:23:20.000Z",
        resolution_seconds: 1,
        points: [{
            bucket_start: "2026-10-15T05:23:17.000Z",
            bucket_end: "2026-10-15T05:23:18.000Z",
            input_accepted_count: 2,
            processing_completed_count: 2,
            processing_failed_count: 0,
            processing_latency_sample_count: 2,
            processing_latency_mean_ms: 0.775214,
        }],
        recent_60s_summary: {
            observed_bucket_count: 1,
            missing_bucket_count: 59,
            input_accepted_count: 2,
            processing_completed_count: 2,
            processing_failed_count: 0,
            processing_latency_sample_count: 2,
            processing_latency_mean_ms: 0.775214,
        },
        observation_quality: { status: "observed" },
        freshness: { status: "recent" },
        last_observed_at: "2026-10-15T05:23:17.642Z",
    };
}

test("Telemetry chart model retains actual AWS bucket counts and server latency", () => {
    // Given
    const response = makeResponse();

    // When
    const model = buildTelemetryChartModel(response);

    // Then
    assert.match(TELEMETRY_ENDPOINT, /scope=reported/);
    assert.equal(model.seconds.length, 60);
    assert.equal(model.seconds[57].inputAcceptedCount, 2);
    assert.equal(model.seconds[57].processingCompletedCount, 2);
    assert.equal(model.seconds[57].processingLatencyMeanMs, 0.775214);
    assert.equal(model.recent60s.processingLatencyMeanMs, 0.775214);
    assert.equal(model.qualityStatus, "observed");
    assert.equal(model.freshnessStatus, "recent");
});

test("Missing buckets are null, not fabricated zero throughput", () => {
    // Given
    const response = makeResponse();

    // When
    const model = buildTelemetryChartModel(response);

    // Then
    assert.equal(model.seconds[0].observed, false);
    assert.equal(model.seconds[0].inputAcceptedCount, null);
    assert.equal(model.seconds[0].processingLatencyMeanMs, null);
    assert.equal(model.observedBucketCount, 1);
    assert.equal(model.missingBucketCount, 59);
});

test("An observed zero count remains zero while latency without samples is null", () => {
    // Given
    const response = makeResponse();
    response.points[0].input_accepted_count = 0;
    response.points[0].processing_completed_count = 2;
    response.points[0].processing_latency_sample_count = 0;
    response.points[0].processing_latency_mean_ms = null;

    // When
    const model = buildTelemetryChartModel(response);

    // Then
    assert.equal(model.seconds[57].observed, true);
    assert.equal(model.seconds[57].inputAcceptedCount, 0);
    assert.equal(model.seconds[57].processingLatencyMeanMs, null);
    assert.equal(model.seconds[56].inputAcceptedCount, null);
});

test("No samples keeps every bucket and recent summary unknown", () => {
    // Given
    const response = makeResponse();
    response.points = [];
    response.recent_60s_summary.observed_bucket_count = 0;
    response.recent_60s_summary.missing_bucket_count = 60;
    for (const key of [
        "input_accepted_count",
        "processing_completed_count",
        "processing_failed_count",
        "processing_latency_sample_count",
        "processing_latency_mean_ms",
    ]) {
        response.recent_60s_summary[key] = null;
    }
    response.observation_quality.status = "no_samples";
    response.freshness.status = "unknown";
    response.last_observed_at = null;

    // When
    const model = buildTelemetryChartModel(response);

    // Then
    assert.equal(model.seconds.filter((point) => point.observed).length, 0);
    assert.equal(model.recent60s.processingCompletedCount, null);
    assert.equal(model.lastObservedAt, null);
    assert.equal(model.qualityStatus, "no_samples");
});

test("Invalid scope or schema fails instead of silently drawing a chart", () => {
    // Given
    const response = makeResponse();
    response.scope = "run";

    // When / Then
    assert.throws(() => buildTelemetryChartModel(response), /Unsupported reported/);
    response.scope = "reported";
    response.schema_version = "unexpected";
    assert.throws(() => buildTelemetryChartModel(response), /Unsupported reported/);
});

test("Duplicate or out-of-order time buckets are rejected", () => {
    // Given
    const response = makeResponse();
    response.points.push({ ...response.points[0] });

    // When / Then
    assert.throws(() => buildTelemetryChartModel(response), /unique, ordered/);
});

test("Invalid or absent latency values are not converted into zero", () => {
    // Given
    const response = makeResponse();
    response.points[0].processing_latency_mean_ms = null;

    // When / Then
    assert.throws(() => buildTelemetryChartModel(response), /nonnegative finite/);
});
