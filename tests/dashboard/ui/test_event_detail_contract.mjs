// Event Detail path contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_event_detail_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    buildEventDetailApiPath,
    buildEventDetailViewPath,
    extractEventDetailIdsFromPathname,
    getSourceLayerLabel,
    resolveEventDetailQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/event-detail-contract.mjs";

function makePayload() {
    return {
        event_id: "evt-001",
        run_id: "RUN-20260920-001",
        timestamp: "2026-09-20T01:00:00.000Z",
        host_id: "WIN-01",
        event_type: "process_create",
        source: "sysmon",
        source_layer: "raw_telemetry",
        source_event_id: "1",
        timestamp_source: "event_time",
        raw_ref: {
            raw_log_id: "RAW-001",
            source_record_id: null,
            segment_no: 1,
            record_no: 1,
            parser_id: null,
            parser_version: null,
        },
    };
}

test("Event Detail view path URL-encodes normal and slash Event IDs", () => {
    // Given
    const runId = "RUN-20260920-001";
    const eventIds = ["evt-001", "evt group/child"];

    // When
    const paths = eventIds.map((eventId) => buildEventDetailViewPath(runId, eventId));

    // Then
    assert.deepEqual(paths, [
        "/dashboard/runs/RUN-20260920-001/events/evt-001",
        "/dashboard/runs/RUN-20260920-001/events/evt%20group%2Fchild",
    ]);
});

test("Event Detail view path URL-encodes the Run ID", () => {
    // Given
    const runId = "RUN 20260920/001";

    // When
    const path = buildEventDetailViewPath(runId, "evt-001");

    // Then
    assert.equal(path, "/dashboard/runs/RUN%2020260920%2F001/events/evt-001");
});

test("Event Detail view path preserves a whitespace-only Event ID", () => {
    // Given
    const eventId = "   ";

    // When
    const path = buildEventDetailViewPath("RUN-20260920-001", eventId);

    // Then
    assert.equal(path, "/dashboard/runs/RUN-20260920-001/events/%20%20%20");
});

test("Event Detail view path rejects missing, blank, and dot-segment IDs", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];
    const invalidEventIds = [null, undefined, "", ".", ".."];

    // When
    const buildWithRunId = (runId) => buildEventDetailViewPath(runId, "evt-001");
    const buildWithEventId = (eventId) => (
        buildEventDetailViewPath("RUN-20260920-001", eventId)
    );

    // Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildWithRunId(runId));
    }
    for (const eventId of invalidEventIds) {
        assert.throws(() => buildWithEventId(eventId));
    }
});

test("Event Detail API path encodes normal, slash, and whitespace Event IDs", () => {
    // Given
    const runId = "RUN-20260920-001";
    const eventIds = ["evt-001", "evt group/child", "   "];

    // When
    const paths = eventIds.map((eventId) => buildEventDetailApiPath(runId, eventId));

    // Then
    assert.deepEqual(paths, [
        "/runs/RUN-20260920-001/events/evt-001",
        "/runs/RUN-20260920-001/events/evt%20group%2Fchild",
        "/runs/RUN-20260920-001/events/%20%20%20",
    ]);
});

test("Event Detail API path uses the existing identifier validation", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];
    const invalidEventIds = [null, undefined, "", ".", ".."];

    // When
    const buildWithRunId = (runId) => buildEventDetailApiPath(runId, "evt-001");
    const buildWithEventId = (eventId) => (
        buildEventDetailApiPath("RUN-20260920-001", eventId)
    );

    // Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildWithRunId(runId));
    }
    for (const eventId of invalidEventIds) {
        assert.throws(() => buildWithEventId(eventId));
    }
});

test("Event Detail pathname parses normal, slash, and whitespace Event IDs", () => {
    // Given
    const pathnames = [
        "/dashboard/runs/RUN-20260920-001/events/evt-001",
        "/dashboard/runs/RUN-20260920-001/events/evt%20group%2Fchild",
        "/dashboard/runs/RUN-20260920-001/events/%20%20%20",
    ];

    // When
    const identifiers = pathnames.map((pathname) => (
        extractEventDetailIdsFromPathname(pathname)
    ));

    // Then
    assert.deepEqual(identifiers, [
        { runId: "RUN-20260920-001", eventId: "evt-001" },
        { runId: "RUN-20260920-001", eventId: "evt group/child" },
        { runId: "RUN-20260920-001", eventId: "   " },
    ]);
});

test("Event Detail pathname rejects malformed and unsafe paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/runs/RUN-20260920-001/events/",
        "/dashboard/runs/RUN-20260920-001/event/evt-001",
        "/runs/RUN-20260920-001/events/evt-001",
        "/dashboard/runs/%/events/evt-001",
        "/dashboard/runs/%20/events/evt-001",
        "/dashboard/runs/RUN-20260920-001/events/%",
        "/dashboard/runs/RUN-20260920-001/events/%2E",
        "/dashboard/runs/RUN-20260920-001/events/%2E%2E",
    ];

    // When
    const identifiers = invalidPathnames.map((pathname) => (
        extractEventDetailIdsFromPathname(pathname)
    ));

    // Then
    assert.deepEqual(identifiers, Array(invalidPathnames.length).fill(null));
});

test("Event Detail query states keep loading and failures distinct", () => {
    // Given
    const previousState = null;

    // When
    const loading = resolveEventDetailQueryState(previousState, { kind: "loading" });
    const notFound = resolveEventDetailQueryState(loading, { kind: "not_found" });
    const error = resolveEventDetailQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(loading, {
        queryState: "loading",
        payload: null,
        message: "Event Detail을 불러오는 중입니다.",
    });
    assert.deepEqual(notFound, {
        queryState: "not_found",
        payload: null,
        message: "Run 또는 Event를 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "Event Detail을 불러오지 못했습니다.",
    });
});

test("Event Detail success preserves the payload reference without mutation", () => {
    // Given
    const payload = makePayload();
    const snapshot = structuredClone(payload);

    // When
    const state = resolveEventDetailQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.equal(state.message, "Event Detail을 불러왔습니다.");
    assert.strictEqual(state.payload, payload);
    assert.deepEqual(payload, snapshot);
});

test("Event Detail success accepts nullable Raw Log Reference fields", () => {
    // Given
    const payload = makePayload();

    // When
    const state = resolveEventDetailQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.payload.raw_ref.source_record_id, null);
    assert.equal(state.payload.raw_ref.parser_id, null);
    assert.equal(state.payload.raw_ref.parser_version, null);
});

test("Event Detail query state rejects malformed top-level fields", () => {
    // Given
    const stringFields = [
        "event_id",
        "run_id",
        "host_id",
        "event_type",
        "source",
        "source_layer",
        "source_event_id",
        "timestamp_source",
    ];
    const missingTimestamp = makePayload();
    delete missingTimestamp.timestamp;
    const missingRawReference = makePayload();
    delete missingRawReference.raw_ref;
    const malformedPayloads = [
        null,
        [],
        { ...makePayload(), timestamp: null },
        missingTimestamp,
        missingRawReference,
    ];
    for (const field of stringFields) {
        malformedPayloads.push({ ...makePayload(), [field]: null });
        const missingPayload = makePayload();
        delete missingPayload[field];
        malformedPayloads.push(missingPayload);
    }

    // When
    const validatePayload = (payload) => resolveEventDetailQueryState(
        null,
        { kind: "success", payload },
    );

    // Then
    for (const payload of malformedPayloads) {
        assert.throws(() => validatePayload(payload));
    }
});

test("Event Detail query state rejects malformed Raw Log References", () => {
    // Given
    const validRawReference = makePayload().raw_ref;
    const malformedRawReferences = [
        null,
        [],
        { ...validRawReference, raw_log_id: null },
        { ...validRawReference, source_record_id: 1 },
        { ...validRawReference, parser_id: 1 },
        { ...validRawReference, parser_version: 1 },
        { ...validRawReference, segment_no: 0 },
        { ...validRawReference, segment_no: true },
        { ...validRawReference, segment_no: 1.5 },
        { ...validRawReference, record_no: 0 },
        { ...validRawReference, record_no: true },
        { ...validRawReference, record_no: 1.5 },
    ];

    // When
    const validateRawReference = (rawReference) => resolveEventDetailQueryState(
        null,
        { kind: "success", payload: { ...makePayload(), raw_ref: rawReference } },
    );

    // Then
    for (const rawReference of malformedRawReferences) {
        assert.throws(() => validateRawReference(rawReference));
    }
});

test("Event Detail query state rejects malformed results and unknown kinds", () => {
    // Given
    const invalidResults = [null, []];

    // When
    const resolveResult = (result) => resolveEventDetailQueryState(null, result);

    // Then
    assert.throws(() => resolveEventDetailQueryState([], { kind: "error" }), TypeError);
    for (const result of invalidResults) {
        assert.throws(() => resolveResult(result), TypeError);
    }
    assert.throws(() => resolveResult({ kind: "unknown" }), RangeError);
});

test("Event Detail source-layer presentation maps known values with raw fallback", () => {
    // Given
    const sourceLayers = ["raw_telemetry", "detector_output", "future_layer"];

    // When
    const labels = sourceLayers.map((sourceLayer) => getSourceLayerLabel(sourceLayer));

    // Then
    assert.deepEqual(labels, ["Raw Telemetry", "Detector Output", "future_layer"]);
});

test("Event Detail contract remains independent of browser and network APIs", async () => {
    // Given
    const contractUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/event-detail-contract.mjs",
        import.meta.url,
    );

    // When
    const source = await readFile(contractUrl, "utf8");

    // Then
    for (const forbiddenApi of [
        "document",
        "window",
        "location",
        "fetch(",
        "setTimeout(",
        "setInterval(",
        "AbortController",
    ]) {
        assert.equal(source.includes(forbiddenApi), false);
    }
});
