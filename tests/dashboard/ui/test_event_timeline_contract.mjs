// Event Timeline UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_event_timeline_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    buildEventTimelineApiPath,
    buildEventTimelineViewPath,
    extractTimelineRunIdFromPathname,
    getEventTimelinePagination,
    resolveEventTimelineQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs";

function makeEvent(index) {
    return {
        event_id: `evt-${String(index).padStart(3, "0")}`,
        timestamp: `2026-09-20T01:00:${String(index % 60).padStart(2, "0")}.000Z`,
        host_id: "WIN-01",
        event_type: "process_create",
    };
}

function makePayload({ itemCount = 2, total = itemCount, limit = 50, offset = 0 } = {}) {
    return {
        items: Array.from({ length: itemCount }, (_, index) => makeEvent(offset + index)),
        total,
        limit,
        offset,
    };
}

test("Event Timeline view and API paths encode identifiers and query parameters", () => {
    // Given
    const runId = "RUN 20260920/001";

    // When
    const viewPath = buildEventTimelineViewPath(runId);
    const apiPath = buildEventTimelineApiPath(runId, 50, 0);

    // Then
    assert.equal(viewPath, "/dashboard/runs/RUN%2020260920%2F001/timeline");
    assert.equal(apiPath, "/runs/RUN%2020260920%2F001/timeline?limit=50&offset=0");
});

test("Event Timeline path builders reject invalid identifiers and pagination", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];
    const invalidPagination = [
        [0, 0],
        [201, 0],
        [50.5, 0],
        [50, -1],
        [50, 0.5],
    ];

    // When
    const buildViewPath = (runId) => buildEventTimelineViewPath(runId);

    // Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildViewPath(runId));
        assert.throws(() => buildEventTimelineApiPath(runId, 50, 0));
    }
    for (const [limit, offset] of invalidPagination) {
        assert.throws(() => buildEventTimelineApiPath("RUN-20260920-001", limit, offset));
    }
});

test("Event Timeline pathname extracts one encoded Run ID segment", () => {
    // Given
    const pathname = "/dashboard/runs/RUN%2020260920%2F001/timeline";

    // When
    const runId = extractTimelineRunIdFromPathname(pathname);

    // Then
    assert.equal(runId, "RUN 20260920/001");
});

test("Event Timeline pathname rejects malformed and unrelated paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/runs/",
        "/dashboard/runs/RUN-001",
        "/dashboard/runs/RUN-001/timeline/extra",
        "/runs/RUN-001/timeline",
        "/dashboard/runs/%/timeline",
        "/dashboard/runs/%20/timeline",
        "/dashboard/runs/A/B/timeline",
    ];

    // When
    const runIds = invalidPathnames.map((pathname) => (
        extractTimelineRunIdFromPathname(pathname)
    ));

    // Then
    assert.deepEqual(runIds, [null, null, null, null, null, null, null, null]);
});

test("Event Timeline query states keep loading and failures distinct", () => {
    // Given
    const previousState = null;

    // When
    const loading = resolveEventTimelineQueryState(previousState, { kind: "loading" });
    const runNotFound = resolveEventTimelineQueryState(loading, {
        kind: "run_not_found",
    });
    const error = resolveEventTimelineQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(loading, {
        queryState: "loading",
        payload: null,
        message: "Event Timeline을 불러오는 중입니다.",
    });
    assert.deepEqual(runNotFound, {
        queryState: "run_not_found",
        payload: null,
        message: "Run을 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "Event Timeline을 불러오지 못했습니다.",
    });
});

test("Event Timeline success preserves API references, order, and payload", () => {
    // Given
    const previousState = resolveEventTimelineQueryState(null, { kind: "loading" });
    const payload = makePayload();
    payload.items = [makeEvent(2), makeEvent(1)];
    const payloadSnapshot = structuredClone(payload);
    const items = payload.items;

    // When
    const state = resolveEventTimelineQueryState(previousState, {
        kind: "success",
        payload,
    });

    // Then
    assert.equal(state.queryState, "success");
    assert.equal(state.message, "Event Timeline을 불러왔습니다.");
    assert.strictEqual(state.payload, payload);
    assert.strictEqual(state.payload.items, items);
    assert.deepEqual(
        state.payload.items.map((event) => event.event_id),
        ["evt-002", "evt-001"],
    );
    assert.deepEqual(payload, payloadSnapshot);
});

test("Event Timeline total zero resolves to the empty state", () => {
    // Given
    const payload = makePayload({ itemCount: 0, total: 0 });

    // When
    const state = resolveEventTimelineQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "empty");
    assert.strictEqual(state.payload, payload);
    assert.equal(state.message, "이 Run에 저장된 Event가 없습니다.");
});

test("Event Timeline preserves a whitespace-only string Event ID", () => {
    // Given
    const payload = makePayload({ itemCount: 1 });
    payload.items[0].event_id = "   ";

    // When
    const state = resolveEventTimelineQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload.items, payload.items);
    assert.equal(state.payload.items[0].event_id, "   ");
});

test("Event Timeline pagination follows API page boundaries", () => {
    // Given
    const pages = [
        makePayload({ itemCount: 50, total: 123, offset: 0 }),
        makePayload({ itemCount: 50, total: 123, offset: 50 }),
        makePayload({ itemCount: 23, total: 123, offset: 100 }),
        makePayload({ itemCount: 0, total: 0, offset: 0 }),
    ];

    // When
    const pagination = pages.map((page) => getEventTimelinePagination(page));

    // Then
    assert.deepEqual(pagination, [
        {
            hasPrevious: false,
            hasNext: true,
            previousOffset: 0,
            nextOffset: 50,
            displayStart: 1,
            displayEnd: 50,
        },
        {
            hasPrevious: true,
            hasNext: true,
            previousOffset: 0,
            nextOffset: 100,
            displayStart: 51,
            displayEnd: 100,
        },
        {
            hasPrevious: true,
            hasNext: false,
            previousOffset: 50,
            nextOffset: 123,
            displayStart: 101,
            displayEnd: 123,
        },
        {
            hasPrevious: false,
            hasNext: false,
            previousOffset: 0,
            nextOffset: 0,
            displayStart: 0,
            displayEnd: 0,
        },
    ]);
});

test("Event Timeline query state rejects malformed responses", () => {
    // Given
    const validItem = makeEvent(1);
    const malformedPayloads = [
        null,
        [],
        { items: null, total: 0, limit: 50, offset: 0 },
        { items: [], total: -1, limit: 50, offset: 0 },
        { items: [], total: 0, limit: 0, offset: 0 },
        { items: [], total: 0, limit: 50, offset: -1 },
        { items: [null], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, event_id: 1 }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, timestamp: null }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, host_id: 1 }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, event_type: 1 }], total: 1, limit: 50, offset: 0 },
    ];

    // When
    const validatePayload = (payload) => resolveEventTimelineQueryState(
        null,
        { kind: "success", payload },
    );

    // Then
    assert.throws(() => resolveEventTimelineQueryState([], { kind: "error" }), TypeError);
    assert.throws(() => resolveEventTimelineQueryState(null, null), TypeError);
    for (const payload of malformedPayloads) {
        assert.throws(() => validatePayload(payload));
    }
    assert.throws(
        () => resolveEventTimelineQueryState(null, { kind: "unknown" }),
        RangeError,
    );
});

test("Event Timeline contract remains independent of browser and network APIs", async () => {
    // Given
    const contractUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs",
        import.meta.url,
    );

    // When
    const source = await readFile(contractUrl, "utf8");

    // Then
    for (const forbiddenApi of [
        "document",
        "window",
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "AbortController",
    ]) {
        assert.equal(source.includes(forbiddenApi), false);
    }
});
