// Event Detail path contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_event_detail_contract.mjs
import assert from "node:assert/strict";
import test from "node:test";

import { buildEventDetailViewPath } from "../../../src/incident_awareness/dashboard/ui/assets/event-detail-contract.mjs";

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
