// Evidence tab contract tests. Run with: node --test tests/dashboard/ui/test_dashboard_evidence_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    EVIDENCE_MESSAGES,
    buildEvidenceApiPath,
    classifyEvidenceFailure,
    describeVerifiedArchive,
    getEvidenceTypeLabel,
    getFeatureChannelLabel,
    getSourceLayerLabel,
    resolveEvidenceResponse,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-evidence-contract.mjs";
import { RUN_ID, SHA, evidenceItem, evidencePayload } from "./evidence-fixture.mjs";

test("Evidence path is Run-scoped, encoded, bounded, and rejects padded Run IDs", () => {
    // When / Then
    assert.equal(buildEvidenceApiPath(RUN_ID), `/runs/${RUN_ID}/evidences?limit=100`);
    assert.equal(buildEvidenceApiPath("RUN/../x", 5), "/runs/RUN%2F..%2Fx/evidences?limit=5");
    for (const runId of ["", " RUN", "RUN ", null]) assert.throws(() => buildEvidenceApiPath(runId), TypeError);
    assert.throws(() => buildEvidenceApiPath(RUN_ID, 0), TypeError);
    assert.throws(() => buildEvidenceApiPath(RUN_ID, 201), TypeError);
    assert.throws(() => buildEvidenceApiPath("R".repeat(513)), TypeError);
});

test("A published archive lists verified items with Run, Entity, and unstored Event counts", () => {
    // When
    const model = resolveEvidenceResponse(evidencePayload(), RUN_ID);
    // Then
    assert.equal(model.state, "published");
    assert.equal(model.items.length, 2);
    assert.deepEqual(model.entityIds, ["PAIR004-DERIVED-HOST"]);
    assert.equal(model.message, "Evidence 조회 완료 · 검증된 2건 · Entity 1개 · 저장 Event 미조회 1건(링크 없음)");
    assert.equal(model.evidenceSha256, SHA);
    assert.equal(describeVerifiedArchive(model), "R1 아카이브 · Extractor r1-v0.1 · SHA-256 aaaaaaaaaaaa… 검증");
});

test("Zero Evidence, no archive, and unpublished archives are separate states", () => {
    // When
    const empty = resolveEvidenceResponse(evidencePayload({ items: [], total: 0, unstored: 0 }), RUN_ID);
    const none = resolveEvidenceResponse(evidencePayload({ availability: "no_archive" }), RUN_ID);
    const pending = resolveEvidenceResponse(evidencePayload({ availability: "not_published", archiveStatus: "pending" }), RUN_ID);
    const retryable = resolveEvidenceResponse(evidencePayload({ availability: "not_published", archiveStatus: "retryable" }), RUN_ID);
    const failed = resolveEvidenceResponse(evidencePayload({ availability: "not_published", archiveStatus: "failed" }), RUN_ID);
    // Then
    assert.deepEqual([empty.state, empty.message], ["empty", EVIDENCE_MESSAGES.empty]);
    assert.deepEqual([none.state, none.message], ["no_archive", EVIDENCE_MESSAGES.noArchive]);
    assert.equal(pending.state, "archive_pending");
    assert.equal(retryable.state, "archive_pending");
    assert.match(retryable.message, /상태: retryable/);
    assert.equal(failed.state, "archive_failed");
    for (const model of [empty, none, pending, failed]) assert.deepEqual(model.items, []);
});

test("A partial page reports the shown range against the verified total", () => {
    // When
    const model = resolveEvidenceResponse(evidencePayload({ items: [evidenceItem()], total: 3, offset: 1, limit: 1 }), RUN_ID);
    // Then
    assert.match(model.message, /검증된 3건 · 2–2건 표시/);
});

const corruptions = {
    "wrong schema": (p) => { p.schema_version = "v0"; },
    "another Run": (p) => { p.run_id = "RUN-OTHER"; },
    "Fusion input claim": (p) => { p.fusion_input = true; },
    "processing-time claim": (p) => { p.timestamp_meaning = "arrival_time"; },
    "Entity scope change": (p) => { p.entity_scope = "entity"; },
    "non-UTC timestamp": (p) => { p.items[0].timestamp = "2026-10-08T17:10:30.538+09:00"; },
    "calendar-invalid timestamp": (p) => { p.items[0].timestamp = "2026-02-30T00:00:00Z"; },
    "no Event references": (p) => { p.items[0].events = []; },
    "non-boolean stored flag": (p) => { p.items[0].events[0].stored = "yes"; },
    "duplicate Evidence ID": (p) => { p.items[1].evidence_id = p.items[0].evidence_id; },
    "item Entity outside scope": (p) => { p.items[0].entity_id = "OTHER-HOST"; },
    "items beyond limit": (p) => { p.limit = 1; },
    "items beyond total": (p) => { p.total = 1; },
    "truncated page": (p) => { p.total = 3; },
    "unknown source layer": (p) => { p.items[0].derived_from_source_layer = "fusion"; },
    "missing extractor": (p) => { p.extractor_version = null; },
    "mismatched item extractor": (p) => { p.items[0].extractor_version = "other-version"; },
    "duplicate Entity scope": (p) => { p.entity_ids.push(p.entity_ids[0]); },
    "limit beyond API maximum": (p) => { p.limit = 201; },
    "malformed SHA-256": (p) => { p.evidence_sha256 = "abc"; },
    "no archive with items": (p) => { p.availability = "no_archive"; p.archive_status = null; },
    "unpublished claiming published": (p) => { p.availability = "not_published"; p.items = []; p.total = null; p.evidence_sha256 = null; },
};
for (const [name, corrupt] of Object.entries(corruptions)) {
    test(`Reject ${name} before rendering any Evidence`, () => {
        // Given
        const payload = evidencePayload();
        corrupt(payload);
        // When / Then
        assert.throws(() => resolveEvidenceResponse(payload, RUN_ID), TypeError);
    });
}

test("Valid early-year UTC timestamps do not become 1900-based dates", () => {
    // Given
    const payload = evidencePayload();
    payload.items[0].timestamp = "0001-01-01T00:00:00.000001Z";
    // When / Then
    assert.equal(resolveEvidenceResponse(payload, RUN_ID).items[0].timestamp, payload.items[0].timestamp);
});

test("An empty page beyond the verified total is not a zero-Evidence archive", () => {
    // Given
    const payload = evidencePayload({ items: [], total: 2, offset: 100, unstored: 0 });
    payload.entity_ids = ["PAIR004-DERIVED-HOST"];
    // When
    const model = resolveEvidenceResponse(payload, RUN_ID);
    // Then
    assert.equal(model.state, "published");
    assert.match(model.message, /검증된 2건 · 현재 페이지 0건/);
});

test("Only documented failure details name a cause; everything else is an API error", () => {
    // When / Then
    assert.equal(classifyEvidenceFailure(404, "Not Found").state, "not_ready");
    assert.equal(classifyEvidenceFailure(503, "Evidence archive storage is not provisioned").state, "not_ready");
    assert.equal(classifyEvidenceFailure(404, "Run not found").state, "run_missing");
    for (const detail of ["Stored Evidence archive is invalid", "Stored Evidence provenance is inconsistent",
        "Stored Evidence archive exceeds the read limit"]) {
        assert.equal(classifyEvidenceFailure(500, detail).state, "invalid");
    }
    for (const [status, detail] of [[503, "Evidence database is unavailable"], [500, "Evidence read failed"],
        [404, "Something else"], [0, null], [502, null]]) {
        assert.deepEqual(classifyEvidenceFailure(status, detail), { state: "error", message: EVIDENCE_MESSAGES.error });
    }
});

test("Labels translate known contract values and pass unknown values through as text", () => {
    // When / Then
    assert.equal(getEvidenceTypeLabel("remote_process_network_follow_on"), "원격 프로세스 네트워크 후속 연결");
    assert.equal(getEvidenceTypeLabel("future_type"), "future_type");
    assert.equal(getSourceLayerLabel("raw_telemetry"), "원시 Telemetry");
    assert.equal(getFeatureChannelLabel("diagnostic_only"), "진단 전용");
});

test("Evidence contract stays pure and never builds HTML", async () => {
    // Given
    const source = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/assets/dashboard-evidence-contract.mjs", import.meta.url), "utf8");
    // When / Then
    for (const forbidden of ["document", "window", "fetch(", "setTimeout(", "setInterval(", "innerHTML", "contributing_evidence_ids"]) {
        assert.equal(source.includes(forbidden), false, forbidden);
    }
});
