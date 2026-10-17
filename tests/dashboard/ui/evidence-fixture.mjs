// Test-only dashboard_run_evidence_v1 responses. Never imported by the operating Dashboard.
export const RUN_ID = "RUN-20261008-917";
export const SHA = "a".repeat(64);

export function evidenceItem(overrides = {}) {
    return {
        evidence_id: "evidence-lineage",
        evidence_type: "remote_session_process_lineage_deviation",
        timestamp: "2026-10-08T17:10:30.538000Z",
        entity_id: "PAIR004-DERIVED-HOST",
        derived_from_source_layer: "raw_telemetry",
        feature_channel_group: "fusion_feature",
        extractor_version: "r1-v0.1",
        attack_technique_ids: [],
        events: [
            { event_id: "evt-anchor", stored: true },
            { event_id: "evt-middle", stored: true },
            { event_id: "evt-terminal", stored: false },
        ],
        policy: { policy_id: "r1-remote-management-approved-lineage", version: "v0.3", config_hash: "b".repeat(64) },
        withheld_field_count: 0,
        ...overrides,
    };
}

export function evidencePayload({ runId = RUN_ID, availability = "published", archiveStatus,
    items, total, offset = 0, limit = 100, unstored } = {}) {
    const published = availability === "published";
    const rows = items ?? (published ? [
        evidenceItem(),
        evidenceItem({ evidence_id: "evidence-network", evidence_type: "remote_process_network_follow_on",
            timestamp: "2026-10-08T17:13:30.899000Z", policy: null,
            events: [{ event_id: "evt-terminal", stored: false }, { event_id: "evt-network", stored: true }] }),
    ] : []);
    return {
        schema_version: "dashboard_run_evidence_v1",
        run_id: runId,
        availability,
        archive_status: archiveStatus !== undefined ? archiveStatus : published ? "published" : null,
        source: "r1_archive_publication",
        evidence_scope: "offline_whole_episode",
        fusion_input: false,
        timestamp_meaning: "event_time",
        entity_scope: "run",
        extractor_version: published ? "r1-v0.1" : null,
        evidence_sha256: published ? SHA : null,
        total: total !== undefined ? total : published ? rows.length : null,
        limit,
        offset,
        entity_ids: published ? [...new Set(rows.map((row) => row.entity_id))].sort() : [],
        unstored_event_reference_count: unstored ?? (published ? 1 : 0),
        items: rows,
    };
}
