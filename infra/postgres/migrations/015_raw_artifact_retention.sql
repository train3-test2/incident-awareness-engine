-- Canonical Raw bytes and generation-time Run/Evidence provenance.
-- Additive only: never backfill historical Runs or alter existing receipts/results.
CREATE TABLE raw_artifact_blobs (
    content_sha256 TEXT PRIMARY KEY CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    byte_size BIGINT NOT NULL CHECK (byte_size BETWEEN 1 AND 67108864),
    content BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(content) = byte_size),
    CHECK (encode(sha256(content), 'hex') = content_sha256)
);

CREATE TABLE raw_run_archives (
    run_id TEXT PRIMARY KEY REFERENCES runs (run_id),
    ingest_id TEXT,
    bucket TEXT,
    object_key TEXT,
    e_tag TEXT,
    raw_log_id TEXT NOT NULL CHECK (btrim(raw_log_id) <> ''),
    content_sha256 TEXT NOT NULL REFERENCES raw_artifact_blobs (content_sha256),
    artifact_uri TEXT NOT NULL,
    manifest_content BYTEA NOT NULL CHECK (octet_length(manifest_content) <= 1048576),
    manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_identity TEXT NOT NULL,
    evidence_content BYTEA NOT NULL CHECK (octet_length(evidence_content) <= 8388608),
    evidence_sha256 TEXT NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    extractor_version TEXT NOT NULL,
    extractor_code_sha256 TEXT NOT NULL CHECK (extractor_code_sha256 ~ '^[0-9a-f]{64}$'),
    raw_format TEXT NOT NULL CHECK (raw_format = 'sysmon_jsonl'),
    format_version TEXT NOT NULL CHECK (format_version = 'sysmon_jsonl_v1'),
    source_metadata JSONB NOT NULL CHECK (jsonb_typeof(source_metadata) = 'object'),
    mirror_required BOOLEAN NOT NULL DEFAULT FALSE,
    archive_created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (bucket, object_key, e_tag),
    CHECK ((ingest_id IS NULL AND bucket IS NULL AND object_key IS NULL AND e_tag IS NULL)
        OR (btrim(ingest_id) <> '' AND btrim(bucket) <> '' AND btrim(object_key) <> ''
            AND btrim(e_tag) <> '' AND ingest_id IS NOT NULL AND bucket IS NOT NULL
            AND object_key IS NOT NULL AND e_tag IS NOT NULL)),
    CHECK (encode(sha256(manifest_content), 'hex') = manifest_sha256),
    CHECK (encode(sha256(evidence_content), 'hex') = evidence_sha256),
    CHECK (artifact_uri = 'raw-db:sha256:' || content_sha256),
    CHECK (manifest_identity = 'raw-manifest:' || run_id || ':sha256:' || manifest_sha256)
);

-- System audit only; not Human Workflow actions. Failed/pre-Run attempts may have no run_id.
CREATE TABLE raw_archive_audit (
    audit_id UUID PRIMARY KEY,
    run_id TEXT,
    ingest_id TEXT,
    bucket TEXT,
    object_key TEXT,
    e_tag TEXT,
    content_sha256 TEXT CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    action TEXT NOT NULL CHECK (action IN (
        'upload_prepared', 'uploaded', 'retained', 'verified', 'repaired', 'failed', 'degraded'
    )),
    reason_code TEXT CHECK (reason_code ~ '^[a-z0-9_]+$'),
    actor_kind TEXT NOT NULL DEFAULT 'system' CHECK (actor_kind = 'system'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX raw_archive_audit_ingest ON raw_archive_audit (ingest_id, recorded_at);
CREATE INDEX raw_archive_audit_run ON raw_archive_audit (run_id, recorded_at);

CREATE FUNCTION guard_raw_archive_immutable() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Raw archive records are append-only';
END;
$$;
CREATE TRIGGER raw_artifact_blobs_immutable BEFORE UPDATE OR DELETE ON raw_artifact_blobs
FOR EACH ROW EXECUTE FUNCTION guard_raw_archive_immutable();
CREATE TRIGGER raw_run_archives_immutable BEFORE UPDATE OR DELETE ON raw_run_archives
FOR EACH ROW EXECUTE FUNCTION guard_raw_archive_immutable();
CREATE TRIGGER raw_archive_audit_immutable BEFORE UPDATE OR DELETE ON raw_archive_audit
FOR EACH ROW EXECUTE FUNCTION guard_raw_archive_immutable();
-- Row triggers do not fire for TRUNCATE; the retained originals must not vanish in bulk.
CREATE TRIGGER raw_artifact_blobs_no_truncate BEFORE TRUNCATE ON raw_artifact_blobs
FOR EACH STATEMENT EXECUTE FUNCTION guard_raw_archive_immutable();
CREATE TRIGGER raw_run_archives_no_truncate BEFORE TRUNCATE ON raw_run_archives
FOR EACH STATEMENT EXECUTE FUNCTION guard_raw_archive_immutable();
CREATE TRIGGER raw_archive_audit_no_truncate BEFORE TRUNCATE ON raw_archive_audit
FOR EACH STATEMENT EXECUTE FUNCTION guard_raw_archive_immutable();
