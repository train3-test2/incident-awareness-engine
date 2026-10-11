-- Durable outbox for generic R1 Evidence archive publication.

CREATE TABLE r1_archive_publications (
    run_id TEXT PRIMARY KEY REFERENCES runs (run_id) ON DELETE CASCADE,
    bucket TEXT NOT NULL,
    object_prefix TEXT NOT NULL,
    evidence_content BYTEA NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    summary_content BYTEA NOT NULL,
    summary_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error_type TEXT,
    last_error_message TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(bucket) <> ''),
    CHECK (btrim(object_prefix) <> ''),
    CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (summary_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (status IN ('pending', 'retryable', 'published', 'failed')),
    CHECK (attempt_count >= 0)
);
