-- Durable idempotency ledger for the future R1 incremental stream ingress.
-- The existing S3/SQS whole-object batch path does not write these tables.

CREATE TABLE r1_stream_chunks (
    run_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    chunk_sequence INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, host_id, source, source_channel, chunk_id),
    UNIQUE (run_id, host_id, source, source_channel, chunk_sequence),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(host_id) <> ''),
    CHECK (btrim(source) <> ''),
    CHECK (btrim(source_channel) <> ''),
    CHECK (btrim(chunk_id) <> ''),
    CHECK (chunk_sequence >= 1),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE r1_stream_watermarks (
    run_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    watermark_id TEXT NOT NULL,
    watermark_sequence INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, host_id, source, source_channel, watermark_id),
    UNIQUE (run_id, host_id, source, source_channel, watermark_sequence),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(host_id) <> ''),
    CHECK (btrim(source) <> ''),
    CHECK (btrim(source_channel) <> ''),
    CHECK (btrim(watermark_id) <> ''),
    CHECK (watermark_sequence >= 1),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE r1_stream_run_closes (
    run_id TEXT NOT NULL,
    close_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, close_id),
    UNIQUE (run_id),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(close_id) <> ''),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
);
