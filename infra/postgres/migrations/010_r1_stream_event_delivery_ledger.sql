-- Preserve immutable Event identities across distinct incremental-stream chunks.

CREATE TABLE r1_stream_events (
    run_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    event_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, host_id, source, source_channel, event_id),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(host_id) <> ''),
    CHECK (btrim(source) <> ''),
    CHECK (btrim(source_channel) <> ''),
    CHECK (btrim(event_id) <> ''),
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
);
