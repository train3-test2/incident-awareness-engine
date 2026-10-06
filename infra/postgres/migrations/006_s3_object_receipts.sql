-- Successful automatic Worker processing receipts for immutable S3 object versions.

CREATE TABLE s3_object_receipts (
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    e_tag TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs (run_id),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (bucket, object_key, e_tag),
    CHECK (btrim(bucket) <> ''),
    CHECK (btrim(object_key) <> ''),
    CHECK (btrim(e_tag) <> ''),
    CHECK (btrim(run_id) <> '')
);
