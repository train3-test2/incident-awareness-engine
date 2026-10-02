-- Immutable Decision-time Runtime snapshot Contract storage.

CREATE TABLE decision_runtime_snapshots (
    decision_id TEXT PRIMARY KEY
        REFERENCES decisions (decision_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (btrim(decision_id) <> ''),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(entity_id) <> ''),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'decision_id' IS NOT DISTINCT FROM decision_id),
    CHECK (payload ->> 'run_id' IS NOT DISTINCT FROM run_id),
    CHECK (payload ->> 'entity_id' IS NOT DISTINCT FROM entity_id)
);

CREATE INDEX decision_runtime_snapshots_run_id_entity_id_idx
    ON decision_runtime_snapshots (run_id, entity_id);
