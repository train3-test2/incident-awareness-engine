-- Immutable Decision-time Runtime snapshot Contract storage.

ALTER TABLE decisions
    ADD CONSTRAINT decisions_decision_scope_key
    UNIQUE (decision_id, run_id, entity_id);

CREATE TABLE decision_runtime_snapshots (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT decision_runtime_snapshots_decision_scope_fk
        FOREIGN KEY (decision_id, run_id, entity_id)
        REFERENCES decisions (decision_id, run_id, entity_id)
        ON DELETE CASCADE,
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
