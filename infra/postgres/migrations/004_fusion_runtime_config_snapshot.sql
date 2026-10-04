-- Mutable latest Fusion Runtime configuration snapshot storage.

CREATE TABLE fusion_runtime_config_snapshots (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    config_version TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, entity_id),
    CHECK (btrim(entity_id) <> ''),
    CHECK (btrim(config_version) <> ''),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'run_id' IS NOT DISTINCT FROM run_id),
    CHECK (payload ->> 'entity_id' IS NOT DISTINCT FROM entity_id),
    CHECK (payload ->> 'config_version' IS NOT DISTINCT FROM config_version)
);
