-- Temporal Fusion stopping trace의 최신 Runtime Contract를 저장한다.

CREATE TABLE fusion_stopping_traces (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    scoring_config_version TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, entity_id),
    CHECK (btrim(entity_id) <> ''),
    CHECK (btrim(scoring_config_version) <> ''),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'run_id' IS NOT DISTINCT FROM run_id),
    CHECK (payload ->> 'entity_id' IS NOT DISTINCT FROM entity_id),
    CHECK (
        payload ->> 'scoring_config_version'
        IS NOT DISTINCT FROM scoring_config_version
    )
);
