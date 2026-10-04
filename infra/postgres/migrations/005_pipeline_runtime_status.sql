-- Mutable latest Pipeline Runtime telemetry for one Run and entity scope.

CREATE TABLE pipeline_runtime_status (
    run_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    current_stage TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, entity_id),
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(entity_id) <> ''),
    CHECK (btrim(execution_id) <> ''),
    CHECK (
        current_stage IS NULL
        OR current_stage IN (
            'artifact_validation',
            'normalization',
            'fusion',
            'fast_handoff',
            'hybrid',
            'persistence'
        )
    ),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'execution_id' IS NOT DISTINCT FROM execution_id),
    CHECK (payload ->> 'run_id' IS NOT DISTINCT FROM run_id),
    CHECK (payload ->> 'entity_id' IS NOT DISTINCT FROM entity_id),
    CHECK (payload ->> 'status' IS NOT DISTINCT FROM status),
    CHECK (payload ->> 'current_stage' IS NOT DISTINCT FROM current_stage)
);

CREATE INDEX pipeline_runtime_status_operational_idx
    ON pipeline_runtime_status (
        (CASE WHEN status = 'running' THEN 0 ELSE 1 END),
        updated_at DESC,
        run_id,
        entity_id
    );
