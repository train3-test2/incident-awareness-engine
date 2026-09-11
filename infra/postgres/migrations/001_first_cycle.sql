-- First Cycle의 구조화된 메타데이터와 결과 Contract를 저장한다.
-- Raw artifact와 Evidence는 후속 migration에서 별도로 관리한다.

BEGIN;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    run_type TEXT NOT NULL CHECK (run_type IN ('normal', 'attack')),
    target_host TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (btrim(run_id) <> ''),
    CHECK (btrim(scenario_id) <> ''),
    CHECK (btrim(target_host) <> ''),
    CHECK (end_time IS NULL OR end_time >= start_time),
    CHECK (jsonb_typeof(metadata) = 'object'),
    CHECK (metadata ->> 'run_id' = run_id)
);

CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,
    host_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (btrim(event_id) <> ''),
    CHECK (btrim(host_id) <> ''),
    CHECK (btrim(event_type) <> ''),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'event_id' = event_id),
    CHECK (payload ->> 'run_id' = run_id)
);

CREATE TABLE fusion_results (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    fusion_status TEXT NOT NULL CHECK (fusion_status IN ('detected', 'miss', 'not_evaluated')),
    fusion_time TIMESTAMPTZ,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, entity_id),
    CHECK (btrim(entity_id) <> ''),
    CHECK (
        (fusion_status = 'detected' AND fusion_time IS NOT NULL)
        OR (fusion_status IN ('miss', 'not_evaluated') AND fusion_time IS NULL)
    ),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'run_id' = run_id),
    CHECK (payload ->> 'entity_id' = entity_id)
);

CREATE TABLE detection_results (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    detector_status TEXT NOT NULL CHECK (detector_status IN ('detected', 'miss', 'not_evaluated')),
    detector_time TIMESTAMPTZ,
    detector_id TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, entity_id),
    CHECK (btrim(entity_id) <> ''),
    CHECK (
        (detector_status = 'detected' AND detector_time IS NOT NULL AND detector_id IS NOT NULL)
        OR (detector_status IN ('miss', 'not_evaluated') AND detector_time IS NULL)
    ),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'run_id' = run_id),
    CHECK (payload ->> 'entity_id' = entity_id)
);

CREATE TABLE decisions (
    decision_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    fast_status TEXT NOT NULL CHECK (fast_status IN ('detected', 'miss', 'not_evaluated')),
    fusion_status TEXT NOT NULL CHECK (fusion_status IN ('detected', 'miss', 'not_evaluated')),
    detector_time TIMESTAMPTZ,
    fusion_time TIMESTAMPTZ,
    t_e TIMESTAMPTZ,
    decision_path TEXT,
    winning_path TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (btrim(decision_id) <> ''),
    CHECK (btrim(entity_id) <> ''),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ->> 'decision_id' = decision_id),
    CHECK (payload ->> 'run_id' = run_id),
    CHECK (payload ->> 'entity_id' = entity_id)
);

CREATE INDEX events_run_id_timestamp_idx ON events (run_id, timestamp);
CREATE INDEX fusion_results_run_id_idx ON fusion_results (run_id);
CREATE INDEX detection_results_run_id_idx ON detection_results (run_id);
CREATE INDEX decisions_run_id_entity_id_idx ON decisions (run_id, entity_id);

COMMIT;
