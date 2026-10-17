-- Independent, immutable ended operations; no FK to mutable Runtime or Business runs.
CREATE TABLE pipeline_stage_timing_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (btrim(attempt_id) <> '' AND btrim(attempt_id) = attempt_id),
    execution_id TEXT UNIQUE,
    run_id TEXT,
    entity_id TEXT,
    revision NUMERIC NOT NULL CHECK (revision >= 0 AND scale(revision) = 0),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    CHECK ((run_id IS NULL) = (entity_id IS NULL)),
    CHECK (execution_id IS NULL OR run_id IS NOT NULL),
    CHECK (execution_id IS NULL OR (btrim(execution_id) <> '' AND btrim(execution_id) = execution_id)),
    CHECK (run_id IS NULL OR (btrim(run_id) <> '' AND btrim(run_id) = run_id)),
    CHECK (entity_id IS NULL OR (btrim(entity_id) <> '' AND btrim(entity_id) = entity_id)),
    CHECK (jsonb_typeof(payload) = 'object' AND NOT (payload ? 'records')),
    CHECK (payload ?& ARRAY['schema_version', 'attempt_id', 'execution_id', 'run_id', 'entity_id',
                           'revision', 'active_stage', 'active_invocation_index', 'issues', 'quality_status']),
    CHECK (payload ->> 'schema_version' = 'pipeline_stage_timing_v1'),
    CHECK (payload ->> 'attempt_id' IS NOT DISTINCT FROM attempt_id),
    CHECK (payload -> 'execution_id' IS NOT DISTINCT FROM COALESCE(to_jsonb(execution_id), 'null'::jsonb)),
    CHECK (payload -> 'run_id' IS NOT DISTINCT FROM COALESCE(to_jsonb(run_id), 'null'::jsonb)),
    CHECK (payload -> 'entity_id' IS NOT DISTINCT FROM COALESCE(to_jsonb(entity_id), 'null'::jsonb)),
    CHECK (payload -> 'revision' IS NOT DISTINCT FROM to_jsonb(revision)),
    CHECK (jsonb_typeof(payload -> 'issues') = 'array'),
    CHECK (payload ->> 'quality_status' IN ('unavailable', 'partial', 'observed')),
    CHECK ((payload -> 'active_stage' = 'null'::jsonb) = (payload -> 'active_invocation_index' = 'null'::jsonb)),
    CHECK (payload ->> 'active_stage' IS NULL OR payload ->> 'active_stage' IN
           ('artifact_validation', 'normalization', 'fusion', 'fast_handoff', 'hybrid', 'persistence')),
    CHECK (payload ->> 'active_invocation_index' IS NULL OR
           (jsonb_typeof(payload -> 'active_invocation_index') = 'number'
            AND (payload ->> 'active_invocation_index')::NUMERIC >= 1
            AND scale((payload ->> 'active_invocation_index')::NUMERIC) = 0))
);

CREATE TABLE pipeline_stage_timing_records (
    attempt_id TEXT NOT NULL REFERENCES pipeline_stage_timing_attempts (attempt_id),
    invocation_index NUMERIC NOT NULL CHECK (invocation_index >= 1 AND scale(invocation_index) = 0),
    stage TEXT NOT NULL CHECK (stage IN
        ('artifact_validation', 'normalization', 'fusion', 'fast_handoff', 'hybrid', 'persistence')),
    outcome TEXT NOT NULL CHECK (outcome IN ('completed', 'failed')),
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    duration_ns NUMERIC CHECK (duration_ns >= 0 AND scale(duration_ns) = 0),
    payload JSONB NOT NULL,
    persisted_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    PRIMARY KEY (attempt_id, invocation_index),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload ?& ARRAY['stage', 'invocation_index', 'outcome', 'started_at', 'ended_at', 'duration_ns', 'issues']),
    CHECK (payload -> 'invocation_index' IS NOT DISTINCT FROM to_jsonb(invocation_index)),
    CHECK (payload ->> 'stage' IS NOT DISTINCT FROM stage),
    CHECK (payload ->> 'outcome' IS NOT DISTINCT FROM outcome),
    CHECK (payload -> 'duration_ns' IS NOT DISTINCT FROM COALESCE(to_jsonb(duration_ns), 'null'::jsonb)),
    CHECK (jsonb_typeof(payload -> 'issues') = 'array'),
    CHECK (started_at IS NULL OR (isfinite(started_at) AND started_at = date_trunc('milliseconds', started_at))),
    CHECK (ended_at IS NULL OR (isfinite(ended_at) AND ended_at = date_trunc('milliseconds', ended_at))),
    CHECK ((started_at IS NULL) = (payload -> 'started_at' = 'null'::jsonb)),
    CHECK ((ended_at IS NULL) = (payload -> 'ended_at' = 'null'::jsonb)),
    CHECK (started_at IS NULL OR (payload ->> 'started_at')::TIMESTAMPTZ = started_at),
    CHECK (ended_at IS NULL OR (payload ->> 'ended_at')::TIMESTAMPTZ = ended_at),
    CHECK ((started_at IS NOT NULL AND ended_at IS NOT NULL) OR payload -> 'issues' ? 'utc_clock_error'),
    CHECK (duration_ns IS NOT NULL OR payload -> 'issues' ?|
           ARRAY['monotonic_clock_error', 'invalid_duration', 'internal_error']),
    CHECK (ended_at >= started_at OR ended_at IS NULL OR started_at IS NULL
           OR payload -> 'issues' ? 'wall_clock_regression')
);

CREATE INDEX pipeline_stage_timing_scope_idx ON pipeline_stage_timing_attempts (run_id, entity_id, updated_at DESC);

CREATE FUNCTION guard_pipeline_stage_timing_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'ended stage timing records are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER pipeline_stage_timing_record_immutable BEFORE UPDATE OR DELETE ON pipeline_stage_timing_records
FOR EACH ROW EXECUTE FUNCTION guard_pipeline_stage_timing_record();

CREATE FUNCTION guard_pipeline_stage_timing_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'stage timing deletion requires a separate retention policy';
    END IF;
    IF NEW.attempt_id <> OLD.attempt_id OR NEW.revision <= OLD.revision
       OR (OLD.run_id IS NOT NULL AND (NEW.execution_id IS DISTINCT FROM OLD.execution_id
           OR NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.entity_id IS DISTINCT FROM OLD.entity_id)) THEN
        RAISE EXCEPTION 'stage timing identity or revision is conflicting';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER pipeline_stage_timing_attempt_guard BEFORE UPDATE OR DELETE ON pipeline_stage_timing_attempts
FOR EACH ROW EXECUTE FUNCTION guard_pipeline_stage_timing_attempt();

-- One SQL statement is atomic even when a record insert fails after parent creation.
CREATE FUNCTION save_pipeline_stage_timing(incoming JSONB) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    previous pipeline_stage_timing_attempts%ROWTYPE;
    inserted BOOLEAN;
    record JSONB;
    existing JSONB;
    metadata JSONB := incoming - 'records';
    items JSONB := incoming -> 'records';
    next_revision NUMERIC := (incoming ->> 'revision')::NUMERIC;
    identity TEXT := incoming ->> 'attempt_id';
    expected_quality TEXT;
BEGIN
    IF jsonb_typeof(items) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'stage timing records must be an array';
    END IF;
    IF EXISTS (SELECT 1 FROM (
        SELECT (value ->> 'invocation_index')::NUMERIC AS current_index,
            lag((value ->> 'invocation_index')::NUMERIC) OVER (ORDER BY ordinality) AS previous_index
        FROM jsonb_array_elements(items) WITH ORDINALITY
    ) ordered WHERE current_index <= previous_index) THEN
        RAISE EXCEPTION 'stage timing invocations must be ordered and unique';
    END IF;
    IF (incoming ->> 'active_invocation_index')::NUMERIC <=
       (SELECT max((value ->> 'invocation_index')::NUMERIC) FROM jsonb_array_elements(items)) THEN
        RAISE EXCEPTION 'active stage timing invocation must follow ended records';
    END IF;
    -- Serialize before INSERT: ON CONFLICT(attempt_id) alone can still race on
    -- the separate execution_id unique index during speculative insertion.
    PERFORM pg_advisory_xact_lock(hashtextextended('pipeline_stage_timing:' || identity, 0));
    INSERT INTO pipeline_stage_timing_attempts (attempt_id, execution_id, run_id, entity_id, revision, payload)
    VALUES (identity, incoming ->> 'execution_id', incoming ->> 'run_id', incoming ->> 'entity_id', next_revision, metadata)
    ON CONFLICT (attempt_id) DO NOTHING RETURNING TRUE INTO inserted;
    SELECT * INTO STRICT previous FROM pipeline_stage_timing_attempts WHERE attempt_id = identity FOR UPDATE;

    -- Reject an altered ended operation at every revision, including stale delivery.
    FOR record IN SELECT value FROM jsonb_array_elements(items) LOOP
        SELECT payload INTO existing FROM pipeline_stage_timing_records
        WHERE attempt_id = identity AND invocation_index = (record ->> 'invocation_index')::NUMERIC;
        IF FOUND AND existing IS DISTINCT FROM record THEN
            RAISE EXCEPTION 'stage timing invocation payload is conflicting';
        END IF;
    END LOOP;
    IF NOT COALESCE(inserted, FALSE) THEN
        IF next_revision < previous.revision THEN
            IF incoming ->> 'run_id' IS NOT NULL AND (incoming ->> 'run_id' IS DISTINCT FROM previous.run_id
                OR incoming ->> 'entity_id' IS DISTINCT FROM previous.entity_id
                OR incoming ->> 'execution_id' IS DISTINCT FROM previous.execution_id) THEN
                RAISE EXCEPTION 'stale stage timing identity is conflicting';
            END IF;
            RETURN FALSE;
        END IF;
        SELECT COALESCE(jsonb_agg(payload ORDER BY invocation_index), '[]'::JSONB) INTO existing
        FROM pipeline_stage_timing_records WHERE attempt_id = identity;
        IF next_revision = previous.revision THEN
            IF previous.payload IS DISTINCT FROM metadata OR existing IS DISTINCT FROM items THEN
                RAISE EXCEPTION 'same stage timing revision has different payload';
            END IF;
            RETURN FALSE;
        END IF;
        IF EXISTS (SELECT 1 FROM pipeline_stage_timing_records old WHERE old.attempt_id = identity
                   AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(items) item WHERE item = old.payload)) THEN
            RAISE EXCEPTION 'stage timing update cannot remove ended operations';
        END IF;
        UPDATE pipeline_stage_timing_attempts SET execution_id = incoming ->> 'execution_id',
            run_id = incoming ->> 'run_id', entity_id = incoming ->> 'entity_id', revision = next_revision,
            payload = metadata, updated_at = date_trunc('milliseconds', clock_timestamp())
        WHERE attempt_id = identity;
    END IF;

    FOR record IN SELECT value FROM jsonb_array_elements(items) LOOP
        INSERT INTO pipeline_stage_timing_records
            (attempt_id, invocation_index, stage, outcome, started_at, ended_at, duration_ns, payload)
        VALUES (identity, (record ->> 'invocation_index')::NUMERIC, record ->> 'stage', record ->> 'outcome',
                (record ->> 'started_at')::TIMESTAMPTZ, (record ->> 'ended_at')::TIMESTAMPTZ,
                (record ->> 'duration_ns')::NUMERIC, record)
        ON CONFLICT (attempt_id, invocation_index) DO NOTHING;
    END LOOP;
    IF (SELECT count(*) FROM pipeline_stage_timing_records WHERE attempt_id = identity) <> jsonb_array_length(items) THEN
        RAISE EXCEPTION 'stage timing invocation keys must be unique';
    END IF;
    expected_quality := CASE WHEN jsonb_array_length(items) = 0 THEN 'unavailable'
        WHEN jsonb_array_length(incoming -> 'issues') > 0 OR EXISTS
             (SELECT 1 FROM jsonb_array_elements(items) item WHERE jsonb_array_length(item -> 'issues') > 0)
        THEN 'partial' ELSE 'observed' END;
    IF incoming ->> 'quality_status' IS DISTINCT FROM expected_quality THEN
        RAISE EXCEPTION 'stage timing quality is inconsistent';
    END IF;
    RETURN TRUE;
END;
$$;
