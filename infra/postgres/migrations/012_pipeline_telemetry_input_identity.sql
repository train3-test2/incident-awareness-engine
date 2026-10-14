-- Add identity without rewriting legacy payloads, counters or snapshot revisions.
ALTER TABLE pipeline_telemetry_executions
    ADD COLUMN input_identity_kind TEXT,
    ADD COLUMN input_identity_sha256 TEXT,
    ADD CONSTRAINT pipeline_telemetry_input_identity_pair CHECK (
        (input_identity_kind IS NULL AND input_identity_sha256 IS NULL)
        OR (input_identity_kind IS NOT NULL AND input_identity_sha256 IS NOT NULL
            AND input_identity_kind IN ('file_content_sha256_v1', 's3_object_sha256_v1')
            AND length(input_identity_sha256) = 64
            AND input_identity_sha256 ~ '^[0-9a-f]{64}$')
    ),
    ADD CONSTRAINT pipeline_telemetry_input_identity_payload CHECK (
        (input_identity_kind IS NULL AND (
            NOT (payload ? 'input_identity') OR payload -> 'input_identity' = 'null'::jsonb
        )) OR (
            input_identity_kind IS NOT NULL
            AND jsonb_typeof(payload -> 'input_identity') IS NOT DISTINCT FROM 'object'
            AND payload -> 'input_identity' ->> 'kind' IS NOT DISTINCT FROM input_identity_kind
            AND payload -> 'input_identity' ->> 'sha256' IS NOT DISTINCT FROM input_identity_sha256
        )
    );

CREATE FUNCTION guard_pipeline_telemetry_input_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.input_identity_kind IS DISTINCT FROM NEW.input_identity_kind
       OR OLD.input_identity_sha256 IS DISTINCT FROM NEW.input_identity_sha256 THEN
        RAISE EXCEPTION 'execution input identity is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER pipeline_telemetry_input_identity_immutable
BEFORE UPDATE OF input_identity_kind, input_identity_sha256
ON pipeline_telemetry_executions
FOR EACH ROW EXECUTE FUNCTION guard_pipeline_telemetry_input_identity();
