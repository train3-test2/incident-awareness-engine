-- Execution-attempt observations. No FK to business runs or mutable Runtime status.
-- Quality belongs to the execution snapshot; sparse buckets do not imply coverage.

CREATE TABLE pipeline_telemetry_executions (
    execution_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    aggregation_basis TEXT NOT NULL CHECK (aggregation_basis = 'execution_attempt'),
    latency_scope TEXT NOT NULL CHECK (latency_scope = 'normalization_and_evidence'),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    input_total BIGINT CHECK (input_total >= 1),
    input_accepted_at TIMESTAMPTZ,
    last_observed_at TIMESTAMPTZ,
    observation_status TEXT NOT NULL CHECK (
        observation_status IN ('unavailable', 'partial', 'observed')
    ),
    collection_disabled BOOLEAN NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    CHECK (btrim(execution_id) <> '' AND btrim(execution_id) = execution_id),
    CHECK (btrim(run_id) <> '' AND btrim(run_id) = run_id),
    CHECK (btrim(entity_id) <> '' AND btrim(entity_id) = entity_id),
    CHECK (snapshot_id = 'pipeline-telemetry:' || execution_id),
    CHECK ((input_total IS NULL) = (input_accepted_at IS NULL)),
    CHECK ((input_accepted_at IS NULL) = (last_observed_at IS NULL)),
    CHECK (last_observed_at >= input_accepted_at),
    CHECK (input_accepted_at IS NULL OR (
        isfinite(input_accepted_at)
        AND input_accepted_at = date_trunc('milliseconds', input_accepted_at, 'UTC')
    )),
    CHECK (last_observed_at IS NULL OR (
        isfinite(last_observed_at)
        AND last_observed_at = date_trunc('milliseconds', last_observed_at, 'UTC')
    )),
    CHECK ((observation_status = 'unavailable') = (input_total IS NULL)),
    CHECK (jsonb_typeof(payload) = 'object' AND NOT (payload ? 'buckets')),
    CHECK (payload ->> 'execution_id' IS NOT DISTINCT FROM execution_id),
    CHECK (payload ->> 'snapshot_id' IS NOT DISTINCT FROM snapshot_id),
    CHECK (payload ->> 'run_id' IS NOT DISTINCT FROM run_id),
    CHECK (payload ->> 'entity_id' IS NOT DISTINCT FROM entity_id),
    CHECK (payload ->> 'aggregation_basis' IS NOT DISTINCT FROM aggregation_basis),
    CHECK (payload ->> 'latency_scope' IS NOT DISTINCT FROM latency_scope),
    CHECK (payload -> 'revision' IS NOT DISTINCT FROM to_jsonb(revision)),
    CHECK (payload -> 'input_total' IS NOT DISTINCT FROM COALESCE(to_jsonb(input_total), 'null'::jsonb)),
    CHECK (payload -> 'collection_disabled' IS NOT DISTINCT FROM to_jsonb(collection_disabled)),
    CHECK (payload ->> 'observation_status' IS NOT DISTINCT FROM observation_status),
    CHECK ((payload ->> 'input_accepted_at')::timestamptz IS NOT DISTINCT FROM input_accepted_at),
    CHECK ((payload ->> 'last_observed_at')::timestamptz IS NOT DISTINCT FROM last_observed_at),
    CHECK (jsonb_typeof(payload -> 'observation_issues') IS NOT DISTINCT FROM 'array'),
    CHECK (NOT collection_disabled OR jsonb_array_length(payload -> 'observation_issues') > 0),
    CHECK (observation_status <> 'observed' OR jsonb_array_length(payload -> 'observation_issues') = 0),
    CHECK (observation_status <> 'partial' OR jsonb_array_length(payload -> 'observation_issues') > 0)
);

CREATE TABLE pipeline_telemetry_buckets (
    execution_id TEXT NOT NULL REFERENCES pipeline_telemetry_executions (execution_id),
    bucket_start TIMESTAMPTZ NOT NULL,
    bucket_end TIMESTAMPTZ NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    input_accepted_count BIGINT NOT NULL CHECK (input_accepted_count >= 0),
    processing_completed_count BIGINT NOT NULL CHECK (processing_completed_count >= 0),
    processing_failed_count BIGINT NOT NULL CHECK (processing_failed_count >= 0),
    latency_sample_count BIGINT NOT NULL CHECK (latency_sample_count >= 0),
    latency_sum_ns BIGINT NOT NULL CHECK (latency_sum_ns >= 0),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (execution_id, bucket_start),
    CHECK (isfinite(bucket_start) AND bucket_start = date_trunc('second', bucket_start, 'UTC')),
    CHECK (bucket_end = bucket_start + INTERVAL '1 second'),
    CHECK (isfinite(first_observed_at) AND isfinite(last_observed_at)),
    CHECK (first_observed_at = date_trunc('milliseconds', first_observed_at, 'UTC')),
    CHECK (last_observed_at = date_trunc('milliseconds', last_observed_at, 'UTC')),
    CHECK (bucket_start <= first_observed_at AND first_observed_at <= last_observed_at),
    CHECK (last_observed_at < bucket_end),
    CHECK (latency_sample_count <= processing_completed_count),
    CHECK (latency_sample_count <> 0 OR latency_sum_ns = 0),
    CHECK (input_accepted_count > 0 OR processing_completed_count > 0 OR processing_failed_count > 0),
    CHECK (jsonb_typeof(payload) = 'object'),
    CHECK (payload -> 'revision' IS NOT DISTINCT FROM to_jsonb(revision)),
    CHECK (payload -> 'input_accepted_count' IS NOT DISTINCT FROM to_jsonb(input_accepted_count)),
    CHECK (payload -> 'processing_completed_count' IS NOT DISTINCT FROM to_jsonb(processing_completed_count)),
    CHECK (payload -> 'processing_failed_count' IS NOT DISTINCT FROM to_jsonb(processing_failed_count)),
    CHECK (payload -> 'latency_sample_count' IS NOT DISTINCT FROM to_jsonb(latency_sample_count)),
    CHECK (payload -> 'latency_sum_ns' IS NOT DISTINCT FROM to_jsonb(latency_sum_ns)),
    CHECK ((payload ->> 'bucket_start')::timestamptz IS NOT DISTINCT FROM bucket_start),
    CHECK ((payload ->> 'bucket_end')::timestamptz IS NOT DISTINCT FROM bucket_end),
    CHECK ((payload ->> 'first_observed_at')::timestamptz IS NOT DISTINCT FROM first_observed_at),
    CHECK ((payload ->> 'last_observed_at')::timestamptz IS NOT DISTINCT FROM last_observed_at)
);

CREATE INDEX pipeline_telemetry_executions_scope_idx
    ON pipeline_telemetry_executions (run_id, entity_id, last_observed_at DESC NULLS LAST, execution_id);
CREATE INDEX pipeline_telemetry_executions_observed_idx
    ON pipeline_telemetry_executions (last_observed_at);
CREATE INDEX pipeline_telemetry_buckets_time_idx
    ON pipeline_telemetry_buckets (bucket_start, execution_id);
