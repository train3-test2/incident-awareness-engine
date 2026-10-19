-- Append-only Role3 ledger for R1 Sysmon RecordId position closes.
-- A position close is a separate finality kind. It never writes r1_stream_watermarks or
-- r1_stream_run_closes, and it is not an event-time watermark or run_closed.

CREATE TABLE r1_stream_position_closes (
    ledger_entry_id BIGINT GENERATED ALWAYS AS IDENTITY,
    run_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_channel TEXT NOT NULL,
    close_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    lower_record_id BIGINT NOT NULL,
    upper_record_id BIGINT NOT NULL,
    covered_through_chunk_sequence INTEGER NOT NULL,
    covered_chunks_sha256 TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT r1_stream_position_closes_pkey PRIMARY KEY (ledger_entry_id),
    CONSTRAINT r1_stream_position_closes_run_close_unique UNIQUE (run_id, close_id),
    CONSTRAINT r1_stream_position_closes_run_unique UNIQUE (run_id),
    CONSTRAINT r1_stream_position_closes_run_id_nonblank CHECK (btrim(run_id) <> ''),
    CONSTRAINT r1_stream_position_closes_host_id_nonblank CHECK (btrim(host_id) <> ''),
    CONSTRAINT r1_stream_position_closes_source_nonblank CHECK (btrim(source) <> ''),
    CONSTRAINT r1_stream_position_closes_source_channel_nonblank
        CHECK (btrim(source_channel) <> ''),
    CONSTRAINT r1_stream_position_closes_close_id_nonblank CHECK (btrim(close_id) <> ''),
    CONSTRAINT r1_stream_position_closes_content_sha256_format
        CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT r1_stream_position_closes_record_id_bounds
        CHECK (lower_record_id >= 1 AND upper_record_id >= lower_record_id),
    CONSTRAINT r1_stream_position_closes_covered_sequence_positive
        CHECK (covered_through_chunk_sequence >= 1),
    CONSTRAINT r1_stream_position_closes_covered_chunks_sha256_format
        CHECK (covered_chunks_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE FUNCTION reject_r1_stream_position_close_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'r1_stream_position_closes is append-only'
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER r1_stream_position_closes_append_only
BEFORE UPDATE OR DELETE ON r1_stream_position_closes
FOR EACH ROW EXECUTE FUNCTION reject_r1_stream_position_close_change();
