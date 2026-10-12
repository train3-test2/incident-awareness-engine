-- Preserve the source-watermark values needed to validate a run_closed binding.

ALTER TABLE r1_stream_watermarks
    ADD COLUMN watermark_at TIMESTAMPTZ,
    ADD COLUMN allowed_lateness_ms INTEGER,
    ADD COLUMN covered_through_chunk_sequence INTEGER,
    ADD CONSTRAINT r1_stream_watermarks_binding_values_complete CHECK (
        (watermark_at IS NULL
         AND allowed_lateness_ms IS NULL
         AND covered_through_chunk_sequence IS NULL)
        OR
        (watermark_at IS NOT NULL
         AND allowed_lateness_ms IS NOT NULL
         AND covered_through_chunk_sequence IS NOT NULL
         AND allowed_lateness_ms >= 0
         AND covered_through_chunk_sequence >= 1)
    );
