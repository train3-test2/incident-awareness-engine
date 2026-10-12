"""Static contract tests for the R1 incremental-stream delivery ledger."""

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "008_r1_stream_delivery_ledger.sql"
)


def test_r1_stream_delivery_migration_preserves_partitioned_idempotency_keys() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "CREATE TABLE r1_stream_chunks" in migration
    assert "PRIMARY KEY (run_id, host_id, source, source_channel, chunk_id)" in migration
    assert "UNIQUE (run_id, host_id, source, source_channel, chunk_sequence)" in migration
    assert "CREATE TABLE r1_stream_watermarks" in migration
    assert "PRIMARY KEY (run_id, host_id, source, source_channel, watermark_id)" in migration
    assert "UNIQUE (run_id, host_id, source, source_channel, watermark_sequence)" in migration


def test_r1_stream_delivery_migration_allows_only_one_close_per_run() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "CREATE TABLE r1_stream_run_closes" in migration
    assert "PRIMARY KEY (run_id, close_id)" in migration
    assert "UNIQUE (run_id)" in migration
    assert "BEGIN;" not in migration
    assert "COMMIT;" not in migration
