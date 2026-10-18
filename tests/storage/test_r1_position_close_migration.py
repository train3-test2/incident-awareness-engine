"""Static contract tests for the R1 position-close ledger migration."""

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "013_r1_stream_position_close_ledger.sql"
)


def test_position_close_ledger_is_a_separate_append_only_table() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "CREATE TABLE r1_stream_position_closes" in migration
    assert "ledger_entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY" in migration
    assert "UNIQUE (run_id, close_id)" in migration
    assert "UNIQUE (run_id)" in migration
    assert "accepted_at TIMESTAMPTZ NOT NULL" in migration
    assert "BEFORE UPDATE OR DELETE ON r1_stream_position_closes" in migration
    assert "BEGIN;" not in migration
    assert "COMMIT;" not in migration


def test_position_close_ledger_does_not_touch_event_time_tables() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")
    statements = "\n".join(
        line for line in migration.splitlines() if not line.lstrip().startswith("--")
    )

    for table in ("r1_stream_watermarks", "r1_stream_run_closes", "r1_stream_chunks"):
        assert table not in statements
    assert "watermark_at" not in statements
