from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "001_first_cycle.sql"
)


def test_first_cycle_migration_defines_only_the_documented_minimum_tables() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    for table_name in (
        "runs",
        "events",
        "fusion_results",
        "detection_results",
        "decisions",
    ):
        assert f"CREATE TABLE {table_name}" in migration

    assert "CREATE TABLE raw_logs" not in migration
    assert "CREATE TABLE evidences" not in migration


def test_first_cycle_migration_preserves_contract_payloads_and_run_relations() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    assert migration.count("payload JSONB NOT NULL") == 4
    assert "metadata JSONB NOT NULL" in migration
    assert migration.count("REFERENCES runs (run_id)") == 4
    assert "ON DELETE CASCADE" in migration


def test_first_cycle_migration_keeps_status_time_constraints() -> None:
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    assert "fusion_status IN ('detected', 'miss', 'not_evaluated')" in migration
    assert "detector_status IN ('detected', 'miss', 'not_evaluated')" in migration
    assert (
        "detector_status = 'detected' AND detector_time IS NOT NULL AND detector_id IS NOT NULL"
        in migration
    )
    assert "end_time IS NULL OR end_time >= start_time" in migration
