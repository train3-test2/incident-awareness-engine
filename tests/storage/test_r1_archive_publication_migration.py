"""Static contract tests for the durable R1 archive publication outbox."""

from pathlib import Path

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "infra"
    / "postgres"
    / "migrations"
    / "007_r1_archive_publications.sql"
)


def test_r1_archive_publication_migration_preserves_payload_and_run_identity() -> None:
    # Given
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    # When
    required_fragments = (
        "run_id TEXT PRIMARY KEY REFERENCES runs (run_id) ON DELETE CASCADE",
        "evidence_content BYTEA NOT NULL",
        "summary_content BYTEA NOT NULL",
        "evidence_sha256 TEXT NOT NULL",
        "summary_sha256 TEXT NOT NULL",
    )

    # Then
    assert all(fragment in migration for fragment in required_fragments)


def test_r1_archive_publication_migration_limits_durable_states() -> None:
    # Given
    migration = MIGRATION_PATH.read_text(encoding="utf-8")

    # When
    status_contract = "status IN ('pending', 'retryable', 'published', 'failed')"

    # Then
    assert status_contract in migration
    assert "attempt_count >= 0" in migration
    assert "BEGIN;" not in migration
    assert "COMMIT;" not in migration
