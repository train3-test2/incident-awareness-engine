from collections.abc import Iterable

import pytest

from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublication,
    R1ArchivePublicationRepository,
)


class _Cursor:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _Connection:
    def __init__(self, rows: Iterable[tuple[object, ...] | None]) -> None:
        self.rows = list(rows)
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.queries.append((query, params))
        return _Cursor(self.rows.pop(0))


def _publication(*, summary_content: bytes = b"summary\n") -> R1ArchivePublication:
    return R1ArchivePublication(
        run_id="RUN-20261010-001",
        bucket="archive-bucket",
        object_prefix="archive/first-cycle/r1/RUN-20261010-001",
        evidence_content=b"evidence\n",
        evidence_sha256="a" * 64,
        summary_content=summary_content,
        summary_sha256="b" * 64,
    )


def _row(publication: R1ArchivePublication) -> tuple[object, ...]:
    return (
        publication.run_id,
        publication.bucket,
        publication.object_prefix,
        publication.evidence_content,
        publication.evidence_sha256,
        publication.summary_content,
        publication.summary_sha256,
        publication.status,
        publication.attempt_count,
        publication.last_error_type,
        publication.last_error_message,
    )


def test_inserts_pending_publication_without_committing() -> None:
    # Given
    connection = _Connection([("RUN-20261010-001",)])
    repository = R1ArchivePublicationRepository(connection)
    publication = _publication()

    # When
    result = repository.save_pending(publication)

    # Then
    assert result == publication
    assert "INSERT INTO r1_archive_publications" in connection.queries[0][0]


def test_accepts_an_identical_existing_run_publication() -> None:
    # Given
    publication = _publication()
    connection = _Connection([None, _row(publication)])
    repository = R1ArchivePublicationRepository(connection)

    # When
    result = repository.save_pending(publication)

    # Then
    assert result == publication


def test_rejects_a_different_payload_for_the_same_run_id() -> None:
    # Given
    publication = _publication()
    existing = _publication(summary_content=b"different\n")
    connection = _Connection([None, _row(existing)])
    repository = R1ArchivePublicationRepository(connection)

    # When
    with pytest.raises(ValueError, match="conflicts"):
        repository.save_pending(publication)

    # Then
    assert len(connection.queries) == 2


def test_updates_retryable_state_with_failure_details() -> None:
    # Given
    connection = _Connection([("RUN-20261010-001",)])
    repository = R1ArchivePublicationRepository(connection)

    # When
    repository.update_status(
        "RUN-20261010-001",
        status="retryable",
        error_type="OSError",
        error_message="temporary",
    )

    # Then
    query, params = connection.queries[0]
    assert "attempt_count = attempt_count + 1" in query
    assert params == ("retryable", "OSError", "temporary", "RUN-20261010-001")
