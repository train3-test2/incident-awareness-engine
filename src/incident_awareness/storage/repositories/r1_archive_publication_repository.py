"""Persist the durable outbox for generic R1 Evidence archive publication."""

from dataclasses import dataclass
from typing import Literal, Protocol, cast

type R1ArchivePublicationStatus = Literal["pending", "retryable", "published", "failed"]


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


@dataclass(frozen=True, slots=True)
class R1ArchivePublication:
    """Durable artifact bytes and publication state for one Run."""

    run_id: str
    bucket: str
    object_prefix: str
    evidence_content: bytes
    evidence_sha256: str
    summary_content: bytes
    summary_sha256: str
    status: R1ArchivePublicationStatus = "pending"
    attempt_count: int = 0
    last_error_type: str | None = None
    last_error_message: str | None = None


_SELECT = """
SELECT run_id, bucket, object_prefix,
       evidence_content, evidence_sha256,
       summary_content, summary_sha256,
       status, attempt_count, last_error_type, last_error_message
FROM r1_archive_publications
WHERE run_id = %s
"""

_INSERT = """
INSERT INTO r1_archive_publications (
    run_id, bucket, object_prefix,
    evidence_content, evidence_sha256,
    summary_content, summary_sha256,
    status
)
VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
ON CONFLICT (run_id) DO NOTHING
RETURNING run_id
"""

# Evidence consumers read payload bytes only for a published archive within the byte limits.
# Bucket, object prefix, attempts, and error text are never selected.
_SELECT_EVIDENCE_READ = """
SELECT
    runs.run_id,
    archive.status,
    archive.evidence_sha256,
    archive.summary_sha256,
    octet_length(archive.evidence_content),
    octet_length(archive.summary_content),
    CASE WHEN archive.status = 'published'
          AND octet_length(archive.evidence_content) <= %s
          AND octet_length(archive.summary_content) <= %s
         THEN archive.evidence_content END,
    CASE WHEN archive.status = 'published'
          AND octet_length(archive.evidence_content) <= %s
          AND octet_length(archive.summary_content) <= %s
         THEN archive.summary_content END
FROM runs
LEFT JOIN r1_archive_publications AS archive ON archive.run_id = runs.run_id
WHERE runs.run_id = %s
"""

_UPDATE_STATUS = """
UPDATE r1_archive_publications
SET status = %s,
    attempt_count = attempt_count + 1,
    last_error_type = %s,
    last_error_message = %s,
    updated_at = CURRENT_TIMESTAMP
WHERE run_id = %s
RETURNING run_id
"""


@dataclass(frozen=True, slots=True)
class R1ArchiveEvidenceRead:
    """Read-only Evidence view of one Run's archive; ``status`` is None without an archive."""

    run_id: str
    status: R1ArchivePublicationStatus | None
    evidence_sha256: str | None
    summary_sha256: str | None
    evidence_size: int | None
    summary_size: int | None
    # Present only for a published archive within the requested byte limits.
    evidence_content: bytes | None
    summary_content: bytes | None


class R1ArchivePublicationRepository:
    """Store and recover immutable R1 archive publication payloads."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def get(self, run_id: str) -> R1ArchivePublication | None:
        row = self._connection.execute(_SELECT, (run_id,)).fetchone()
        return None if row is None else _publication_from_row(row)

    def read_evidence_archive(
        self,
        run_id: str,
        *,
        max_evidence_bytes: int,
        max_summary_bytes: int,
    ) -> R1ArchiveEvidenceRead | None:
        """Return None when the Run does not exist."""
        row = self._connection.execute(
            _SELECT_EVIDENCE_READ,
            (
                max_evidence_bytes,
                max_summary_bytes,
                max_evidence_bytes,
                max_summary_bytes,
                run_id,
            ),
        ).fetchone()
        return None if row is None else _evidence_read_from_row(row)

    def save_pending(self, publication: R1ArchivePublication) -> R1ArchivePublication:
        inserted = self._connection.execute(
            _INSERT,
            (
                publication.run_id,
                publication.bucket,
                publication.object_prefix,
                publication.evidence_content,
                publication.evidence_sha256,
                publication.summary_content,
                publication.summary_sha256,
            ),
        ).fetchone()
        if inserted is not None:
            return publication

        existing = self.get(publication.run_id)
        if existing is None:
            raise RuntimeError("R1 archive publication conflict lookup returned no row")
        if _publication_identity(existing) != _publication_identity(publication):
            raise ValueError("R1 archive publication conflicts with the existing run_id payload")
        return existing

    def update_status(
        self,
        run_id: str,
        *,
        status: R1ArchivePublicationStatus,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> None:
        updated = self._connection.execute(
            _UPDATE_STATUS,
            (status, error_type, error_message, run_id),
        ).fetchone()
        if updated is None:
            raise RuntimeError("R1 archive publication status update found no row")


def _publication_from_row(row: tuple[object, ...]) -> R1ArchivePublication:
    if len(row) != 11:
        raise TypeError("R1 archive publication row must contain 11 columns")
    evidence_content = bytes(row[3]) if isinstance(row[3], (bytes, bytearray, memoryview)) else None
    summary_content = bytes(row[5]) if isinstance(row[5], (bytes, bytearray, memoryview)) else None
    if evidence_content is None or summary_content is None:
        raise TypeError("R1 archive publication payloads must be bytes")
    return R1ArchivePublication(
        run_id=_required_string(row[0], "run_id"),
        bucket=_required_string(row[1], "bucket"),
        object_prefix=_required_string(row[2], "object_prefix"),
        evidence_content=evidence_content,
        evidence_sha256=_required_string(row[4], "evidence_sha256"),
        summary_content=summary_content,
        summary_sha256=_required_string(row[6], "summary_sha256"),
        status=_publication_status(row[7]),
        attempt_count=_required_int(row[8], "attempt_count"),
        last_error_type=_optional_string(row[9], "last_error_type"),
        last_error_message=_optional_string(row[10], "last_error_message"),
    )


def _evidence_read_from_row(row: tuple[object, ...]) -> R1ArchiveEvidenceRead:
    if len(row) != 8:
        raise TypeError("R1 archive Evidence read row must contain 8 columns")
    run_id = _required_string(row[0], "run_id")
    if row[1] is None:
        if any(value is not None for value in row[2:]):
            raise TypeError("R1 archive Evidence read without an archive must have no payload")
        return R1ArchiveEvidenceRead(run_id, None, None, None, None, None, None, None)
    status = _publication_status(row[1])
    evidence_content = _optional_bytes(row[6], "evidence_content")
    summary_content = _optional_bytes(row[7], "summary_content")
    if (evidence_content is None) != (summary_content is None):
        raise TypeError("R1 archive Evidence read must return both payloads or neither")
    if evidence_content is not None and status != "published":
        raise TypeError("R1 archive Evidence read returned an unpublished payload")
    return R1ArchiveEvidenceRead(
        run_id=run_id,
        status=status,
        evidence_sha256=_required_string(row[2], "evidence_sha256"),
        summary_sha256=_required_string(row[3], "summary_sha256"),
        evidence_size=_required_int(row[4], "evidence_size"),
        summary_size=_required_int(row[5], "summary_size"),
        evidence_content=evidence_content,
        summary_content=summary_content,
    )


def _optional_bytes(value: object, field_name: str) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"R1 archive Evidence read {field_name} must be bytes")
    return bytes(value)


def _publication_identity(publication: R1ArchivePublication) -> tuple[object, ...]:
    return (
        publication.run_id,
        publication.bucket,
        publication.object_prefix,
        publication.evidence_content,
        publication.evidence_sha256,
        publication.summary_content,
        publication.summary_sha256,
    )


def _required_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"R1 archive publication {field_name} must be a non-blank string")
    return value


def _optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, field_name)


def _required_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"R1 archive publication {field_name} must be a non-negative integer")
    return value


def _publication_status(value: object) -> R1ArchivePublicationStatus:
    if value not in {"pending", "retryable", "published", "failed"}:
        raise TypeError("R1 archive publication status is invalid")
    return cast("R1ArchivePublicationStatus", value)


__all__ = [
    "R1ArchiveEvidenceRead",
    "R1ArchivePublication",
    "R1ArchivePublicationRepository",
    "R1ArchivePublicationStatus",
]
