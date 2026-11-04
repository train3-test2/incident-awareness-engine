"""Immutable Raw contracts, bounded content addressing, and atomic no-replace mirrors."""

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from incident_awareness.common.models.evidence import Evidence

MAX_RAW_BYTES = 64 * 1024 * 1024
RAW_RETENTION_ENV = "IAE_RAW_RETENTION_ENABLED"
RAW_MIRROR_ENV = "IAE_RAW_ARCHIVE_MIRROR_ROOT"


class RawArchiveError(ValueError):
    """A code-owned error, safe to log without raw content or sensitive paths."""


# The same identity names different bytes; a later delivery cannot change the outcome.
CONTENT_CONFLICT_CODES = frozenset(
    {
        "archive_mirror_content_conflict",
        "raw_content_hash_collision",
        "receipt_raw_identity_mismatch",
        "run_archive_content_conflict",
        "stored_archive_identity_mismatch",
        "stored_archive_sha256_mismatch",
        "upload_content_sha256_mismatch",
        "upload_identity_content_conflict",
    }
)


def is_content_conflict(error):
    return isinstance(error, RawArchiveError) and str(error) in CONTENT_CONFLICT_CODES


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def retention_enabled():
    return os.environ.get(RAW_RETENTION_ENV) == "1"


def mirror_root():
    value = os.environ.get(RAW_MIRROR_ENV)
    return Path(value).resolve() if value else None


@dataclass(frozen=True)
class RawCollectionIdentity:
    ingest_id: str
    bucket: str
    object_key: str
    e_tag: str


_COLLECTION: ContextVar[RawCollectionIdentity | None] = ContextVar("raw_collection", default=None)


@contextmanager
def raw_collection_context(identity):
    token = _COLLECTION.set(identity)
    try:
        yield
    finally:
        _COLLECTION.reset(token)


def collection_identity():
    return _COLLECTION.get()


@dataclass(frozen=True)
class RawRunArchive:
    run_id: str
    raw_log_id: str
    content: bytes
    manifest_content: bytes
    evidence_content: bytes
    extractor_version: str
    extractor_code_sha256: str
    source_metadata: dict
    collection: RawCollectionIdentity | None = None
    mirror_required: bool = False
    archive_created_at: str | None = None

    @property
    def content_sha256(self):
        return sha256(self.content)

    @property
    def manifest_sha256(self):
        return sha256(self.manifest_content)

    @property
    def evidence_sha256(self):
        return sha256(self.evidence_content)

    @property
    def artifact_uri(self):
        return "raw-db:sha256:" + self.content_sha256

    @property
    def manifest_identity(self):
        return f"raw-manifest:{self.run_id}:sha256:{self.manifest_sha256}"

    def evidences(self):
        values = json.loads(self.evidence_content)
        if not isinstance(values, list):
            raise RawArchiveError("evidence_archive_invalid")
        try:
            items = tuple(Evidence.model_validate(value) for value in values)
        except (ValueError, TypeError) as error:
            raise RawArchiveError("evidence_archive_invalid") from error
        if len({e.evidence_id for e in items}) != len(items) or any(
            e.run_id != self.run_id or e.extractor_version != self.extractor_version for e in items
        ):
            raise RawArchiveError("evidence_archive_scope_mismatch")
        return items

    def validate(self):
        if not 0 < len(self.content) <= MAX_RAW_BYTES:
            raise RawArchiveError("raw_archive_size_limit")
        if len(self.manifest_content) > 1024 * 1024 or len(self.evidence_content) > 8 * 1024 * 1024:
            raise RawArchiveError("raw_archive_size_limit")
        manifest = json.loads(self.manifest_content)
        if manifest.get("run_id") != self.run_id:
            raise RawArchiveError("manifest_run_mismatch")
        items = [i for i in manifest.get("items", []) if i.get("raw_log_id") == self.raw_log_id]
        if len(items) != 1 or items[0].get("sha256") != self.content_sha256:
            raise RawArchiveError("manifest_raw_mapping_mismatch")
        self.evidences()
        return self


class AtomicRawMirror:
    """A required replica when configured; the PostgreSQL copy is the recovery source.

    fsync a same-directory temporary file, then hard-link to publish atomically without
    replacement. A crash leaves an unclaimed temporary file, never a partial target.
    Existing mismatched bytes are a conflict; they are never overwritten or deleted.
    """

    def __init__(self, root):
        self.root = Path(root).resolve()

    def files(self, archive):
        if not re.fullmatch(r"RUN-\d{8}-\d{3}", archive.run_id):
            raise RawArchiveError("invalid_archive_run_id")
        return {
            f"sha256/{archive.content_sha256[:2]}/{archive.content_sha256}.jsonl": archive.content,
            f"manifests/{archive.run_id}/{archive.manifest_sha256}.json": archive.manifest_content,
            f"evidence/{archive.run_id}/{archive.evidence_sha256}.json": archive.evidence_content,
        }

    def _path(self, relative):
        # Components are code-generated (validated Run ID, hex digests). Reject any link
        # below the root instead of resolve(): on Windows, resolving a file another writer
        # is publishing can keep a \\?\ prefix and misreport an in-root path.
        path = self.root
        for part in relative.split("/"):
            if part in {"", ".", ".."}:
                raise RawArchiveError("archive_path_outside_root")
            path = path / part
            if path.is_symlink() or path.is_junction():
                raise RawArchiveError("archive_path_outside_root")
        return path

    def verify(self, archive):
        for relative, expected in self.files(archive).items():
            path = self._path(relative)
            try:
                with path.open("rb") as stream:
                    data = stream.read(len(expected) + 1)
            except FileNotFoundError as error:
                raise RawArchiveError("archive_mirror_missing") from error
            except OSError as error:
                raise RawArchiveError("archive_mirror_unreadable") from error
            if data != expected:
                raise RawArchiveError("archive_mirror_content_conflict")

    def publish(self, archive):
        for relative, content in self.files(archive).items():
            path = self._path(relative)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Check again after mkdir, so a preexisting link cannot escape the root.
                self._path(relative)
                descriptor, temporary = tempfile.mkstemp(prefix=".raw-pending-", dir=path.parent)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.link(temporary, path)
                    except FileExistsError:
                        pass  # verify below compares all bytes, not a hash alone.
                    if os.name != "nt":
                        directory = os.open(path.parent, os.O_RDONLY)
                        try:
                            os.fsync(directory)
                        finally:
                            os.close(directory)
                finally:
                    Path(temporary).unlink(missing_ok=True)  # Only this call's owned temp file.
            except OSError as error:
                raise RawArchiveError("archive_mirror_write_failed") from error
        self.verify(archive)
