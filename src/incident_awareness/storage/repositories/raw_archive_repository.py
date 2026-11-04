"""Canonical PostgreSQL Raw bytes; same transaction owner as Run/Receipt persistence."""

from dataclasses import asdict
from uuid import uuid4

from psycopg.types.json import Jsonb

from incident_awareness.storage.raw_archive import (
    RawArchiveError,
    RawCollectionIdentity,
    RawRunArchive,
    sha256,
)


class RawArchiveRepository:
    def __init__(self, connection):
        self.connection = connection

    def available(self):
        row = self.connection.execute("SELECT to_regclass('public.raw_run_archives')").fetchone()
        return row is not None and row[0] is not None

    def save_blob(self, content):
        if not 0 < len(content) <= 64 * 1024 * 1024:
            raise RawArchiveError("raw_archive_size_limit")
        digest = sha256(content)
        inserted = self.connection.execute(
            "INSERT INTO raw_artifact_blobs (content_sha256,byte_size,content) VALUES (%s,%s,%s) "
            "ON CONFLICT(content_sha256) DO NOTHING RETURNING content_sha256",
            (digest, len(content), content),
        ).fetchone()
        if inserted is None:
            row = self.connection.execute(
                "SELECT byte_size,content FROM raw_artifact_blobs WHERE content_sha256=%s",
                (digest,),
            ).fetchone()
            if row is None or row[0] != len(content) or bytes(row[1]) != content:
                raise RawArchiveError("raw_content_hash_collision")
        return digest

    def audit(self, action, *, run_id=None, collection=None, content_sha256=None, reason=None):
        self.connection.execute(
            "INSERT INTO raw_archive_audit "
            "(audit_id,run_id,ingest_id,bucket,object_key,e_tag,content_sha256,action,reason_code) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                run_id,
                collection.ingest_id if collection else None,
                collection.bucket if collection else None,
                collection.object_key if collection else None,
                collection.e_tag if collection else None,
                content_sha256,
                action,
                reason,
            ),
        )

    def expected_upload_hash(self, collection):
        rows = self.connection.execute(
            "SELECT content_sha256 FROM raw_archive_audit WHERE action='upload_prepared' "
            "AND ingest_id=%s AND bucket=%s AND object_key=%s",
            (collection.ingest_id, collection.bucket, collection.object_key),
        ).fetchall()
        hashes = {row[0] for row in rows}
        if len(hashes) > 1:
            raise RawArchiveError("upload_identity_content_conflict")
        return next(iter(hashes), None)

    def save(self, archive):
        archive.validate()
        collection = archive.collection
        if collection:
            expected = self.expected_upload_hash(collection)
            if expected is not None and expected != archive.content_sha256:
                raise RawArchiveError("upload_content_sha256_mismatch")
        self.save_blob(archive.content)
        row = self.connection.execute(
            "INSERT INTO raw_run_archives "
            "(run_id,ingest_id,bucket,object_key,e_tag,raw_log_id,content_sha256,artifact_uri,"
            "manifest_content,manifest_sha256,manifest_identity,evidence_content,evidence_sha256,"
            "extractor_version,extractor_code_sha256,raw_format,format_version,source_metadata,mirror_required) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'sysmon_jsonl','sysmon_jsonl_v1',%s,%s) "
            "ON CONFLICT(run_id) DO NOTHING RETURNING run_id",
            (
                archive.run_id,
                collection.ingest_id if collection else None,
                collection.bucket if collection else None,
                collection.object_key if collection else None,
                collection.e_tag if collection else None,
                archive.raw_log_id,
                archive.content_sha256,
                archive.artifact_uri,
                archive.manifest_content,
                archive.manifest_sha256,
                archive.manifest_identity,
                archive.evidence_content,
                archive.evidence_sha256,
                archive.extractor_version,
                archive.extractor_code_sha256,
                Jsonb(archive.source_metadata),
                archive.mirror_required,
            ),
        ).fetchone()
        if row is None:
            saved = self.get(archive.run_id)
            if saved is None:
                raise RawArchiveError("raw_archive_conflict_lookup_failed")
            left, right = asdict(saved), asdict(archive)
            left.pop("archive_created_at")
            right.pop("archive_created_at")
            if left != right:
                raise RawArchiveError("run_archive_content_conflict")
            return saved
        self.audit(
            "retained",
            run_id=archive.run_id,
            collection=collection,
            content_sha256=archive.content_sha256,
        )
        return self.get(archive.run_id)

    def get(self, run_id):
        row = self.connection.execute(
            "SELECT to_jsonb(a)-'manifest_content'-'evidence_content',a.manifest_content,"
            "a.evidence_content,b.content,b.byte_size,b.content_sha256 FROM raw_run_archives a "
            "JOIN raw_artifact_blobs b ON b.content_sha256=a.content_sha256 WHERE a.run_id=%s",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        meta, manifest, evidence, raw, size, blob_sha = row
        manifest, evidence, raw = bytes(manifest), bytes(evidence), bytes(raw)
        if (
            len(raw) != size
            or sha256(raw) != blob_sha
            or blob_sha != meta["content_sha256"]
            or sha256(manifest) != meta["manifest_sha256"]
            or sha256(evidence) != meta["evidence_sha256"]
        ):
            raise RawArchiveError("stored_archive_sha256_mismatch")
        collection = (
            RawCollectionIdentity(
                meta["ingest_id"], meta["bucket"], meta["object_key"], meta["e_tag"]
            )
            if meta["ingest_id"]
            else None
        )
        archive = RawRunArchive(
            run_id=meta["run_id"],
            raw_log_id=meta["raw_log_id"],
            content=raw,
            manifest_content=manifest,
            evidence_content=evidence,
            extractor_version=meta["extractor_version"],
            extractor_code_sha256=meta["extractor_code_sha256"],
            source_metadata=meta["source_metadata"],
            collection=collection,
            mirror_required=meta["mirror_required"],
            archive_created_at=meta["archive_created_at"],
        ).validate()
        if (
            archive.artifact_uri != meta["artifact_uri"]
            or archive.manifest_identity != meta["manifest_identity"]
        ):
            raise RawArchiveError("stored_archive_identity_mismatch")
        return archive
