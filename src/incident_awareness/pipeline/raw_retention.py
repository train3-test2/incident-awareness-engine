"""Retain original inputs and generation-time Evidence before a successful commit."""

from pathlib import Path

import psycopg

from incident_awareness.evidence.extractor import EXTRACTOR_VERSION, extract_evidence
from incident_awareness.pipeline.experiment_input import current_experiment_declaration
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.raw_archive import (
    AtomicRawMirror,
    RawArchiveError,
    RawRunArchive,
    canonical_bytes,
    collection_identity,
    mirror_root,
    sha256,
)
from incident_awareness.storage.repositories.raw_archive_repository import RawArchiveRepository


def retain_generation(connection, prepared, artifacts, normalized):
    content = prepared.inputs.sysmon_jsonl_path.read_bytes()
    if sha256(content) != artifacts.sysmon_content_sha256:
        raise RawArchiveError("accepted_raw_content_changed")
    manifest = prepared.inputs.manifest_path.read_bytes()
    root = mirror_root()
    archive = RawRunArchive(
        run_id=artifacts.run_metadata.run_id,
        raw_log_id=artifacts.normalization_context.raw_log_id,
        content=content,
        manifest_content=manifest,
        evidence_content=canonical_bytes([e.model_dump(mode="json") for e in normalized.evidences]),
        extractor_version=EXTRACTOR_VERSION,
        extractor_code_sha256=sha256(Path(extract_evidence.__code__.co_filename).read_bytes()),
        collection=collection_identity(),
        mirror_required=root is not None,
        source_metadata={
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "target_host": artifacts.run_metadata.target_host,
            "normalized_event_count": len(normalized.events),
            "parser_id": "sysmon-normalizer",
            "parser_version": "v0.3",
            "origin": "s3_object" if collection_identity() else "standalone",
            "experiment_declaration": current_experiment_declaration(),
            "effective_run_type": artifacts.run_metadata.run_type.value,
            "label_source": "explicit_local_demo_declaration"
            if current_experiment_declaration()
            else "legacy_standalone_parameter_or_default",
        },
    ).validate()
    saved = RawArchiveRepository(connection).save(archive)
    if root is not None:
        AtomicRawMirror(root).publish(saved)
    return saved


def verify_or_repair_mirror(archive, *, repair=False):
    if not archive.mirror_required:
        return False
    root = mirror_root()
    if root is None:
        raise RawArchiveError("archive_mirror_unconfigured")
    mirror = AtomicRawMirror(root)
    try:
        mirror.verify(archive)
    except RawArchiveError as error:
        if not repair or str(error) != "archive_mirror_missing":
            raise
        mirror.publish(archive)  # No replacement of a corrupted/conflicting target.
        return True
    return False


def retain_upload(content, identity, *, completed=False):
    # Independent upload transaction: keep original bytes even before S3/SQS succeeds.
    # Never infer an analysis Run from this record.
    with psycopg.connect(DatabaseConfig.from_environment().url, connect_timeout=2) as connection:
        repository = RawArchiveRepository(connection)
        expected = repository.expected_upload_hash(identity)
        digest = repository.save_blob(content)
        if expected is not None and expected != digest:
            raise RawArchiveError("upload_identity_content_conflict")
        repository.audit(
            "uploaded" if completed else "upload_prepared",
            collection=identity,
            content_sha256=digest,
        )
    return digest
