"""Read-only S0 reconstruction, separate from the existing R1 archive API.

Only IDs explicitly present in a Fusion snapshot are resolved. Scanning a Run to
reproduce deterministic IDs never joins a nearby Event or changes stored results.
"""

import hashlib
import os
from pathlib import Path

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.evidence.extractor import EXTRACTOR_VERSION, extract_evidence
from incident_awareness.evidence.provenance import EvidenceResolution, resolve_evidence
from incident_awareness.evidence.raw_verification import RawArtifactVerifier
from incident_awareness.pipeline.raw_retention import verify_or_repair_mirror
from incident_awareness.storage.raw_archive import RawArchiveError
from incident_awareness.storage.repositories.raw_archive_repository import RawArchiveRepository

MAX_RECONSTRUCTION_EVENTS = 50_000


def configured_raw_verifier():
    root = os.environ.get("IAE_PROVENANCE_ARCHIVE_ROOT")
    return RawArtifactVerifier(Path(root) if root else None)


def read_provenance(connection, run_id, *, fusion_snapshots=None, raw_verifier=None):
    if not connection.execute("SELECT 1 FROM runs WHERE run_id=%s", (run_id,)).fetchone():
        raise LookupError("Run not found")
    if fusion_snapshots is None:
        fusion_snapshots = [
            row[0]
            for row in connection.execute(
                "SELECT payload FROM fusion_results WHERE run_id=%s ORDER BY entity_id",
                (run_id,),
            ).fetchall()
        ]
    fusions = [FusionResult.model_validate(item) for item in fusion_snapshots]
    if any(f.run_id != run_id for f in fusions):
        raise ValueError("Fusion provenance scope mismatch")
    archives = RawArchiveRepository(connection)
    archive = None
    archive_error = None
    try:
        if archives.available():
            archive = archives.get(run_id)
    except RawArchiveError as error:
        archive_error = str(error)
    retention_failure = archive_error
    if archive is not None:
        try:
            verify_or_repair_mirror(archive)
        except RawArchiveError as error:
            retention_failure = str(error)
    targets = []
    for fusion in fusions:
        # A miss/not_evaluated Run cannot acquire attack Evidence through reconstruction.
        if fusion.fusion_status != "detected":
            continue
        ids = list(fusion.contributing_evidence_ids)
        for episode in fusion.fusion_episodes:
            ids.extend(episode.contributing_evidence_ids)
        targets.extend((fusion.entity_id, eid) for eid in dict.fromkeys(ids))
    rows = []
    if targets:
        rows = connection.execute(
            "SELECT event_id,run_id,host_id,timestamp,event_type,payload FROM events "
            "WHERE run_id=%s ORDER BY event_id LIMIT %s",
            (run_id, MAX_RECONSTRUCTION_EVENTS + 1),
        ).fetchall()
    if len(rows) > MAX_RECONSTRUCTION_EVENTS:
        raise ValueError("Evidence reconstruction exceeds the read limit")
    events = {}
    reconstructed = {}
    for event_id, stored_run, host, timestamp, event_type, payload in rows:
        event = NormalizedEvent.model_validate(payload)
        if (
            (event.event_id, event.run_id, event.host_id, event.timestamp, event.event_type)
            != (event_id, run_id, host, timestamp, event_type)
            or stored_run != run_id
            or event_id in events
        ):
            raise ValueError("Stored Event provenance is inconsistent")
        events[event_id] = event
        for evidence in [] if archive is not None or archive_error else extract_evidence(event):
            if evidence.evidence_id in reconstructed:
                raise ValueError("Ambiguous reconstructed Evidence ID")
            reconstructed[evidence.evidence_id] = evidence
    verifier = raw_verifier if raw_verifier is not None else configured_raw_verifier()
    code_sha = hashlib.sha256(Path(extract_evidence.__code__.co_filename).read_bytes()).hexdigest()
    historical_verified = bool(
        archive
        and archive.extractor_version == EXTRACTOR_VERSION
        and archive.extractor_code_sha256 == code_sha
    )
    if archive is not None:
        # The retained Evidence is the generation-time original, so a later extractor edit
        # does not break its Event/Raw chain. Prose still requires current re-extraction
        # to reproduce it exactly (behavior_summary), and the digest difference is reported.
        reconstructed = {item.evidence_id: item for item in archive.evidences()}
        if raw_verifier is None:

            def load_artifact(event):
                if event.run_id != archive.run_id or event.raw_ref.raw_log_id != archive.raw_log_id:
                    raise RawArchiveError("archive_event_identity_mismatch")
                if retention_failure:
                    raise RawArchiveError(retention_failure)
                return (
                    archive.manifest_content,
                    archive.content,
                    {
                        "storage_backend": "postgresql",
                        "artifact_uri": archive.artifact_uri,
                        "archive_created_at": archive.archive_created_at,
                        "manifest_identity": archive.manifest_identity,
                        "mirror_status": "verified" if archive.mirror_required else "not_required",
                    },
                )

            verifier = RawArtifactVerifier(artifact_loader=load_artifact)
    items = []
    for entity, evidence_id in dict.fromkeys(targets):
        evidence = reconstructed.get(evidence_id)
        if evidence is None or archive_error:
            item = EvidenceResolution(
                evidence_id=evidence_id,
                run_id=run_id,
                entity_id=entity,
                evidence_origin="missing",
                unresolved_reason=archive_error or "current_extractor_did_not_reproduce_id",
            )
        else:
            item = resolve_evidence(
                evidence,
                events,
                run_id=run_id,
                entity_id=entity,
                raw_verifier=verifier,
                origin="retained_archive" if archive else "current_extractor_reconstruction",
                historical_extractor_verified=historical_verified,
            )
        details = {
            **item.validation_details,
            "current_extractor_version": EXTRACTOR_VERSION,
            "extractor_code_sha256": code_sha,
            "historical_rule_identity": "saved_generation_code_digest"
            if historical_verified
            else "generation_code_digest_differs"
            if archive
            else "not_attested",
            "generation_extractor_code_sha256": archive.extractor_code_sha256 if archive else None,
            "original_evidence_stored": archive is not None,
        }
        items.append(
            item.model_copy(update={"validation_details": details}).model_dump(mode="json")
        )
    referenced_ids = {eid for item in items for eid in item["event_ids"]}
    return {
        "schema_version": "evidence_provenance_v1",
        "run_id": run_id,
        "scope": "fusion_contributing_ids_only",
        "reconstruction": "retained_generation_archive"
        if archive
        else "current_s0_extractor_not_original_evidence_archive",
        "historical_extractor_verified": historical_verified,
        "experiment_input": {
            "declaration": archive.source_metadata.get("experiment_declaration"),
            "execution_run_type": archive.source_metadata.get("effective_run_type"),
            "label_source": archive.source_metadata.get("label_source", "legacy_unattested"),
        }
        if archive
        else None,
        "raw_retention": {
            "available": archive is not None,
            "status": "storage_verified"
            if archive and not retention_failure
            else "degraded"
            if archive or retention_failure
            else "unavailable",
            "failure": retention_failure,
            "content_sha256": archive.content_sha256 if archive else None,
            "byte_size": len(archive.content) if archive else None,
            "archive_created_at": archive.archive_created_at if archive else None,
            "manifest_identity": archive.manifest_identity if archive else None,
        },
        "items": items,
        "source_events": [
            events[eid].model_dump(mode="json") for eid in sorted(referenced_ids) if eid in events
        ],
        "verified_observations": [o for item in items for o in item["observed_behavior"]],
        "summary": {
            status: sum(i["resolution_status"] == status for i in items)
            for status in ("unresolved", "event_verified", "raw_verified")
        },
    }
