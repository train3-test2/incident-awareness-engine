"""Verified Run Evidence from the durable R1 archive outbox.

Only a ``published`` archive is read, and only after the same writer-contract checks used to
load local R1 artifacts.  Events, Fusion contributing Evidence IDs, and other Runs are never
used to build or fill the list.
"""

import hashlib
import re
from datetime import datetime
from typing import Literal

import psycopg
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_multi_event import REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION
from incident_awareness.pipeline.r1_artifacts import verify_r1_evidence_archive_content
from incident_awareness.storage.repositories.event_repository import (
    EventProvenance,
    EventRepository,
)
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchiveEvidenceRead,
    R1ArchivePublicationRepository,
    R1ArchivePublicationStatus,
)

MAX_EVIDENCE_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_SUMMARY_ARCHIVE_BYTES = 1024 * 1024
MAX_EVIDENCE_PAGE_SIZE = 200
DEFAULT_EVIDENCE_PAGE_SIZE = 100
_ATTACK_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_POLICY_FEATURE_KEYS = frozenset({"policy_id", "version", "config_hash"})


class EvidenceReadError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def evidence_database_error(error: psycopg.Error) -> EvidenceReadError:
    if isinstance(error, (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn)):
        return EvidenceReadError(503, "Evidence archive storage is not provisioned")
    if isinstance(error, psycopg.OperationalError):
        return EvidenceReadError(503, "Evidence database is unavailable")
    return EvidenceReadError(500, "Evidence read failed")


class EvidenceListQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=DEFAULT_EVIDENCE_PAGE_SIZE, ge=1, le=MAX_EVIDENCE_PAGE_SIZE)
    offset: int = Field(default=0, ge=0)


class EvidenceEventReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: str
    # True only when the Event is stored for this Run; the UI links only stored Events.
    stored: bool


class EvidencePolicyProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_id: str
    version: str
    config_hash: str


class RunEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: str
    evidence_type: str
    # Event time of the referenced Events; not t_e, t_h, or processing arrival time.
    timestamp: datetime
    entity_id: str
    derived_from_source_layer: Literal["raw_telemetry", "detector_output", "mixed"]
    feature_channel_group: Literal["fusion_feature", "diagnostic_only"]
    extractor_version: str
    attack_technique_ids: tuple[str, ...]
    events: tuple[EvidenceEventReference, ...]
    policy: EvidencePolicyProvenance | None
    # Feature or technique values that are not part of the public allowlist.
    withheld_field_count: int


class RunEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["dashboard_run_evidence_v1"] = "dashboard_run_evidence_v1"
    run_id: str
    availability: Literal["published", "no_archive", "not_published"]
    archive_status: R1ArchivePublicationStatus | None
    source: Literal["r1_archive_publication"] = "r1_archive_publication"
    evidence_scope: Literal["offline_whole_episode"] = "offline_whole_episode"
    fusion_input: Literal[False] = False
    timestamp_meaning: Literal["event_time"] = "event_time"
    entity_scope: Literal["run"] = "run"
    extractor_version: str | None
    evidence_sha256: str | None
    total: int | None
    limit: int
    offset: int
    entity_ids: tuple[str, ...]
    unstored_event_reference_count: int
    items: tuple[RunEvidenceItem, ...]


class DashboardEvidenceReader:
    def __init__(
        self,
        archives: R1ArchivePublicationRepository,
        events: EventRepository,
    ) -> None:
        self._archives = archives
        self._events = events

    def read(self, run_id: str, query: EvidenceListQuery) -> RunEvidenceResponse:
        try:
            archive = self._archives.read_evidence_archive(
                run_id,
                max_evidence_bytes=MAX_EVIDENCE_ARCHIVE_BYTES,
                max_summary_bytes=MAX_SUMMARY_ARCHIVE_BYTES,
            )
            if archive is None:
                raise EvidenceReadError(404, "Run not found")
            if archive.run_id != run_id:
                raise EvidenceReadError(500, "Evidence read failed")
            if archive.status is None or archive.status != "published":
                return _unavailable_response(run_id, archive.status, query)
            evidences, extractor_version = _verified_evidences(archive, run_id)
            event_ids = tuple(dict.fromkeys(e for item in evidences for e in item.event_ids))
            provenance = self._events.get_provenance(event_ids)
        except psycopg.Error as error:
            raise evidence_database_error(error) from error
        except TypeError as error:
            raise EvidenceReadError(500, "Evidence read failed") from error

        _require_consistent_provenance(evidences, provenance, run_id)
        page = evidences[query.offset : query.offset + query.limit]
        return RunEvidenceResponse(
            run_id=run_id,
            availability="published",
            archive_status="published",
            extractor_version=extractor_version,
            evidence_sha256=archive.evidence_sha256,
            total=len(evidences),
            limit=query.limit,
            offset=query.offset,
            entity_ids=tuple(sorted({item.entity_id for item in evidences})),
            unstored_event_reference_count=sum(
                event_id not in provenance for event_id in event_ids
            ),
            items=tuple(_public_item(item, provenance) for item in page),
        )


def _unavailable_response(
    run_id: str,
    status: R1ArchivePublicationStatus | None,
    query: EvidenceListQuery,
) -> RunEvidenceResponse:
    # A pending, retryable, or failed archive is not a completed publication; its bytes are
    # not loaded and nothing about its contents is reported.
    return RunEvidenceResponse(
        run_id=run_id,
        availability="no_archive" if status is None else "not_published",
        archive_status=status,
        extractor_version=None,
        evidence_sha256=None,
        total=None,
        limit=query.limit,
        offset=query.offset,
        entity_ids=(),
        unstored_event_reference_count=0,
        items=(),
    )


def _verified_evidences(
    archive: R1ArchiveEvidenceRead,
    run_id: str,
) -> tuple[tuple[Evidence, ...], str]:
    if archive.evidence_content is None or archive.summary_content is None:
        raise EvidenceReadError(500, "Stored Evidence archive exceeds the read limit")
    if (
        hashlib.sha256(archive.evidence_content).hexdigest() != archive.evidence_sha256
        or hashlib.sha256(archive.summary_content).hexdigest() != archive.summary_sha256
    ):
        raise EvidenceReadError(500, "Stored Evidence archive is invalid")
    try:
        verified = verify_r1_evidence_archive_content(
            archive.evidence_content,
            archive.summary_content,
        )
    except (TypeError, ValueError) as error:
        raise EvidenceReadError(500, "Stored Evidence archive is invalid") from error
    if verified.summary.run_id != run_id:
        raise EvidenceReadError(500, "Stored Evidence archive is invalid")
    return verified.evidences, verified.summary.extractor_version


def _require_consistent_provenance(
    evidences: tuple[Evidence, ...],
    provenance: dict[str, EventProvenance],
    run_id: str,
) -> None:
    # A stored Event of another Run or another host contradicts the Evidence scope.
    for evidence in evidences:
        for event_id in evidence.event_ids:
            stored = provenance.get(event_id)
            if stored is not None and (
                stored.run_id != run_id or stored.host_id != evidence.entity_id
            ):
                raise EvidenceReadError(500, "Stored Evidence provenance is inconsistent")


def _public_item(
    evidence: Evidence,
    provenance: dict[str, EventProvenance],
) -> RunEvidenceItem:
    policy = None
    withheld = 0
    features = evidence.features
    if (
        evidence.evidence_type == REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION
        and set(features) == _POLICY_FEATURE_KEYS
        and all(isinstance(value, str) for value in features.values())
    ):
        policy = EvidencePolicyProvenance(
            policy_id=str(features["policy_id"]),
            version=str(features["version"]),
            config_hash=str(features["config_hash"]),
        )
    else:
        withheld += len(features)
    techniques = tuple(
        technique
        for technique in evidence.attack_technique_ids
        if _ATTACK_TECHNIQUE_ID.fullmatch(technique)
    )
    withheld += len(evidence.attack_technique_ids) - len(techniques)
    return RunEvidenceItem(
        evidence_id=evidence.evidence_id,
        evidence_type=evidence.evidence_type,
        timestamp=evidence.timestamp,
        entity_id=evidence.entity_id,
        derived_from_source_layer=evidence.derived_from_source_layer,
        feature_channel_group=evidence.feature_channel_group,
        extractor_version=evidence.extractor_version,
        attack_technique_ids=techniques,
        events=tuple(
            EvidenceEventReference(event_id=event_id, stored=event_id in provenance)
            for event_id in evidence.event_ids
        ),
        policy=policy,
        withheld_field_count=withheld,
    )


__all__ = [
    "DEFAULT_EVIDENCE_PAGE_SIZE",
    "MAX_EVIDENCE_ARCHIVE_BYTES",
    "MAX_EVIDENCE_PAGE_SIZE",
    "MAX_SUMMARY_ARCHIVE_BYTES",
    "DashboardEvidenceReader",
    "EvidenceListQuery",
    "EvidenceReadError",
    "RunEvidenceResponse",
    "evidence_database_error",
]
