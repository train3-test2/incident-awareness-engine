"""Separate provenance contracts; Evidence and FusionResult remain unchanged."""

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.extractor import EXTRACTOR_VERSION, extract_evidence
from incident_awareness.evidence.raw_verification import RawArtifactVerifier

ResolutionStatus = Literal["unresolved", "event_verified", "raw_verified"]


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


class SupportingReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    event_id: str
    source_event_id: str
    raw_ref: RawLogReference
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerifiedObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observation_id: str
    observed_at: str
    evidence_id: str
    evidence_type: str
    event_ids: tuple[str, ...]
    behavior_summary: str
    verification_level: Literal["raw_verified"] = "raw_verified"
    supporting_references: tuple[SupportingReference, ...]


class EvidenceResolution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: str
    evidence_type: str | None = None
    extractor_version: str | None = None
    resolution_status: ResolutionStatus = "unresolved"
    run_id: str
    entity_id: str
    timestamp: str | None = None
    derived_from_source_layer: str | None = None
    feature_channel_group: str | None = None
    features: dict = Field(default_factory=dict)
    event_ids: tuple[str, ...] = ()
    source_event_ids: tuple[str, ...] = ()
    raw_references: tuple[RawLogReference, ...] = ()
    # Current reconstruction is explicitly distinct from an original stored Evidence.
    evidence_origin: Literal["current_extractor_reconstruction", "retained_archive", "missing"]
    historical_extractor_verified: bool = False
    observed_behavior: tuple[VerifiedObservation, ...] = ()
    validation_details: dict = Field(default_factory=dict)
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def resolved_chain_is_complete(self):
        if self.resolution_status != "unresolved" and (
            not self.event_ids
            or len(set(self.event_ids)) != len(self.event_ids)
            or len(self.event_ids) != len(self.source_event_ids)
            or len(self.event_ids) != len(self.raw_references)
        ):
            raise ValueError("Resolved Evidence requires every exact Event reference")
        if self.resolution_status != "raw_verified" and self.observed_behavior:
            raise ValueError("Raw verification is required for behavioral prose")
        if self.resolution_status == "raw_verified" and self.unresolved_reason is not None:
            raise ValueError("Raw-verified Evidence cannot have an unresolved failure")
        if (
            self.evidence_origin == "current_extractor_reconstruction"
            and self.historical_extractor_verified
        ):
            raise ValueError("Current reconstruction does not attest historical rules")
        return self


def behavior_summary(evidence, event):
    """Only two current S0 rules have a verified human-readable interpretation."""
    if evidence.extractor_version != EXTRACTOR_VERSION:
        return None
    # Re-extraction checks the full rule/features, not just a claimed Evidence type.
    if evidence not in extract_evidence(event):
        return None
    host = json.dumps(event.host_id, ensure_ascii=False)
    process = json.dumps(event.process.name, ensure_ascii=False)
    prefix = f"{event.timestamp.isoformat(timespec='milliseconds')} 관측 시스템 {host}의 {process} 프로세스에서 "
    if evidence.evidence_type == "encoded_powershell_command":
        option = json.dumps(evidence.features["matched_option"], ensure_ascii=False)
        return prefix + f"인코딩된 PowerShell 실행 옵션 {option}이 관측되었습니다."
    if evidence.evidence_type == "script_interpreter_external_connection":
        destination = json.dumps(event.network.dst_ip, ensure_ascii=False)
        return prefix + (
            f"공인 IP {destination}:{event.network.dst_port} 연결이 관측되었습니다. "
            "연결의 악성 여부는 미확인입니다."
        )
    return None


def make_observation(evidence, event, proof):
    summary = behavior_summary(evidence, event)
    if summary is None:
        return None
    reference = SupportingReference(
        event_id=event.event_id,
        source_event_id=event.source_event_id,
        raw_ref=event.raw_ref,
        **{key: proof[key] for key in ("manifest_sha256", "raw_sha256", "raw_record_sha256")},
    )
    facts = {
        "observed_at": event.timestamp.isoformat(timespec="milliseconds"),
        "evidence_id": evidence.evidence_id,
        "evidence_type": evidence.evidence_type,
        "event_ids": (event.event_id,),
        "behavior_summary": summary,
        "supporting_references": (reference.model_dump(mode="json"),),
    }
    return VerifiedObservation(observation_id="OBS-" + digest(facts), **facts)


def resolve_evidence(
    evidence: Evidence,
    events: dict[str, NormalizedEvent],
    *,
    run_id: str,
    entity_id: str,
    raw_verifier: RawArtifactVerifier,
    expected_extractor_version: str | None = None,
    origin="current_extractor_reconstruction",
    historical_extractor_verified=False,
):
    base = {
        "evidence_id": evidence.evidence_id,
        "evidence_type": evidence.evidence_type,
        "extractor_version": evidence.extractor_version,
        "run_id": run_id,
        "entity_id": entity_id,
        "timestamp": evidence.timestamp.isoformat(timespec="milliseconds"),
        "derived_from_source_layer": evidence.derived_from_source_layer,
        "feature_channel_group": evidence.feature_channel_group,
        "features": evidence.features,
        "event_ids": tuple(evidence.event_ids),
        "evidence_origin": origin,
        "historical_extractor_verified": historical_extractor_verified,
    }
    details = {"evidence_sha256": digest(evidence.model_dump(mode="json"))}

    def result(status, reason=None, **extra):
        return EvidenceResolution(
            **base,
            resolution_status=status,
            unresolved_reason=reason,
            validation_details=details,
            **extra,
        )

    if (evidence.run_id, evidence.entity_id) != (run_id, entity_id):
        return result("unresolved", "evidence_scope_mismatch")
    if expected_extractor_version and evidence.extractor_version != expected_extractor_version:
        return result("unresolved", "extractor_version_mismatch")
    referenced = []
    for event_id in evidence.event_ids:
        event = events.get(event_id)
        if event is None or event.event_id != event_id:
            return result("unresolved", "evidence_event_id_mismatch")
        if (event.run_id, event.host_id) != (run_id, entity_id):
            return result("unresolved", "event_scope_mismatch")
        if evidence.derived_from_source_layer not in {event.source_layer, "mixed"}:
            return result("unresolved", "event_source_layer_mismatch")
        referenced.append(event)
    if len(set(evidence.event_ids)) != len(evidence.event_ids):
        return result("unresolved", "duplicate_event_reference")
    if (
        not min(e.timestamp for e in referenced)
        <= evidence.timestamp
        <= max(e.timestamp for e in referenced)
    ):
        return result("unresolved", "evidence_event_timestamp_mismatch")
    details["event_checks"] = "exact_ids_run_host_timestamp_source_and_raw_reference"
    details["events"] = [
        {
            "event_id": e.event_id,
            "source": e.source,
            "source_layer": e.source_layer,
            "event_sha256": digest(e.model_dump(mode="json")),
        }
        for e in referenced
    ]
    proofs = [raw_verifier.verify(event) for event in referenced]
    details["raw_checks"] = [
        {"event_id": e.event_id, "verified": p.verified, "reason": p.reason, **p.details}
        for e, p in zip(referenced, proofs, strict=True)
    ]
    shared = {
        "source_event_ids": tuple(e.source_event_id for e in referenced),
        "raw_references": tuple(e.raw_ref for e in referenced),
    }
    if not all(p.verified for p in proofs):
        reason = next(p.reason for p in proofs if not p.verified)
        return result("event_verified", reason, **shared)
    observations = []
    if evidence.feature_channel_group == "fusion_feature":
        for event, proof in zip(referenced, proofs, strict=True):
            observation = make_observation(evidence, event, proof.details)
            if observation:
                observations.append(observation)
    return result("raw_verified", observed_behavior=tuple(observations), **shared)
