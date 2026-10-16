"""Source-artifact-preserving v0.2 validation, before Fusion output evaluation.

This boundary supports synthetic contract checks only. It does not manufacture a
Role1 receive time, a Fusion provenance artifact, or performance eligibility.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.collection.r1_candidate_generation_seal import R1CandidateGenerationPolicy
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evaluation.context_inputs import validate_context_inputs
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_provenance import resolve_r1_evidence_provenance
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1LineageInputProvenance,
    load_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_causal_replay import (
    R1CausalReplayInput,
    prepare_r1_incremental_causal_replay_input,
)
from incident_awareness.pipeline.r1_causal_replay_artifacts import canonical_model_sha256
from incident_awareness.pipeline.r1_incremental_availability import (
    load_r1_incremental_availability_publication_receipt,
    load_r1_incremental_causal_availability_envelope,
    load_r1_incremental_replay_input_validation,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import load_r1_incremental_checkpoint
from incident_awareness.pipeline.r1_incremental_evidence import R1IncrementalEvidenceState
from incident_awareness.pipeline.r1_stream_ingress import R1StreamIngress
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
)

ARTIFACT_NAMES = (
    "r1_evidence.jsonl",
    "r1_extraction_summary.json",
    "r1_incremental_checkpoint.json",
    "r1_incremental_availability_v0.2.json",
    "r1_incremental_availability_v0.2.json.publication.json",
    "r1_incremental_replay_input_validation.json",
)


class IncrementalInputPins(BaseModel):
    """External receipt pins; never derive these from untrusted files at evaluation time."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["evaluation-incremental-input-v1"]
    usage: Literal["synthetic_contract_check"]
    run_metadata_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # One canonical digest binds filenames and exact bytes for all six artifacts.
    execution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class IncrementalInputTrust:
    """Trusted policies/close bindings plus a dedicated ingress for checkpoint recovery.

    Recovery can write to the ingress ledger: use an isolated verification ledger,
    not the live ingestion ledger. Bindings must come from accepted source records.
    """

    selector: R1SelectorPolicy
    approved: ApprovedLineagePolicy
    candidate: R1CandidateGenerationPolicy
    ingress: R1StreamIngress
    accepted_close_receipt: R1AcceptedRunCloseReceipt
    accepted_source_seal_id: str
    accepted_source_seal_projection_sha256: str


def incremental_execution_sha256(contents: dict[str, bytes]) -> str:
    """Digest for receipt registration and verification, including the complete summary."""
    if set(contents) != set(ARTIFACT_NAMES):
        raise ValueError("incremental execution requires exactly six named artifacts")
    digest = hashlib.sha256()
    for name in ARTIFACT_NAMES:
        digest.update(name.encode("utf-8") + b"\x00")
        digest.update(hashlib.sha256(contents[name]).digest())
    return digest.hexdigest()


def validate_incremental_execution_input(
    directory: Path,
    pins: IncrementalInputPins,
    *,
    run: RunMetadata,
    trust: IncrementalInputTrust,
) -> R1CausalReplayInput:
    """Validate stored v0.2 inputs and return the canonical scheduled Evidence.

    Missing validation records fail before the producer adapter is called. The
    adapter receives a private byte snapshot, so it cannot create/overwrite the
    source record or quietly replace its first-observed availability with now.
    Checkpoint recovery CAN WRITE to trust.ingress's ledger, even if later
    validation fails. This function neither detects nor blocks a production ledger
    and does not roll back its writes. Callers MUST supply a disposable isolated
    verification ingress/ledger, never a live ingestion ingress.
    This result is replay input, NOT a CausalReplayEvaluationInput/metric result.
    """
    pins = IncrementalInputPins.model_validate(pins.model_dump())
    if canonical_model_sha256(run) != pins.run_metadata_sha256:
        raise ValueError("RunMetadata differs from pinned incremental execution")
    contents = {name: (directory / name).read_bytes() for name in ARTIFACT_NAMES}
    if incremental_execution_sha256(contents) != pins.execution_sha256:
        raise ValueError("incremental execution differs from pinned artifact bytes")
    with TemporaryDirectory(prefix="role5-incremental-") as temporary:
        snapshot_dir = Path(temporary)
        for name, content in contents.items():
            (snapshot_dir / name).write_bytes(content)
        artifact = load_r1_evidence_artifacts(snapshot_dir)
        checkpoint = load_r1_incremental_checkpoint(snapshot_dir / ARTIFACT_NAMES[2])
        envelope = load_r1_incremental_causal_availability_envelope(
            snapshot_dir / ARTIFACT_NAMES[3]
        )
        publication = load_r1_incremental_availability_publication_receipt(
            snapshot_dir / ARTIFACT_NAMES[4]
        )
        validation_path = snapshot_dir / ARTIFACT_NAMES[5]
        validation = load_r1_incremental_replay_input_validation(validation_path)
        restored = R1IncrementalEvidenceState.restore_from_checkpoint(
            checkpoint,
            selector_policy=trust.selector,
            approved_policy=trust.approved,
            candidate_policy=trust.candidate,
            ingress=trust.ingress,
            accepted_close_receipt=trust.accepted_close_receipt,
            accepted_source_seal_id=trust.accepted_source_seal_id,
            accepted_source_seal_projection_sha256=trust.accepted_source_seal_projection_sha256,
        ).snapshot
        if tuple(artifact.evidences) != restored.evidences:
            raise ValueError("stored Evidence differs from recovered checkpoint")
        if artifact.summary.diagnostics or restored.extraction_diagnostics:
            raise ValueError("incremental input contains extraction/recovery diagnostics")
        # Stream checkpoints retain retransmissions; collapse only identical Events.
        by_id = {}
        for chunk in checkpoint.accepted_chunks:
            for event in chunk.events:
                if event.event_id in by_id and by_id[event.event_id] != event:
                    raise ValueError("conflicting Event identity in checkpoint")
                by_id[event.event_id] = event
        events = list(by_id.values())
        if run.end_time is None:
            raise ValueError("incremental validation requires authoritative Run end")
        validate_context_inputs(
            artifact,
            events,
            run_id=run.run_id,
            entity_id=run.target_host,
            run_start=run.start_time,
            run_end=run.end_time,
        )
        selector = artifact.summary.selector
        if selector is None or (selector.policy_id, selector.version, selector.config_hash) != (
            trust.selector.policy_id,
            trust.selector.version,
            trust.selector.config_hash,
        ):
            raise ValueError("summary selector identity differs from trusted policy")
        if (selector.status, selector.diagnostics) != (
            "selected" if restored.selector_result.selection is not None else "failed",
            restored.selector_result.diagnostics,
        ):
            raise ValueError("summary selector result differs from recovered checkpoint")
        lineage = restored.lineage_input
        expected_lineage = (
            ()
            if lineage is None
            else (
                R1LineageInputProvenance(
                    anchor_event_id=lineage.anchor_event_id,
                    terminal_event_id=lineage.terminal_event_id,
                    policy_id=trust.approved.policy_id,
                    policy_version=trust.approved.version,
                    policy_config_hash=trust.approved.config_hash,
                    context_event_ids=lineage.context_event_ids,
                ),
            )
        )
        if tuple(artifact.summary.lineage_inputs or ()) != expected_lineage:
            raise ValueError("summary lineage provenance differs from recovered checkpoint")
        expected_context = set(
            restored.lineage_input.context_event_ids if restored.lineage_input else ()
        )
        summary_context = {
            event_id
            for lineage in artifact.summary.lineage_inputs or ()
            for event_id in lineage.context_event_ids
        }
        if summary_context != expected_context:
            raise ValueError("summary context differs from recovered checkpoint")
        resolve_r1_evidence_provenance(artifact.evidences, events)
        replay_input = prepare_r1_incremental_causal_replay_input(
            restored,
            envelope,
            checkpoint,
            publication,
            input_validation_path=validation_path,
            run_metadata=run,
            selector_policy=trust.selector,
            approved_policy=trust.approved,
            candidate_policy=trust.candidate,
        )
        if replay_input.incremental_input_validation != validation:
            raise ValueError("first validation record changed")
        if validation_path.read_bytes() != contents[ARTIFACT_NAMES[5]]:
            raise ValueError("first validation record bytes changed")
        return replay_input
