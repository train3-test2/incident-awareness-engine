"""검증된 R1 Evidence와 availability를 Role1 causal replay에 연결한다."""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
)
from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import FusionConfig
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.decision.fusion.temporal_replay import (
    ScheduledEvidence,
    TemporalReplayResult,
)
from incident_awareness.evidence.r1_approved_lineage_policy import (
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.fusion import build_fusion_runtime_config_snapshot
from incident_awareness.pipeline.r1_artifacts import R1EvidenceArtifactRun
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalAvailabilityEnvelope,
    R1CausalPolicyIdentity,
)
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    R1_CAUSAL_AVAILABILITY_GATE_CONTRACT,
    R1_CAUSAL_REPLAY_ORDERING_CONTRACT,
    R1_CAUSAL_REPLAY_PROVENANCE_CONTRACT_VERSION,
    R1CausalReplayArtifactSet,
    R1CausalReplayProvenance,
    R1CausalReplayProvenanceArtifact,
    canonical_model_sha256,
    write_r1_causal_replay_artifacts,
)
from incident_awareness.pipeline.r1_incremental_availability import (
    R1IncrementalAvailabilityPublicationReceipt,
    R1IncrementalCausalAvailabilityEnvelope,
    build_r1_incremental_causal_availability_envelope,
    validate_r1_incremental_availability_publication,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    R1IncrementalEvidenceCheckpoint,
)
from incident_awareness.pipeline.r1_incremental_evidence import (
    R1IncrementalEvidenceSnapshot,
)


@dataclass(frozen=True, slots=True)
class R1CausalReplayInput:
    """Strict join을 통과한 결정적 scheduled Evidence 입력."""

    scheduled_evidences: tuple[ScheduledEvidence, ...]


@dataclass(frozen=True, slots=True)
class R1CausalReplayPipelineResult:
    replay_result: TemporalReplayResult
    fusion_result: FusionResult
    stopping_trace: FusionStoppingTrace
    runtime_config_snapshot: FusionRuntimeConfigSnapshot
    provenance: R1CausalReplayProvenance


@dataclass(frozen=True, slots=True)
class R1CausalReplayArtifactPipelineResult:
    pipeline_result: R1CausalReplayPipelineResult
    artifacts: R1CausalReplayArtifactSet
    provenance_artifact: R1CausalReplayProvenanceArtifact


def prepare_r1_causal_replay_input(
    artifact_run: R1EvidenceArtifactRun,
    envelope: R1CausalAvailabilityEnvelope,
    *,
    run_metadata: RunMetadata,
    approved_policy: ApprovedLineagePolicy,
) -> R1CausalReplayInput:
    """검증된 artifact와 envelope를 evidence_id 기준으로 정확히 결합한다."""
    if not isinstance(artifact_run, R1EvidenceArtifactRun):
        raise TypeError("artifact_run must be an R1EvidenceArtifactRun")
    if not isinstance(envelope, R1CausalAvailabilityEnvelope):
        raise TypeError("envelope must be an R1CausalAvailabilityEnvelope")
    if not isinstance(run_metadata, RunMetadata):
        raise TypeError("run_metadata must be a RunMetadata")
    if not isinstance(approved_policy, ApprovedLineagePolicy):
        raise TypeError("approved_policy must be an ApprovedLineagePolicy")

    # model_copy 등으로 우회된 값도 version-specific envelope validator로 다시 막는다.
    envelope = R1CausalAvailabilityEnvelope.model_validate(
        envelope.model_dump(),
        strict=True,
    )
    if run_metadata.end_time is None:
        raise ValueError("causal replay requires authoritative RunMetadata.end_time")
    if envelope.run_id != run_metadata.run_id:
        raise ValueError("causal envelope run_id must match RunMetadata run_id")
    if envelope.entity_id != run_metadata.target_host:
        raise ValueError("causal envelope entity_id must match RunMetadata target_host")
    if envelope.run_start != run_metadata.start_time:
        raise ValueError("causal envelope run_start must match RunMetadata start_time")
    if envelope.run_end != run_metadata.end_time:
        raise ValueError("causal envelope run_end must match RunMetadata end_time")
    if run_metadata.family_id is None:
        raise ValueError("causal replay requires RunMetadata.family_id")
    validate_r1_policy_family_binding(run_metadata.family_id, approved_policy)

    summary = artifact_run.summary
    if summary.status != "completed":
        raise ValueError("causal replay requires a completed Evidence artifact")
    if summary.run_id != envelope.run_id:
        raise ValueError("Evidence summary run_id must match causal envelope run_id")
    if summary.diagnostics:
        raise ValueError("causal replay requires an artifact without extraction diagnostics")
    if summary.evidence_count != len(artifact_run.evidences):
        raise ValueError("Evidence summary count must match loaded Evidence")
    if envelope.source_evidence_count != len(artifact_run.evidences):
        raise ValueError("causal envelope count must match loaded Evidence")
    if summary.extractor_version != envelope.source_extractor_version:
        raise ValueError("causal envelope extractor version must match Evidence summary")
    if summary.evidence_artifact_sha256 != envelope.source_evidence_artifact_sha256:
        raise ValueError("causal envelope Evidence SHA-256 must match loaded artifact")
    if artifact_run.summary_artifact_sha256 != envelope.source_extraction_summary_sha256:
        raise ValueError("causal envelope summary SHA-256 must match loaded artifact")

    selector = summary.selector
    if selector is None or selector.status != "selected":
        raise ValueError("causal replay requires selected selector provenance")
    selector_identity = R1CausalPolicyIdentity(
        policy_id=selector.policy_id,
        version=selector.version,
        config_hash=selector.config_hash,
    )
    if selector_identity != envelope.selector_policy_identity:
        raise ValueError("selector identity must match the causal envelope")

    lineage_inputs = summary.lineage_inputs
    if lineage_inputs is None or len(lineage_inputs) != 1:
        raise ValueError("causal replay requires one lineage provenance input")
    lineage = lineage_inputs[0]
    approved_identity = R1CausalPolicyIdentity(
        policy_id=lineage.policy_id,
        version=lineage.policy_version,
        config_hash=lineage.policy_config_hash,
    )
    if approved_identity != envelope.approved_policy_identity:
        raise ValueError("approved policy identity must match the causal envelope")
    if approved_identity != R1CausalPolicyIdentity(
        policy_id=approved_policy.policy_id,
        version=approved_policy.version,
        config_hash=approved_policy.config_hash,
    ):
        raise ValueError("loaded approved policy identity must match the causal envelope")

    evidences_by_id = {}
    for evidence in artifact_run.evidences:
        if evidence.evidence_id in evidences_by_id:
            raise ValueError("loaded Evidence IDs must be unique")
        if evidence.run_id != envelope.run_id:
            raise ValueError("Evidence run_id must match the causal envelope")
        if evidence.entity_id != envelope.entity_id:
            raise ValueError("Evidence entity_id must match the causal envelope")
        evidences_by_id[evidence.evidence_id] = evidence

    availability_by_id = {}
    for availability in envelope.evidences:
        if availability.evidence_id in availability_by_id:
            raise ValueError("availability Evidence IDs must be unique")
        availability_by_id[availability.evidence_id] = availability
    if evidences_by_id.keys() != availability_by_id.keys():
        raise ValueError("Evidence and availability ID sets must match exactly")

    scheduled: list[ScheduledEvidence] = []
    for evidence_id, evidence in evidences_by_id.items():
        availability = availability_by_id[evidence_id]
        if availability.timestamp != evidence.timestamp:
            raise ValueError("availability timestamp must match Evidence timestamp")
        if availability.event_ids != tuple(evidence.event_ids):
            raise ValueError("availability event_ids must match Evidence event_ids")
        if availability.context_event_ids != lineage.context_event_ids:
            raise ValueError("availability context_event_ids must match lineage provenance")
        if availability.available_at < availability.timestamp:
            raise ValueError("available_at must not be earlier than Evidence timestamp")
        scheduled.append(
            ScheduledEvidence(
                evidence=evidence,
                available_at=availability.available_at,
            )
        )

    scheduled.sort(
        key=lambda item: (
            item.available_at,
            item.evidence.timestamp,
            item.evidence.evidence_id,
        )
    )
    return R1CausalReplayInput(scheduled_evidences=tuple(scheduled))


def prepare_r1_incremental_causal_replay_input(
    snapshot: R1IncrementalEvidenceSnapshot,
    envelope: R1IncrementalCausalAvailabilityEnvelope,
    checkpoint: R1IncrementalEvidenceCheckpoint,
    publication_receipt: R1IncrementalAvailabilityPublicationReceipt,
    *,
    run_metadata: RunMetadata,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
    candidate_policy: R1CandidateGenerationPolicy,
) -> R1CausalReplayInput:
    """Strictly join finalized incremental Evidence and v0.2 availability."""

    if not isinstance(snapshot, R1IncrementalEvidenceSnapshot):
        raise TypeError("snapshot must be an R1IncrementalEvidenceSnapshot")
    if not isinstance(envelope, R1IncrementalCausalAvailabilityEnvelope):
        raise TypeError("envelope must be an R1IncrementalCausalAvailabilityEnvelope")
    if not isinstance(checkpoint, R1IncrementalEvidenceCheckpoint):
        raise TypeError("checkpoint must be an R1IncrementalEvidenceCheckpoint")
    expected = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=run_metadata,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
        candidate_policy=candidate_policy,
    )
    validated = R1IncrementalCausalAvailabilityEnvelope.model_validate(
        envelope.model_dump(),
        strict=True,
    )
    if validated != expected:
        raise ValueError("incremental availability envelope does not match trusted inputs")
    validate_r1_incremental_availability_publication(publication_receipt, validated)

    evidences_by_id = {item.evidence_id: item for item in snapshot.evidences}
    if len(evidences_by_id) != len(snapshot.evidences):
        raise ValueError("incremental Evidence IDs must be unique")
    availability_by_id = {item.evidence_id: item for item in validated.evidences}
    if evidences_by_id.keys() != availability_by_id.keys():
        raise ValueError("incremental Evidence and availability ID sets must match exactly")
    scheduled = tuple(
        sorted(
            (
                ScheduledEvidence(
                    evidence=evidence,
                    available_at=publication_receipt.publication_completed_at,
                )
                for evidence_id, evidence in evidences_by_id.items()
            ),
            key=lambda item: (
                item.available_at,
                item.evidence.timestamp,
                item.evidence.evidence_id,
            ),
        )
    )
    return R1CausalReplayInput(scheduled_evidences=scheduled)


def run_r1_causal_replay(
    artifact_run: R1EvidenceArtifactRun,
    envelope: R1CausalAvailabilityEnvelope,
    *,
    run_metadata: RunMetadata,
    approved_policy: ApprovedLineagePolicy,
    config: FusionConfig,
    execution_commit: str,
) -> R1CausalReplayPipelineResult:
    """Ground Truth 입력 없이 R1 causal replay와 Fusion output을 생성한다."""
    if not isinstance(config, FusionConfig):
        raise TypeError("config must be a FusionConfig")
    causal_input = prepare_r1_causal_replay_input(
        artifact_run,
        envelope,
        run_metadata=run_metadata,
        approved_policy=approved_policy,
    )
    runner = config.build_runner()
    replay_result = runner.run_causal(
        causal_input.scheduled_evidences,
        run_id=envelope.run_id,
        entity_id=envelope.entity_id,
        run_start=envelope.run_start,
        run_end=envelope.run_end,
    )
    fusion_result = build_fusion_result(
        replay_result,
        run_id=envelope.run_id,
        entity_id=envelope.entity_id,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
    stopping_trace = FusionStoppingTrace(
        run_id=envelope.run_id,
        entity_id=envelope.entity_id,
        scoring_config_version=config.config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=point.timestamp,
                score=point.score,
                persistence_count=point.persistence_count,
                policy_state=point.policy_state,
            )
            for point in replay_result.stopping_trace
        ],
    )
    runtime_config_snapshot = build_fusion_runtime_config_snapshot(
        config=config,
        run_id=envelope.run_id,
        entity_id=envelope.entity_id,
    )
    terminal_partial_tick = (envelope.run_end - envelope.run_start) % runner.step_size != timedelta(
        0
    )
    provenance = R1CausalReplayProvenance(
        contract_version=R1_CAUSAL_REPLAY_PROVENANCE_CONTRACT_VERSION,
        run_id=envelope.run_id,
        entity_id=envelope.entity_id,
        source_causal_envelope_contract_version=envelope.contract_version,
        source_evidence_artifact_sha256=envelope.source_evidence_artifact_sha256,
        source_extraction_summary_sha256=envelope.source_extraction_summary_sha256,
        selector_policy_identity=envelope.selector_policy_identity,
        approved_policy_identity=envelope.approved_policy_identity,
        watermark_at=envelope.watermark_at,
        watermark_basis=envelope.watermark_basis,
        availability_gate_contract=R1_CAUSAL_AVAILABILITY_GATE_CONTRACT,
        replay_ordering_contract=R1_CAUSAL_REPLAY_ORDERING_CONTRACT,
        replay_start=envelope.run_start,
        replay_end=envelope.run_end,
        step_size_sec=config.replay.step_size_sec,
        terminal_partial_tick=terminal_partial_tick,
        evaluated_replay_points=tuple(point.timestamp for point in replay_result.trajectory),
        fusion_runtime_config=runtime_config_snapshot,
        fusion_result_sha256=canonical_model_sha256(fusion_result),
        fusion_stopping_trace_sha256=canonical_model_sha256(stopping_trace),
        fusion_status=fusion_result.fusion_status,
        fusion_time=fusion_result.fusion_time,
        contributing_evidence_ids=tuple(fusion_result.contributing_evidence_ids),
        fusion_episode_ids=tuple(episode.episode_id for episode in fusion_result.fusion_episodes),
        execution_commit=execution_commit,
    )
    return R1CausalReplayPipelineResult(
        replay_result=replay_result,
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
        provenance=provenance,
    )


def run_and_write_r1_causal_replay(
    artifact_run: R1EvidenceArtifactRun,
    envelope: R1CausalAvailabilityEnvelope,
    *,
    run_metadata: RunMetadata,
    approved_policy: ApprovedLineagePolicy,
    config: FusionConfig,
    execution_commit: str,
    output_directory: Path,
) -> R1CausalReplayArtifactPipelineResult:
    """Causal replay 후 별도 provenance artifact를 immutable하게 게시한다."""
    pipeline_result = run_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=run_metadata,
        approved_policy=approved_policy,
        config=config,
        execution_commit=execution_commit,
    )
    artifacts = write_r1_causal_replay_artifacts(
        pipeline_result.fusion_result,
        pipeline_result.stopping_trace,
        pipeline_result.provenance,
        output_directory=output_directory,
    )
    return R1CausalReplayArtifactPipelineResult(
        pipeline_result=pipeline_result,
        artifacts=artifacts,
        provenance_artifact=artifacts.provenance,
    )


__all__ = [
    "R1CausalReplayArtifactPipelineResult",
    "R1CausalReplayInput",
    "R1CausalReplayPipelineResult",
    "prepare_r1_causal_replay_input",
    "prepare_r1_incremental_causal_replay_input",
    "run_and_write_r1_causal_replay",
    "run_r1_causal_replay",
]
