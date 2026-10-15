"""Evaluation-side binding of the versioned R1 causal replay artifacts.

This checks pinned provenance and availability, not the authenticity of a producer
or a full rerun of the scorer. Upstream strict-join validation remains required.
"""

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.pipeline.r1_causal_availability import R1CausalAvailabilityEnvelope
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    R1CausalReplayProvenance,
    canonical_model_sha256,
)


class CausalReplayPins(BaseModel):
    """Canonical model hashes selected for one execution before evaluation."""

    model_config = ConfigDict(extra="forbid")
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    envelope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CausalReplayEvaluationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provenance: R1CausalReplayProvenance
    envelope: R1CausalAvailabilityEnvelope
    stopping_trace: FusionStoppingTrace


def validate_causal_replay(
    value: CausalReplayEvaluationInput,
    pins: CausalReplayPins,
    *,
    run: RunMetadata,
    fusion: FusionResult,
    observation_start: datetime,
    observation_end: datetime,
) -> None:
    """Reject an unbound, backdated, or inconsistent causal evaluation result."""
    p, envelope, trace = value.provenance, value.envelope, value.stopping_trace
    if canonical_model_sha256(p) != pins.provenance_sha256:
        raise ValueError("causal provenance does not match the pinned execution hash")
    if canonical_model_sha256(envelope) != pins.envelope_sha256:
        raise ValueError("causal envelope does not match the pinned execution hash")
    for artifact in (p, envelope, trace):
        if (artifact.run_id, artifact.entity_id) != (run.run_id, run.target_host):
            raise ValueError("causal artifact Run/entity mismatch")
    if (envelope.run_start, envelope.run_end) != (run.start_time, run.end_time):
        raise ValueError("causal envelope must match authoritative Run boundaries")
    if (p.replay_start, p.replay_end) != (envelope.run_start, envelope.run_end):
        raise ValueError("causal replay must match envelope boundaries")
    if (observation_start, observation_end) != (p.replay_start, p.replay_end):
        raise ValueError("Fusion observation must match causal replay boundaries")
    if p.source_causal_envelope_contract_version != envelope.contract_version:
        raise ValueError("causal envelope version mismatch")
    for name in (
        "source_evidence_artifact_sha256",
        "source_extraction_summary_sha256",
        "selector_policy_identity",
        "approved_policy_identity",
        "watermark_at",
        "watermark_basis",
    ):
        if getattr(p, name) != getattr(envelope, name):
            raise ValueError(f"causal provenance/envelope mismatch: {name}")
    if canonical_model_sha256(fusion) != p.fusion_result_sha256:
        raise ValueError("FusionResult does not match causal provenance hash")
    if canonical_model_sha256(trace) != p.fusion_stopping_trace_sha256:
        raise ValueError("stopping trace does not match causal provenance hash")
    for name in ("fusion_status", "fusion_time"):
        if getattr(p, name) != getattr(fusion, name):
            raise ValueError(f"causal provenance/FusionResult mismatch: {name}")
    if p.contributing_evidence_ids != tuple(fusion.contributing_evidence_ids):
        raise ValueError("causal contributing Evidence mismatch")
    if p.fusion_episode_ids != tuple(e.episode_id for e in fusion.fusion_episodes):
        raise ValueError("causal episode identity mismatch")
    config = p.fusion_runtime_config
    if config.config_version != fusion.scoring_config_version:
        raise ValueError("causal runtime config version mismatch")
    if config.model_version != fusion.model_version:
        raise ValueError("causal runtime model version mismatch")
    for name, actual in (
        ("scoring_method", config.scoring.method),
        ("scorer_version", config.scoring.scorer_version),
        ("scoring_profile_id", config.scoring.profile_id),
    ):
        if getattr(fusion, name) != actual:
            raise ValueError(f"causal runtime config mismatch: {name}")
    if trace.scoring_config_version != config.config_version:
        raise ValueError("causal trace config version mismatch")
    if tuple(point.timestamp for point in trace.points) != p.evaluated_replay_points:
        raise ValueError("causal trace must cover every evaluated replay point")
    by_id = {item.evidence_id: item for item in envelope.evidences}
    points = {point.timestamp: point for point in trace.points}
    window = timedelta(seconds=config.window.window_size_sec)
    for point in trace.points:
        available = any(
            item.available_at <= point.timestamp
            and point.timestamp - window <= item.timestamp <= point.timestamp
            for item in envelope.evidences
        )
        if not available and point.score != 0:
            raise ValueError("causal trace score precedes available in-window Evidence")
    for episode in fusion.fusion_episodes:
        if episode.start_time not in points or episode.end_time not in points:
            raise ValueError("causal episode boundaries must be evaluated replay points")
        point = points[episode.start_time]
        if point.policy_state != "on" or point.score != episode.score_at_start:
            raise ValueError("causal episode start must match stopping trace")
        for evidence_id in episode.contributing_evidence_ids:
            evidence = by_id.get(evidence_id)
            if evidence is None:
                raise ValueError("causal episode references unknown Evidence")
            if evidence.available_at > episode.start_time:
                raise ValueError("causal episode precedes Evidence availability")
            if not episode.start_time - window <= evidence.timestamp <= episode.start_time:
                raise ValueError("causal episode Evidence is outside the event-time window")
