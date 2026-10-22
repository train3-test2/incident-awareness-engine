"""Bind v0.2 source execution to Fusion outputs for synthetic input checks only."""

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import FusionConfig
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.evaluation.evaluation_v0 import _validate_precision
from incident_awareness.evaluation.incremental_inputs import (
    IncrementalInputPins,
    IncrementalInputTrust,
    validate_incremental_execution_input,
)
from incident_awareness.pipeline.r1_causal_replay_artifacts import canonical_model_sha256


class IncrementalFusionPins(BaseModel):
    """Evaluation-side receipt, not an approved producer provenance contract.

    Register pins only after reviewing producer source/output bindings. The config
    digest is canonical model content; output digests are exact received bytes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["evaluation-incremental-fusion-v1"]
    usage: Literal["synthetic_contract_check"]
    source: IncrementalInputPins
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fusion_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stopping_trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_horizon_sec: int = Field(strict=True, ge=0)


class IncrementalFusionInput(BaseModel):
    """Validated consumer record; never implicitly authorizes performance evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["evaluation-incremental-fusion-v1"]
    usage: Literal["synthetic_contract_check"]
    pins: IncrementalFusionPins
    run_id: str
    entity_id: str
    inputs_validated_at: datetime
    fusion_status: Literal["detected", "miss"]
    eligible_episode_start: datetime | None
    replay_points: int
    # No historical receive observation exists in the current handoff.
    handoff_accepted_at: None = None


def build_incremental_fusion_input(
    source_directory: Path,
    fusion_result_path: Path,
    stopping_trace_path: Path,
    pins: IncrementalFusionPins,
    *,
    run: RunMetadata,
    config: FusionConfig,
    trust: IncrementalInputTrust,
) -> tuple[IncrementalFusionInput, pd.DataFrame]:
    """Revalidate sources and independently replay before deriving an eligible start.

    Missing/invalid inputs and post-Run availability raise; they never become miss.
    No DecisionResult or Fast output is fabricated. The returned Fusion-only frame
    has the evaluator's input columns but is synthetic, not a performance report.
    This function does not call evaluate() or write source/producer artifacts.
    """
    pins = IncrementalFusionPins.model_validate(pins.model_dump())
    run = RunMetadata.model_validate(run.model_dump())
    config = FusionConfig.model_validate(config.model_dump())
    if canonical_model_sha256(config) != pins.config_sha256:
        raise ValueError("Fusion config differs from pinned execution")
    result_bytes = fusion_result_path.read_bytes()
    trace_bytes = stopping_trace_path.read_bytes()
    if hashlib.sha256(result_bytes).hexdigest() != pins.fusion_result_sha256:
        raise ValueError("FusionResult differs from pinned output bytes")
    if hashlib.sha256(trace_bytes).hexdigest() != pins.stopping_trace_sha256:
        raise ValueError("stopping trace differs from pinned output bytes")
    fusion = FusionResult.model_validate_json(result_bytes)
    trace = FusionStoppingTrace.model_validate_json(trace_bytes)
    if run.end_time is None:
        raise ValueError("completed observation requires Run end")
    if run.reference_time is not None:
        _validate_precision(run.reference_time, "reference_time")
    if run.run_type == "attack":
        if run.reference_time is None or not run.start_time <= run.reference_time <= run.end_time:
            raise ValueError("attack requires an in-Run reference_time")
        lower = run.reference_time
        upper = min(lower + timedelta(seconds=pins.evaluation_horizon_sec), run.end_time)
    else:
        if run.reference_time is not None:
            raise ValueError("normal reference_time must be null")
        lower, upper = run.start_time, run.end_time
    inputs = validate_incremental_execution_input(
        source_directory, pins.source, run=run, trust=trust
    )
    replay = config.build_runner().run_causal(
        inputs.scheduled_evidences,
        run_id=run.run_id,
        entity_id=run.target_host,
        run_start=run.start_time,
        run_end=run.end_time,
    )
    expected = build_fusion_result(
        replay,
        run_id=run.run_id,
        entity_id=run.target_host,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
    expected_trace = FusionStoppingTrace(
        run_id=run.run_id,
        entity_id=run.target_host,
        scoring_config_version=config.config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=p.timestamp,
                score=p.score,
                persistence_count=p.persistence_count,
                policy_state=p.policy_state,
            )
            for p in replay.stopping_trace
        ],
    )
    if fusion != expected:
        raise ValueError("FusionResult/episodes differ from source-bound replay")
    if trace != expected_trace:
        raise ValueError("complete stopping trace differs from source-bound replay")
    eligible = min(
        (e.start_time for e in fusion.fusion_episodes if lower <= e.start_time <= upper),
        default=None,
    )
    validation = inputs.incremental_input_validation
    assert validation is not None
    record = IncrementalFusionInput(
        contract_version=pins.contract_version,
        usage=pins.usage,
        pins=pins,
        run_id=run.run_id,
        entity_id=run.target_host,
        inputs_validated_at=validation.inputs_validated_at,
        fusion_status=fusion.fusion_status,
        eligible_episode_start=eligible,
        replay_points=len(replay.trajectory),
    )
    frame = pd.DataFrame(
        [
            {
                "run_id": run.run_id,
                "entity_id": run.target_host,
                "scenario_id": run.scenario_id,
                "family_id": run.family_id,
                "variation_id": run.variation_id,
                "class": run.run_type.value,
                "run_start": run.start_time,
                "run_end": run.end_time,
                "reference_time": run.reference_time,
                "timestamp": eligible,
                "evaluation_horizon_sec": pins.evaluation_horizon_sec,
                "method": "Fusion",
                "scoring_config_version": fusion.scoring_config_version,
                "usage": pins.usage,
                "execution_receipt_sha256": canonical_model_sha256(pins),
            }
        ]
    )
    for name in ("run_start", "run_end", "reference_time", "timestamp"):
        frame[name] = pd.to_datetime(frame[name], utc=True)
    frame.attrs["usage"] = pins.usage
    return record, frame
