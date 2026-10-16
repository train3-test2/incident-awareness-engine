"""Synthetic source-to-output pairing and eligible episode boundary regressions."""

import hashlib
import json
from dataclasses import replace

import pandas as pd
import pytest
from pydantic import ValidationError
from test_incremental_inputs import execution  # noqa: F401

from incident_awareness.common.models.fusion import FusionStoppingTrace, FusionStoppingTracePoint
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.evaluation.incremental_fusion_inputs import (
    IncrementalFusionPins,
    build_incremental_fusion_input,
)
from incident_awareness.evaluation.incremental_inputs import validate_incremental_execution_input
from incident_awareness.pipeline.r1_causal_replay_artifacts import canonical_model_sha256


@pytest.fixture
def output(execution):  # noqa: F811
    """Create synthetic producer outputs with a long test window to exercise detection."""
    directory, source, run, trust, f = execution
    config = f._config()
    inp = validate_incremental_execution_input(directory, source, run=run, trust=trust)
    replay = config.build_runner().run_causal(
        inp.scheduled_evidences,
        run_id=run.run_id,
        entity_id=run.target_host,
        run_start=run.start_time,
        run_end=run.end_time,
    )
    fusion = build_fusion_result(
        replay,
        run_id=run.run_id,
        entity_id=run.target_host,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
    trace = FusionStoppingTrace(
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
    result_path = directory / "fusion.json"
    trace_path = directory / "trace.json"
    result_path.write_text(fusion.model_dump_json())
    trace_path.write_text(trace.model_dump_json())
    pins = IncrementalFusionPins(
        contract_version="evaluation-incremental-fusion-v1",
        usage="synthetic_contract_check",
        source=source,
        config_sha256=canonical_model_sha256(config),
        fusion_result_sha256=hashlib.sha256(result_path.read_bytes()).hexdigest(),
        stopping_trace_sha256=hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        evaluation_horizon_sec=900,
    )
    return (
        directory,
        pins,
        run,
        replace(trust, ingress=f._ingress()),
        config,
        result_path,
        trace_path,
        fusion,
    )


def call(value, **changes):
    """Invoke the real evaluation converter with optional test overrides."""
    directory, pins, run, trust, config, result, trace, _ = value
    args = {"pins": pins, "run": run, "trust": trust, "config": config}
    args.update(changes)
    return build_incremental_fusion_input(directory, result, trace, **args)


def test_detected_input_is_eligible_and_scope_is_preserved(output):
    """Expose the first eligible episode without inventing Fast/Decision outputs."""
    record, frame = call(output)
    assert record.eligible_episode_start == output[-1].fusion_episodes[0].start_time
    assert record.handoff_accepted_at is None
    assert frame.iloc[0]["method"] == "Fusion"
    assert frame.attrs["usage"] == "synthetic_contract_check"
    assert "decision_id" not in frame


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_horizon_inclusive_boundary(output, delta):
    """Include an episode exactly at horizon, exclude one after horizon."""
    run = output[2].model_copy(
        update={"reference_time": output[2].reference_time.replace(microsecond=0)}
    )
    duration = int((output[-1].fusion_episodes[0].start_time - run.reference_time).total_seconds())
    source = output[1].source.model_copy(
        update={"run_metadata_sha256": canonical_model_sha256(run)}
    )
    pins = output[1].model_copy(
        update={"evaluation_horizon_sec": duration + delta, "source": source}
    )
    record, frame = call(output, pins=pins, run=run)
    assert (record.eligible_episode_start is None) == (delta < 0)
    assert pd.isna(frame.iloc[0]["timestamp"]) == (delta < 0)


@pytest.mark.parametrize("which", [5, 6])
def test_changed_bytes_rejected(output, which):
    """Reject modifications before relying on model equivalence."""
    path = output[which]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="pinned output bytes"):
        call(output)


def test_trace_tamper_rejected_even_with_updated_hash(output):
    """A matching outer hash does not authorize a fabricated trace."""
    path = output[6]
    data = json.loads(path.read_text())
    data["points"][0]["score"] = 0.5
    path.write_text(json.dumps(data))
    pins = output[1].model_copy(
        update={"stopping_trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    with pytest.raises(ValueError, match="stopping trace"):
        call(output, pins=pins)


def test_result_tamper_rejected_even_with_updated_hash(output):
    """Reject a plausible but unexecuted result identity."""
    path = output[5]
    data = json.loads(path.read_text())
    data["scoring_config_version"] = "other"
    path.write_text(json.dumps(data))
    pins = output[1].model_copy(
        update={"fusion_result_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    with pytest.raises(ValueError, match="source-bound replay"):
        call(output, pins=pins)


def test_changed_config_rejected(output):
    """Require the planned config, not a post-hoc window adjustment."""
    config = output[4].model_copy(
        update={"window": output[4].window.model_copy(update={"window_size_sec": 300})}
    )
    with pytest.raises(ValueError, match="config"):
        call(output, config=config)


def test_performance_promotion_rejected(output):
    """Keep the receipt limited to synthetic connection checks."""
    with pytest.raises(ValidationError):
        call(output, pins=output[1].model_copy(update={"usage": "performance"}))


def test_missing_output_is_not_miss(output):
    """Propagate absent execution artifacts instead of synthesizing a miss."""
    output[5].unlink()
    with pytest.raises(FileNotFoundError):
        call(output)
