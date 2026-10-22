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
    return make_output(directory, source, run, trust, config, f)


def make_output(directory, source, run, trust, config, f):
    """Build actual runner output from the selected synthetic configuration."""
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
    result_path.write_text(fusion.model_dump_json(), encoding="utf-8")
    trace_path.write_text(trace.model_dump_json(), encoding="utf-8")
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
    # Given
    # When
    record, frame = call(output)
    # Then
    assert record.eligible_episode_start == output[-1].fusion_episodes[0].start_time
    assert record.handoff_accepted_at is None
    assert frame.iloc[0]["method"] == "Fusion"
    assert frame.attrs["usage"] == "synthetic_contract_check"
    assert "decision_id" not in frame


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_horizon_inclusive_boundary(output, delta):
    """Include an episode exactly at horizon, exclude one after horizon."""
    # Given
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
    # When
    record, frame = call(output, pins=pins, run=run)
    # Then
    assert (record.eligible_episode_start is None) == (delta < 0)
    assert pd.isna(frame.iloc[0]["timestamp"]) == (delta < 0)


@pytest.mark.parametrize("which", [5, 6])
def test_changed_bytes_rejected(output, which):
    """Reject modifications before relying on model equivalence."""
    # Given
    path = output[which]
    path.write_bytes(path.read_bytes() + b"\n")
    # When
    with pytest.raises(ValueError) as exc:
        call(output)

    # Then
    assert "pinned output bytes" in str(exc.value)


def test_trace_tamper_rejected_even_with_updated_hash(output):
    """A matching outer hash does not authorize a fabricated trace."""
    # Given
    path = output[6]
    data = json.loads(path.read_text(encoding="utf-8"))
    data["points"][0]["score"] = 0.5
    path.write_text(json.dumps(data), encoding="utf-8")
    pins = output[1].model_copy(
        update={"stopping_trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    # When
    with pytest.raises(ValueError) as exc:
        call(output, pins=pins)

    # Then
    assert "stopping trace" in str(exc.value)


def test_result_tamper_rejected_even_with_updated_hash(output):
    """Reject a plausible but unexecuted result identity."""
    # Given
    path = output[5]
    data = json.loads(path.read_text(encoding="utf-8"))
    data["scoring_config_version"] = "other"
    path.write_text(json.dumps(data), encoding="utf-8")
    pins = output[1].model_copy(
        update={"fusion_result_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    # When
    with pytest.raises(ValueError) as exc:
        call(output, pins=pins)

    # Then
    assert "source-bound replay" in str(exc.value)


def test_changed_config_rejected(output):
    """Require the planned config, not a post-hoc window adjustment."""
    # Given
    config = output[4].model_copy(
        update={"window": output[4].window.model_copy(update={"window_size_sec": 300})}
    )
    # When
    with pytest.raises(ValueError) as exc:
        call(output, config=config)

    # Then
    assert "config" in str(exc.value)


def test_performance_promotion_rejected(output):
    """Keep the receipt limited to synthetic connection checks."""
    # Given
    # When
    with pytest.raises(ValidationError) as exc:
        call(output, pins=output[1].model_copy(update={"usage": "performance"}))

    # Then
    assert str(exc.value)


def test_missing_output_is_not_miss(output):
    """Propagate absent execution artifacts instead of synthesizing a miss."""
    # Given
    output[5].unlink()
    # When
    with pytest.raises(FileNotFoundError) as exc:
        call(output)

    # Then
    assert str(exc.value)


@pytest.mark.parametrize("consumer_horizon", [799, 900])
def test_prefiltered_frame_requires_matching_evaluation_horizon(output, consumer_horizon):
    # Given
    from incident_awareness.evaluation.evaluation_v0 import evaluate

    pins = output[1].model_copy(update={"evaluation_horizon_sec": 799})
    _, frame = call(output, pins=pins)

    # When
    if consumer_horizon == 900:
        with pytest.raises(ValueError) as exc:
            evaluate(frame, evaluation_horizon=pd.Timedelta(seconds=consumer_horizon))
        error = str(exc.value)
        report = None
    else:
        report = evaluate(frame, evaluation_horizon=pd.Timedelta(seconds=consumer_horizon))
        error = None

    # Then
    assert frame.iloc[0].evaluation_horizon_sec == 799
    if error is not None:
        assert "must match evaluation_horizon" in error
    else:
        assert report is not None


def test_reference_lower_bound_is_inclusive(output):
    # Given
    start = output[-1].fusion_episodes[0].start_time
    run = output[2].model_copy(update={"reference_time": start})
    source = output[1].source.model_copy(
        update={"run_metadata_sha256": canonical_model_sha256(run)}
    )
    pins = output[1].model_copy(update={"source": source, "evaluation_horizon_sec": 0})

    # When
    record, frame = call(output, pins=pins, run=run)

    # Then
    assert record.eligible_episode_start == start
    assert frame.iloc[0].timestamp == start


def test_run_end_truncates_long_horizon(output):
    # Given
    pins = output[1].model_copy(update={"evaluation_horizon_sec": 3600})

    # When
    record, frame = call(output, pins=pins)

    # Then
    assert output[2].end_time < output[2].reference_time + pd.Timedelta(seconds=3600)
    assert record.eligible_episode_start <= output[2].end_time
    assert frame.iloc[0].run_end == output[2].end_time


def test_submillisecond_reference_is_rejected(output):
    # Given
    run = output[2].model_copy(
        update={"reference_time": output[2].reference_time.replace(microsecond=1)}
    )

    # When
    with pytest.raises(ValueError) as exc:
        call(output, run=run)

    # Then
    assert "millisecond precision" in str(exc.value)


@pytest.mark.parametrize("normal", [False, True])
def test_miss_has_null_timestamp_for_attack_and_normal(execution, normal):  # noqa: F811
    # Given
    from incident_awareness.common.models.run import RunType

    directory, source, run, trust, f = execution
    if normal:
        run = run.model_copy(update={"run_type": RunType.NORMAL, "reference_time": None})
        source = source.model_copy(update={"run_metadata_sha256": canonical_model_sha256(run)})
    config = f._config().model_copy(
        update={"window": f._config().window.model_copy(update={"window_size_sec": 300})}
    )
    value = make_output(directory, source, run, trust, config, f)

    # When
    record, frame = call(value)

    # Then
    assert record.fusion_status == "miss"
    assert record.eligible_episode_start is None
    assert pd.isna(frame.iloc[0].timestamp)
    assert frame.iloc[0]["class"] == ("normal" if normal else "attack")


@pytest.mark.parametrize("delay,expected", [(100, "detected"), (301, "miss")])
def test_300_second_window_with_synthetic_availability_delay(
    execution,  # noqa: F811
    monkeypatch,
    delay,
    expected,
):
    # Given: isolated scheduling contract; delay is not measured processing latency.
    from datetime import timedelta

    from incident_awareness.evaluation import incremental_fusion_inputs as module

    directory, source, run, trust, f = execution
    inputs = validate_incremental_execution_input(directory, source, run=run, trust=trust)
    scheduled = tuple(
        replace(item, available_at=item.evidence.timestamp + timedelta(seconds=delay))
        for item in inputs.scheduled_evidences
    )
    synthetic = replace(inputs, scheduled_evidences=scheduled)
    monkeypatch.setattr(module, "validate_incremental_execution_input", lambda *a, **kw: synthetic)
    monkeypatch.setattr(
        __import__(__name__, fromlist=["validate_incremental_execution_input"]),
        "validate_incremental_execution_input",
        lambda *a, **kw: synthetic,
    )
    config = f._config().model_copy(
        update={"window": f._config().window.model_copy(update={"window_size_sec": 300})}
    )
    value = make_output(directory, source, run, trust, config, f)

    # When
    record, frame = call(value)

    # Then
    assert record.fusion_status == expected
    assert pd.isna(frame.iloc[0].timestamp) == (expected == "miss")
