"""Evaluate Static ML replays against an explicit complete Run inventory."""

from datetime import timedelta
from typing import Literal

import pandas as pd

from incident_awareness.common.models.result import _serialize_utc_datetime
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evaluation.baselines.static_ml import StaticModel
from incident_awareness.evaluation.baselines.static_ml_episodes import (
    EpisodeConfig,
    TimedFeatureRow,
    _hash,
    replay_static_model,
)
from incident_awareness.evaluation.evaluation_v0 import evaluate


def evaluate_static_model(
    model: StaticModel,
    inventory: list[RunMetadata],
    rows_by_run: dict[str, list[TimedFeatureRow] | None],
    config: EpisodeConfig,
    *,
    coverage_sha256_by_run: dict[str, str],
    evaluation_horizon_sec: int,
    purpose: Literal["smoke", "performance"],
) -> dict:
    """None explicitly excludes an unexecuted Run; absent keys and empty rows fail.

    Evaluated inputs must cover the full start-anchored cadence grid through the
    last grid point <= measured end. Caller must verify telemetry completeness
    before supplying rows. Grid completeness alone is not collection evidence.
    """
    model = StaticModel.model_validate(model)
    config = EpisodeConfig.model_validate(config)
    if purpose not in ("smoke", "performance"):
        raise ValueError("purpose must be smoke or performance")
    if type(evaluation_horizon_sec) is not int or evaluation_horizon_sec < 0:
        raise ValueError("evaluation_horizon_sec must be a non-negative integer")
    try:
        horizon = timedelta(seconds=evaluation_horizon_sec)
    except OverflowError as exc:
        raise ValueError("horizon exceeds supported range") from exc
    inventory = [RunMetadata.model_validate(r.model_dump(mode="python")) for r in inventory]
    ids = [r.run_id for r in inventory]
    if not ids or len(ids) != len(set(ids)) or set(ids) != set(rows_by_run):
        raise ValueError("unique nonempty inventory must exactly match rows_by_run")
    if purpose != "smoke" and set(ids) & set(model.training_run_ids):
        raise ValueError("performance evaluation must not reuse training Runs")
    evaluated_ids = {key for key, value in rows_by_run.items() if value is not None}
    if set(coverage_sha256_by_run) != evaluated_ids or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
        for value in coverage_sha256_by_run.values()
    ):
        raise ValueError("evaluated Runs require coverage artifact SHA-256 references")
    frames, per_run, exclusions, artifacts = [], [], [], {}
    benign_seconds = benign_episodes = 0
    pre_reference_false_alerts = 0
    step = timedelta(seconds=config.step_seconds)
    for run in inventory:
        if purpose != "smoke" and run.scenario_id == "S0":
            raise ValueError("S0 is smoke-only")
        if run.end_time is None or run.end_time <= run.start_time:
            raise ValueError("measured Run must have positive duration")
        for time in (run.start_time, run.end_time, run.reference_time):
            if time is not None and (time.utcoffset() != timedelta(0) or time.microsecond % 1000):
                raise ValueError("Run times must be UTC milliseconds")
        if run.run_type == "attack" and run.reference_time is None:
            raise ValueError("attack requires reference_time")
        if run.run_type == "attack" and not (run.start_time <= run.reference_time <= run.end_time):
            raise ValueError("attack reference_time must be within the measured Run")
        source = rows_by_run[run.run_id]
        if source is None:
            exclusions.append({"run_id": run.run_id, "reason": "not_evaluated"})
            continue
        rows = [TimedFeatureRow.model_validate(r) for r in source]
        if not rows:
            raise ValueError("empty rows are not a miss")
        last_grid = run.start_time + ((run.end_time - run.start_time) // step) * step
        if rows[0].timestamp != run.start_time or rows[-1].timestamp != last_grid:
            raise ValueError("replay must cover the measured Run cadence grid")
        if any(r.run_id != run.run_id or r.entity_id != run.target_host for r in rows):
            raise ValueError("rows must match metadata Run/host")
        replay = replay_static_model(model, rows, config)
        artifacts[run.run_id] = replay
        starts = [pd.Timestamp(e["start_time"]).to_pydatetime() for e in replay["episodes"]]
        lower = run.reference_time if run.run_type == "attack" else run.start_time
        upper = (
            min(run.reference_time + horizon, run.end_time)
            if run.run_type == "attack"
            else run.end_time
        )
        eligible = min((t for t in starts if lower <= t <= upper), default=None)
        frames.append(
            {
                "run_id": run.run_id,
                "class": run.run_type.value,
                "run_start": run.start_time,
                "run_end": run.end_time,
                "reference_time": run.reference_time,
                "timestamp": eligible,
                "method": "StaticML",
            }
        )
        pre_reference_count = (
            sum(run.start_time <= t < run.reference_time for t in starts)
            if run.run_type == "attack"
            else None
        )
        if pre_reference_count is not None:
            pre_reference_false_alerts += pre_reference_count
        count = len(starts)
        seconds = (run.end_time - run.start_time).total_seconds()
        if run.run_type == "normal":
            benign_seconds += seconds
            benign_episodes += count
        per_run.append(
            {
                "run_id": run.run_id,
                "entity_id": run.target_host,
                "scenario_id": run.scenario_id,
                "family_id": run.family_id,
                "variation_id": run.variation_id,
                "repetition": run.repetition,
                "eligible_status": "detected" if eligible else "miss",
                "eligible_time": _serialize_utc_datetime(eligible),
                "episode_count": count,
                "pre_reference_false_alerts": pre_reference_count,
                "observation_seconds": seconds,
            }
        )
    frame = pd.DataFrame(frames)
    if frames:
        for field in ("run_start", "run_end", "reference_time", "timestamp"):
            frame[field] = pd.to_datetime(frame[field], utc=True)
    return {
        "schema_version": "static-ml-evaluation-v0.1",
        "purpose": purpose,
        "inventory_sha256": _hash([r.model_dump(mode="json") for r in inventory]),
        "model_sha256": _hash(model.model_dump(mode="json")),
        "config": config.model_dump(mode="json"),
        "evaluation_horizon_sec": evaluation_horizon_sec,
        "inventory_run_ids": ids,
        "training_run_ids": list(model.training_run_ids),
        "split_sha256": model.split_sha256,
        "coverage_sha256_by_run": coverage_sha256_by_run,
        "exclusions": exclusions,
        "comparison_ready": not exclusions,
        "metrics": evaluate(frame, evaluation_horizon=pd.Timedelta(horizon)) if frames else None,
        "alert_burden": {
            "false_alert_episodes": benign_episodes,
            "pre_reference_false_alerts": pre_reference_false_alerts,
            "benign_run_hours": benign_seconds / 3600,
            "false_alerts_per_benign_run_hour": benign_episodes * 3600 / benign_seconds
            if benign_seconds
            else None,
        },
        "per_run": per_run,
        "replays": artifacts,
    }
