"""Convert an explicit, version-pinned result snapshot into evaluation inputs.

These models are evaluation-side envelopes, not new runtime/DB contracts.
Fast episode extraction belongs to a separately versioned upstream policy.
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.evaluation.evaluation_v0 import evaluate

METHODS = ("Fast", "Fusion", "Hybrid")
COLUMNS = (
    "run_id",
    "entity_id",
    "scenario_id",
    "family_id",
    "variation_id",
    "class",
    "run_start",
    "run_end",
    "reference_time",
    "timestamp",
    "method",
    "decision_id",
    "config_version",
    "scoring_config_version",
    "detector_set_version",
    "fast_episode_policy_version",
)


class EvaluationPlan(BaseModel):
    """Versions and exact inventory chosen before reading experiment outcomes."""

    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str
    purpose: Literal["smoke", "performance"]
    decision_ids: dict[str, str]
    decision_config_version: str
    scoring_config_version: str
    detector_set_version: str
    fast_episode_policy_version: str
    evaluation_horizon_sec: int = Field(ge=0)
    parallel_required: Literal[True] = True


class FastEpisodeStarts(BaseModel):
    """Complete upstream episode starts for one measured Run/entity interval."""

    model_config = ConfigDict(extra="forbid")
    run_id: str
    entity_id: str
    policy_version: str
    detector_set_version: str
    observation_start: datetime
    observation_end: datetime
    start_times: list[datetime]


class StoredRunResults(BaseModel):
    """One snapshot bundle; absent results are errors, never detector misses."""

    model_config = ConfigDict(extra="forbid")
    run_metadata: RunMetadata
    detection: DetectionResult | None = None
    fusion: FusionResult | None = None
    decision: DecisionResult | None = None
    fast_episodes: FastEpisodeStarts | None = None


class EvaluationSnapshot(BaseModel):
    """Explicit result export whose Run inventory is checked against the plan."""

    model_config = ConfigDict(extra="forbid")
    snapshot_id: str
    plan: EvaluationPlan
    runs: list[StoredRunResults]


def load_evaluation_snapshot(path: Path) -> EvaluationSnapshot:
    """Load exported model payloads without opening production database connections."""
    return EvaluationSnapshot.model_validate_json(path.read_text(encoding="utf-8"))


def _identifier(value: str, name: str) -> None:
    if not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be non-blank without surrounding whitespace")


def _time(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond % 1000:
        raise ValueError(f"{name} must use UTC millisecond precision")


def _validate_bundle(bundle: StoredRunResults, plan: EvaluationPlan) -> None:
    run = bundle.run_metadata
    if run.end_time is None:
        raise ValueError(f"{run.run_id}: missing measured end_time")
    for name in ("start_time", "end_time", "reference_time"):
        value = getattr(run, name)
        if value is not None:
            _time(value, name)
    if run.run_type == "attack":
        if run.reference_time is None:
            raise ValueError(f"{run.run_id}: attack reference_time is required")
        if not run.start_time <= run.reference_time <= run.end_time:
            raise ValueError("reference_time must lie within the measured Run")
    if run.scenario_id != plan.scenario_id:
        raise ValueError("scenario_id must match plan; evaluate S0 separately")
    if run.detector_set_version != plan.detector_set_version:
        raise ValueError("Run detector_set_version must match plan")
    for name in ("detection", "fusion", "decision"):
        result = getattr(bundle, name)
        if result is None:
            raise ValueError(f"{run.run_id}: missing {name} result")
        if result.run_id != run.run_id or result.entity_id != run.target_host:
            raise ValueError(f"{name} run_id/entity_id must match Run metadata")
    detection, fusion, decision = bundle.detection, bundle.fusion, bundle.decision
    assert detection is not None and fusion is not None and decision is not None
    if decision.decision_id != plan.decision_ids[run.run_id]:
        raise ValueError("decision_id must match the pinned execution")
    if decision.config_version != plan.decision_config_version:
        raise ValueError("decision config_version must match plan")
    if fusion.scoring_config_version != plan.scoring_config_version:
        raise ValueError("Fusion scoring_config_version must match plan")
    if decision.detector_set_version not in (None, plan.detector_set_version):
        raise ValueError("Decision detector_set_version must match plan")
    # A saved Decision must agree with the supplied path results, not a later DB overwrite.
    expected = combine_results(
        detection,
        fusion,
        decision_id=decision.decision_id,
        config_version=decision.config_version,
        parallel_required=True,
        source_hit_ids=decision.source_hit_ids,
        selected_source_hit_id=decision.selected_source_hit_id,
    )
    for name in (
        "fast_status",
        "fusion_status",
        "detector_time",
        "fusion_time",
        "t_e",
        "decision_path",
        "winning_path",
        "rule_version",
        "model_version",
        "contributing_evidence_ids",
    ):
        if getattr(decision, name) != getattr(expected, name):
            raise ValueError(f"Decision and path results disagree: {name}")
    for value in (detection.detector_time, fusion.fusion_time):
        if value is not None and not run.start_time <= value <= run.end_time:
            raise ValueError("runtime detection timestamp outside measured Run")


def _fast_starts(bundle: StoredRunResults, plan: EvaluationPlan) -> list[datetime]:
    detection, run, episodes = bundle.detection, bundle.run_metadata, bundle.fast_episodes
    assert detection is not None
    if detection.detector_status == "not_evaluated":
        if episodes is not None:
            raise ValueError("not_evaluated Fast must not carry episode history")
        return []
    if episodes is None:
        if detection.detector_status == "miss":
            return []
        raise ValueError("detected Fast requires complete versioned episode starts, not raw hits")
    if episodes.run_id != run.run_id or episodes.entity_id != run.target_host:
        raise ValueError("Fast episodes run_id/entity_id mismatch")
    if episodes.policy_version != plan.fast_episode_policy_version:
        raise ValueError("Fast episode policy_version mismatch")
    if episodes.detector_set_version != plan.detector_set_version:
        raise ValueError("Fast episode detector_set_version mismatch")
    for name in ("observation_start", "observation_end"):
        _time(getattr(episodes, name), name)
    if (episodes.observation_start, episodes.observation_end) != (run.start_time, run.end_time):
        raise ValueError("Fast episode history must cover the entire measured Run")
    starts = sorted(episodes.start_times)
    for timestamp in starts:
        _time(timestamp, "Fast episode start")
        if not episodes.observation_start <= timestamp <= episodes.observation_end:
            raise ValueError("Fast episode outside measured Run")
    if detection.detector_status == "miss" and starts:
        raise ValueError("miss Fast must not carry episode starts")
    if detection.detector_status == "detected" and (
        not starts or starts[0] != detection.detector_time
    ):
        raise ValueError("first Fast episode must match detector_time")
    return starts


def _fusion_starts(bundle: StoredRunResults) -> list[datetime]:
    fusion, run = bundle.fusion, bundle.run_metadata
    assert fusion is not None and run.end_time is not None
    episodes = sorted(fusion.fusion_episodes, key=lambda item: item.start_time)
    previous_end = None
    for episode in episodes:
        _time(episode.start_time, "Fusion episode start")
        if episode.end_time is None:
            raise ValueError("completed Fusion episode end_time is required")
        _time(episode.end_time, "Fusion episode end")
        if not run.start_time <= episode.start_time <= episode.end_time <= run.end_time:
            raise ValueError("Fusion episode outside measured Run")
        if previous_end is not None and episode.start_time < previous_end:
            raise ValueError("Fusion episodes must not overlap")
        previous_end = episode.end_time
    return [episode.start_time for episode in episodes]


def build_evaluation_inputs(
    snapshot: EvaluationSnapshot,
) -> tuple[dict[str, pd.DataFrame], list[dict[str, str]]]:
    """Validate a complete inventory and derive per-path eligible start times.

    Missing artifacts raise. Unexecuted paths are explicitly excluded and listed.
    A pre-reference episode continuing past reference receives no detection credit.
    Hybrid time is the minimum *eligible* Fast/Fusion time, never runtime t_e.
    """
    # Revalidate mutated model instances without silently truncating time precision.
    snapshot = EvaluationSnapshot.model_validate(snapshot.model_dump(mode="python"))
    plan = snapshot.plan
    _identifier(snapshot.snapshot_id, "snapshot_id")
    for name in (
        "scenario_id",
        "decision_config_version",
        "scoring_config_version",
        "detector_set_version",
        "fast_episode_policy_version",
    ):
        _identifier(getattr(plan, name), name)
    if plan.scenario_id == "S0" and plan.purpose != "smoke":
        raise ValueError("S0 must be evaluated separately for smoke purposes only")
    run_ids = [bundle.run_metadata.run_id for bundle in snapshot.runs]
    if not run_ids or len(set(run_ids)) != len(run_ids):
        raise ValueError("Run inventory must be nonempty and contain unique run_ids")
    if set(run_ids) != set(plan.decision_ids):
        raise ValueError("Run inventory must exactly match the planned decision_ids")
    if len(set(plan.decision_ids.values())) != len(plan.decision_ids):
        raise ValueError("planned decision_ids must be unique")
    for decision_id in plan.decision_ids.values():
        _identifier(decision_id, "decision_id")
    rows: dict[str, list[dict]] = {method: [] for method in METHODS}
    exclusions = []
    horizon = timedelta(seconds=plan.evaluation_horizon_sec)
    for bundle in snapshot.runs:
        _validate_bundle(bundle, plan)
        run, detection, fusion, decision = (
            bundle.run_metadata,
            bundle.detection,
            bundle.fusion,
            bundle.decision,
        )
        assert detection is not None and fusion is not None and decision is not None
        assert run.end_time is not None
        starts = {"Fast": _fast_starts(bundle, plan), "Fusion": _fusion_starts(bundle)}
        lower = run.reference_time if run.run_type == "attack" else run.start_time
        assert lower is not None
        upper = min(lower + horizon, run.end_time) if run.run_type == "attack" else run.end_time
        eligible = {
            method: min((t for t in times if lower <= t <= upper), default=None)
            for method, times in starts.items()
        }
        eligible["Hybrid"] = min(
            (time for time in eligible.values() if time is not None), default=None
        )
        unavailable = {
            "Fast": detection.detector_status == "not_evaluated",
            "Fusion": fusion.fusion_status == "not_evaluated",
        }
        unavailable["Hybrid"] = unavailable["Fast"] or unavailable["Fusion"]
        for method in METHODS:
            if unavailable[method]:
                exclusions.append(
                    {"run_id": run.run_id, "method": method, "reason": "not_evaluated"}
                )
                continue
            rows[method].append(
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
                    "timestamp": eligible[method],
                    "method": method,
                    "decision_id": decision.decision_id,
                    "config_version": decision.config_version,
                    "scoring_config_version": fusion.scoring_config_version,
                    "detector_set_version": plan.detector_set_version,
                    "fast_episode_policy_version": plan.fast_episode_policy_version,
                }
            )
    frames = {}
    for method, values in rows.items():
        frame = pd.DataFrame(values, columns=COLUMNS)
        for name in ("run_start", "run_end", "reference_time", "timestamp"):
            frame[name] = pd.to_datetime(frame[name], utc=True)
        frames[method] = frame
    return frames, exclusions


def evaluate_snapshot(snapshot: EvaluationSnapshot) -> dict:
    """Evaluate each path and expose missing execution coverage alongside metrics."""
    frames, exclusions = build_evaluation_inputs(snapshot)
    horizon = pd.Timedelta(seconds=snapshot.plan.evaluation_horizon_sec)
    cohorts = {method: frame["run_id"].tolist() for method, frame in frames.items()}
    return {
        "snapshot_id": snapshot.snapshot_id,
        "plan": snapshot.plan.model_dump(mode="json"),
        "exclusions": exclusions,
        "evaluated_run_ids": cohorts,
        "comparison_ready": not exclusions,
        "metrics": {
            method: evaluate(frame, evaluation_horizon=horizon) if not frame.empty else None
            for method, frame in frames.items()
        },
    }


def main() -> None:
    """Print an evaluation report from a saved snapshot; never overwrite artifacts."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    args = parser.parse_args()
    report = evaluate_snapshot(load_evaluation_snapshot(args.snapshot))
    print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
