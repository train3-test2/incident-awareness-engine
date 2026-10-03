"""Normal-Run episode burden, separate from binary Benign Run FPR."""

from incident_awareness.evaluation.result_inputs import EvaluationSnapshot, build_evaluation_inputs


def evaluate_normal_alert_burden(snapshot: EvaluationSnapshot) -> dict:
    """Count upstream episodes per measured normal Run-hour for Fast and Fusion.

    Full snapshot validation is required even though only normal Runs enter this
    metric. No Hybrid episode union, raw-hit counting, or missing-result imputation.
    """
    snapshot = EvaluationSnapshot.model_validate(snapshot.model_dump(mode="python"))
    _, exclusions = build_evaluation_inputs(snapshot)
    normal_runs = [bundle for bundle in snapshot.runs if bundle.run_metadata.run_type == "normal"]
    normal_ids = {bundle.run_metadata.run_id for bundle in normal_runs}
    exclusions = [
        item
        for item in exclusions
        if item["run_id"] in normal_ids and item["method"] in ("Fast", "Fusion")
    ]
    excluded = {(item["run_id"], item["method"]) for item in exclusions}
    metrics = {}
    for method in ("Fast", "Fusion"):
        per_run = []
        for bundle in normal_runs:
            run = bundle.run_metadata
            if (run.run_id, method) in excluded:
                continue
            duration = (run.end_time - run.start_time).total_seconds()
            if duration <= 0:
                raise ValueError("evaluated normal Run must have positive observation duration")
            if method == "Fast":
                starts = bundle.fast_episodes.start_times
                if len(starts) != len(set(starts)):
                    raise ValueError("duplicate Fast episode starts are ambiguous")
                count = len(starts)
            else:
                count = len(bundle.fusion.fusion_episodes)
            per_run.append(
                {
                    "run_id": run.run_id,
                    "entity_id": run.target_host,
                    "false_alert_episodes": count,
                    "observation_seconds": duration,
                }
            )
        seconds = sum(row["observation_seconds"] for row in per_run)
        count = sum(row["false_alert_episodes"] for row in per_run)
        metrics[method] = {
            "evaluated_run_ids": [row["run_id"] for row in per_run],
            "false_alert_episodes": count,
            "benign_run_hours": seconds / 3600,
            "false_alerts_per_benign_run_hour": count * 3600 / seconds if seconds else None,
            "per_run": per_run,
        }
    return {
        "snapshot_id": snapshot.snapshot_id,
        "plan": snapshot.plan.model_dump(mode="json"),
        "normal_run_ids": [bundle.run_metadata.run_id for bundle in normal_runs],
        "exclusions": exclusions,
        "comparison_ready": bool(normal_runs) and not exclusions,
        "metrics": metrics,
    }
