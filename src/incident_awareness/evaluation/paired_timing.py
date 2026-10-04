"""Descriptive Fast/Fusion timing on identical attack Runs, without imputation."""

from datetime import UTC
from statistics import median

import pandas as pd

from incident_awareness.evaluation.result_inputs import EvaluationSnapshot, build_evaluation_inputs


def compare_paired_timing(snapshot: EvaluationSnapshot) -> dict:
    """Compare first eligible episode starts, not latched result timestamps."""
    snapshot = EvaluationSnapshot.model_validate(snapshot.model_dump(mode="python"))
    frames, exclusions = build_evaluation_inputs(snapshot)
    indexed = {method: frames[method].set_index("run_id") for method in ("Fast", "Fusion")}
    counts = dict.fromkeys(
        ("both_detected", "fast_only", "fusion_only", "both_miss", "not_evaluated"), 0
    )
    rows = []
    deltas = []
    attack_ids = set()
    for bundle in sorted(snapshot.runs, key=lambda item: item.run_metadata.run_id):
        run = bundle.run_metadata
        if run.run_type != "attack":
            continue
        attack_ids.add(run.run_id)
        paths = {}
        times = {}
        for method in ("Fast", "Fusion"):
            frame = indexed[method]
            value = frame.loc[run.run_id, "timestamp"] if run.run_id in frame.index else None
            time = None if value is None or pd.isna(value) else value
            times[method] = time
            status = (
                "not_evaluated"
                if run.run_id not in frame.index
                else "detected"
                if time is not None
                else "miss"
            )
            paths[method] = {
                "eligible_status": status,
                "eligible_time": time.astimezone(UTC)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
                if time is not None
                else None,
                "ttsd_sec": (time - run.reference_time).total_seconds()
                if time is not None
                else None,
            }
        fast, fusion = times["Fast"], times["Fusion"]
        delta = None
        earlier = None
        if any(path["eligible_status"] == "not_evaluated" for path in paths.values()):
            outcome = "not_evaluated"
        elif fast is not None and fusion is not None:
            outcome = "both_detected"
            delta = (fusion - fast).total_seconds()
            deltas.append(delta)
            earlier = "Fast" if delta > 0 else "Fusion" if delta < 0 else "tie"
        elif fast is not None:
            outcome = "fast_only"
        elif fusion is not None:
            outcome = "fusion_only"
        else:
            outcome = "both_miss"
        counts[outcome] += 1
        rows.append(
            {
                "run_id": run.run_id,
                "entity_id": run.target_host,
                "family_id": run.family_id,
                "variation_id": run.variation_id,
                "repetition": run.repetition,
                "decision_id": bundle.decision.decision_id,
                "reference_time": run.reference_time.astimezone(UTC)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
                "paths": paths,
                "outcome": outcome,
                "fusion_minus_fast_sec": delta,
                "earlier_eligible_path": earlier,
            }
        )
    return {
        "schema_version": "paired-timing-v0.1",
        "snapshot_id": snapshot.snapshot_id,
        "plan": snapshot.plan.model_dump(mode="json"),
        "attack_run_ids": sorted(attack_ids),
        "exclusions": [
            item
            for item in exclusions
            if item["run_id"] in attack_ids and item["method"] in ("Fast", "Fusion")
        ],
        "paired_coverage_complete": bool(rows) and counts["not_evaluated"] == 0,
        "counts": counts,
        "both_detected_summary": {
            "run_count": len(deltas),
            "fast_earlier": sum(delta > 0 for delta in deltas),
            "fusion_earlier": sum(delta < 0 for delta in deltas),
            "ties": sum(delta == 0 for delta in deltas),
            "median_fusion_minus_fast_sec": median(deltas) if deltas else None,
        },
        "per_run": rows,
    }
