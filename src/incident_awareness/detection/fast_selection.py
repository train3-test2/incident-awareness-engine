"""Role 5 selection over a completed, configuration-pinned Fast handoff."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from incident_awareness.detection.fast_hit_adapter import (
    hayabusa_rows_to_fast_hits,
    read_hayabusa_csv,
)
from incident_awareness.detection.fast_runner import FastRunnerConfig, Identifier
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionSelection,
    FastHitRecord,
    Sha256,
    adapt_fast_hit_handoff,
    read_fast_hit_handoff,
)


class FastSelectionPolicy(BaseModel):
    """An operator-provided set/config binding, not approval inferred from hits."""

    model_config = ConfigDict(extra="forbid")
    policy_version: Literal["fast-selection-v1"]
    detector_set_version: Identifier
    detector_config_version: Identifier
    config_sha256: Sha256
    timestamp_source: Literal["hayabusa_csv_timestamp"]
    tie_break: Literal["timestamp_rule_id_hit_id"]
    host_entity_map: dict[Identifier, Identifier]


def select_fast_hit(
    *,
    hits_path: Path,
    trace_path: Path,
    policy: FastSelectionPolicy,
    run_id: str,
    entity_id: str,
) -> tuple[FastDetectionSelection, dict]:
    """Select earliest canonical millisecond hit; reject unknown ownership/configs."""
    policy = FastSelectionPolicy.model_validate(policy.model_dump(mode="json"))
    if entity_id not in policy.host_entity_map.values():
        raise ValueError("requested entity must be present in host_entity_map")
    handoff = read_fast_hit_handoff(hits_path, trace_path, run_id=run_id)
    if handoff.trace.config_sha256 != policy.config_sha256:
        raise ValueError("handoff config hash differs from selection policy")
    config = FastRunnerConfig.model_validate_json(Path(handoff.trace.config_path).read_bytes())
    if config.detector_config_version != policy.detector_config_version:
        raise ValueError("config version differs from selection policy")
    if not config.qualifying_rule_ids:
        raise ValueError("empty qualifying rule set cannot establish a measured miss")
    for rule_id in config.qualifying_rule_ids:
        if rule_id not in config.rule_metadata:
            raise ValueError("qualifying rule metadata is missing")
    # Verify semantics as well as hashes: a rewritten JSONL plus trace must not
    # silently omit earlier hits or change timestamps/rule metadata.
    expected = hayabusa_rows_to_fast_hits(
        read_hayabusa_csv(Path(handoff.trace.input_csv)),
        run_id=run_id,
        detector_engine_version=config.detector_engine_version,
        detector_config_version=config.detector_config_version,
        qualifying_rule_ids=set(config.qualifying_rule_ids),
        rule_metadata={k: v.model_dump() for k, v in config.rule_metadata.items()},
    )
    if tuple(FastHitRecord.model_validate(row) for row in expected) != handoff.records:
        raise ValueError("handoff differs from qualifying source CSV/config replay")
    for hit in handoff.records:
        if hit.native_host_id not in policy.host_entity_map:
            raise ValueError("qualifying hit has no explicit entity mapping")
    candidates = [
        h for h in handoff.records if policy.host_entity_map[h.native_host_id] == entity_id
    ]
    candidates.sort(key=lambda h: (h.timestamp, h.rule_id, h.hit_id))
    selected = candidates[0] if candidates else None
    selection = FastDetectionSelection(
        detector_status="detected" if selected else "miss",
        selected_hit_id=selected.hit_id if selected else None,
    )
    # Keep Role 3's mapping and result checks as the actual consumer boundary.
    adapt_fast_hit_handoff(
        handoff, entity_id=entity_id, selection=selection, entity_mapper=policy.host_entity_map.get
    )
    policy_json = json.dumps(
        policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    audit = {
        "run_id": run_id,
        "entity_id": entity_id,
        "policy": policy.model_dump(mode="json"),
        "policy_sha256": hashlib.sha256(policy_json.encode()).hexdigest(),
        "hits_sha256": handoff.trace.output_sha256,
        "trace_sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        "input_csv_sha256": handoff.trace.input_sha256,
        "candidate_hit_ids": [h.hit_id for h in candidates],
        "selection": selection.model_dump(mode="json"),
    }
    return selection, audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hits", "trace", "policy", "output-dir"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--entity-id", required=True)
    args = parser.parse_args()
    try:
        policy = FastSelectionPolicy.model_validate_json(args.policy.read_bytes())
        selection, audit = select_fast_hit(
            hits_path=args.hits,
            trace_path=args.trace,
            policy=policy,
            run_id=args.run_id,
            entity_id=args.entity_id,
        )
        args.output_dir.mkdir(exist_ok=False)
        (args.output_dir / "selection.json").write_text(
            selection.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        # Written last; consumers should require this completion/provenance file.
        (args.output_dir / "selection-audit.json").write_text(
            json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except (ValueError, TypeError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
