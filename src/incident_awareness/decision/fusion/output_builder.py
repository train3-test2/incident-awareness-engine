import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.fusion_output import FusionOutput
from incident_awareness.decision.fusion.replay import ReplayResult
from incident_awareness.decision.fusion.simple_score import SimpleScorer


@dataclass(frozen=True, slots=True)
class FusionOutputMetadata:
    scoring_method: str
    scorer_version: str
    evidence_schema_version: str
    scoring_config_version: str
    scoring_profile_id: str
    git_commit: str


def build_fusion_output(
    *,
    replay_result: ReplayResult,
    evidence: Sequence[Evidence],
    run_id: str,
    entity_id: str,
    window_size: timedelta,
    scorer: SimpleScorer,
    metadata: FusionOutputMetadata,
) -> FusionOutput:
    stopping_result = replay_result.stopping_result

    if stopping_result.fusion_status == "detected":
        if stopping_result.fusion_time is None:
            raise ValueError("detected replay result must have fusion_time")

        if stopping_result.score_at_decision is None:
            raise ValueError("detected replay result must have score_at_decision")

        fusion_time = stopping_result.fusion_time
        cutoff = fusion_time - window_size

        active_at_decision = [
            item
            for item in evidence
            if item.run_id == run_id
            and item.entity_id == entity_id
            and cutoff <= item.timestamp <= fusion_time
        ]

        scoring_evidence = scorer.select_scoring_evidence(active_at_decision)

        sorted_evidence = sorted(
            scoring_evidence,
            key=lambda item: (
                item.timestamp,
                item.evidence_id,
            ),
        )

        contributing_evidence_ids = [item.evidence_id for item in sorted_evidence]

        decision_reason = "threshold_persistence_satisfied"

    else:
        contributing_evidence_ids = []
        decision_reason = "stopping_condition_not_satisfied"

    return FusionOutput(
        run_id=run_id,
        entity_id=entity_id,
        fusion_status=stopping_result.fusion_status,
        fusion_time=stopping_result.fusion_time,
        score_at_decision=stopping_result.score_at_decision,
        contributing_evidence_ids=contributing_evidence_ids,
        decision_reason=decision_reason,
        scoring_method=metadata.scoring_method,
        scorer_version=metadata.scorer_version,
        evidence_schema_version=metadata.evidence_schema_version,
        scoring_config_version=metadata.scoring_config_version,
        scoring_profile_id=metadata.scoring_profile_id,
        git_commit=metadata.git_commit,
    )


def serialize_fusion_output(
    output: FusionOutput,
) -> bytes:
    payload = output.model_dump(
        mode="json",
        exclude_none=False,
    )

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return f"{serialized}\n".encode()


def write_fusion_output(
    output: FusionOutput,
    path: Path,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_bytes(serialize_fusion_output(output))
