from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ScorePoint,
    StoppingResult,
    ThresholdStoppingPolicy,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine


@dataclass(frozen=True, slots=True)
class ReplayResult:
    trajectory: tuple[ScorePoint, ...]
    stopping_result: StoppingResult


def replay_fusion(
    *,
    evidence: Sequence[Evidence],
    run_id: str,
    entity_id: str,
    run_start: datetime,
    run_end: datetime,
    window_size: timedelta,
    step_size: timedelta,
    scorer: SimpleScorer,
    stopping_policy: ThresholdStoppingPolicy,
) -> ReplayResult:
    if run_end < run_start:
        raise ValueError("run_end must not be earlier than run_start")

    if step_size <= timedelta(0):
        raise ValueError("step_size must be greater than zero")

    run_duration = run_end - run_start

    if run_duration % step_size != timedelta(0):
        raise ValueError("run interval must align with step_size")

    previous_timestamp: datetime | None = None

    for item in evidence:
        if item.run_id != run_id:
            raise ValueError("Evidence run_id does not match replay run_id")

        if item.entity_id != entity_id:
            raise ValueError("Evidence entity_id does not match replay entity_id")

        if item.timestamp < run_start or item.timestamp > run_end:
            raise ValueError("Evidence timestamp must be inside the replay interval")

        if previous_timestamp is not None and item.timestamp < previous_timestamp:
            raise ValueError("Evidence timestamps must be non-decreasing")

        previous_timestamp = item.timestamp

    window = WindowEngine(window_size=window_size)

    trajectory: list[ScorePoint] = []
    evidence_index = 0
    current_time = run_start

    while current_time <= run_end:
        while evidence_index < len(evidence) and evidence[evidence_index].timestamp <= current_time:
            window.ingest(evidence[evidence_index])
            evidence_index += 1

        window.advance_to(
            run_id=run_id,
            entity_id=entity_id,
            timestamp=current_time,
        )

        active_evidence = window.get_active_evidence(
            run_id=run_id,
            entity_id=entity_id,
        )

        score = scorer.score(active_evidence)

        trajectory.append(
            ScorePoint(
                timestamp=current_time,
                score=score,
            )
        )

        current_time += step_size

    stopping_result = stopping_policy.evaluate(trajectory)

    return ReplayResult(
        trajectory=tuple(trajectory),
        stopping_result=stopping_result,
    )
