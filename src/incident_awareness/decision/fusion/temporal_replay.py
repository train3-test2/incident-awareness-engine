from collections.abc import Iterable
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
class TemporalReplayResult:
    trajectory: tuple[ScorePoint, ...]
    stopping_result: StoppingResult


class TemporalReplayRunner:
    def __init__(
        self,
        *,
        window_engine: WindowEngine,
        scorer: SimpleScorer,
        stopping_policy: ThresholdStoppingPolicy,
        step_size: timedelta,
    ) -> None:
        if step_size <= timedelta(0):
            raise ValueError("step_size must be greater than zero")

        self.window_engine = window_engine
        self.scorer = scorer
        self.stopping_policy = stopping_policy
        self.step_size = step_size

    def run(
        self,
        evidences: Iterable[Evidence],
        *,
        run_id: str,
        entity_id: str,
        run_start: datetime,
        run_end: datetime,
    ) -> TemporalReplayResult:
        self._validate_run_time(run_start, field_name="run_start")
        self._validate_run_time(run_end, field_name="run_end")

        if run_end < run_start:
            raise ValueError("run_end must not be earlier than run_start")

        ordered_evidences = list(evidences)
        previous_evidence_timestamp: datetime | None = None

        for evidence in ordered_evidences:
            if evidence.run_id != run_id:
                raise ValueError("Evidence run_id must match replay run_id")

            if evidence.entity_id != entity_id:
                raise ValueError("Evidence entity_id must match replay entity_id")

            if (
                previous_evidence_timestamp is not None
                and evidence.timestamp < previous_evidence_timestamp
            ):
                raise ValueError("Evidence timestamps must be non-decreasing")

            previous_evidence_timestamp = evidence.timestamp

        self.window_engine.reset(
            run_id=run_id,
            entity_id=entity_id,
        )

        trajectory: list[ScorePoint] = []
        evidence_index = 0
        current_time = run_start

        while current_time <= run_end:
            while (
                evidence_index < len(ordered_evidences)
                and ordered_evidences[evidence_index].timestamp <= current_time
            ):
                evidence = ordered_evidences[evidence_index]

                self.window_engine.ingest(evidence)
                evidence_index += 1

            self.window_engine.advance_to(
                run_id=run_id,
                entity_id=entity_id,
                timestamp=current_time,
            )

            active_evidence = self.window_engine.get_active_evidence(
                run_id=run_id,
                entity_id=entity_id,
            )

            trajectory.append(
                ScorePoint(
                    timestamp=current_time,
                    score=self.scorer.score(active_evidence),
                )
            )

            current_time += self.step_size

        stopping_result = self.stopping_policy.evaluate(
            trajectory,
            run_id=run_id,
            entity_id=entity_id,
            run_end=run_end,
        )

        return TemporalReplayResult(
            trajectory=tuple(trajectory),
            stopping_result=stopping_result,
        )

    @staticmethod
    def _validate_run_time(value: datetime, *, field_name: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must include timezone information")

        if value.utcoffset() != timedelta(0):
            raise ValueError(f"{field_name} must be UTC")
