from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ScorePoint,
    StoppingResult,
    StoppingTracePoint,
    ThresholdStoppingPolicy,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine


@dataclass(frozen=True, slots=True)
class ReplayEvidenceSnapshot:
    timestamp: datetime
    contributing_evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScheduledEvidence:
    """Causal activation time과 Evidence semantic time을 분리한다."""

    evidence: Evidence
    available_at: datetime


@dataclass(frozen=True, slots=True)
class TemporalReplayResult:
    trajectory: tuple[ScorePoint, ...]
    evidence_snapshots: tuple[ReplayEvidenceSnapshot, ...]
    stopping_result: StoppingResult
    stopping_trace: tuple[StoppingTracePoint, ...] = ()


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
        replay_end: datetime | None = None,
    ) -> TemporalReplayResult:
        self._validate_run_time(run_start, field_name="run_start")
        self._validate_run_time(run_end, field_name="run_end")

        if run_end < run_start:
            raise ValueError("run_end must not be earlier than run_start")

        effective_end = run_end
        boundary_end_reason = "run_end"
        boundary_field_name = "run_end"

        if replay_end is not None:
            self._validate_run_time(replay_end, field_name="replay_end")

            if replay_end < run_start:
                raise ValueError("replay_end must not be earlier than run_start")

            if replay_end > run_end:
                raise ValueError("replay_end must not be later than run_end")

            effective_end = replay_end

            if replay_end < run_end:
                boundary_end_reason = "replay_end"
                boundary_field_name = "replay_end"

        if (effective_end - run_start) % self.step_size != timedelta(0):
            raise ValueError(f"{boundary_field_name} must align with step_size from run_start")

        ordered_evidences = list(evidences)
        previous_evidence_timestamp: datetime | None = None

        for evidence in ordered_evidences:
            self._validate_run_time(
                evidence.timestamp,
                field_name="Evidence timestamp",
            )

            if evidence.run_id != run_id:
                raise ValueError("Evidence run_id must match replay run_id")

            if evidence.entity_id != entity_id:
                raise ValueError("Evidence entity_id must match replay entity_id")

            if evidence.timestamp < run_start:
                raise ValueError("Evidence timestamp must not be earlier than run_start")

            if evidence.timestamp > effective_end:
                raise ValueError(f"Evidence timestamp must not exceed {boundary_field_name}")

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
        evidence_snapshots: list[ReplayEvidenceSnapshot] = []
        stopping_trace: list[StoppingTracePoint] = []
        evidence_index = 0
        current_time = run_start

        while current_time <= effective_end:
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

            evidence_snapshots.append(
                ReplayEvidenceSnapshot(
                    timestamp=current_time,
                    contributing_evidence_ids=self.scorer.contributing_evidence_ids(
                        active_evidence
                    ),
                )
            )

            current_time += self.step_size

        stopping_result = self.stopping_policy.evaluate(
            trajectory,
            run_id=run_id,
            entity_id=entity_id,
            run_end=effective_end,
            boundary_end_reason=boundary_end_reason,
            observer=stopping_trace.append,
        )

        return TemporalReplayResult(
            trajectory=tuple(trajectory),
            evidence_snapshots=tuple(evidence_snapshots),
            stopping_result=stopping_result,
            stopping_trace=tuple(stopping_trace),
        )

    def run_causal(
        self,
        scheduled_evidences: Iterable[ScheduledEvidence],
        *,
        run_id: str,
        entity_id: str,
        run_start: datetime,
        run_end: datetime,
    ) -> TemporalReplayResult:
        """Availability gate와 event-time window를 함께 적용해 replay한다."""
        self._validate_run_time(run_start, field_name="run_start")
        self._validate_run_time(run_end, field_name="run_end")
        if run_end < run_start:
            raise ValueError("run_end must not be earlier than run_start")

        scheduled_batch = tuple(scheduled_evidences)
        evidence_ids: set[str] = set()
        for scheduled in scheduled_batch:
            if not isinstance(scheduled, ScheduledEvidence):
                raise TypeError("scheduled_evidences must contain ScheduledEvidence items")

            evidence = scheduled.evidence
            if not isinstance(evidence, Evidence):
                raise TypeError("ScheduledEvidence.evidence must be an Evidence")
            self._validate_run_time(evidence.timestamp, field_name="Evidence timestamp")
            self._validate_run_time(scheduled.available_at, field_name="available_at")
            if evidence.evidence_id in evidence_ids:
                raise ValueError("scheduled Evidence IDs must be unique")
            evidence_ids.add(evidence.evidence_id)
            if evidence.run_id != run_id:
                raise ValueError("Evidence run_id must match replay run_id")
            if evidence.entity_id != entity_id:
                raise ValueError("Evidence entity_id must match replay entity_id")
            if not run_start <= evidence.timestamp <= run_end:
                raise ValueError("Evidence timestamp must fall within replay boundaries")
            if not run_start <= scheduled.available_at <= run_end:
                raise ValueError("available_at must fall within replay boundaries")
            if scheduled.available_at < evidence.timestamp:
                raise ValueError("available_at must not be earlier than Evidence timestamp")

        ordered_scheduled = tuple(
            sorted(
                scheduled_batch,
                key=lambda item: (
                    item.available_at,
                    item.evidence.timestamp,
                    item.evidence.evidence_id,
                ),
            )
        )
        replay_points = self._causal_replay_points(run_start=run_start, run_end=run_end)
        trajectory: list[ScorePoint] = []
        evidence_snapshots: list[ReplayEvidenceSnapshot] = []
        stopping_trace: list[StoppingTracePoint] = []
        activated: list[Evidence] = []
        scheduled_index = 0

        for replay_time in replay_points:
            while (
                scheduled_index < len(ordered_scheduled)
                and ordered_scheduled[scheduled_index].available_at <= replay_time
            ):
                activated.append(ordered_scheduled[scheduled_index].evidence)
                scheduled_index += 1

            # 늦게 활성화된 Evidence도 기존 semantic event-time window로만 평가한다.
            active_evidence = self.window_engine.filter_by_event_time_window(
                activated,
                timestamp=replay_time,
            )
            trajectory.append(
                ScorePoint(
                    timestamp=replay_time,
                    score=self.scorer.score(active_evidence),
                )
            )
            evidence_snapshots.append(
                ReplayEvidenceSnapshot(
                    timestamp=replay_time,
                    contributing_evidence_ids=self.scorer.contributing_evidence_ids(
                        active_evidence
                    ),
                )
            )

        stopping_result = self.stopping_policy.evaluate(
            trajectory,
            run_id=run_id,
            entity_id=entity_id,
            run_end=run_end,
            boundary_end_reason="run_end",
            observer=stopping_trace.append,
        )
        return TemporalReplayResult(
            trajectory=tuple(trajectory),
            evidence_snapshots=tuple(evidence_snapshots),
            stopping_result=stopping_result,
            stopping_trace=tuple(stopping_trace),
        )

    def _causal_replay_points(
        self,
        *,
        run_start: datetime,
        run_end: datetime,
    ) -> tuple[datetime, ...]:
        replay_points: list[datetime] = []
        replay_time = run_start
        while replay_time <= run_end:
            replay_points.append(replay_time)
            replay_time += self.step_size

        # Grid 밖 run_end도 authoritative terminal observation으로 한 번만 평가한다.
        if replay_points[-1] != run_end:
            replay_points.append(run_end)
        return tuple(replay_points)

    @staticmethod
    def _validate_run_time(value: datetime, *, field_name: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{field_name} must include timezone information")

        if value.utcoffset() != timedelta(0):
            raise ValueError(f"{field_name} must be UTC")
