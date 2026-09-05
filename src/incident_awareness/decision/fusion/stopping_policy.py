from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True, slots=True)
class ScorePoint:
    timestamp: datetime
    score: float


@dataclass(frozen=True, slots=True)
class FusionEpisode:
    episode_id: str
    run_id: str
    entity_id: str | None
    start_time: datetime
    end_time: datetime
    end_reason: Literal["released", "run_end"]
    score_at_start: float
    peak_score: float


@dataclass(frozen=True, slots=True)
class StoppingResult:
    fusion_status: Literal["detected", "miss"]
    fusion_time: datetime | None
    score_at_decision: float | None
    fusion_episodes: tuple[FusionEpisode, ...]


class ThresholdStoppingPolicy:
    def __init__(
        self,
        *,
        threshold_on: float,
        threshold_off: float,
        persistence_k: int,
    ) -> None:
        if not 0.0 <= threshold_on <= 1.0:
            raise ValueError("threshold_on must be between 0.0 and 1.0")

        if not 0.0 <= threshold_off <= 1.0:
            raise ValueError("threshold_off must be between 0.0 and 1.0")

        if threshold_off >= threshold_on:
            raise ValueError("threshold_off must be less than threshold_on")

        if persistence_k < 1:
            raise ValueError("persistence_k must be at least 1")

        self.threshold_on = threshold_on
        self.threshold_off = threshold_off
        self.persistence_k = persistence_k

    def evaluate(
        self,
        trajectory: list[ScorePoint],
        *,
        run_id: str,
        entity_id: str | None,
        run_end: datetime,
    ) -> StoppingResult:
        consecutive = 0
        active = False
        fusion_time: datetime | None = None
        score_at_decision: float | None = None
        episode_start_time: datetime | None = None
        episode_score_at_start: float | None = None
        peak_score: float | None = None
        episodes: list[FusionEpisode] = []
        previous_timestamp: datetime | None = None

        for point in trajectory:
            if previous_timestamp is not None and point.timestamp < previous_timestamp:
                raise ValueError("ScorePoint timestamps must be non-decreasing")

            if point.timestamp > run_end:
                raise ValueError("ScorePoint timestamp must not exceed run_end")

            previous_timestamp = point.timestamp

            if active:
                if point.score < self.threshold_off:
                    assert episode_start_time is not None
                    assert episode_score_at_start is not None
                    assert peak_score is not None

                    episodes.append(
                        FusionEpisode(
                            episode_id=f"FEP-{len(episodes) + 1:03d}",
                            run_id=run_id,
                            entity_id=entity_id,
                            start_time=episode_start_time,
                            end_time=point.timestamp,
                            end_reason="released",
                            score_at_start=episode_score_at_start,
                            peak_score=peak_score,
                        )
                    )

                    active = False
                    consecutive = 0
                    episode_start_time = None
                    episode_score_at_start = None
                    peak_score = None
                    continue

                if peak_score is None or point.score > peak_score:
                    peak_score = point.score

                continue

            if point.score >= self.threshold_on:
                consecutive += 1
            else:
                consecutive = 0

            if consecutive >= self.persistence_k:
                active = True
                consecutive = 0
                episode_start_time = point.timestamp
                episode_score_at_start = point.score
                peak_score = point.score

                if fusion_time is None:
                    fusion_time = point.timestamp
                    score_at_decision = point.score

        if fusion_time is None:
            return StoppingResult(
                fusion_status="miss",
                fusion_time=None,
                score_at_decision=None,
                fusion_episodes=(),
            )

        if active:
            assert episode_start_time is not None
            assert episode_score_at_start is not None
            assert peak_score is not None

            episodes.append(
                FusionEpisode(
                    episode_id=f"FEP-{len(episodes) + 1:03d}",
                    run_id=run_id,
                    entity_id=entity_id,
                    start_time=episode_start_time,
                    end_time=run_end,
                    end_reason="run_end",
                    score_at_start=episode_score_at_start,
                    peak_score=peak_score,
                )
            )

        return StoppingResult(
            fusion_status="detected",
            fusion_time=fusion_time,
            score_at_decision=score_at_decision,
            fusion_episodes=tuple(episodes),
        )
