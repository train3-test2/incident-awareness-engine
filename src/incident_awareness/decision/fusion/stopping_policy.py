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
