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
