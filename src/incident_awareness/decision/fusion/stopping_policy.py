from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True, slots=True)
class ScorePoint:
    timestamp: datetime
    score: float


@dataclass(frozen=True, slots=True)
class StoppingResult:
    fusion_status: Literal["detected", "miss"]
    fusion_time: datetime | None
    score_at_decision: float | None


class ThresholdStoppingPolicy:
    def __init__(
        self,
        *,
        threshold_on: float,
        persistence_k: int,
    ) -> None:
        if not 0.0 <= threshold_on <= 1.0:
            raise ValueError("threshold_on must be between 0.0 and 1.0")

        if persistence_k < 1:
            raise ValueError("persistence_k must be at least 1")

        self.threshold_on = threshold_on
        self.persistence_k = persistence_k

    def evaluate(self, trajectory: list[ScorePoint]) -> StoppingResult:
        """완료된 Score trajectory를 대상으로 최종 Stopping 결과를 계산한다.

        이 함수의 ``miss``는 Run이 끝날 때까지 정지조건이 성립하지 않았다는
        최종 결과를 의미한다. 진행 중인 trajectory의 중간 상태를 ``miss``로
        해석해서는 안 된다.
        """

        consecutive = 0
        previous_timestamp: datetime | None = None

        for point in trajectory:
            if previous_timestamp is not None and point.timestamp < previous_timestamp:
                raise ValueError("ScorePoint timestamps must be non-decreasing")

            previous_timestamp = point.timestamp

            if point.score >= self.threshold_on:
                consecutive += 1
            else:
                consecutive = 0

            if consecutive >= self.persistence_k:
                return StoppingResult(
                    fusion_status="detected",
                    fusion_time=point.timestamp,
                    score_at_decision=point.score,
                )

        return StoppingResult(
            fusion_status="miss",
            fusion_time=None,
            score_at_decision=None,
        )
