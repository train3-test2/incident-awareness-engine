from dataclasses import dataclass

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.runtime_snapshot import DecisionRuntimeSnapshot
from incident_awareness.dashboard.decision_history import build_decision_history
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DecisionRuntimeSnapshotRepository,
    DetectionResultRepository,
    FusionResultRepository,
    FusionStoppingTraceRepository,
)

_CURRENT_READ_MAX_ATTEMPTS = 3


class DashboardReadConsistencyError(RuntimeError):
    """A stable Current Decision and Runtime view could not be read."""


@dataclass(frozen=True, slots=True)
class CurrentDecisionReadModel:
    decision: DecisionResult
    latest_detection_result: DetectionResult | None
    latest_fusion_result: FusionResult | None
    latest_fusion_stopping_trace: FusionStoppingTrace | None


@dataclass(frozen=True, slots=True)
class HistoricalDecisionReadModel:
    decision: DecisionResult
    runtime_snapshot: DecisionRuntimeSnapshot | None


class DashboardDecisionReader:
    def __init__(
        self,
        *,
        decision_repository: DecisionRepository,
        detection_repository: DetectionResultRepository,
        fusion_repository: FusionResultRepository,
        stopping_trace_repository: FusionStoppingTraceRepository,
        snapshot_repository: DecisionRuntimeSnapshotRepository,
    ) -> None:
        self._decision_repository = decision_repository
        self._detection_repository = detection_repository
        self._fusion_repository = fusion_repository
        self._stopping_trace_repository = stopping_trace_repository
        self._snapshot_repository = snapshot_repository

    def get_current(
        self,
        run_id: str,
        entity_id: str,
    ) -> CurrentDecisionReadModel | None:
        for _ in range(_CURRENT_READ_MAX_ATTEMPTS):
            head_before = self._decision_repository.get_current_head(run_id, entity_id)
            if head_before is None:
                return None

            detection_result = self._detection_repository.get(run_id, entity_id)
            fusion_result = self._fusion_repository.get(run_id, entity_id)
            stopping_trace = self._stopping_trace_repository.get(run_id, entity_id)
            head_after = self._decision_repository.get_current_head(run_id, entity_id)

            if head_after is not None and head_before.decision_id == head_after.decision_id:
                return CurrentDecisionReadModel(
                    decision=head_before,
                    latest_detection_result=detection_result,
                    latest_fusion_result=fusion_result,
                    latest_fusion_stopping_trace=stopping_trace,
                )

        raise DashboardReadConsistencyError(
            "unable to read a stable Current Decision and Runtime view after "
            f"{_CURRENT_READ_MAX_ATTEMPTS} attempts for "
            f"run_id={run_id!r}, entity_id={entity_id!r}"
        )

    def list_history(self, run_id: str, entity_id: str) -> list[DecisionResult]:
        decisions = self._decision_repository.list_by_scope(run_id, entity_id)
        return build_decision_history(decisions)

    def get_historical(self, decision_id: str) -> HistoricalDecisionReadModel | None:
        decision = self._decision_repository.get(decision_id)
        if decision is None:
            return None

        return HistoricalDecisionReadModel(
            decision=decision,
            runtime_snapshot=self._snapshot_repository.get(decision_id),
        )
