from dataclasses import dataclass

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.fusion_runtime_config import FusionRuntimeConfigSnapshot
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.dashboard.decision_read_model import DashboardReadConsistencyError
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    FusionResultRepository,
    FusionRuntimeConfigSnapshotRepository,
    FusionStoppingTraceRepository,
)

_CURRENT_READ_MAX_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class FusionEngineReadModel:
    current_decision: DecisionResult | None
    fusion_result: FusionResult | None
    stopping_trace: FusionStoppingTrace | None
    runtime_config_snapshot: FusionRuntimeConfigSnapshot | None


class DashboardFusionEngineReader:
    def __init__(
        self,
        *,
        decision_repository: DecisionRepository,
        fusion_repository: FusionResultRepository,
        stopping_trace_repository: FusionStoppingTraceRepository,
        runtime_config_repository: FusionRuntimeConfigSnapshotRepository,
    ) -> None:
        self._decision_repository = decision_repository
        self._fusion_repository = fusion_repository
        self._stopping_trace_repository = stopping_trace_repository
        self._runtime_config_repository = runtime_config_repository

    def get_current(self, run_id: str, entity_id: str) -> FusionEngineReadModel:
        for _ in range(_CURRENT_READ_MAX_ATTEMPTS):
            head_before = self._decision_repository.get_current_head(run_id, entity_id)
            fusion_result = self._fusion_repository.get(run_id, entity_id)
            stopping_trace = self._stopping_trace_repository.get(run_id, entity_id)
            runtime_config_snapshot = self._runtime_config_repository.get(run_id, entity_id)
            head_after = self._decision_repository.get_current_head(run_id, entity_id)

            if _same_current_head(head_before, head_after) and _runtime_versions_match(
                fusion_result,
                stopping_trace,
                runtime_config_snapshot,
            ):
                return FusionEngineReadModel(
                    current_decision=head_before,
                    fusion_result=fusion_result,
                    stopping_trace=stopping_trace,
                    runtime_config_snapshot=runtime_config_snapshot,
                )

        raise DashboardReadConsistencyError(
            "unable to read a stable Current Decision and Fusion Engine Runtime view after "
            f"{_CURRENT_READ_MAX_ATTEMPTS} attempts for "
            f"run_id={run_id!r}, entity_id={entity_id!r}"
        )


def _same_current_head(
    before: DecisionResult | None,
    after: DecisionResult | None,
) -> bool:
    if before is None or after is None:
        return before is after

    return before.decision_id == after.decision_id


def _runtime_versions_match(
    fusion_result: FusionResult | None,
    stopping_trace: FusionStoppingTrace | None,
    runtime_config_snapshot: FusionRuntimeConfigSnapshot | None,
) -> bool:
    versions = {
        version
        for version in (
            None if fusion_result is None else fusion_result.scoring_config_version,
            None if stopping_trace is None else stopping_trace.scoring_config_version,
            (None if runtime_config_snapshot is None else runtime_config_snapshot.config_version),
        )
        if version is not None
    }
    return len(versions) <= 1
