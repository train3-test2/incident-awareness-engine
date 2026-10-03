from dataclasses import dataclass

from incident_awareness.common.models.result import DecisionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.dashboard.decision_read_model import (
    CurrentDecisionReadModel,
    DashboardDecisionReader,
    DashboardReadConsistencyError,
)

_RUN_DETAIL_READ_MAX_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class RunDetailReadModel:
    current_decision: CurrentDecisionReadModel | None
    decision_history: list[DecisionResult]


def get_run_detail(
    *,
    run: RunMetadata,
    reader: DashboardDecisionReader,
) -> RunDetailReadModel:
    entity_id = run.target_host
    for _ in range(_RUN_DETAIL_READ_MAX_ATTEMPTS):
        current = reader.get_current(run.run_id, entity_id)
        history = reader.list_history(run.run_id, entity_id)

        if current is None and not history:
            return RunDetailReadModel(
                current_decision=None,
                decision_history=[],
            )
        if (
            current is not None
            and history
            and current.decision.decision_id == history[0].decision_id
        ):
            return RunDetailReadModel(
                current_decision=current,
                decision_history=history,
            )

    raise DashboardReadConsistencyError(
        "unable to read a stable Current Decision and History view after "
        f"{_RUN_DETAIL_READ_MAX_ATTEMPTS} attempts for "
        f"run_id={run.run_id!r}, entity_id={entity_id!r}"
    )
