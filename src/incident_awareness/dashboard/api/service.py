from dataclasses import dataclass

from incident_awareness.common.models.result import DecisionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.dashboard.decision_read_model import (
    CurrentDecisionReadModel,
    DashboardDecisionReader,
    DashboardReadConsistencyError,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

_RUN_DETAIL_READ_MAX_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class RunDetailReadModel:
    run: RunMetadata
    current_decision: CurrentDecisionReadModel | None
    decision_history: list[DecisionResult]


def get_run_detail(
    *,
    run_id: str,
    run_repository: RunRepository,
    reader: DashboardDecisionReader,
) -> RunDetailReadModel | None:
    for _ in range(_RUN_DETAIL_READ_MAX_ATTEMPTS):
        run_before = run_repository.get(run_id)
        if run_before is None:
            return None

        entity_id = run_before.target_host
        current = reader.get_current(run_id, entity_id)
        history = reader.list_history(run_id, entity_id)
        run_after = run_repository.get(run_id)

        run_is_stable = run_before == run_after
        decisions_are_stable = (current is None and not history) or (
            current is not None
            and history
            and current.decision.decision_id == history[0].decision_id
        )

        if run_is_stable and decisions_are_stable:
            return RunDetailReadModel(
                run=run_before,
                current_decision=current,
                decision_history=history,
            )

    raise DashboardReadConsistencyError(
        "unable to read a stable Current Decision and History view with Run Metadata after "
        f"{_RUN_DETAIL_READ_MAX_ATTEMPTS} attempts for "
        f"run_id={run_id!r}"
    )
