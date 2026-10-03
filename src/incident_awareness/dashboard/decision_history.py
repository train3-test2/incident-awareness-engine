from collections.abc import Sequence

from incident_awareness.common.models.result import DecisionResult
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


def build_decision_history(
    decisions: Sequence[DecisionResult],
) -> list[DecisionResult]:
    """Build a newest-first Decision chain from immutable supersedes links."""
    if not decisions:
        return []

    expected_scope = (decisions[0].run_id, decisions[0].entity_id)
    decisions_by_id: dict[str, DecisionResult] = {}
    for decision in decisions:
        if (decision.run_id, decision.entity_id) != expected_scope:
            raise DecisionIntegrityError(
                "Decision history contains a scope mismatch for "
                f"decision_id={decision.decision_id!r}"
            )
        if decision.decision_id in decisions_by_id:
            raise DecisionIntegrityError(f"duplicate Decision decision_id={decision.decision_id!r}")
        decisions_by_id[decision.decision_id] = decision

    superseded_ids = {
        decision.supersedes_decision_id
        for decision in decisions
        if decision.supersedes_decision_id is not None
    }
    inferred_heads = [
        decision_id for decision_id in decisions_by_id if decision_id not in superseded_ids
    ]
    if not inferred_heads:
        raise DecisionIntegrityError("no current Decision head in stored history")
    if len(inferred_heads) > 1:
        raise DecisionIntegrityError(
            f"multiple current Decision heads in stored history: {inferred_heads!r}"
        )

    history: list[DecisionResult] = []
    visited: set[str] = set()
    current_id = inferred_heads[0]
    while True:
        if current_id in visited:
            raise DecisionIntegrityError(
                f"Decision lifecycle cycle detected at decision_id={current_id!r}"
            )

        current = decisions_by_id[current_id]
        visited.add(current_id)
        history.append(current)

        predecessor_id = current.supersedes_decision_id
        if predecessor_id is None:
            break
        if predecessor_id not in decisions_by_id:
            raise DecisionIntegrityError(
                f"Decision {current_id!r} references missing predecessor {predecessor_id!r}"
            )
        current_id = predecessor_id

    if len(visited) != len(decisions_by_id):
        disconnected_ids = [
            decision_id for decision_id in decisions_by_id if decision_id not in visited
        ]
        raise DecisionIntegrityError(
            f"Decision history contains disconnected decisions: {disconnected_ids!r}"
        )

    return history
