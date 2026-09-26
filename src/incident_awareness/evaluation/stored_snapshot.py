"""Read version-pinned evaluation inputs through the existing repositories."""

from collections.abc import Mapping

from psycopg import Connection
from psycopg.pq import TransactionStatus

from incident_awareness.evaluation.result_inputs import (
    EvaluationPlan,
    EvaluationSnapshot,
    FastEpisodeStarts,
    StoredRunResults,
    build_evaluation_inputs,
)
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository


def read_stored_snapshot(
    connection: Connection,
    *,
    snapshot_id: str,
    plan: EvaluationPlan,
    fast_episodes: Mapping[str, FastEpisodeStarts],
) -> EvaluationSnapshot:
    """Read the exact inventory in one read-only, repeatable-read transaction.

    Use a dedicated idle connection. No latest-Decision heuristic or inner join
    may silently remove missing Runs. Fast episode history is supplied separately
    because DetectionResult retains only the first runtime detection.
    """
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError("snapshot loading requires a dedicated idle database connection")
    if set(fast_episodes) - set(plan.decision_ids):
        raise ValueError("Fast episode history contains unplanned Runs")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        runs = []
        for run_id, decision_id in plan.decision_ids.items():
            run = RunRepository(connection).get(run_id)
            if run is None:
                raise ValueError(f"planned Run is missing: {run_id}")
            runs.append(
                StoredRunResults(
                    run_metadata=run,
                    detection=DetectionResultRepository(connection).get(run_id, run.target_host),
                    fusion=FusionResultRepository(connection).get(run_id, run.target_host),
                    decision=DecisionRepository(connection).get(decision_id),
                    fast_episodes=fast_episodes.get(run_id),
                )
            )
        snapshot = EvaluationSnapshot(snapshot_id=snapshot_id, plan=plan, runs=runs)
        build_evaluation_inputs(snapshot)
        return snapshot
