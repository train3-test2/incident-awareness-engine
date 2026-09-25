"""Exercise actual repository reads against a deterministic database boundary."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from incident_awareness.evaluation.result_inputs import (
    build_evaluation_inputs,
    load_evaluation_snapshot,
)
from incident_awareness.evaluation.stored_snapshot import read_stored_snapshot

FIXTURE = Path("tests/fixtures/evaluation/result_snapshot.json")


class SnapshotConnection:
    def __init__(self, source):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.source = source
        self.queries = []
        self.finished = False

    @contextmanager
    def transaction(self):
        yield
        self.finished = True

    def execute(self, query, params=()):
        self.queries.append(query)
        if query.startswith("SET TRANSACTION"):
            return None
        tables = {
            "FROM runs": ("run_metadata", "metadata"),
            "FROM detection_results": ("detection", "payload"),
            "FROM fusion_results": ("fusion", "payload"),
            "FROM decisions": ("decision", "payload"),
        }
        for table, (field, _) in tables.items():
            if table in query:
                for bundle in self.source.runs:
                    result = getattr(bundle, field)
                    if result is None:
                        continue
                    key = result.decision_id if field == "decision" else result.run_id
                    if key == params[0]:
                        payload = result.model_dump(mode="json")
                        return SimpleNamespace(fetchone=lambda value=payload: (value,))
                return SimpleNamespace(fetchone=lambda: None)
        raise AssertionError(f"unexpected non-read SQL: {query}")


def test_exact_inventory_loaded_through_repositories_in_read_only_transaction():
    source = load_evaluation_snapshot(FIXTURE)
    connection = SnapshotConnection(source)
    actual = read_stored_snapshot(
        connection,
        snapshot_id=source.snapshot_id,
        plan=source.plan,
        fast_episodes={
            b.run_metadata.run_id: b.fast_episodes
            for b in source.runs
            if b.fast_episodes is not None
        },
    )
    assert actual == source
    assert connection.finished
    assert connection.queries[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    assert len(connection.queries) == 1 + len(source.runs) * 4
    assert len(build_evaluation_inputs(actual)[0]["Fast"]) == len(source.runs)


def test_missing_db_result_is_not_silently_dropped():
    source = load_evaluation_snapshot(FIXTURE)
    source.runs[0].detection = None
    with pytest.raises(ValueError, match="missing detection"):
        read_stored_snapshot(
            SnapshotConnection(source),
            snapshot_id="test",
            plan=source.plan,
            fast_episodes={
                b.run_metadata.run_id: b.fast_episodes
                for b in source.runs
                if b.fast_episodes is not None
            },
        )


def test_active_caller_transaction_is_not_modified():
    source = load_evaluation_snapshot(FIXTURE)
    connection = SnapshotConnection(source)
    connection.info.transaction_status = TransactionStatus.INTRANS
    with pytest.raises(ValueError, match="idle"):
        read_stored_snapshot(connection, snapshot_id="test", plan=source.plan, fast_episodes={})
    assert connection.queries == []
