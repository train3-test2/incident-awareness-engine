from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetryBucket,
    PipelineTelemetryInputIdentity,
    PipelineTelemetrySnapshot,
    TelemetryObservationIssue,
)
from incident_awareness.storage.repositories import (
    pipeline_telemetry_repository as repository_module,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryIntegrityError,
    PipelineTelemetryRepository,
)

START = datetime(2026, 10, 14, 1, tzinfo=UTC)


def _snapshot(
    *, execution_id: str = "execution-001", completed: int = 0
) -> PipelineTelemetrySnapshot:
    bucket = PipelineTelemetryBucket(
        bucket_start=START,
        bucket_end=START + timedelta(seconds=1),
        first_observed_at=START,
        last_observed_at=START,
        revision=1 + completed,
        input_accepted_count=3,
        processing_completed_count=completed,
        latency_sample_count=completed,
        latency_sum_ns=completed * 7,
    )
    return PipelineTelemetrySnapshot(
        snapshot_id=f"pipeline-telemetry:{execution_id}",
        execution_id=execution_id,
        run_id="RUN-20261014-001",
        entity_id="WIN-01",
        revision=1 + completed,
        input_total=3,
        input_accepted_at=START,
        last_observed_at=START,
        observation_status="observed",
        buckets=(bucket,),
    )


class _Cursor:
    def __init__(self, rows: list[tuple[object, ...]] | None = None) -> None:
        self.rows = rows or []

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self) -> None:
        self.autocommit = False
        self.isolation = "read committed"
        self.executions: dict[str, dict[str, object]] = {}
        self.buckets: dict[tuple[str, datetime], dict[str, object]] = {}
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.failure_on_bucket: datetime | None = None
        self.savepoint_rollbacks = 0
        self.locks = 0
        self.in_transaction = False

    @contextmanager
    def transaction(self) -> Iterator[None]:
        assert self.in_transaction  # SHOW begins the caller-owned outer transaction.
        executions, buckets = deepcopy(self.executions), deepcopy(self.buckets)
        try:
            yield
        except Exception:
            self.executions, self.buckets = executions, buckets
            self.savepoint_rollbacks += 1
            raise

    def _payload(self, execution_id: str) -> dict[str, object]:
        return {
            **deepcopy(self.executions[execution_id]),
            "buckets": [
                deepcopy(payload)
                for (identity, _), payload in sorted(self.buckets.items())
                if identity == execution_id
            ],
        }

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Cursor:
        self.queries.append((query, params))
        if query == "SHOW transaction_isolation":
            self.in_transaction = True
            return _Cursor([(self.isolation,)])
        if query == repository_module._TELEMETRY_ADVISORY_LOCK_SQL:
            self.locks += 1
            return _Cursor([(None,)])
        if query == repository_module._GET_EXECUTION:
            return (
                _Cursor([(self._payload(params[0]),)])
                if params[0] in self.executions
                else _Cursor()
            )
        if query == repository_module._UPSERT_EXECUTION:
            assert self.locks
            self.executions[params[0]] = deepcopy(params[-1].obj)
            return _Cursor([(1,)])
        if query == repository_module._UPSERT_BUCKET:
            if params[1] == self.failure_on_bucket:
                raise RuntimeError("injected DB write failure")
            self.buckets[(params[0], params[1])] = deepcopy(params[-1].obj)
            return _Cursor([(1,)])
        if query == repository_module._LIST_BUCKETS:
            execution_id, start, _, end, _ = params
            return _Cursor(
                [
                    (deepcopy(payload),)
                    for (identity, timestamp), payload in sorted(self.buckets.items())
                    if identity == execution_id
                    and (start is None or timestamp >= start)
                    and (end is None or timestamp < end)
                ]
            )
        if query == repository_module._LIST_EXECUTIONS:
            run_id, entity_id, limit = params
            values = [
                self._payload(identity)
                for identity, payload in self.executions.items()
                if payload["run_id"] == run_id and payload["entity_id"] == entity_id
            ]
            return _Cursor([(value,) for value in values[:limit]])
        raise AssertionError(f"unexpected query: {query}")


def test_saves_and_restores_snapshot_under_execution_lock() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    snapshot = _snapshot(completed=1)

    # When
    saved = repository.save_snapshot(snapshot)
    restored = repository.get_execution(snapshot.execution_id)

    # Then
    assert saved
    assert restored == snapshot
    assert connection.queries[:2] == [
        ("SHOW transaction_isolation", ()),
        (
            repository_module._TELEMETRY_ADVISORY_LOCK_SQL,
            (repository_module._telemetry_lock_key(snapshot.execution_id),),
        ),
    ]
    assert "buckets" not in connection.executions[snapshot.execution_id]


@pytest.mark.parametrize(
    "previous_identity",
    [None, PipelineTelemetryInputIdentity(kind="file_content_sha256_v1", sha256="a" * 64)],
)
@pytest.mark.parametrize("completed", [0, 1])
def test_execution_input_identity_cannot_change_even_on_stale_or_newer_snapshots(
    previous_identity, completed
) -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    previous = _snapshot(completed=1).model_copy(update={"input_identity": previous_identity})
    repository.save_snapshot(previous)
    changed = _snapshot(completed=completed).model_copy(
        update={
            "input_identity": PipelineTelemetryInputIdentity(
                kind="s3_object_sha256_v1", sha256="b" * 64
            ),
        }
    )

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="identity"):
        repository.save_snapshot(changed)

    # Then
    assert repository.get_execution(previous.execution_id) == previous


def test_identical_and_older_snapshots_are_no_write_no_ops() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    snapshot = _snapshot(completed=1)
    repository.save_snapshot(snapshot)
    connection.queries.clear()

    # When
    identical = repository.save_snapshot(snapshot)
    stale = repository.save_snapshot(_snapshot())

    # Then
    assert not identical and not stale
    assert repository.get_execution(snapshot.execution_id) == snapshot
    assert not any(
        query in {repository_module._UPSERT_BUCKET, repository_module._UPSERT_EXECUTION}
        for query, _ in connection.queries
    )


def test_higher_snapshot_revision_replaces_counts_without_adding() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    repository.save_snapshot(_snapshot(completed=1))
    snapshot = _snapshot(completed=2)

    # When
    repository.save_snapshot(snapshot)
    repository.save_snapshot(snapshot)

    # Then
    restored = repository.get_execution(snapshot.execution_id)
    assert restored == snapshot
    assert restored.buckets[0].processing_completed_count == 2
    assert restored.buckets[0].latency_sum_ns == 14


def test_same_snapshot_revision_with_different_payload_raises_integrity_error() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot(completed=1)
    repository.save_snapshot(original)
    values = original.model_dump()
    values["buckets"][0]["latency_sum_ns"] = 8
    conflict = PipelineTelemetrySnapshot.model_validate(values)

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="same snapshot revision"):
        repository.save_snapshot(conflict)

    # Then
    assert repository.get_execution(original.execution_id) == original


@pytest.mark.parametrize("lower_bucket_revision", [True, False])
def test_higher_snapshot_cannot_smuggle_stale_or_conflicting_bucket(
    lower_bucket_revision: bool,
) -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot(completed=1)
    repository.save_snapshot(original)
    values = original.model_dump()
    values["revision"] += 1
    if lower_bucket_revision:
        values["buckets"][0]["revision"] -= 1
    else:
        values["buckets"][0]["latency_sum_ns"] += 1

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="bucket revision"):
        repository.save_snapshot(PipelineTelemetrySnapshot.model_validate(values))

    # Then
    assert repository.get_execution(original.execution_id) == original


def test_metadata_quality_update_leaves_bucket_revision_and_values_unchanged() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot(completed=1)
    repository.save_snapshot(original)
    partial = original.model_copy(
        update={
            "revision": original.revision + 1,
            "observation_status": "partial",
            "observation_issues": (TelemetryObservationIssue.INTERNAL_ERROR,),
            "collection_disabled": True,
        }
    )
    connection.queries.clear()

    # When
    repository.save_snapshot(partial)

    # Then
    assert repository.get_execution(original.execution_id) == partial
    assert not any(query == repository_module._UPSERT_BUCKET for query, _ in connection.queries)


def test_same_run_entity_preserves_separate_executions() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    first = _snapshot(execution_id="first")
    second = _snapshot(execution_id="retry", completed=1)

    # When
    repository.save_snapshot(first)
    repository.save_snapshot(second)

    # Then
    assert repository.get_execution("first") == first
    assert repository.get_execution("retry") == second
    assert {
        item.execution_id for item in repository.list_executions(first.run_id, first.entity_id)
    } == {"first", "retry"}
    assert repository.list_executions(first.run_id, "other-entity") == []
    assert repository.get_execution("unknown") is None


@pytest.mark.parametrize("field", ["run_id", "entity_id"])
def test_execution_scope_cannot_change_even_with_older_revision(field: str) -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot(completed=1)
    repository.save_snapshot(original)
    conflict = _snapshot().model_copy(update={field: "different-scope"})

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="scope changed"):
        repository.save_snapshot(conflict)

    # Then
    assert repository.get_execution(original.execution_id) == original


@pytest.mark.parametrize("existing_execution", [False, True])
def test_failed_second_bucket_rolls_back_execution_and_first_bucket_then_retry_succeeds(
    existing_execution: bool,
) -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot()
    if existing_execution:
        repository.save_snapshot(original)
    later = PipelineTelemetryBucket(
        bucket_start=START + timedelta(seconds=20),
        bucket_end=START + timedelta(seconds=21),
        first_observed_at=START + timedelta(seconds=20),
        last_observed_at=START + timedelta(seconds=20),
        revision=1,
        processing_failed_count=1,
    )
    newer = _snapshot(completed=1).model_copy(
        update={
            "revision": 3,
            "last_observed_at": later.last_observed_at,
            "buckets": (_snapshot(completed=1).buckets[0], later),
        }
    )
    connection.failure_on_bucket = later.bucket_start

    # When
    with pytest.raises(RuntimeError, match="injected DB write failure"):
        repository.save_snapshot(newer)
    rolled_back = repository.get_execution(original.execution_id)
    connection.failure_on_bucket = None
    repository.save_snapshot(newer)

    # Then
    assert rolled_back == (original if existing_execution else None)
    assert connection.savepoint_rollbacks == 1
    assert repository.get_execution(original.execution_id) == newer
    assert repository.list_buckets(original.execution_id) == list(newer.buckets)
    assert (
        repository.list_buckets(
            original.execution_id, start=START + timedelta(seconds=1), end=later.bucket_start
        )
        == []
    )
    assert repository.list_buckets(
        original.execution_id, start=later.bucket_start, end=later.bucket_end
    ) == [later]


@pytest.mark.parametrize(
    "autocommit,isolation", [(True, "read committed"), (False, "repeatable read")]
)
def test_rejects_incompatible_transaction_before_writes(autocommit: bool, isolation: str) -> None:
    # Given
    connection = _Connection()
    connection.autocommit, connection.isolation = autocommit, isolation

    # When
    with pytest.raises(ValueError):
        PipelineTelemetryRepository(connection).save_snapshot(_snapshot())

    # Then
    assert connection.executions == connection.buckets == {}
    assert connection.locks == 0


@pytest.mark.parametrize(
    "field,value", [("latency_sum_ns", -1), ("processing_completed_count", True)]
)
def test_revalidates_nested_model_copy_before_any_sql(field: str, value: object) -> None:
    # Given
    connection = _Connection()
    original = _snapshot(completed=1)
    invalid = original.model_copy(
        update={"buckets": (original.buckets[0].model_copy(update={field: value}),)}
    )

    # When
    with pytest.raises(ValidationError):
        PipelineTelemetryRepository(connection).save_snapshot(invalid)

    # Then
    assert connection.queries == []


@pytest.mark.parametrize(
    "value",
    [
        START.replace(tzinfo=None),
        START.astimezone(timezone(timedelta(hours=9))),
        START.replace(microsecond=1),
        "2026-10-14T01:00:00Z",
    ],
)
def test_rejects_invalid_query_boundaries_before_sql(value: object) -> None:
    # Given
    connection = _Connection()

    # When
    with pytest.raises(ValueError):
        PipelineTelemetryRepository(connection).list_buckets("execution", start=value)

    # Then
    assert connection.queries == []


@pytest.mark.parametrize("limit", [True, 0, 101, 1.5])
def test_rejects_invalid_execution_query_limit(limit: object) -> None:
    # Given
    connection = _Connection()

    # When
    with pytest.raises(ValueError):
        PipelineTelemetryRepository(connection).list_executions("run", "entity", limit=limit)

    # Then
    assert connection.queries == []


def test_newer_snapshot_cannot_omit_previously_observed_bucket() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    admission = _snapshot()
    later = PipelineTelemetryBucket(
        bucket_start=START + timedelta(seconds=20),
        bucket_end=START + timedelta(seconds=21),
        first_observed_at=START + timedelta(seconds=20),
        last_observed_at=START + timedelta(seconds=20),
        revision=1,
        processing_failed_count=1,
    )
    original = admission.model_copy(
        update={
            "revision": 2,
            "last_observed_at": later.last_observed_at,
            "buckets": (*admission.buckets, later),
        }
    )
    repository.save_snapshot(original)
    conflict = admission.model_copy(update={"revision": 3})

    # When
    with pytest.raises(PipelineTelemetryIntegrityError, match="omits"):
        repository.save_snapshot(conflict)

    # Then
    assert repository.get_execution(original.execution_id) == original


def test_revalidates_invalid_stored_payloads() -> None:
    # Given
    connection = _Connection()
    repository = PipelineTelemetryRepository(connection)
    original = _snapshot()
    repository.save_snapshot(original)
    connection.buckets[(original.execution_id, START)]["processing_completed_count"] = -1

    # When
    with pytest.raises(ValidationError):
        repository.get_execution(original.execution_id)

    # Then
    assert connection.executions[original.execution_id]["revision"] == original.revision
