"""Transactional, revision-checked storage of execution-attempt telemetry."""

from collections.abc import Mapping
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetryBucket,
    PipelineTelemetrySnapshot,
    _validate_telemetry_datetime,
)

_TELEMETRY_ADVISORY_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))"
_TELEMETRY_ADVISORY_LOCK_PREFIX = "incident_awareness_engine:telemetry:"

_SNAPSHOT_SELECT = """
SELECT e.payload || jsonb_build_object(
    'buckets', COALESCE((
        SELECT jsonb_agg(b.payload ORDER BY b.bucket_start)
        FROM pipeline_telemetry_buckets b
        WHERE b.execution_id = e.execution_id
    ), '[]'::jsonb)
) AS payload
FROM pipeline_telemetry_executions e
"""
_GET_EXECUTION = _SNAPSHOT_SELECT + "WHERE e.execution_id = %s"
_LIST_EXECUTIONS = (
    _SNAPSHOT_SELECT
    + """
WHERE e.run_id = %s AND e.entity_id = %s
ORDER BY e.last_observed_at DESC NULLS LAST, e.execution_id
LIMIT %s
"""
)
_LIST_BUCKETS = """
SELECT payload FROM pipeline_telemetry_buckets
WHERE execution_id = %s
  AND (%s::timestamptz IS NULL OR bucket_start >= %s::timestamptz)
  AND (%s::timestamptz IS NULL OR bucket_start < %s::timestamptz)
ORDER BY bucket_start
"""

# A single statement snapshot covers metadata and absolute bucket counters. Each
# bucket joins exactly one execution PK; no Runtime/Run join or pagination truncation.
_READ_WINDOW = """
WITH scoped AS MATERIALIZED (
    SELECT e.* FROM pipeline_telemetry_executions e
    WHERE (%s::text IS NULL OR e.execution_id = %s)
      AND (%s::text IS NULL OR e.run_id = %s)
      AND (%s::text IS NULL OR e.entity_id = %s)
      AND (NOT %s OR EXISTS (
          SELECT 1 FROM pipeline_telemetry_buckets b
          WHERE b.execution_id = e.execution_id
            AND b.bucket_start >= %s AND b.bucket_start < %s
      ))
), input_check AS (
    -- Run identity is checked across ALL entities and ALL times, not only scoped buckets.
    SELECT count(*) > 1 AND (
        count(input_identity_kind) <> count(*)
        OR count(DISTINCT (input_identity_kind, input_identity_sha256)) <> 1
    ) AS input_conflict
    FROM pipeline_telemetry_executions
    WHERE run_id = %s
), points AS (
    SELECT b.bucket_start, b.bucket_end, count(*) AS executions_count,
           sum(b.input_accepted_count) AS input_accepted_count,
           sum(b.processing_completed_count) AS processing_completed_count,
           sum(b.processing_failed_count) AS processing_failed_count,
           sum(b.latency_sample_count) AS processing_latency_sample_count,
           sum(b.latency_sum_ns) AS processing_latency_sum_ns,
           max(b.last_observed_at) AS observed_at
    FROM pipeline_telemetry_buckets b JOIN scoped e USING (execution_id)
    WHERE b.bucket_start >= %s AND b.bucket_start < %s
      AND NOT (SELECT input_conflict FROM input_check)
    GROUP BY b.bucket_start, b.bucket_end
), metadata AS (
    SELECT count(*) AS executions_count,
           count(*) FILTER (WHERE observation_status = 'observed') AS observed_executions,
           count(*) FILTER (WHERE observation_status = 'partial') AS partial_executions,
           count(*) FILTER (WHERE observation_status = 'unavailable') AS unavailable_executions,
           count(*) FILTER (WHERE collection_disabled) AS disabled_executions,
           max(last_observed_at) FILTER (WHERE last_observed_at < %s) AS last_observed_at,
           max(updated_at) AS persisted_at
    FROM scoped
)
SELECT jsonb_build_object(
    'input_conflict', (SELECT input_conflict FROM input_check),
    'points', COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY bucket_start)
                        FROM points p), '[]'::jsonb),
    'executions_count', m.executions_count,
    'observed_executions', m.observed_executions,
    'partial_executions', m.partial_executions,
    'unavailable_executions', m.unavailable_executions,
    'disabled_executions', m.disabled_executions,
    'last_observed_at', GREATEST(m.last_observed_at, (SELECT max(observed_at) FROM points)),
    'persisted_at', m.persisted_at,
    'observation_issues', COALESCE((
        SELECT jsonb_agg(DISTINCT issue ORDER BY issue)
        FROM scoped e CROSS JOIN LATERAL
             jsonb_array_elements_text(e.payload -> 'observation_issues') AS issues(issue)
    ), '[]'::jsonb)
)
FROM metadata m
"""
_UPSERT_EXECUTION = """
INSERT INTO pipeline_telemetry_executions (
    execution_id, snapshot_id, run_id, entity_id, aggregation_basis, latency_scope,
    revision, input_total, input_accepted_at, last_observed_at,
    observation_status, collection_disabled, input_identity_kind, input_identity_sha256, payload
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (execution_id) DO UPDATE SET
    revision = EXCLUDED.revision,
    input_total = EXCLUDED.input_total,
    input_accepted_at = EXCLUDED.input_accepted_at,
    last_observed_at = EXCLUDED.last_observed_at,
    observation_status = EXCLUDED.observation_status,
    collection_disabled = EXCLUDED.collection_disabled,
    payload = EXCLUDED.payload,
    updated_at = date_trunc('milliseconds', clock_timestamp())
WHERE pipeline_telemetry_executions.revision < EXCLUDED.revision
RETURNING 1
"""
_UPSERT_BUCKET = """
INSERT INTO pipeline_telemetry_buckets (
    execution_id, bucket_start, bucket_end, revision, input_accepted_count,
    processing_completed_count, processing_failed_count, latency_sample_count,
    latency_sum_ns, first_observed_at, last_observed_at, payload
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (execution_id, bucket_start) DO UPDATE SET
    bucket_end = EXCLUDED.bucket_end,
    revision = EXCLUDED.revision,
    input_accepted_count = EXCLUDED.input_accepted_count,
    processing_completed_count = EXCLUDED.processing_completed_count,
    processing_failed_count = EXCLUDED.processing_failed_count,
    latency_sample_count = EXCLUDED.latency_sample_count,
    latency_sum_ns = EXCLUDED.latency_sum_ns,
    first_observed_at = EXCLUDED.first_observed_at,
    last_observed_at = EXCLUDED.last_observed_at,
    payload = EXCLUDED.payload
WHERE pipeline_telemetry_buckets.revision < EXCLUDED.revision
RETURNING 1
"""


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]: ...


class _Connection(Protocol):
    autocommit: bool

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Cursor: ...

    def transaction(self) -> AbstractContextManager[object]: ...


class PipelineTelemetryIntegrityError(RuntimeError):
    """Conflicting identity, payload, or revision for an execution snapshot."""


class PipelineTelemetryInputConflictError(RuntimeError):
    """Multiple run attempts cannot safely be identified as the same input."""


def _telemetry_lock_key(execution_id: str) -> str:
    return _TELEMETRY_ADVISORY_LOCK_PREFIX + execution_id


def _read_utc_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(parsed, datetime) or parsed.utcoffset() is None:
        raise ValueError("stored telemetry timestamp must be timezone-aware")
    return _validate_telemetry_datetime(parsed.astimezone(UTC), field_name="stored timestamp")


class PipelineTelemetryRepository:
    """Save whole snapshots on a dedicated, caller-owned READ COMMITTED transaction.

    save_snapshot never commits: SHOW starts the outer transaction when necessary,
    and transaction() creates a savepoint around all writes. The caller commits or
    rolls back and releases the execution lock. Repository errors propagate to the
    future Observer. Reads assemble metadata and buckets in one SQL statement so
    concurrent commits cannot mix snapshot versions.
    """

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save_snapshot(self, snapshot: PipelineTelemetrySnapshot) -> bool:
        """Return True for a write, False for identical/stale snapshots; conflicts raise."""
        # model_copy/model_construct can bypass frozen model validation; validate nested data.
        snapshot = PipelineTelemetrySnapshot.model_validate(snapshot.model_dump())
        self._validate_transaction()
        with self._connection.transaction():
            self._connection.execute(
                _TELEMETRY_ADVISORY_LOCK_SQL, (_telemetry_lock_key(snapshot.execution_id),)
            )
            previous = self.get_execution(snapshot.execution_id)
            if previous is not None:
                _validate_scope(previous, snapshot)
                if snapshot.revision < previous.revision:
                    return False
                if snapshot.revision == previous.revision:
                    if snapshot != previous:
                        raise PipelineTelemetryIntegrityError(
                            "same snapshot revision has different payload"
                        )
                    return False
                _validate_replacement(previous, snapshot)

            previous_buckets = (
                {bucket.bucket_start: bucket for bucket in previous.buckets}
                if previous is not None
                else {}
            )
            changed = tuple(
                bucket
                for bucket in snapshot.buckets
                if previous_buckets.get(bucket.bucket_start) != bucket
            )
            metadata = snapshot.model_dump(mode="json", exclude={"buckets"})
            row = self._connection.execute(
                _UPSERT_EXECUTION,
                (
                    snapshot.execution_id,
                    snapshot.snapshot_id,
                    snapshot.run_id,
                    snapshot.entity_id,
                    snapshot.aggregation_basis,
                    snapshot.latency_scope,
                    snapshot.revision,
                    snapshot.input_total,
                    snapshot.input_accepted_at,
                    snapshot.last_observed_at,
                    snapshot.observation_status,
                    snapshot.collection_disabled,
                    snapshot.input_identity.kind if snapshot.input_identity is not None else None,
                    snapshot.input_identity.sha256 if snapshot.input_identity is not None else None,
                    Jsonb(metadata),
                ),
            ).fetchone()
            if row is None:
                raise PipelineTelemetryIntegrityError("execution revision changed outside its lock")
            for bucket in changed:
                row = self._connection.execute(
                    _UPSERT_BUCKET,
                    (
                        snapshot.execution_id,
                        bucket.bucket_start,
                        bucket.bucket_end,
                        bucket.revision,
                        bucket.input_accepted_count,
                        bucket.processing_completed_count,
                        bucket.processing_failed_count,
                        bucket.latency_sample_count,
                        bucket.latency_sum_ns,
                        bucket.first_observed_at,
                        bucket.last_observed_at,
                        Jsonb(bucket.model_dump(mode="json")),
                    ),
                ).fetchone()
                if row is None:
                    raise PipelineTelemetryIntegrityError(
                        "bucket revision changed outside its lock"
                    )
        return True

    def get_execution(self, execution_id: str) -> PipelineTelemetrySnapshot | None:
        row = self._connection.execute(_GET_EXECUTION, (execution_id,)).fetchone()
        return None if row is None else PipelineTelemetrySnapshot.model_validate(_payload(row))

    def read_window(
        self,
        *,
        start: datetime,
        end: datetime,
        execution_id: str | None = None,
        run_id: str | None = None,
        entity_id: str | None = None,
        reported: bool = False,
    ) -> dict[str, object]:
        """Read at most 300 sparse seconds, across all matching execution attempts."""
        for name, value in (("start", start), ("end", end)):
            _validate_telemetry_datetime(value, field_name=name)
            if value.microsecond:
                raise ValueError("telemetry window boundaries must be UTC seconds")
        if not 0 < (end - start).total_seconds() <= 300:
            raise ValueError("telemetry window must span 1 to 300 seconds")
        if (
            (reported and any((execution_id, run_id, entity_id)))
            or (execution_id is not None and any((run_id, entity_id)))
            or (not reported and execution_id is None and run_id is None)
        ):
            raise ValueError("invalid telemetry scope")
        row = self._connection.execute(
            _READ_WINDOW,
            (
                execution_id,
                execution_id,
                run_id,
                run_id,
                entity_id,
                entity_id,
                reported,
                start,
                end,
                run_id,
                start,
                end,
                end,
            ),
        ).fetchone()
        if row is None:
            raise PipelineTelemetryIntegrityError("telemetry aggregate returned no metadata")
        data = dict(_payload(row))
        if data.pop("input_conflict", False):
            raise PipelineTelemetryInputConflictError("Run telemetry input identities conflict")
        # PostgreSQL JSON timestamptz uses the session timezone, unlike the stored
        # Collector payload. Normalize DB instants before the API's strict UTC model.
        for name in ("last_observed_at", "persisted_at"):
            if name in data:
                data[name] = _read_utc_datetime(data[name])
        for point in data["points"]:
            for name in ("bucket_start", "bucket_end", "observed_at"):
                point[name] = _read_utc_datetime(point[name])
        return data

    def list_buckets(
        self, execution_id: str, *, start: datetime | None = None, end: datetime | None = None
    ) -> list[PipelineTelemetryBucket]:
        """Return sparse buckets by start time in [start, end), without synthesizing rows."""
        for name, value in (("start", start), ("end", end)):
            if value is not None:
                if not isinstance(value, datetime):
                    raise ValueError(f"{name} must be a UTC datetime")
                _validate_telemetry_datetime(value, field_name=name)
        if start is not None and end is not None and start >= end:
            raise ValueError("start must be before end")
        rows = self._connection.execute(
            _LIST_BUCKETS, (execution_id, start, start, end, end)
        ).fetchall()
        return [PipelineTelemetryBucket.model_validate(_payload(row)) for row in rows]

    def list_executions(
        self, run_id: str, entity_id: str, *, limit: int = 20
    ) -> list[PipelineTelemetrySnapshot]:
        """Return distinct attempts for one scope, most recently observed first."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        rows = self._connection.execute(_LIST_EXECUTIONS, (run_id, entity_id, limit)).fetchall()
        return [PipelineTelemetrySnapshot.model_validate(_payload(row)) for row in rows]

    def _validate_transaction(self) -> None:
        if self._connection.autocommit:
            raise ValueError("telemetry snapshot storage requires autocommit=False")
        row = self._connection.execute("SHOW transaction_isolation").fetchone()
        isolation = (
            row[0]
            if isinstance(row, tuple)
            else row.get("transaction_isolation")
            if row is not None
            else None
        )
        if isolation != "read committed":
            raise ValueError("telemetry snapshot storage requires READ COMMITTED")


def _payload(row: tuple[object, ...] | Mapping[str, object]) -> Mapping[str, object]:
    value = row[0] if isinstance(row, tuple) else row["payload"]
    if not isinstance(value, Mapping):
        raise TypeError("pipeline telemetry payload must be a JSON object")
    return value


def _validate_scope(
    previous: PipelineTelemetrySnapshot, incoming: PipelineTelemetrySnapshot
) -> None:
    for field in (
        "snapshot_id",
        "execution_id",
        "run_id",
        "entity_id",
        "input_identity",
        "aggregation_basis",
        "latency_scope",
    ):
        if getattr(previous, field) != getattr(incoming, field):
            raise PipelineTelemetryIntegrityError("execution identity or measurement scope changed")


def _validate_replacement(
    previous: PipelineTelemetrySnapshot, incoming: PipelineTelemetrySnapshot
) -> None:
    if previous.input_total is not None and (
        previous.input_total != incoming.input_total
        or previous.input_accepted_at != incoming.input_accepted_at
    ):
        raise PipelineTelemetryIntegrityError("accepted batch changed within execution")
    buckets = {bucket.bucket_start: bucket for bucket in incoming.buckets}
    for prior in previous.buckets:
        candidate = buckets.get(prior.bucket_start)
        if candidate is None:
            raise PipelineTelemetryIntegrityError("replacement omits a previously observed bucket")
        if candidate.revision < prior.revision:
            raise PipelineTelemetryIntegrityError("bucket revision regressed in newer snapshot")
        if candidate.revision == prior.revision and candidate != prior:
            raise PipelineTelemetryIntegrityError("same bucket revision has different payload")
