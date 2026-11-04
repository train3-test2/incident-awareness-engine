"""Atomic immutable stage invocation storage, independent of Business transactions."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol

import psycopg
from psycopg.types.json import Jsonb

from incident_awareness.common.models.pipeline_stage_timing import PipelineStageTimingSnapshot


class StageTimingIntegrityError(RuntimeError):
    """Conflicting attempt identity, revision or immutable invocation payload."""


class _Cursor(Protocol):
    def fetchone(self) -> tuple | Mapping | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple = ()) -> _Cursor: ...


_SAVE = "SELECT save_pipeline_stage_timing(%s) AS saved"
_READ = """
WITH stored AS (
    SELECT a.payload || jsonb_build_object('records', COALESCE(
        (SELECT jsonb_agg(r.payload ORDER BY r.invocation_index)
         FROM pipeline_stage_timing_records r WHERE r.attempt_id = a.attempt_id), '[]'::jsonb)) AS snapshot,
        a.updated_at AS persisted_at
    FROM pipeline_stage_timing_attempts a WHERE a.execution_id = %s
)
SELECT (SELECT snapshot FROM stored) AS snapshot, (SELECT persisted_at FROM stored) AS persisted_at,
    EXISTS (SELECT 1 FROM stored)
    OR EXISTS (SELECT 1 FROM pipeline_runtime_status WHERE execution_id = %s)
    OR EXISTS (SELECT 1 FROM pipeline_telemetry_executions WHERE execution_id = %s) AS execution_known
"""
_READ_ATTEMPT = """
SELECT a.payload || jsonb_build_object('records', COALESCE(
    (SELECT jsonb_agg(r.payload ORDER BY r.invocation_index)
     FROM pipeline_stage_timing_records r WHERE r.attempt_id = a.attempt_id), '[]'::jsonb)) AS snapshot,
    a.updated_at AS persisted_at
FROM pipeline_stage_timing_attempts a WHERE a.attempt_id = %s
"""


class PipelineStageTimingRepository:
    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save_snapshot(self, snapshot: PipelineStageTimingSnapshot) -> bool:
        # Revalidate even if a caller constructed an unchecked model_copy/model_construct.
        checked = PipelineStageTimingSnapshot.model_validate(snapshot.model_dump())
        try:
            row = self._connection.execute(
                _SAVE, (Jsonb(checked.model_dump(mode="json")),)
            ).fetchone()
        except (psycopg.errors.RaiseException, psycopg.IntegrityError) as error:
            raise StageTimingIntegrityError("Stage timing storage conflict") from error
        if row is None:
            raise RuntimeError("Stage timing write returned no result")
        return bool(row[0] if isinstance(row, tuple) else row["saved"])

    def read_attempt(self, attempt_id: str) -> PipelineStageTimingSnapshot | None:
        """Restore even unbound validation failures, without inventing an Execution ID."""
        row = self._connection.execute(_READ_ATTEMPT, (attempt_id,)).fetchone()
        if row is None:
            return None
        payload = row[0] if isinstance(row, tuple) else row["snapshot"]
        snapshot = PipelineStageTimingSnapshot.model_validate(payload)
        if snapshot.attempt_id != attempt_id:
            raise StageTimingIntegrityError("Stored stage timing attempt scope is inconsistent")
        return snapshot

    def read_execution(
        self, execution_id: str
    ) -> tuple[PipelineStageTimingSnapshot | None, datetime | None, bool]:
        if not execution_id or execution_id != execution_id.strip():
            raise ValueError("execution_id must be nonblank and trimmed")
        row = self._connection.execute(_READ, (execution_id,) * 3).fetchone()
        if row is None:
            raise RuntimeError("Stage timing read returned no result")
        values = (
            row
            if isinstance(row, tuple)
            else (row["snapshot"], row["persisted_at"], row["execution_known"])
        )
        payload, persisted_at, known = values
        if isinstance(persisted_at, datetime) and persisted_at.utcoffset() is not None:
            persisted_at = persisted_at.astimezone(UTC)
        snapshot = (
            PipelineStageTimingSnapshot.model_validate(payload) if payload is not None else None
        )
        if snapshot is not None and snapshot.execution_id != execution_id:
            raise StageTimingIntegrityError("Stored stage timing execution scope is inconsistent")
        return snapshot, persisted_at, bool(known)
