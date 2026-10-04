"""Persist and query the latest Pipeline Runtime telemetry state."""

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
)


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_UPSERT_PIPELINE_RUNTIME_STATUS = """
INSERT INTO pipeline_runtime_status (
    run_id,
    entity_id,
    execution_id,
    status,
    current_stage,
    started_at,
    updated_at,
    payload
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (run_id, entity_id) DO UPDATE SET
    execution_id = EXCLUDED.execution_id,
    status = EXCLUDED.status,
    current_stage = EXCLUDED.current_stage,
    started_at = EXCLUDED.started_at,
    updated_at = EXCLUDED.updated_at,
    payload = EXCLUDED.payload
WHERE (
    pipeline_runtime_status.execution_id = EXCLUDED.execution_id
    AND pipeline_runtime_status.started_at = EXCLUDED.started_at
    AND pipeline_runtime_status.updated_at <= EXCLUDED.updated_at
    AND (
        pipeline_runtime_status.status = 'running'
        OR pipeline_runtime_status.status = EXCLUDED.status
    )
) OR (
    pipeline_runtime_status.execution_id <> EXCLUDED.execution_id
    AND pipeline_runtime_status.started_at < EXCLUDED.started_at
)
RETURNING 1
"""

_SELECT_PIPELINE_RUNTIME_STATUS_PAYLOAD = """
SELECT payload
FROM pipeline_runtime_status
WHERE run_id = %s AND entity_id = %s
"""

_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS = """
SELECT payload
FROM pipeline_runtime_status
ORDER BY
    CASE WHEN status = 'running' THEN 0 ELSE 1 END,
    updated_at DESC,
    run_id ASC,
    entity_id ASC
LIMIT %s
"""

_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE = """
SELECT payload
FROM pipeline_runtime_status
WHERE status = %s
ORDER BY
    CASE WHEN status = 'running' THEN 0 ELSE 1 END,
    updated_at DESC,
    run_id ASC,
    entity_id ASC
LIMIT %s
"""

_SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS = """
SELECT payload
FROM pipeline_runtime_status
ORDER BY
    CASE
        WHEN status = 'running' AND updated_at >= %s THEN 0
        WHEN status = 'running' THEN 2
        ELSE 1
    END,
    updated_at DESC,
    run_id ASC,
    entity_id ASC
LIMIT %s
"""


class PipelineRuntimeStatusRepository:
    """Store one mutable latest Runtime status per Run and entity scope."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, status: PipelineRuntimeStatus) -> bool:
        """Atomically apply a current snapshot and report whether it won."""
        row = self._connection.execute(
            _UPSERT_PIPELINE_RUNTIME_STATUS,
            (
                status.run_id,
                status.entity_id,
                status.execution_id,
                status.status.value,
                status.current_stage.value if status.current_stage is not None else None,
                status.started_at,
                status.updated_at,
                Jsonb(status.model_dump(mode="json")),
            ),
        ).fetchone()
        return row is not None

    def get(self, run_id: str, entity_id: str) -> PipelineRuntimeStatus | None:
        row = self._connection.execute(
            _SELECT_PIPELINE_RUNTIME_STATUS_PAYLOAD,
            (run_id, entity_id),
        ).fetchone()
        if row is None:
            return None

        return PipelineRuntimeStatus.model_validate(
            _payload_from_row(row, table_name="pipeline_runtime_status")
        )

    def list_recent(
        self,
        *,
        limit: int,
        status: PipelineRuntimeState | None = None,
        running_fresh_after: datetime | None = None,
    ) -> list[PipelineRuntimeStatus]:
        """List recent Runtime states without rewriting any persisted status.

        ``running_fresh_after`` only orders unfiltered results: running rows updated at or
        after the cutoff come first, then terminal rows, then running rows without recent
        telemetry. It never excludes rows, so a status filter returns every row persisted
        in that state. Without a cutoff, the original running-first ordering is kept.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        if running_fresh_after is not None and (
            not isinstance(running_fresh_after, datetime) or running_fresh_after.utcoffset() is None
        ):
            raise ValueError("running_fresh_after must be a timezone-aware datetime")

        if status is not None:
            query = _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_BY_STATE
            params: tuple[object, ...] = (status.value, limit)
        elif running_fresh_after is not None:
            query = _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS_WITH_RUNNING_FRESHNESS
            params = (running_fresh_after, limit)
        else:
            query = _SELECT_RECENT_PIPELINE_RUNTIME_STATUS_PAYLOADS
            params = (limit,)

        rows = self._connection.execute(query, params).fetchall()
        return [
            PipelineRuntimeStatus.model_validate(
                _payload_from_row(row, table_name="pipeline_runtime_status")
            )
            for row in rows
        ]


def _payload_from_row(
    row: tuple[object, ...] | Mapping[str, object],
    *,
    table_name: str,
) -> Mapping[str, object]:
    payload = row[0] if isinstance(row, tuple) else row["payload"]
    if not isinstance(payload, Mapping):
        raise TypeError(f"{table_name}.payload must be a JSON object")
    return payload


__all__ = ["PipelineRuntimeStatusRepository"]
