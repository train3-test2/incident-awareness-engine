from collections.abc import Mapping
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.run import RunMetadata


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_UPSERT_RUN = """
INSERT INTO runs (
    run_id,
    scenario_id,
    run_type,
    target_host,
    start_time,
    end_time,
    metadata
)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (run_id) DO UPDATE SET
    scenario_id = EXCLUDED.scenario_id,
    run_type = EXCLUDED.run_type,
    target_host = EXCLUDED.target_host,
    start_time = EXCLUDED.start_time,
    end_time = EXCLUDED.end_time,
    metadata = EXCLUDED.metadata
"""

_SELECT_RUN_METADATA = "SELECT metadata FROM runs WHERE run_id = %s"

_SELECT_RECENT_RUN_METADATA = """
SELECT metadata
FROM runs
ORDER BY start_time DESC, run_id DESC
LIMIT %s
"""

_SELECT_RUN_COUNT = "SELECT COUNT(*) FROM runs"


class RunRepository:
    """RunMetadata Contract를 runs 테이블에 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, run: RunMetadata) -> None:
        """동일 run_id가 있으면 최신 RunMetadata로 갱신한다."""
        self._connection.execute(
            _UPSERT_RUN,
            (
                run.run_id,
                run.scenario_id,
                run.run_type.value,
                run.target_host,
                run.start_time,
                run.end_time,
                Jsonb(run.model_dump(mode="json")),
            ),
        )

    def get(self, run_id: str) -> RunMetadata | None:
        """run_id에 해당하는 저장된 RunMetadata를 반환한다."""
        row = self._connection.execute(_SELECT_RUN_METADATA, (run_id,)).fetchone()
        if row is None:
            return None

        return RunMetadata.model_validate(_metadata_from_row(row))

    def list_recent(self, limit: int) -> list[RunMetadata]:
        """Return the most recently started Runs with deterministic ordering."""
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        rows = self._connection.execute(_SELECT_RECENT_RUN_METADATA, (limit,)).fetchall()
        return [RunMetadata.model_validate(_metadata_from_row(row)) for row in rows]

    def count(self) -> int:
        """Return the number of stored Runs without changing transaction state."""
        row = self._connection.execute(_SELECT_RUN_COUNT, ()).fetchone()
        if row is None:
            raise TypeError("Run count query must return one row")

        count = row[0] if isinstance(row, tuple) else row["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise TypeError("Run count must be a non-negative integer")

        return count


def _metadata_from_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> Mapping[str, object]:
    metadata = row[0] if isinstance(row, tuple) else row["metadata"]
    if not isinstance(metadata, Mapping):
        raise TypeError("runs.metadata는 JSON 객체여야 합니다.")

    return metadata
