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

_SELECT_RECENT_RUNS_WITH_TOTAL_COUNT = """
WITH recent_runs AS (
    SELECT
        metadata,
        start_time,
        run_id
    FROM runs
    ORDER BY start_time DESC, run_id DESC
    LIMIT %s
),
run_count AS (
    SELECT COUNT(*) AS total_runs
    FROM runs
)
SELECT
    run_count.total_runs,
    recent_runs.metadata
FROM run_count
LEFT JOIN recent_runs ON TRUE
ORDER BY
    recent_runs.start_time DESC NULLS LAST,
    recent_runs.run_id DESC NULLS LAST
"""


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

    def list_recent_with_total_count(
        self,
        limit: int,
    ) -> tuple[int, list[RunMetadata]]:
        """Return the total and recent Runs from one database statement."""
        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        rows = self._connection.execute(
            _SELECT_RECENT_RUNS_WITH_TOTAL_COUNT,
            (limit,),
        ).fetchall()
        if not rows:
            raise TypeError("Run overview query must return at least one row")

        total_runs: int | None = None
        recent_runs: list[RunMetadata] = []
        for row in rows:
            row_total, metadata = _overview_values_from_row(row)
            if total_runs is None:
                total_runs = row_total
            elif row_total != total_runs:
                raise TypeError("Run overview query returned inconsistent total counts")

            if metadata is None:
                if row_total != 0 or len(rows) != 1:
                    raise TypeError("Run overview metadata may be null only for an empty table")
            else:
                recent_runs.append(RunMetadata.model_validate(metadata))

        if total_runs == 0:
            if recent_runs or len(rows) != 1:
                raise TypeError("Empty Run overview must return one row without metadata")
        elif not recent_runs or total_runs < len(recent_runs):
            raise TypeError("Run overview result is inconsistent with the total count")

        return total_runs, recent_runs


def _metadata_from_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> Mapping[str, object]:
    metadata = row[0] if isinstance(row, tuple) else row["metadata"]
    if not isinstance(metadata, Mapping):
        raise TypeError("runs.metadata는 JSON 객체여야 합니다.")

    return metadata


def _overview_values_from_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> tuple[int, Mapping[str, object] | None]:
    try:
        if isinstance(row, tuple):
            total_runs, metadata = row
        else:
            total_runs = row["total_runs"]
            metadata = row["metadata"]
    except (KeyError, ValueError) as error:
        raise TypeError("Run overview query returned an invalid row") from error

    if isinstance(total_runs, bool) or not isinstance(total_runs, int) or total_runs < 0:
        raise TypeError("Run total count must be a non-negative integer")
    if metadata is not None and not isinstance(metadata, Mapping):
        raise TypeError("runs.metadata must be a JSON object")

    return total_runs, metadata
