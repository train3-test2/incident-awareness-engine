from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.event import NormalizedEvent


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_UPSERT_EVENT = """
INSERT INTO events (
    event_id,
    run_id,
    timestamp,
    host_id,
    event_type,
    payload
)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (event_id) DO UPDATE SET
    run_id = EXCLUDED.run_id,
    timestamp = EXCLUDED.timestamp,
    host_id = EXCLUDED.host_id,
    event_type = EXCLUDED.event_type,
    payload = EXCLUDED.payload
"""

_SELECT_EVENT_PAYLOAD = "SELECT payload FROM events WHERE event_id = %s"

_SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT = """
WITH target_run AS (
    SELECT run_id
    FROM runs
    WHERE run_id = %s
),
event_count AS (
    SELECT COUNT(*) AS total
    FROM events
    WHERE run_id = %s
),
event_page AS (
    SELECT
        payload,
        timestamp,
        event_id
    FROM events
    WHERE run_id = %s
    ORDER BY timestamp ASC, event_id ASC
    LIMIT %s OFFSET %s
)
SELECT
    target_run.run_id,
    event_count.total,
    event_page.payload
FROM target_run
CROSS JOIN event_count
LEFT JOIN event_page ON TRUE
ORDER BY
    event_page.timestamp ASC NULLS LAST,
    event_page.event_id ASC NULLS LAST
"""

_SELECT_EVENT_BY_RUN = """
SELECT
    runs.run_id,
    events.payload
FROM runs
LEFT JOIN events
  ON events.run_id = runs.run_id
 AND events.event_id = %s
WHERE runs.run_id = %s
"""


@dataclass(frozen=True, slots=True)
class EventLookupResult:
    run_exists: bool
    event: NormalizedEvent | None


class EventRepository:
    """NormalizedEvent Contract를 events 테이블에 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, event: NormalizedEvent) -> None:
        """동일 event_id가 있으면 최신 NormalizedEvent로 갱신한다."""
        self._connection.execute(
            _UPSERT_EVENT,
            (
                event.event_id,
                event.run_id,
                event.timestamp,
                event.host_id,
                event.event_type,
                Jsonb(event.model_dump(mode="json")),
            ),
        )

    def get(self, event_id: str) -> NormalizedEvent | None:
        """event_id에 해당하는 저장된 NormalizedEvent를 반환한다."""
        row = self._connection.execute(_SELECT_EVENT_PAYLOAD, (event_id,)).fetchone()
        if row is None:
            return None

        payload = row[0] if isinstance(row, tuple) else row["payload"]
        if not isinstance(payload, Mapping):
            raise TypeError("events.payload는 JSON 객체여야 합니다.")

        return NormalizedEvent.model_validate(payload)

    def list_by_run_with_total_count(
        self,
        run_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[int, list[NormalizedEvent]] | None:
        """Return one ordered Event page and its total from one statement."""
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        rows = self._connection.execute(
            _SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT,
            (run_id, run_id, run_id, limit, offset),
        ).fetchall()
        if not rows:
            return None

        total: int | None = None
        events: list[NormalizedEvent] = []
        for row in rows:
            row_run_id, row_total, payload = _timeline_values_from_row(row)
            if row_run_id != run_id:
                raise TypeError("Event timeline query returned an unexpected run_id")
            if total is None:
                total = row_total
            elif row_total != total:
                raise TypeError("Event timeline query returned inconsistent totals")

            if payload is None:
                if len(rows) != 1:
                    raise TypeError("Empty Event timeline page must return exactly one row")
            else:
                events.append(NormalizedEvent.model_validate(payload))

        if total == 0:
            if events:
                raise TypeError("Empty Event timeline cannot contain Event payloads")
        elif total < len(events):
            raise TypeError("Event timeline page exceeds its total count")

        return total, events

    def get_by_run(self, run_id: str, event_id: str) -> EventLookupResult:
        """Look up one Event and its requested Run in one statement."""
        row = self._connection.execute(
            _SELECT_EVENT_BY_RUN,
            (event_id, run_id),
        ).fetchone()
        if row is None:
            return EventLookupResult(run_exists=False, event=None)

        row_run_id, payload = _event_lookup_values_from_row(row)
        if row_run_id != run_id:
            raise TypeError("Event lookup query returned an unexpected run_id")
        if payload is None:
            return EventLookupResult(run_exists=True, event=None)

        return EventLookupResult(
            run_exists=True,
            event=NormalizedEvent.model_validate(payload),
        )


def _timeline_values_from_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> tuple[str, int, Mapping[str, object] | None]:
    try:
        if isinstance(row, tuple):
            run_id, total, payload = row
        else:
            run_id = row["run_id"]
            total = row["total"]
            payload = row["payload"]
    except (KeyError, ValueError) as error:
        raise TypeError("Event timeline query returned an invalid row") from error

    if not isinstance(run_id, str):
        raise TypeError("Event timeline run_id must be a string")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        raise TypeError("Event timeline total must be a non-negative integer")
    if payload is not None and not isinstance(payload, Mapping):
        raise TypeError("events.payload must be a JSON object")

    return run_id, total, payload


def _event_lookup_values_from_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> tuple[str, Mapping[str, object] | None]:
    try:
        if isinstance(row, tuple):
            run_id, payload = row
        else:
            run_id = row["run_id"]
            payload = row["payload"]
    except (KeyError, ValueError) as error:
        raise TypeError("Event lookup query returned an invalid row") from error

    if not isinstance(run_id, str):
        raise TypeError("Event lookup run_id must be a string")
    if payload is not None and not isinstance(payload, Mapping):
        raise TypeError("events.payload must be a JSON object")

    return run_id, payload
