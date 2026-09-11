from collections.abc import Mapping
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.event import NormalizedEvent


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...

    def commit(self) -> None: ...


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
        self._connection.commit()

    def get(self, event_id: str) -> NormalizedEvent | None:
        """event_id에 해당하는 저장된 NormalizedEvent를 반환한다."""
        row = self._connection.execute(_SELECT_EVENT_PAYLOAD, (event_id,)).fetchone()
        if row is None:
            return None

        payload = row[0] if isinstance(row, tuple) else row["payload"]
        if not isinstance(payload, Mapping):
            raise TypeError("events.payload는 JSON 객체여야 합니다.")

        return NormalizedEvent.model_validate(payload)
