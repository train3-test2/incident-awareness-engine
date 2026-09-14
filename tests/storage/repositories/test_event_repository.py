from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.storage.repositories.event_repository import (
    _SELECT_EVENT_PAYLOAD,
    _UPSERT_EVENT,
    EventRepository,
)


class FakeCursor:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row


class FakeConnection:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self.row = row
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> FakeCursor:
        self.statements.append((query, params))
        return FakeCursor(self.row)

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture
def normalized_event() -> NormalizedEvent:
    timestamp = datetime(2026, 9, 12, 1, tzinfo=UTC)
    return NormalizedEvent(
        event_id="evt-001",
        run_id="RUN-20260912-001",
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id="WIN-01",
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="153",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            segment_no=1,
            record_no=153,
        ),
    )


def test_save_upserts_event_and_commits(normalized_event: NormalizedEvent) -> None:
    connection = FakeConnection()

    EventRepository(connection).save(normalized_event)

    assert connection.commits == 1
    assert len(connection.statements) == 1
    query, params = connection.statements[0]
    assert query == _UPSERT_EVENT
    assert params[:5] == (
        "evt-001",
        "RUN-20260912-001",
        datetime(2026, 9, 12, 1, tzinfo=UTC),
        "WIN-01",
        "process_create",
    )
    assert isinstance(params[5], Jsonb)
    assert params[5].obj["raw_ref"]["raw_log_id"] == "RAW-001"


def test_get_rebuilds_normalized_event_from_json_payload(normalized_event: NormalizedEvent) -> None:
    connection = FakeConnection((normalized_event.model_dump(mode="json"),))

    stored_event = EventRepository(connection).get(normalized_event.event_id)

    assert stored_event == normalized_event
    assert connection.statements == [(_SELECT_EVENT_PAYLOAD, (normalized_event.event_id,))]


def test_get_returns_none_when_event_does_not_exist() -> None:
    connection = FakeConnection()

    assert EventRepository(connection).get("evt-001") is None


def test_get_rejects_non_object_payload() -> None:
    connection = FakeConnection(("not-an-object",))

    with pytest.raises(TypeError, match="JSON 객체"):
        EventRepository(connection).get("evt-001")
