from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.storage.repositories.event_repository import (
    _SELECT_EVENT_BY_RUN,
    _SELECT_EVENT_PAYLOAD,
    _SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT,
    _UPSERT_EVENT,
    EventLookupResult,
    EventRepository,
)


class FakeCursor:
    def __init__(
        self,
        row: tuple[object, ...] | Mapping[str, object] | None = None,
        rows: list[tuple[object, ...] | Mapping[str, object]] | None = None,
    ) -> None:
        self._row = row
        self._rows = rows if rows is not None else []

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]:
        return self._rows


class FakeConnection:
    def __init__(
        self,
        row: tuple[object, ...] | Mapping[str, object] | None = None,
        rows: list[tuple[object, ...] | Mapping[str, object]] | None = None,
    ) -> None:
        self.row = row
        self.rows = rows
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> FakeCursor:
        self.statements.append((query, params))
        return FakeCursor(self.row, self.rows)

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


def test_save_upserts_event_without_committing(normalized_event: NormalizedEvent) -> None:
    connection = FakeConnection()

    EventRepository(connection).save(normalized_event)

    assert connection.commits == 0
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


def test_list_by_run_with_total_count_returns_ordered_events_from_one_statement(
    normalized_event: NormalizedEvent,
) -> None:
    # Given
    event_1 = _event_at(normalized_event, event_id="evt-001", second=1)
    event_2 = _event_at(normalized_event, event_id="evt-002", second=2)
    event_3 = _event_at(normalized_event, event_id="evt-003", second=2)
    connection = FakeConnection(
        rows=[
            (normalized_event.run_id, 3, event_1.model_dump(mode="json")),
            {
                "run_id": normalized_event.run_id,
                "total": 3,
                "payload": event_2.model_dump(mode="json"),
            },
            (normalized_event.run_id, 3, event_3.model_dump(mode="json")),
        ]
    )

    # When
    result = EventRepository(connection).list_by_run_with_total_count(
        normalized_event.run_id,
        limit=20,
        offset=0,
    )

    # Then
    assert result == (3, [event_1, event_2, event_3])
    assert connection.statements == [
        (
            _SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT,
            (
                normalized_event.run_id,
                normalized_event.run_id,
                normalized_event.run_id,
                20,
                0,
            ),
        )
    ]
    assert "ORDER BY timestamp ASC, event_id ASC" in _SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT
    assert "LIMIT %s OFFSET %s" in _SELECT_EVENT_TIMELINE_WITH_TOTAL_COUNT
    assert connection.commits == 0


def test_list_by_run_with_total_count_returns_none_when_run_does_not_exist() -> None:
    # Given
    connection = FakeConnection(rows=[])

    # When
    result = EventRepository(connection).list_by_run_with_total_count(
        "RUN-UNKNOWN",
        limit=20,
        offset=0,
    )

    # Then
    assert result is None
    assert len(connection.statements) == 1


@pytest.mark.parametrize(
    ("total", "expected"),
    [
        (0, (0, [])),
        (10, (10, [])),
    ],
)
def test_list_by_run_with_total_count_distinguishes_empty_event_pages(
    total: int,
    expected: tuple[int, list[NormalizedEvent]],
) -> None:
    # Given
    connection = FakeConnection(rows=[("RUN-20260912-001", total, None)])

    # When
    result = EventRepository(connection).list_by_run_with_total_count(
        "RUN-20260912-001",
        limit=20,
        offset=100,
    )

    # Then
    assert result == expected


@pytest.mark.parametrize(
    ("limit", "offset", "message"),
    [
        (0, 0, "greater than zero"),
        (-1, 0, "greater than zero"),
        (20, -1, "non-negative"),
    ],
)
def test_list_by_run_with_total_count_rejects_invalid_pagination(
    limit: int,
    offset: int,
    message: str,
) -> None:
    # Given
    connection = FakeConnection()

    # When / Then
    with pytest.raises(ValueError, match=message):
        EventRepository(connection).list_by_run_with_total_count(
            "RUN-20260912-001",
            limit=limit,
            offset=offset,
        )
    assert connection.statements == []


@pytest.mark.parametrize("total", [True, -1, "3", None])
def test_list_by_run_with_total_count_rejects_invalid_total(total: object) -> None:
    # Given
    connection = FakeConnection(rows=[("RUN-20260912-001", total, None)])

    # When / Then
    with pytest.raises(TypeError, match="total"):
        EventRepository(connection).list_by_run_with_total_count(
            "RUN-20260912-001",
            limit=20,
            offset=0,
        )


def test_list_by_run_with_total_count_rejects_invalid_event_payload() -> None:
    # Given
    connection = FakeConnection(rows=[("RUN-20260912-001", 1, "not-an-object")])

    # When / Then
    with pytest.raises(TypeError, match="JSON object"):
        EventRepository(connection).list_by_run_with_total_count(
            "RUN-20260912-001",
            limit=20,
            offset=0,
        )


def test_get_by_run_returns_event_from_one_scoped_statement(
    normalized_event: NormalizedEvent,
) -> None:
    # Given
    connection = FakeConnection((normalized_event.run_id, normalized_event.model_dump(mode="json")))

    # When
    result = EventRepository(connection).get_by_run(
        normalized_event.run_id,
        normalized_event.event_id,
    )

    # Then
    assert result == EventLookupResult(run_exists=True, event=normalized_event)
    assert connection.statements == [
        (
            _SELECT_EVENT_BY_RUN,
            (normalized_event.event_id, normalized_event.run_id),
        )
    ]
    assert "events.run_id = runs.run_id" in _SELECT_EVENT_BY_RUN
    assert "events.event_id = %s" in _SELECT_EVENT_BY_RUN


def test_get_by_run_returns_empty_event_for_existing_run() -> None:
    # Given
    connection = FakeConnection(("RUN-20260912-001", None))

    # When
    result = EventRepository(connection).get_by_run(
        "RUN-20260912-001",
        "evt-unknown",
    )

    # Then
    assert result == EventLookupResult(run_exists=True, event=None)
    assert len(connection.statements) == 1


def test_get_by_run_returns_missing_run() -> None:
    # Given
    connection = FakeConnection()

    # When
    result = EventRepository(connection).get_by_run("RUN-UNKNOWN", "evt-001")

    # Then
    assert result == EventLookupResult(run_exists=False, event=None)
    assert len(connection.statements) == 1


def test_get_by_run_does_not_return_event_from_another_run() -> None:
    # Given
    connection = FakeConnection(("RUN-20260912-001", None))

    # When
    result = EventRepository(connection).get_by_run(
        "RUN-20260912-001",
        "evt-owned-by-another-run",
    )

    # Then
    assert result == EventLookupResult(run_exists=True, event=None)
    query, params = connection.statements[0]
    assert query == _SELECT_EVENT_BY_RUN
    assert params == ("evt-owned-by-another-run", "RUN-20260912-001")
    assert "events.run_id = runs.run_id" in query


def test_get_by_run_rejects_invalid_event_payload() -> None:
    # Given
    connection = FakeConnection(("RUN-20260912-001", "not-an-object"))

    # When / Then
    with pytest.raises(TypeError, match="JSON object"):
        EventRepository(connection).get_by_run("RUN-20260912-001", "evt-001")
    assert len(connection.statements) == 1


def _event_at(
    event: NormalizedEvent,
    *,
    event_id: str,
    second: int,
) -> NormalizedEvent:
    timestamp = datetime(2026, 9, 12, 1, 0, second, tzinfo=UTC)
    return event.model_copy(
        update={
            "event_id": event_id,
            "timestamp": timestamp,
            "event_time": timestamp,
        }
    )
