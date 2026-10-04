from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_event_repository

RUN_ID = "RUN-20261003-001"


class FakeEventRepository:
    def __init__(
        self,
        result: tuple[int, list[NormalizedEvent]] | None,
    ) -> None:
        self.result = result
        self.timeline_calls: list[tuple[str, int, int]] = []

    def list_by_run_with_total_count(
        self,
        run_id: str,
        *,
        limit: int,
        offset: int,
    ) -> tuple[int, list[NormalizedEvent]] | None:
        self.timeline_calls.append((run_id, limit, offset))
        return self.result


def test_get_event_timeline_returns_default_page_with_only_summary_fields() -> None:
    # Given
    events = [
        _event("evt-001", second=1),
        _event("evt-002", second=2),
        _event("evt-003", second=2),
    ]
    repository = FakeEventRepository((3, events))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/timeline")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert payload["limit"] == 50
    assert payload["offset"] == 0
    assert [item["event_id"] for item in payload["items"]] == [
        "evt-001",
        "evt-002",
        "evt-003",
    ]
    assert payload["items"][0]["timestamp"] == "2026-10-03T01:00:01Z"
    assert all(
        set(item) == {"event_id", "timestamp", "host_id", "event_type"} for item in payload["items"]
    )
    assert repository.timeline_calls == [(RUN_ID, 50, 0)]


def test_get_event_timeline_passes_explicit_pagination() -> None:
    # Given
    repository = FakeEventRepository((10, []))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/timeline?limit=10&offset=20")

    # Then
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 10, "limit": 10, "offset": 20}
    assert repository.timeline_calls == [(RUN_ID, 10, 20)]


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=201",
        "offset=-1",
    ],
)
def test_get_event_timeline_rejects_invalid_pagination(query: str) -> None:
    # Given
    repository = FakeEventRepository((0, []))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/timeline?{query}")

    # Then
    assert response.status_code == 422
    assert repository.timeline_calls == []


@pytest.mark.parametrize(
    ("result", "url", "expected"),
    [
        ((0, []), f"/runs/{RUN_ID}/timeline", {"items": [], "total": 0, "limit": 50, "offset": 0}),
        (
            (10, []),
            f"/runs/{RUN_ID}/timeline?offset=100",
            {"items": [], "total": 10, "limit": 50, "offset": 100},
        ),
    ],
)
def test_get_event_timeline_returns_empty_pages(
    result: tuple[int, list[NormalizedEvent]],
    url: str,
    expected: dict[str, object],
) -> None:
    # Given
    client = _client(FakeEventRepository(result))

    # When
    response = client.get(url)

    # Then
    assert response.status_code == 200
    assert response.json() == expected


def test_get_event_timeline_returns_404_when_run_does_not_exist() -> None:
    # Given
    repository = FakeEventRepository(None)
    client = _client(repository)

    # When
    response = client.get("/runs/RUN-UNKNOWN/timeline")

    # Then
    assert response.status_code == 404
    assert response.json() == {"detail": "Run not found"}
    assert repository.timeline_calls == [("RUN-UNKNOWN", 50, 0)]


def _client(repository: FakeEventRepository) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_event_repository] = lambda: repository
    return TestClient(app)


def _event(event_id: str, *, second: int) -> NormalizedEvent:
    timestamp = datetime(2026, 10, 3, 1, 0, second, tzinfo=UTC)
    return NormalizedEvent(
        event_id=event_id,
        run_id=RUN_ID,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id="WIN-01",
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="1",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            source_record_id="record-001",
            segment_no=1,
            record_no=1,
            parser_id="sysmon-parser",
            parser_version="v1",
        ),
        user="alice",
        process=ProcessInfo(
            path="C:/Windows/System32/cmd.exe",
            command_line="cmd.exe /c whoami",
            parent_name="explorer.exe",
        ),
        network=NetworkInfo(
            src_ip="10.0.0.1",
            src_port=49152,
            dst_ip="10.0.0.2",
            dst_port=443,
        ),
    )
