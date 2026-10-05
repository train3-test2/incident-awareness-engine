from collections.abc import Mapping
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
from incident_awareness.storage.repositories.event_repository import EventLookupResult

RUN_ID = "RUN-20261003-001"
EVENT_ID = "evt-001"
EVENT_ID_WITH_SLASH = "evt group/child"
ENCODED_EVENT_ID_WITH_SLASH = "evt%20group%2Fchild"


class FakeEventRepository:
    def __init__(self, result: EventLookupResult) -> None:
        self.result = result
        self.detail_calls: list[tuple[str, str]] = []

    def get_by_run(self, run_id: str, event_id: str) -> EventLookupResult:
        self.detail_calls.append((run_id, event_id))
        return self.result


def test_get_event_returns_provenance_projection_without_sensitive_fields() -> None:
    # Given
    event = _event()
    repository = FakeEventRepository(EventLookupResult(run_exists=True, event=event))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/events/{EVENT_ID}")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "event_id": EVENT_ID,
        "run_id": RUN_ID,
        "timestamp": "2026-10-03T01:00:01Z",
        "host_id": "WIN-01",
        "event_type": "process_create",
        "source": "sysmon",
        "source_layer": "raw_telemetry",
        "source_event_id": "1",
        "timestamp_source": "event_time",
        "raw_ref": {
            "raw_log_id": "RAW-001",
            "source_record_id": "record-001",
            "segment_no": 1,
            "record_no": 1,
            "parser_id": "sysmon-parser",
            "parser_version": "v1",
        },
    }
    assert _all_keys(payload).isdisjoint(
        {
            "user",
            "process",
            "network",
            "command_line",
            "path",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "event_time",
            "record_time",
            "ingest_time",
        }
    )
    assert repository.detail_calls == [(RUN_ID, EVENT_ID)]


def test_get_event_preserves_nullable_raw_reference_fields() -> None:
    # Given
    event = _event().model_copy(
        update={
            "raw_ref": RawLogReference(
                raw_log_id="RAW-001",
                segment_no=1,
                record_no=1,
            )
        }
    )
    client = _client(FakeEventRepository(EventLookupResult(run_exists=True, event=event)))

    # When
    response = client.get(f"/runs/{RUN_ID}/events/{EVENT_ID}")

    # Then
    assert response.status_code == 200
    assert response.json()["raw_ref"] == {
        "raw_log_id": "RAW-001",
        "source_record_id": None,
        "segment_no": 1,
        "record_no": 1,
        "parser_id": None,
        "parser_version": None,
    }


@pytest.mark.parametrize(
    ("result", "expected_detail"),
    [
        pytest.param(
            EventLookupResult(run_exists=False, event=None),
            "Run not found",
            id="run-missing",
        ),
        pytest.param(
            EventLookupResult(run_exists=True, event=None),
            "Event not found",
            id="event-missing",
        ),
        pytest.param(
            EventLookupResult(run_exists=True, event=None),
            "Event not found",
            id="event-owned-by-another-run",
        ),
    ],
)
def test_get_event_returns_scoped_404(
    result: EventLookupResult,
    expected_detail: str,
) -> None:
    # Given
    repository = FakeEventRepository(result)
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/events/{EVENT_ID}")

    # Then
    assert response.status_code == 404
    assert response.json() == {"detail": expected_detail}
    assert repository.detail_calls == [(RUN_ID, EVENT_ID)]


def test_encoded_slash_event_id_reaches_json_application_route() -> None:
    # Given
    repository = FakeEventRepository(EventLookupResult(run_exists=True, event=None))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/events/{ENCODED_EVENT_ID_WITH_SLASH}")

    # Then
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"detail": "Event not found"}
    assert repository.detail_calls == [(RUN_ID, EVENT_ID_WITH_SLASH)]


def test_empty_event_id_is_rejected_before_repository_lookup() -> None:
    # Given
    repository = FakeEventRepository(EventLookupResult(run_exists=True, event=None))
    client = _client(repository)

    # When
    response = client.get(f"/runs/{RUN_ID}/events/")

    # Then
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "detail": [
            {
                "type": "string_too_short",
                "loc": ["path", "event_id"],
                "msg": "String should have at least 1 character",
                "input": "",
                "ctx": {"min_length": 1},
            }
        ]
    }
    assert repository.detail_calls == []


def _client(repository: FakeEventRepository) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_event_repository] = lambda: repository
    return TestClient(app)


def _event() -> NormalizedEvent:
    timestamp = datetime(2026, 10, 3, 1, 0, 1, tzinfo=UTC)
    return NormalizedEvent(
        event_id=EVENT_ID,
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


def _all_keys(value: object) -> set[str]:
    if isinstance(value, Mapping):
        return set(value).union(*(nested for item in value.values() if (nested := _all_keys(item))))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()
