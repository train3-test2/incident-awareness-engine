import os
from datetime import UTC, datetime
from urllib.parse import unquote, urlparse
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.run_repository import RunRepository

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"


@pytest.fixture
def database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_DATABASE_URL_ENV} is required for PostgreSQL integration tests")

    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})

    database_name = unquote(urlparse(url).path).strip("/").lower()
    explicitly_marked = os.environ.get(TEST_DATABASE_MARKER_ENV, "").lower() == "true"
    if "test" not in database_name and not explicitly_marked:
        pytest.skip(
            "PostgreSQL integration requires a database containing 'test' in its name or "
            f"{TEST_DATABASE_MARKER_ENV}=true"
        )

    return url


def test_dashboard_event_api_against_postgres(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id, other_run_id, empty_run_id, unknown_run_id = _unique_run_ids(UUID(suffix))
    event_ids = [f"evt-{index:02d}-{suffix}" for index in range(1, 5)]
    other_event_id = f"evt-other-{suffix}"
    unknown_event_id = f"evt-unknown-{suffix}"
    timestamps = [
        datetime(2026, 10, 3, 1, 0, 1, tzinfo=UTC),
        datetime(2026, 10, 3, 1, 0, 2, tzinfo=UTC),
        datetime(2026, 10, 3, 1, 0, 2, tzinfo=UTC),
        datetime(2026, 10, 3, 1, 0, 3, tzinfo=UTC),
    ]
    runs = [
        _run(run_id, target_host="WIN-PRIMARY"),
        _run(other_run_id, target_host="WIN-OTHER"),
        _run(empty_run_id, target_host="WIN-EMPTY"),
    ]
    events = [
        _event(
            event_ids[0],
            run_id,
            timestamps[0],
            host_id="WIN-PRIMARY",
            include_sensitive_fields=True,
        ),
        *[
            _event(event_id, run_id, timestamp, host_id="WIN-PRIMARY")
            for event_id, timestamp in zip(event_ids[1:], timestamps[1:], strict=True)
        ],
        _event(
            other_event_id,
            other_run_id,
            datetime(2026, 10, 3, 1, 0, 4, tzinfo=UTC),
            host_id="WIN-OTHER",
        ),
    ]

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        run_repository = RunRepository(connection)
        event_repository = EventRepository(connection)

        try:
            for run in runs:
                run_repository.save(run)
            for event in events:
                event_repository.save(event)
            connection.commit()

            monkeypatch.setenv(DATABASE_URL_ENV, database_url)
            app = create_app()

            # When
            with TestClient(app) as client:
                timeline_response = client.get(f"/runs/{run_id}/timeline")
                page_response = client.get(f"/runs/{run_id}/timeline?limit=2&offset=1")
                empty_page_response = client.get(f"/runs/{run_id}/timeline?limit=10&offset=100")
                empty_run_response = client.get(f"/runs/{empty_run_id}/timeline")
                unknown_run_timeline_response = client.get(f"/runs/{unknown_run_id}/timeline")

                counts_before_invalid_requests = _table_counts(connection)
                invalid_pagination_responses = [
                    client.get(f"/runs/{run_id}/timeline?limit=0"),
                    client.get(f"/runs/{run_id}/timeline?limit=201"),
                    client.get(f"/runs/{run_id}/timeline?offset=-1"),
                ]
                counts_after_invalid_requests = _table_counts(connection)

                detail_response = client.get(f"/runs/{run_id}/events/{event_ids[0]}")
                unknown_event_response = client.get(f"/runs/{run_id}/events/{unknown_event_id}")
                cross_run_response = client.get(f"/runs/{run_id}/events/{other_event_id}")
                other_run_detail_response = client.get(
                    f"/runs/{other_run_id}/events/{other_event_id}"
                )
                unknown_run_detail_response = client.get(
                    f"/runs/{unknown_run_id}/events/{event_ids[0]}"
                )

            # Then
            assert timeline_response.status_code == 200
            timeline = timeline_response.json()
            assert timeline["total"] == 4
            assert timeline["limit"] == 50
            assert timeline["offset"] == 0
            assert [item["event_id"] for item in timeline["items"]] == event_ids
            assert all(
                set(item) == {"event_id", "timestamp", "host_id", "event_type"}
                for item in timeline["items"]
            )
            assert timeline["items"][1]["timestamp"] == timeline["items"][2]["timestamp"]
            assert event_ids[1] < event_ids[2]

            assert page_response.status_code == 200
            assert page_response.json() == {
                "items": timeline["items"][1:3],
                "total": 4,
                "limit": 2,
                "offset": 1,
            }
            assert empty_page_response.status_code == 200
            assert empty_page_response.json() == {
                "items": [],
                "total": 4,
                "limit": 10,
                "offset": 100,
            }
            assert empty_run_response.status_code == 200
            assert empty_run_response.json() == {
                "items": [],
                "total": 0,
                "limit": 50,
                "offset": 0,
            }
            assert unknown_run_timeline_response.status_code == 404
            assert unknown_run_timeline_response.json() == {"detail": "Run not found"}
            assert all(response.status_code == 422 for response in invalid_pagination_responses)
            assert counts_after_invalid_requests == counts_before_invalid_requests

            assert detail_response.status_code == 200
            detail = detail_response.json()
            assert detail == {
                "event_id": event_ids[0],
                "run_id": run_id,
                "timestamp": "2026-10-03T01:00:01Z",
                "host_id": "WIN-PRIMARY",
                "event_type": "process_create",
                "source": "sysmon",
                "source_layer": "raw_telemetry",
                "source_event_id": "1",
                "timestamp_source": "event_time",
                "raw_ref": {
                    "raw_log_id": f"RAW-{event_ids[0]}",
                    "source_record_id": f"record-{event_ids[0]}",
                    "segment_no": 1,
                    "record_no": 101,
                    "parser_id": "sysmon-parser",
                    "parser_version": "v1",
                },
            }
            assert set(detail) == {
                "event_id",
                "run_id",
                "timestamp",
                "host_id",
                "event_type",
                "source",
                "source_layer",
                "source_event_id",
                "timestamp_source",
                "raw_ref",
            }
            assert set(detail["raw_ref"]) == {
                "raw_log_id",
                "source_record_id",
                "segment_no",
                "record_no",
                "parser_id",
                "parser_version",
            }
            for field in ("user", "process", "network", "event_time", "record_time", "ingest_time"):
                assert field not in detail
            for sensitive_marker in (
                "alice",
                "powershell.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "EncodedCommand",
                "explorer.exe",
                "tcp",
                "10.203.0.10",
                "198.51.100.25",
                "49152",
                "443",
            ):
                assert sensitive_marker not in detail_response.text

            assert unknown_event_response.status_code == 404
            assert unknown_event_response.json() == {"detail": "Event not found"}
            assert cross_run_response.status_code == 404
            assert cross_run_response.json() == {"detail": "Event not found"}
            assert other_run_detail_response.status_code == 200
            assert other_run_detail_response.json()["event_id"] == other_event_id
            assert other_run_detail_response.json()["run_id"] == other_run_id
            assert unknown_run_detail_response.status_code == 404
            assert unknown_run_detail_response.json() == {"detail": "Run not found"}

            responses = (
                timeline_response,
                page_response,
                empty_page_response,
                empty_run_response,
                unknown_run_timeline_response,
                *invalid_pagination_responses,
                detail_response,
                unknown_event_response,
                cross_run_response,
                other_run_detail_response,
                unknown_run_detail_response,
            )
            parsed_url = urlparse(database_url)
            secret_markers = {
                DATABASE_URL_ENV,
                TEST_DATABASE_URL_ENV,
                "postgresql://",
                "password",
                "Traceback",
                "SELECT ",
                database_url,
                parsed_url.password,
                parsed_url.hostname,
            }
            for response in responses:
                for marker in secret_markers:
                    if marker:
                        assert marker not in response.text
        finally:
            connection.rollback()
            for created_run_id in (run_id, other_run_id, empty_run_id):
                connection.execute("DELETE FROM runs WHERE run_id = %s", (created_run_id,))
            connection.commit()


def _run(run_id: str, *, target_host: str) -> RunMetadata:
    return RunMetadata(
        run_id=run_id,
        scenario_id="dashboard-event-api-integration",
        run_type=RunType.ATTACK,
        target_host=target_host,
        start_time=datetime(2026, 10, 3, 1, tzinfo=UTC),
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.3",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def _event(
    event_id: str,
    run_id: str,
    timestamp: datetime,
    *,
    host_id: str,
    include_sensitive_fields: bool = False,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        run_id=run_id,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id=host_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="1",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id=f"RAW-{event_id}",
            source_record_id=f"record-{event_id}",
            segment_no=1,
            record_no=101,
            parser_id="sysmon-parser",
            parser_version="v1",
        ),
        user="alice" if include_sensitive_fields else None,
        process=(
            ProcessInfo(
                name="powershell.exe",
                path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                command_line="powershell.exe -EncodedCommand U2VjcmV0",
                parent_name="explorer.exe",
            )
            if include_sensitive_fields
            else None
        ),
        network=(
            NetworkInfo(
                protocol="tcp",
                src_ip="10.203.0.10",
                src_port=49152,
                dst_ip="198.51.100.25",
                dst_port=443,
            )
            if include_sensitive_fields
            else None
        ),
    )


def _table_counts(
    connection: psycopg.Connection[tuple[object, ...]],
) -> tuple[int, int]:
    run_count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()
    event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()
    assert run_count is not None
    assert event_count is not None
    return run_count[0], event_count[0]


def _unique_run_ids(value: UUID) -> tuple[str, str, str, str]:
    integer = value.int
    year = 2077 + integer % 20
    month = 1 + (integer >> 8) % 12
    day = 1 + (integer >> 16) % 28
    first_sequence = (integer >> 24) % 997
    return tuple(
        f"RUN-{year:04d}{month:02d}{day:02d}-{sequence:03d}"
        for sequence in range(first_sequence, first_sequence + 4)
    )
