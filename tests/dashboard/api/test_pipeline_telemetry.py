from datetime import UTC, datetime, timedelta, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from incident_awareness.dashboard.api import dependencies
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_telemetry_reader
from incident_awareness.dashboard.telemetry_read_model import (
    DashboardTelemetryReader,
    PipelineTelemetryResponse,
    TelemetryQuery,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryInputConflictError,
)

END = datetime(2026, 10, 14, 1, 5, tzinfo=UTC)
NOW = END + timedelta(milliseconds=789)


def _point(seconds_ago: int = 1, *, count: int = 1, samples: int = 1, ns: int = 7) -> dict:
    start = END - timedelta(seconds=seconds_ago)
    return {
        "bucket_start": start,
        "bucket_end": start + timedelta(seconds=1),
        "observed_at": start + timedelta(milliseconds=123),
        "executions_count": 1,
        "input_accepted_count": 0,
        "processing_completed_count": count,
        "processing_failed_count": 0,
        "processing_latency_sample_count": samples,
        "processing_latency_sum_ns": ns,
    }


def _data(points: list[dict] | None = None, **updates: object) -> dict:
    points = points or []
    return {
        "points": points,
        "executions_count": 1 if points else 0,
        "observed_executions": 1 if points else 0,
        "partial_executions": 0,
        "unavailable_executions": 0,
        "disabled_executions": 0,
        "observation_issues": [],
        "last_observed_at": points[-1]["observed_at"] if points else None,
        "persisted_at": NOW if points else None,
        **updates,
    }


class FakeTelemetryRepository:
    def __init__(self, data: dict | None = None, error: Exception | None = None) -> None:
        self.data = data or _data()
        self.error = error
        self.calls: list[dict] = []

    def read_window(self, **kwargs: object) -> dict:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.data


def test_run_input_conflict_returns_409_without_sensitive_source_or_error_details() -> None:
    # Given
    repository = FakeTelemetryRepository(
        error=PipelineTelemetryInputConflictError(
            "s3://private/path postgres://secret:password@host SQL"
        )
    )

    # When
    response = _client(repository).get("/operations/telemetry?scope=run&run_id=RUN-A")

    # Then
    assert response.status_code == 409
    assert response.json() == {
        "detail": "Run telemetry input identity is conflicting or unknown across executions"
    }
    assert (
        "s3://" not in response.text
        and "password" not in response.text
        and "SQL" not in response.text
    )


def _client(repository: FakeTelemetryRepository, clock=lambda: NOW) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_dashboard_telemetry_reader] = lambda: DashboardTelemetryReader(
        repository, clock=clock
    )
    return TestClient(app)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", {"reported": True, "execution_id": None, "run_id": None, "entity_id": None}),
        (
            "scope=execution&execution_id=E1",
            {
                "reported": False,
                "execution_id": "E1",
                "run_id": None,
                "entity_id": None,
            },
        ),
        (
            "scope=run&run_id=RUN-001",
            {
                "reported": False,
                "execution_id": None,
                "run_id": "RUN-001",
                "entity_id": None,
            },
        ),
        (
            "scope=run&run_id=RUN-001&entity_id=WIN-B",
            {
                "reported": False,
                "execution_id": None,
                "run_id": "RUN-001",
                "entity_id": "WIN-B",
            },
        ),
    ],
)
def test_scope_and_one_request_clock(query: str, expected: dict) -> None:
    # Given
    repository = FakeTelemetryRepository(_data([_point()]))
    clocks = []

    def clock() -> datetime:
        clocks.append(NOW)
        return NOW

    client = _client(repository, clock)

    # When
    response = client.get(f"/operations/telemetry?{query}")

    # Then
    assert response.status_code == 200
    assert clocks == [NOW]
    assert repository.calls == [
        {
            "start": END - timedelta(seconds=300),
            "end": END,
            **expected,
        }
    ]
    payload = response.json()
    assert payload["range_end"] == "2026-10-14T01:05:00.000Z"
    assert payload["response_generated_at"] == "2026-10-14T01:05:00.789Z"
    assert payload["points"][0]["processing_latency_mean_ms"] == 0.000007
    assert payload["freshness"]["process_liveness"] == "unknown"
    assert (
        PipelineTelemetryResponse.model_validate_json(response.text).model_dump_json()
        == response.text
    )


def test_recent_summary_uses_last_60_completed_seconds_and_weighted_latency() -> None:
    # Given
    points = [
        _point(300, ns=999),
        _point(61, ns=999),
        _point(60, count=2, samples=2, ns=1_000_000),
        _point(1, count=1, samples=1, ns=2_000_000),
    ]
    repository = FakeTelemetryRepository(_data(points))

    # When
    response = _client(repository).get("/operations/telemetry")

    # Then
    assert response.status_code == 200
    summary = response.json()["recent_60s_summary"]
    assert summary["processing_completed_count"] == 3
    assert summary["processing_latency_sample_count"] == 3
    assert summary["processing_latency_sum_ns"] == 3_000_000
    assert summary["processing_latency_mean_ms"] == 1.0  # Not the mean of bucket means.
    assert summary["observed_bucket_count"] == 2
    assert summary["missing_bucket_count"] == 58
    assert summary["continuous_coverage"] is False


def test_real_zero_is_distinct_from_missing_and_latency_without_samples() -> None:
    # Given
    point = _point(count=0, samples=0, ns=0)
    point["input_accepted_count"] = 4  # Admission observed; processing 0, no duration sample.

    # When
    observed = _client(FakeTelemetryRepository(_data([point]))).get("/operations/telemetry").json()
    missing = _client(FakeTelemetryRepository()).get("/operations/telemetry").json()

    # Then
    assert observed["points"][0]["processing_completed_count"] == 0
    assert observed["points"][0]["processing_latency_mean_ms"] is None
    assert observed["recent_60s_summary"]["processing_completed_count"] == 0
    assert missing["points"] == []
    assert missing["recent_60s_summary"]["processing_completed_count"] is None
    assert missing["recent_60s_summary"]["processing_latency_sum_ns"] is None
    assert missing["observation_quality"]["status"] == "no_samples"
    assert missing["freshness"]["status"] == "unknown"


@pytest.mark.parametrize("issue", ["storage_error", "buffer_limit", "invalid_monotonic_duration"])
def test_quality_issues_and_disabled_collection_are_preserved(issue: str) -> None:
    # Given
    repository = FakeTelemetryRepository(
        _data(
            [_point(30)],
            partial_executions=1,
            disabled_executions=1,
            observation_issues=[issue],
        )
    )

    # When
    payload = _client(repository).get("/operations/telemetry").json()

    # Then
    assert payload["observation_quality"]["status"] == "partial"
    assert payload["observation_quality"]["observation_issues"] == [issue]
    assert payload["observation_quality"]["disabled_executions"] == 1
    assert payload["freshness"]["status"] == "stale"
    assert payload["freshness"]["process_liveness"] == "unknown"


def test_unavailable_execution_is_not_a_report_of_system_zero() -> None:
    # Given
    repository = FakeTelemetryRepository(
        _data(
            executions_count=1,
            unavailable_executions=1,
            observation_issues=["internal_error"],
            disabled_executions=1,
        )
    )

    # When
    payload = (
        _client(repository).get("/operations/telemetry?scope=execution&execution_id=E1").json()
    )

    # Then
    assert payload["points"] == []
    assert payload["observation_quality"]["status"] == "partial"
    assert payload["observation_quality"]["unreported_executions_included"] is False
    assert payload["recent_60s_summary"]["input_accepted_count"] is None


def test_historical_end_at_and_explicit_resolution() -> None:
    # Given
    repository = FakeTelemetryRepository()

    # When
    response = _client(repository).get(
        "/operations/telemetry",
        params={
            "end_at": "2026-10-13T23:59:59.123Z",
            "window_seconds": "60",
            "resolution_seconds": "1",
        },
    )

    # Then
    assert response.status_code == 200
    assert response.json()["range_end"] == "2026-10-13T23:59:59.000Z"
    assert repository.calls[0]["start"] == datetime(2026, 10, 13, 23, 58, 59, tzinfo=UTC)
    assert response.json()["freshness"]["reference_at"] == response.json()["range_end"]


@pytest.mark.parametrize(
    "query",
    [
        "scope=other",
        "scope=execution",
        "scope=run",
        "scope=reported&run_id=R1",
        "scope=execution&execution_id=E1&entity_id=H1",
        "scope=run&run_id=R1&execution_id=E1",
        "entity_id=H1",
        "scope=run&run_id=",
        "scope=run&run_id=%20%20",
        "window_seconds=301",
        "window_seconds=59",
        "window_seconds=60.5",
        "resolution_seconds=2",
        "resolution_seconds=true",
        "unexpected=1",
        "end_at=123456",
        "end_at=true",
        "end_at=2026-10-14T01:05:00",
        "end_at=2026-10-14T01:05:00%2B09:00",
        "end_at=2026-10-14T01:05:00.123456Z",
        "end_at=2027-01-01T00:00:00Z",
        "end_at=0001-01-01T00:00:00Z",
    ],
)
def test_invalid_query_does_not_read_repository(query: str) -> None:
    # Given
    repository = FakeTelemetryRepository()

    # When
    response = _client(repository).get(f"/operations/telemetry?{query}")

    # Then
    assert response.status_code == 422
    assert repository.calls == []


_SECRET_ERROR_TEXT = "postgresql://secret:password@db SELECT secret_column Traceback"
_UNAVAILABLE = (503, {"detail": "Telemetry database is unavailable"})
_READ_DEFECT = (500, {"detail": "Telemetry read failed"})


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        (psycopg.OperationalError, _UNAVAILABLE),
        (psycopg.errors.ConnectionFailure, _UNAVAILABLE),
        (psycopg.errors.QueryCanceled, _UNAVAILABLE),
        (psycopg.errors.AdminShutdown, _UNAVAILABLE),
        (psycopg.errors.CannotConnectNow, _UNAVAILABLE),
        (psycopg.errors.TooManyConnections, _UNAVAILABLE),
        (psycopg.errors.InvalidPassword, _UNAVAILABLE),
        (psycopg.errors.LockNotAvailable, _UNAVAILABLE),
        (psycopg.errors.SerializationFailure, _UNAVAILABLE),
        (psycopg.errors.UndefinedTable, _READ_DEFECT),
        (psycopg.errors.UndefinedColumn, _READ_DEFECT),
        (psycopg.errors.SyntaxError, _READ_DEFECT),
        (psycopg.errors.InsufficientPrivilege, _READ_DEFECT),
        (psycopg.errors.InvalidDatetimeFormat, _READ_DEFECT),
        (psycopg.errors.InFailedSqlTransaction, _READ_DEFECT),
        (psycopg.errors.FeatureNotSupported, _READ_DEFECT),
        (psycopg.InterfaceError, _READ_DEFECT),
    ],
)
def test_database_errors_split_availability_from_internal_defects_without_secrets(
    error_type: type[psycopg.Error],
    expected: tuple[int, dict[str, str]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    repository = FakeTelemetryRepository(error=error_type(_SECRET_ERROR_TEXT))

    # When
    with caplog.at_level("WARNING", logger="incident_awareness.dashboard.telemetry_read_model"):
        response = _client(repository).get("/operations/telemetry")

    # Then
    assert (response.status_code, response.json()) == expected
    assert "secret" not in response.text and "Traceback" not in response.text
    assert [record.levelname for record in caplog.records] == [
        "WARNING" if expected == _UNAVAILABLE else "ERROR"
    ]
    assert caplog.records[0].exc_info[1] is repository.error


def test_stored_aggregate_error_keeps_the_existing_500_contract() -> None:
    # Given
    repository = FakeTelemetryRepository(error=ValueError(_SECRET_ERROR_TEXT))

    # When
    response = _client(repository).get("/operations/telemetry")

    # Then
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored telemetry is invalid"}


@pytest.mark.parametrize(
    "points",
    [
        [_point(0)],
        [_point(301)],
        [_point(), _point()],
        [_point(), _point(2)],
    ],
)
def test_invalid_stored_bucket_order_and_bounds_are_not_silent_zero(points: list[dict]) -> None:
    # Given
    repository = FakeTelemetryRepository(_data(points))

    # When
    response = _client(repository).get("/operations/telemetry")

    # Then
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored telemetry is invalid"}


@pytest.mark.parametrize(
    "value",
    [
        123,
        123.5,
        True,
        "123",
        datetime(2026, 10, 14, tzinfo=UTC).replace(tzinfo=None),
        datetime(2026, 10, 14, tzinfo=timezone(timedelta(hours=9))),
    ],
)
def test_query_timestamp_core_validation(value: object) -> None:
    # Given / When / Then
    with pytest.raises(ValidationError):
        TelemetryQuery(end_at=value)


def test_single_request_returns_exactly_300_points_when_every_second_has_observations() -> None:
    # Given
    repository = FakeTelemetryRepository(_data([_point(i) for i in range(300, 0, -1)]))

    # When
    response = _client(repository).get("/operations/telemetry")

    # Then
    assert response.status_code == 200
    assert len(response.json()["points"]) == 300
    assert response.json()["recent_60s_summary"]["observed_bucket_count"] == 60
    assert response.json()["recent_60s_summary"]["continuous_coverage"] is False


def test_weighted_ns_sum_is_not_truncated_to_ms_or_float_before_aggregation() -> None:
    # Given
    total = 2**53 + 1
    point = _point(count=3, samples=3, ns=total)

    # When
    payload = _client(FakeTelemetryRepository(_data([point]))).get("/operations/telemetry").json()

    # Then
    assert payload["recent_60s_summary"]["processing_latency_sum_ns"] == total
    assert payload["points"][0]["processing_latency_sum_ns"] == total


def test_measured_zero_latency_with_a_sample_is_not_null() -> None:
    # Given
    repository = FakeTelemetryRepository(_data([_point(ns=0)]))

    # When
    payload = _client(repository).get("/operations/telemetry").json()

    # Then
    assert payload["points"][0]["processing_latency_mean_ms"] == 0.0
    assert payload["recent_60s_summary"]["processing_latency_mean_ms"] == 0.0


@pytest.mark.parametrize(("age", "expected"), [(15, "recent"), (16, "stale")])
def test_freshness_boundary_is_only_observation_age(age: int, expected: str) -> None:
    # Given
    point = _point(age)
    point["observed_at"] = point["bucket_start"]

    # When
    payload = _client(FakeTelemetryRepository(_data([point]))).get("/operations/telemetry").json()

    # Then
    assert payload["freshness"]["status"] == expected
    assert payload["freshness"]["age_seconds"] == age
    assert payload["freshness"]["process_liveness"] == "unknown"


@pytest.mark.parametrize("config_error", [RuntimeError, ValueError])
def test_database_configuration_defect_is_500_and_invalid_scope_does_not_connect(
    monkeypatch: pytest.MonkeyPatch,
    config_error: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    calls = []

    def failed_config():
        calls.append(True)
        raise config_error("DATABASE_URL postgresql://secret:password@host SQL details")

    monkeypatch.setattr(dependencies.DatabaseConfig, "from_environment", failed_config)
    client = TestClient(create_app())

    # When
    with caplog.at_level("WARNING", logger="incident_awareness.dashboard.telemetry_read_model"):
        invalid = client.get("/operations/telemetry?scope=execution")
        defect = client.get("/operations/telemetry?scope=reported")

    # Then
    assert invalid.status_code == 422
    assert (defect.status_code, defect.json()) == _READ_DEFECT
    assert "secret" not in defect.text
    assert calls == [True]
    assert [record.levelname for record in caplog.records] == ["ERROR"]
    assert isinstance(caplog.records[0].exc_info[1], config_error)


@pytest.mark.parametrize(
    ("connect_error", "expected"),
    [
        (psycopg.errors.ConnectionTimeout, _UNAVAILABLE),
        (psycopg.errors.InvalidPassword, _UNAVAILABLE),
        (psycopg.errors.CannotConnectNow, _UNAVAILABLE),
        (psycopg.ProgrammingError, _READ_DEFECT),
    ],
)
def test_database_connect_failure_is_classified_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    connect_error: type[psycopg.Error],
    expected: tuple[int, dict[str, str]],
) -> None:
    # Given
    monkeypatch.setattr(
        dependencies.DatabaseConfig,
        "from_environment",
        lambda: dependencies.DatabaseConfig("postgresql://user:secret@db.example/telemetry_test"),
    )

    def failed_connect(*args: object, **kwargs: object) -> None:
        raise connect_error(_SECRET_ERROR_TEXT)

    monkeypatch.setattr(dependencies.psycopg, "connect", failed_connect)

    # When
    response = TestClient(create_app()).get("/operations/telemetry")

    # Then
    assert (response.status_code, response.json()) == expected
    assert "secret" not in response.text


def test_telemetry_openapi_documents_fixed_scope_and_existing_runtime_remains_present() -> None:
    # Given
    client = _client(FakeTelemetryRepository())

    # When
    document = client.get("/openapi.json").json()

    # Then
    assert "/operations/runtime" in document["paths"]
    operation = document["paths"]["/operations/telemetry"]["get"]
    parameters = {item["name"]: item for item in operation["parameters"]}
    assert parameters["scope"]["schema"]["enum"] == ["execution", "run", "reported"]
    assert parameters["window_seconds"]["schema"]["maximum"] == 300
    assert parameters["resolution_seconds"]["schema"]["minimum"] == 1
    assert parameters["resolution_seconds"]["schema"]["maximum"] == 1


def test_period_without_samples_keeps_known_observed_execution_quality_and_age() -> None:
    # Given
    repository = FakeTelemetryRepository(
        _data(
            executions_count=1,
            observed_executions=1,
            last_observed_at=END - timedelta(hours=1),
            persisted_at=NOW,
        )
    )

    # When
    payload = (
        _client(repository).get("/operations/telemetry?scope=execution&execution_id=E1").json()
    )

    # Then
    assert payload["points"] == []
    assert payload["observation_quality"]["status"] == "no_samples"
    assert payload["observation_quality"]["observed_executions"] == 1
    assert payload["freshness"]["status"] == "stale"
    assert payload["freshness"]["process_liveness"] == "unknown"
