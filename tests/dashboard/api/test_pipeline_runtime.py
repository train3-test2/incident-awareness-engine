from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.dashboard.api import routes
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_pipeline_runtime_repository

STARTED_AT = datetime(2026, 10, 4, 1, tzinfo=UTC)
FRESHNESS_WINDOW = timedelta(minutes=5)
REQUEST_NOW = STARTED_AT + timedelta(minutes=1)
FRESH_AFTER = REQUEST_NOW - FRESHNESS_WINDOW


class FakePipelineRuntimeStatusRepository:
    def __init__(self, results: list[PipelineRuntimeStatus]) -> None:
        self.results = results
        self.calls: list[tuple[int, PipelineRuntimeState | None, datetime | None]] = []

    def list_recent(
        self,
        *,
        limit: int,
        status: PipelineRuntimeState | None = None,
        running_fresh_after: datetime | None = None,
    ) -> list[PipelineRuntimeStatus]:
        self.calls.append((limit, status, running_fresh_after))
        return self.results


@pytest.fixture(autouse=True)
def fixed_runtime_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_runtime_utc_now", lambda: REQUEST_NOW)


def test_lists_runtime_statuses_in_repository_order_with_all_fields() -> None:
    # Given
    failed = _failed_status()
    running = _running_status()
    completed = _completed_status()
    repository = FakePipelineRuntimeStatusRepository([failed, running, completed])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert response.status_code == 200
    assert repository.calls == [(20, None, FRESH_AFTER)]
    payload = response.json()
    assert [item["execution_id"] for item in payload["items"]] == [
        "execution-failed",
        "execution-running",
        "execution-completed",
    ]
    assert payload["items"][0] == {
        "execution_id": "execution-failed",
        "run_id": "RUN-20261004-003",
        "entity_id": "WIN-03",
        "status": "failed",
        "current_stage": None,
        "input_total": 4,
        "normalization_processed_count": 1,
        "remaining_count": 3,
        "started_at": "2026-10-04T01:00:00Z",
        "stage_started_at": None,
        "updated_at": "2026-10-04T01:00:05Z",
        "completed_at": None,
        "failed_stage": "fusion",
        "has_error": True,
        "is_stale": False,
    }
    assert payload["items"][1]["remaining_count"] == 2
    assert payload["items"][1]["has_error"] is False
    assert payload["items"][2]["remaining_count"] == 0
    assert payload["items"][2]["has_error"] is False


def test_passes_explicit_limit_to_runtime_repository() -> None:
    # Given
    repository = FakePipelineRuntimeStatusRepository([])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime?limit=5")

    # Then
    assert response.status_code == 200
    assert repository.calls == [(5, None, FRESH_AFTER)]


@pytest.mark.parametrize(
    ("query_value", "expected_status"),
    [
        ("running", PipelineRuntimeState.RUNNING),
        ("completed", PipelineRuntimeState.COMPLETED),
        ("failed", PipelineRuntimeState.FAILED),
    ],
)
def test_passes_runtime_status_filter_to_repository(
    query_value: str,
    expected_status: PipelineRuntimeState,
) -> None:
    # Given
    repository = FakePipelineRuntimeStatusRepository([])
    client = _client(repository)

    # When
    response = client.get(f"/operations/runtime?status={query_value}")

    # Then
    assert response.status_code == 200
    assert repository.calls == [(20, expected_status, FRESH_AFTER)]


@pytest.mark.parametrize(
    "query",
    ["limit=0", "limit=101", "status=unknown"],
)
def test_rejects_invalid_runtime_query_without_calling_repository(query: str) -> None:
    # Given
    repository = FakePipelineRuntimeStatusRepository([])
    client = _client(repository)

    # When
    response = client.get(f"/operations/runtime?{query}")

    # Then
    assert response.status_code == 422
    assert repository.calls == []


def test_returns_empty_runtime_items_without_not_found() -> None:
    # Given
    repository = FakePipelineRuntimeStatusRepository([])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_runtime_response_does_not_expose_database_or_exception_details() -> None:
    # Given
    repository = FakePipelineRuntimeStatusRepository([_failed_status()])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert response.status_code == 200
    response_text = response.text
    for secret_marker in (
        "DATABASE_URL",
        "postgresql://",
        "password",
        "Traceback",
        "exception",
    ):
        assert secret_marker not in response_text


def test_reports_running_within_freshness_window_as_not_stale() -> None:
    # Given
    running = _running_status()
    repository = FakePipelineRuntimeStatusRepository([running])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert running.updated_at >= FRESH_AFTER
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["status"] == "running"
    assert item["has_error"] is False
    assert item["is_stale"] is False


def test_returns_stale_running_without_reporting_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    running = _running_status()
    request_now = running.updated_at + FRESHNESS_WINDOW + timedelta(milliseconds=1)
    monkeypatch.setattr(routes, "_runtime_utc_now", lambda: request_now)
    repository = FakePipelineRuntimeStatusRepository([running])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert response.status_code == 200
    assert repository.calls == [(20, None, request_now - FRESHNESS_WINDOW)]
    item = response.json()["items"][0]
    assert item["execution_id"] == "execution-running"
    assert item["status"] == "running"
    assert item["has_error"] is False
    assert item["is_stale"] is True


def test_running_filter_returns_fresh_and_stale_running_with_staleness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    stale_running = _running_status()
    fresh_running = stale_running.model_copy(
        update={
            "execution_id": "execution-running-fresh",
            "run_id": "RUN-20261004-004",
            "updated_at": STARTED_AT + timedelta(minutes=10),
        }
    )
    request_now = fresh_running.updated_at + timedelta(minutes=1)
    monkeypatch.setattr(routes, "_runtime_utc_now", lambda: request_now)
    repository = FakePipelineRuntimeStatusRepository([fresh_running, stale_running])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime?status=running")

    # Then
    assert stale_running.updated_at < request_now - FRESHNESS_WINDOW <= fresh_running.updated_at
    assert response.status_code == 200
    assert repository.calls == [
        (20, PipelineRuntimeState.RUNNING, request_now - FRESHNESS_WINDOW),
    ]
    assert [
        (item["execution_id"], item["status"], item["has_error"], item["is_stale"])
        for item in response.json()["items"]
    ] == [
        ("execution-running-fresh", "running", False, False),
        ("execution-running", "running", False, True),
    ]


def test_never_marks_terminal_runtime_as_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    completed = _completed_status()
    failed = _failed_status()
    request_now = STARTED_AT + timedelta(days=1)
    monkeypatch.setattr(routes, "_runtime_utc_now", lambda: request_now)
    repository = FakePipelineRuntimeStatusRepository([completed, failed])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime")

    # Then
    assert completed.updated_at < request_now - FRESHNESS_WINDOW
    assert failed.updated_at < request_now - FRESHNESS_WINDOW
    assert response.status_code == 200
    assert [
        (item["status"], item["has_error"], item["is_stale"]) for item in response.json()["items"]
    ] == [
        ("completed", False, False),
        ("failed", True, False),
    ]


def test_uses_one_request_time_for_repository_cutoff_and_staleness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    boundary_running = _running_status()
    request_now = boundary_running.updated_at + FRESHNESS_WINDOW
    clock_values = iter((request_now, request_now + timedelta(milliseconds=1)))
    clock_calls: list[datetime] = []

    def advancing_clock() -> datetime:
        value = next(clock_values)
        clock_calls.append(value)
        return value

    monkeypatch.setattr(routes, "_runtime_utc_now", advancing_clock)
    repository = FakePipelineRuntimeStatusRepository([boundary_running])
    client = _client(repository)

    # When
    response = client.get("/operations/runtime?status=running")

    # Then
    assert response.status_code == 200
    assert clock_calls == [request_now]
    assert repository.calls == [
        (20, PipelineRuntimeState.RUNNING, boundary_running.updated_at),
    ]
    assert response.json()["items"][0]["is_stale"] is False


def _client(repository: FakePipelineRuntimeStatusRepository) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_pipeline_runtime_repository] = lambda: repository
    return TestClient(app)


def _running_status() -> PipelineRuntimeStatus:
    return PipelineRuntimeStatus(
        execution_id="execution-running",
        run_id="RUN-20261004-002",
        entity_id="WIN-02",
        status=PipelineRuntimeState.RUNNING,
        current_stage=PipelineStage.NORMALIZATION,
        input_total=4,
        normalization_processed_count=2,
        started_at=STARTED_AT,
        stage_started_at=STARTED_AT + timedelta(seconds=1),
        updated_at=STARTED_AT + timedelta(seconds=2),
        completed_at=None,
        failed_stage=None,
    )


def _completed_status() -> PipelineRuntimeStatus:
    return PipelineRuntimeStatus(
        execution_id="execution-completed",
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        status=PipelineRuntimeState.COMPLETED,
        current_stage=None,
        input_total=4,
        normalization_processed_count=4,
        started_at=STARTED_AT,
        stage_started_at=None,
        updated_at=STARTED_AT + timedelta(seconds=4),
        completed_at=STARTED_AT + timedelta(seconds=4),
        failed_stage=None,
    )


def _failed_status() -> PipelineRuntimeStatus:
    return PipelineRuntimeStatus(
        execution_id="execution-failed",
        run_id="RUN-20261004-003",
        entity_id="WIN-03",
        status=PipelineRuntimeState.FAILED,
        current_stage=None,
        input_total=4,
        normalization_processed_count=1,
        started_at=STARTED_AT,
        stage_started_at=None,
        updated_at=STARTED_AT + timedelta(seconds=5),
        completed_at=None,
        failed_stage=PipelineStage.FUSION,
    )
