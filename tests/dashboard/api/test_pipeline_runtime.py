from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_pipeline_runtime_repository

STARTED_AT = datetime(2026, 10, 4, 1, tzinfo=UTC)


class FakePipelineRuntimeStatusRepository:
    def __init__(self, results: list[PipelineRuntimeStatus]) -> None:
        self.results = results
        self.calls: list[tuple[int, PipelineRuntimeState | None]] = []

    def list_recent(
        self,
        *,
        limit: int,
        status: PipelineRuntimeState | None = None,
    ) -> list[PipelineRuntimeStatus]:
        self.calls.append((limit, status))
        return self.results


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
    assert repository.calls == [(20, None)]
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
    assert repository.calls == [(5, None)]


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
    assert repository.calls == [(20, expected_status)]


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
