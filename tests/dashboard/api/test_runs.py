from datetime import UTC, datetime

from fastapi.testclient import TestClient

from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_run_repository


class FakeRunRepository:
    def __init__(self, runs: list[RunMetadata] | None = None) -> None:
        self.runs = runs if runs is not None else []
        self.limits: list[int] = []

    def list_recent(self, limit: int) -> list[RunMetadata]:
        self.limits.append(limit)
        return self.runs


def test_get_runs_uses_default_limit_and_serializes_run_fields() -> None:
    # Given
    run = _run_metadata()
    repository = FakeRunRepository([run])
    client = _client(repository)

    # When
    response = client.get("/runs")

    # Then
    assert response.status_code == 200
    assert repository.limits == [20]
    assert response.json() == {
        "runs": [
            {
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "run_type": "attack",
                "target_host": run.target_host,
                "start_time": "2026-09-11T01:00:00Z",
                "end_time": None,
            }
        ]
    }


def test_get_runs_passes_explicit_limit() -> None:
    # Given
    repository = FakeRunRepository([_run_metadata()])
    client = _client(repository)

    # When
    response = client.get("/runs?limit=5")

    # Then
    assert response.status_code == 200
    assert repository.limits == [5]


def test_get_runs_returns_empty_list() -> None:
    # Given
    repository = FakeRunRepository()
    client = _client(repository)

    # When
    response = client.get("/runs")

    # Then
    assert response.status_code == 200
    assert response.json() == {"runs": []}


def test_get_runs_rejects_limit_outside_api_range() -> None:
    # Given
    repository = FakeRunRepository()
    client = _client(repository)

    # When
    responses = [client.get("/runs?limit=0"), client.get("/runs?limit=101")]

    # Then
    assert [response.status_code for response in responses] == [422, 422]
    assert repository.limits == []


def test_get_runs_does_not_expose_database_configuration() -> None:
    # Given
    client = _client(FakeRunRepository([_run_metadata()]))

    # When
    response = client.get("/runs")

    # Then
    assert response.status_code == 200
    for secret_marker in ("DATABASE_URL", "postgresql://", "password"):
        assert secret_marker not in response.text


def _client(repository: FakeRunRepository) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    return TestClient(app)


def _run_metadata() -> RunMetadata:
    return RunMetadata(
        run_id="RUN-20260911-001",
        scenario_id="scenario-001",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 11, 1, tzinfo=UTC),
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.2",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )
