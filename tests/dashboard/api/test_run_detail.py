from datetime import UTC, datetime

from fastapi.testclient import TestClient

from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectionResult,
    DetectorStatus,
    Severity,
    WinningPath,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_decision_reader,
    get_run_repository,
)
from incident_awareness.dashboard.decision_read_model import CurrentDecisionReadModel
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError

RUN_ID = "RUN-20261003-001"
ENTITY_ID = "WIN-01"
BASE_TIME = datetime(2026, 10, 3, 1, tzinfo=UTC)


class FakeRunRepository:
    def __init__(self, run: RunMetadata | None) -> None:
        self.run = run
        self.get_calls: list[str] = []

    def get(self, run_id: str) -> RunMetadata | None:
        self.get_calls.append(run_id)
        return self.run


class FakeDashboardDecisionReader:
    def __init__(
        self,
        *,
        current_results: list[CurrentDecisionReadModel | None] | None = None,
        history_results: list[list[DecisionResult] | Exception] | None = None,
    ) -> None:
        self.current_results = list(current_results) if current_results is not None else []
        self.history_results = list(history_results) if history_results is not None else []
        self.current_calls: list[tuple[str, str]] = []
        self.history_calls: list[tuple[str, str]] = []

    def get_current(self, run_id: str, entity_id: str) -> CurrentDecisionReadModel | None:
        self.current_calls.append((run_id, entity_id))
        if not self.current_results:
            raise AssertionError("unexpected get_current call")
        return self.current_results.pop(0)

    def list_history(self, run_id: str, entity_id: str) -> list[DecisionResult]:
        self.history_calls.append((run_id, entity_id))
        if not self.history_results:
            raise AssertionError("unexpected list_history call")
        result = self.history_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_get_run_detail_returns_current_runtime_and_history() -> None:
    # Given
    run = _run_metadata()
    d1 = _decision("DEC-001")
    d2 = _decision("DEC-002", supersedes_decision_id=d1.decision_id)
    d3 = _decision("DEC-003", supersedes_decision_id=d2.decision_id)
    current = _current(d3)
    history = [d3, d2, d1]
    repository = FakeRunRepository(run)
    reader = FakeDashboardDecisionReader(
        current_results=[current],
        history_results=[history],
    )
    client = _client(repository, reader)

    # When
    response = client.get(f"/runs/{RUN_ID}")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["run_id"] == RUN_ID
    assert payload["current_decision"]["decision"]["decision_id"] == "DEC-003"
    assert payload["current_decision"]["latest_detection_result"]["rule_id"] == "rule-v3"
    assert payload["current_decision"]["latest_fusion_result"]["scorer_version"] == "v3"
    assert payload["current_decision"]["latest_fusion_stopping_trace"]["points"][0]["score"] == 0.7
    assert [decision["decision_id"] for decision in payload["decision_history"]] == [
        "DEC-003",
        "DEC-002",
        "DEC-001",
    ]
    assert repository.get_calls == [RUN_ID]
    assert reader.current_calls == [(RUN_ID, ENTITY_ID)]
    assert reader.history_calls == [(RUN_ID, ENTITY_ID)]


def test_get_run_detail_returns_404_without_querying_decisions() -> None:
    # Given
    repository = FakeRunRepository(None)
    reader = FakeDashboardDecisionReader()
    client = _client(repository, reader)

    # When
    response = client.get("/runs/RUN-20261003-999")

    # Then
    assert response.status_code == 404
    assert response.json() == {"detail": "Run not found"}
    assert reader.current_calls == []
    assert reader.history_calls == []


def test_get_run_detail_returns_empty_decisions_for_existing_run() -> None:
    # Given
    run = _run_metadata()
    reader = FakeDashboardDecisionReader(
        current_results=[None],
        history_results=[[]],
    )
    client = _client(FakeRunRepository(run), reader)

    # When
    response = client.get(f"/runs/{RUN_ID}")

    # Then
    assert response.status_code == 200
    assert response.json()["current_decision"] is None
    assert response.json()["decision_history"] == []


def test_get_run_detail_maps_retry_exhaustion_to_503() -> None:
    # Given
    d1 = _decision("DEC-001")
    d2 = _decision("DEC-002", supersedes_decision_id=d1.decision_id)
    current = _current(d1)
    reader = FakeDashboardDecisionReader(
        current_results=[current, current, current],
        history_results=[[d2, d1], [d2, d1], [d2, d1]],
    )
    client = _client(FakeRunRepository(_run_metadata()), reader)

    # When
    response = client.get(f"/runs/{RUN_ID}")

    # Then
    assert response.status_code == 503
    assert response.json() == {"detail": "Dashboard data is changing; retry the request"}
    assert len(reader.current_calls) == 3
    assert len(reader.history_calls) == 3


def test_get_run_detail_maps_decision_integrity_error_without_leaking_details() -> None:
    # Given
    d1 = _decision("DEC-001")
    error = DecisionIntegrityError(
        "SELECT secret FROM decisions at postgresql://user:password@database/dashboard"
    )
    reader = FakeDashboardDecisionReader(
        current_results=[_current(d1)],
        history_results=[error],
    )
    client = _client(FakeRunRepository(_run_metadata()), reader)

    # When
    response = client.get(f"/runs/{RUN_ID}")

    # Then
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored Decision lifecycle is inconsistent"}
    for secret_marker in ("SELECT", "postgresql://", "password", "Traceback"):
        assert secret_marker not in response.text


def _client(
    repository: FakeRunRepository,
    reader: FakeDashboardDecisionReader,
) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    app.dependency_overrides[get_dashboard_decision_reader] = lambda: reader
    return TestClient(app)


def _current(decision: DecisionResult) -> CurrentDecisionReadModel:
    detection = DetectionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id="rule-v3",
        rule_version="v3",
        severity=Severity.UNKNOWN,
    )
    fusion = FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-v3",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="v3",
        fusion_episodes=[],
    )
    trace = FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        scoring_config_version="fusion-config-v3",
        points=[
            FusionStoppingTracePoint(
                timestamp=BASE_TIME,
                score=0.7,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )
    return CurrentDecisionReadModel(
        decision=decision,
        latest_detection_result=detection,
        latest_fusion_result=fusion,
        latest_fusion_stopping_trace=trace,
    )


def _decision(
    decision_id: str,
    *,
    supersedes_decision_id: str | None = None,
) -> DecisionResult:
    return DecisionResult(
        run_id=RUN_ID,
        decision_id=decision_id,
        entity_id=ENTITY_ID,
        fast_status=DetectorStatus.MISS,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=None,
        t_e=None,
        decision_path=DecisionPath.NONE,
        winning_path=WinningPath.NONE,
        decision_reason="Runtime paths evaluated",
        config_version="parallel-v0.2",
        supersedes_decision_id=supersedes_decision_id,
    )


def _run_metadata() -> RunMetadata:
    return RunMetadata(
        run_id=RUN_ID,
        scenario_id="scenario-001",
        run_type=RunType.ATTACK,
        target_host=ENTITY_ID,
        start_time=BASE_TIME,
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
