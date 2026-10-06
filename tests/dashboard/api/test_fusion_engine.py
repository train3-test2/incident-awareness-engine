from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
    FusionRuntimeReplaySnapshot,
    FusionRuntimeScoringSnapshot,
    FusionRuntimeStoppingSnapshot,
    FusionRuntimeWindowSnapshot,
)
from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectorStatus,
    WinningPath,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_fusion_engine_reader,
    get_run_repository,
)
from incident_awareness.dashboard.decision_read_model import DashboardReadConsistencyError
from incident_awareness.dashboard.fusion_engine_read_model import FusionEngineReadModel

RUN_ID = "RUN-20261007-001"
ENTITY_ID = "WIN-01"
BASE_TIME = datetime(2026, 10, 7, 1, tzinfo=UTC)


class FakeRunRepository:
    def __init__(self, runs: list[RunMetadata | None]) -> None:
        self.runs = list(runs)
        self.calls: list[str] = []

    def get(self, run_id: str) -> RunMetadata | None:
        self.calls.append(run_id)
        if not self.runs:
            raise AssertionError("unexpected RunRepository.get call")
        return self.runs.pop(0)


class FakeFusionEngineReader:
    def __init__(
        self,
        results: list[FusionEngineReadModel | Exception] | None = None,
    ) -> None:
        self.results = list(results) if results is not None else []
        self.calls: list[tuple[str, str]] = []

    def get_current(self, run_id: str, entity_id: str) -> FusionEngineReadModel:
        self.calls.append((run_id, entity_id))
        if not self.results:
            raise AssertionError("unexpected get_current call")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_get_fusion_engine_returns_all_stored_runtime_contracts() -> None:
    # Given
    run = _run_metadata()
    runtime = _runtime()
    repository = FakeRunRepository([run, run])
    reader = FakeFusionEngineReader([runtime])
    client = _client(repository, reader)

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    assert response.json() == {
        "run": run.model_dump(mode="json"),
        "current_decision": runtime.current_decision.model_dump(mode="json"),
        "fusion_result": runtime.fusion_result.model_dump(mode="json"),
        "stopping_trace": runtime.stopping_trace.model_dump(mode="json"),
        "runtime_config_snapshot": runtime.runtime_config_snapshot.model_dump(mode="json"),
    }
    assert repository.calls == [RUN_ID, RUN_ID]
    assert reader.calls == [(RUN_ID, ENTITY_ID)]


def test_get_fusion_engine_returns_404_without_querying_runtime() -> None:
    # Given
    repository = FakeRunRepository([None])
    reader = FakeFusionEngineReader()
    client = _client(repository, reader)

    # When
    response = client.get("/runs/RUN-20261007-999/fusion-engine")

    # Then
    assert response.status_code == 404
    assert response.json() == {"detail": "Run not found"}
    assert reader.calls == []


def test_get_fusion_engine_preserves_runtime_without_current_decision() -> None:
    # Given
    run = _run_metadata()
    runtime = _runtime(current_decision=None)
    client = _client(FakeRunRepository([run, run]), FakeFusionEngineReader([runtime]))

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["current_decision"] is None
    assert payload["fusion_result"] == runtime.fusion_result.model_dump(mode="json")
    assert payload["stopping_trace"] == runtime.stopping_trace.model_dump(mode="json")
    assert payload["runtime_config_snapshot"] == (
        runtime.runtime_config_snapshot.model_dump(mode="json")
    )


@pytest.mark.parametrize(
    ("missing_field", "runtime_update"),
    [
        ("fusion_result", {"fusion_result": None}),
        ("stopping_trace", {"stopping_trace": None}),
        ("runtime_config_snapshot", {"runtime_config_snapshot": None}),
    ],
)
def test_get_fusion_engine_preserves_each_missing_runtime_as_null(
    missing_field: str,
    runtime_update: dict[str, object],
) -> None:
    # Given
    run = _run_metadata()
    runtime = _runtime(**runtime_update)
    client = _client(FakeRunRepository([run, run]), FakeFusionEngineReader([runtime]))

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    assert response.json()[missing_field] is None


def test_get_fusion_engine_preserves_all_missing_runtime_as_null() -> None:
    # Given
    run = _run_metadata()
    runtime = FusionEngineReadModel(
        current_decision=None,
        fusion_result=None,
        stopping_trace=None,
        runtime_config_snapshot=None,
    )
    client = _client(FakeRunRepository([run, run]), FakeFusionEngineReader([runtime]))

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["current_decision"] is None
    assert payload["fusion_result"] is None
    assert payload["stopping_trace"] is None
    assert payload["runtime_config_snapshot"] is None


def test_get_fusion_engine_maps_unstable_current_head_to_503() -> None:
    # Given
    error = DashboardReadConsistencyError("sensitive Current head details")
    client = _client(
        FakeRunRepository([_run_metadata()]),
        FakeFusionEngineReader([error]),
    )

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 503
    assert response.json() == {"detail": "Dashboard data is changing; retry the request"}
    assert "sensitive Current head details" not in response.text


def test_get_fusion_engine_retries_changed_run_with_new_entity_scope() -> None:
    # Given
    run_v1 = _run_metadata(scenario_id="scenario-v1", target_host="WIN-OLD")
    run_v2 = _run_metadata(scenario_id="scenario-v2", target_host="WIN-NEW")
    runtime_v1 = _runtime(entity_id=run_v1.target_host)
    runtime_v2 = _runtime(entity_id=run_v2.target_host)
    repository = FakeRunRepository([run_v1, run_v2, run_v2, run_v2])
    reader = FakeFusionEngineReader([runtime_v1, runtime_v2])
    client = _client(repository, reader)

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    assert response.json()["run"]["scenario_id"] == "scenario-v2"
    assert reader.calls == [(RUN_ID, "WIN-OLD"), (RUN_ID, "WIN-NEW")]
    assert repository.calls == [RUN_ID] * 4


def test_get_fusion_engine_maps_unstable_run_to_503() -> None:
    # Given
    run_v1 = _run_metadata(scenario_id="scenario-v1")
    run_v2 = _run_metadata(scenario_id="scenario-v2")
    repository = FakeRunRepository([run_v1, run_v2] * 3)
    reader = FakeFusionEngineReader([_runtime()] * 3)
    client = _client(repository, reader)

    # When
    response = client.get(f"/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 503
    assert response.json() == {"detail": "Dashboard data is changing; retry the request"}
    assert repository.calls == [RUN_ID] * 6
    assert reader.calls == [(RUN_ID, ENTITY_ID)] * 3


def test_existing_run_detail_response_schema_is_unchanged() -> None:
    # Given
    app = create_app()

    # When
    openapi = app.openapi()

    # Then
    current_properties = openapi["components"]["schemas"]["CurrentDecisionResponse"]["properties"]
    assert set(current_properties) == {
        "decision",
        "latest_detection_result",
        "latest_fusion_result",
        "latest_fusion_stopping_trace",
    }
    assert "runtime_config_snapshot" not in current_properties


def _client(
    repository: FakeRunRepository,
    reader: FakeFusionEngineReader,
) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    app.dependency_overrides[get_dashboard_fusion_engine_reader] = lambda: reader
    return TestClient(app)


def _runtime(
    *,
    entity_id: str = ENTITY_ID,
    current_decision: DecisionResult | None | object = ...,
    fusion_result: FusionResult | None | object = ...,
    stopping_trace: FusionStoppingTrace | None | object = ...,
    runtime_config_snapshot: FusionRuntimeConfigSnapshot | None | object = ...,
) -> FusionEngineReadModel:
    return FusionEngineReadModel(
        current_decision=(
            _decision(entity_id=entity_id) if current_decision is ... else current_decision
        ),
        fusion_result=(
            _fusion_result(entity_id=entity_id) if fusion_result is ... else fusion_result
        ),
        stopping_trace=(
            _stopping_trace(entity_id=entity_id) if stopping_trace is ... else stopping_trace
        ),
        runtime_config_snapshot=(
            _runtime_config_snapshot(entity_id=entity_id)
            if runtime_config_snapshot is ...
            else runtime_config_snapshot
        ),
    )


def _decision(*, entity_id: str = ENTITY_ID) -> DecisionResult:
    return DecisionResult(
        run_id=RUN_ID,
        decision_id="DEC-001",
        entity_id=entity_id,
        fast_status=DetectorStatus.MISS,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=None,
        t_e=None,
        decision_path=DecisionPath.NONE,
        winning_path=WinningPath.NONE,
        decision_reason="Runtime paths evaluated",
        config_version="parallel-v0.2",
    )


def _fusion_result(*, entity_id: str = ENTITY_ID) -> FusionResult:
    return FusionResult(
        run_id=RUN_ID,
        entity_id=entity_id,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-v1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v1",
        fusion_episodes=[],
    )


def _stopping_trace(*, entity_id: str = ENTITY_ID) -> FusionStoppingTrace:
    return FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v1",
        points=[
            FusionStoppingTracePoint(
                timestamp=BASE_TIME,
                score=0.5,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )


def _runtime_config_snapshot(
    *,
    entity_id: str = ENTITY_ID,
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=RUN_ID,
        entity_id=entity_id,
        config_version="fusion-config-v1",
        model_version=None,
        window=FusionRuntimeWindowSnapshot(window_size_sec=60.0),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10.0),
        scoring=FusionRuntimeScoringSnapshot(
            method="simple_score",
            scorer_version="simple-score-v1",
            profile_id="s0-profile",
            evidence_types=("process_start",),
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )


def _run_metadata(
    *,
    scenario_id: str = "scenario-001",
    target_host: str = ENTITY_ID,
) -> RunMetadata:
    return RunMetadata(
        run_id=RUN_ID,
        scenario_id=scenario_id,
        run_type=RunType.ATTACK,
        target_host=target_host,
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
