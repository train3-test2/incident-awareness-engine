from datetime import UTC, datetime

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
    DetectionResult,
    DetectorStatus,
    WinningPath,
)
from incident_awareness.common.models.runtime_snapshot import (
    DecisionRuntimeSnapshot,
    build_decision_runtime_snapshot,
)
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_decision_reader
from incident_awareness.dashboard.decision_read_model import HistoricalDecisionReadModel
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError

RUN_ID = "RUN-20261003-001"
ENTITY_ID = "WIN-01"
DECISION_ID = "DEC-001"
BASE_TIME = datetime(2026, 10, 3, 1, tzinfo=UTC)


class FakeDashboardDecisionReader:
    def __init__(
        self,
        result: HistoricalDecisionReadModel | Exception | None,
    ) -> None:
        self.result = result
        self.historical_calls: list[str] = []

    def get_historical(self, decision_id: str) -> HistoricalDecisionReadModel | None:
        self.historical_calls.append(decision_id)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def get_current(self, *_args: object) -> None:
        raise AssertionError("Historical API must not query latest Current Runtime")

    def list_history(self, *_args: object) -> None:
        raise AssertionError("Historical API must not query Decision history")


def test_get_historical_decision_returns_immutable_runtime_snapshot() -> None:
    # Given
    decision = _decision()
    snapshot = build_decision_runtime_snapshot(
        decision_result=decision,
        detection_result=_detection_result(),
        fusion_result=_fusion_result(),
        fusion_stopping_trace=_stopping_trace(),
        fusion_runtime_config_snapshot=_runtime_config_snapshot(),
    )
    reader = FakeDashboardDecisionReader(
        HistoricalDecisionReadModel(
            decision=decision,
            runtime_snapshot=snapshot,
        )
    )
    client = _client(reader)

    # When
    response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 200
    assert response.json()["decision"]["decision_id"] == DECISION_ID
    assert response.json()["runtime_snapshot"]["decision_id"] == DECISION_ID
    assert response.json()["runtime_snapshot"]["fusion_runtime_config_snapshot"] == (
        _runtime_config_snapshot().model_dump(mode="json")
    )
    assert reader.historical_calls == [DECISION_ID]


def test_get_historical_decision_restores_embedded_legacy_snapshot_without_config() -> None:
    # Given
    decision = _decision()
    current_snapshot = build_decision_runtime_snapshot(
        decision_result=decision,
        detection_result=_detection_result(),
        fusion_result=_fusion_result(),
        fusion_stopping_trace=_stopping_trace(),
        fusion_runtime_config_snapshot=_runtime_config_snapshot(),
    )
    legacy_payload = current_snapshot.model_dump(mode="json")
    del legacy_payload["fusion_runtime_config_snapshot"]
    legacy_snapshot = DecisionRuntimeSnapshot.model_validate(legacy_payload)
    reader = FakeDashboardDecisionReader(
        HistoricalDecisionReadModel(
            decision=decision,
            runtime_snapshot=legacy_snapshot,
        )
    )
    client = _client(reader)

    # When
    response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 200
    assert response.json()["runtime_snapshot"] is not None
    assert response.json()["runtime_snapshot"]["fusion_runtime_config_snapshot"] is None


def test_get_historical_decision_preserves_legacy_null_snapshot() -> None:
    # Given
    decision = _decision()
    reader = FakeDashboardDecisionReader(
        HistoricalDecisionReadModel(
            decision=decision,
            runtime_snapshot=None,
        )
    )
    client = _client(reader)

    # When
    response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 200
    assert response.json()["decision"]["decision_id"] == DECISION_ID
    assert response.json()["runtime_snapshot"] is None
    assert reader.historical_calls == [DECISION_ID]


def test_get_historical_decision_returns_404_when_decision_does_not_exist() -> None:
    # Given
    reader = FakeDashboardDecisionReader(None)
    client = _client(reader)

    # When
    response = client.get("/decisions/DEC-UNKNOWN")

    # Then
    assert response.status_code == 404
    assert response.json() == {"detail": "Decision not found"}
    assert reader.historical_calls == ["DEC-UNKNOWN"]


def test_get_historical_decision_uses_existing_safe_integrity_error_mapping() -> None:
    # Given
    error = DecisionIntegrityError(
        "SELECT password FROM decisions at postgresql://user:secret@database/dashboard"
    )
    client = _client(FakeDashboardDecisionReader(error))

    # When
    response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored Decision lifecycle is inconsistent"}
    for secret_marker in ("SELECT", "postgresql://", "password", "Traceback"):
        assert secret_marker not in response.text


def _client(reader: FakeDashboardDecisionReader) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_dashboard_decision_reader] = lambda: reader
    return TestClient(app)


def _decision() -> DecisionResult:
    return DecisionResult(
        run_id=RUN_ID,
        decision_id=DECISION_ID,
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
    )


def _detection_result() -> DetectionResult:
    return DetectionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )


def _fusion_result() -> FusionResult:
    return FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="historical-v1",
        scoring_profile_id="historical-v1",
        scoring_method="simple_score",
        scorer_version="historical-v1",
        fusion_episodes=[],
    )


def _stopping_trace() -> FusionStoppingTrace:
    return FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        scoring_config_version="historical-v1",
        points=[
            FusionStoppingTracePoint(
                timestamp=BASE_TIME,
                score=0.1,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )


def _runtime_config_snapshot() -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        config_version="historical-v1",
        model_version=None,
        window=FusionRuntimeWindowSnapshot(window_size_sec=60.0),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10.0),
        scoring=FusionRuntimeScoringSnapshot(
            method="simple_score",
            scorer_version="historical-v1",
            profile_id="historical-v1",
            evidence_types=("process_start",),
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )
