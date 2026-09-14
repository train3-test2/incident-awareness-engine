from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectionResult,
    DetectorStatus,
    Severity,
    WinningPath,
)
from incident_awareness.storage.repositories.result_repository import (
    _INSERT_DECISION,
    _SELECT_DECISION_PAYLOAD,
    _SELECT_DETECTION_RESULT_PAYLOAD,
    _SELECT_FUSION_RESULT_PAYLOAD,
    _UPSERT_DETECTION_RESULT,
    _UPSERT_FUSION_RESULT,
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
)


class FakeCursor:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row


class FakeConnection:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self.row = row
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> FakeCursor:
        self.statements.append((query, params))
        return FakeCursor(self.row)

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture
def fusion_result() -> FusionResult:
    return FusionResult(
        run_id="RUN-20260912-001",
        entity_id="WIN-01",
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="v0.2",
        scoring_profile_id="S0",
        scoring_method="temporal_fusion",
        scorer_version="v0.2",
        fusion_episodes=[],
    )


@pytest.fixture
def detection_result() -> DetectionResult:
    return DetectionResult(
        run_id="RUN-20260912-001",
        entity_id="WIN-01",
        detector_time=datetime(2026, 9, 12, 1, tzinfo=UTC),
        detector_status=DetectorStatus.DETECTED,
        detector_id="hayabusa",
        rule_id="RULE-001",
        rule_version="v0.2",
        severity=Severity.HIGH,
    )


@pytest.fixture
def decision_result() -> DecisionResult:
    decision_time = datetime(2026, 9, 12, 1, tzinfo=UTC)
    return DecisionResult(
        run_id="RUN-20260912-001",
        decision_id="DEC-001",
        entity_id="WIN-01",
        fast_status=DetectorStatus.DETECTED,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=decision_time,
        t_e=decision_time,
        decision_path=DecisionPath.FAST,
        winning_path=WinningPath.FAST,
        decision_reason="Fast 경로 탐지",
        config_version="v0.2",
    )


def test_fusion_repository_saves_and_rebuilds_result(fusion_result: FusionResult) -> None:
    connection = FakeConnection((fusion_result.model_dump(mode="json"),))
    repository = FusionResultRepository(connection)

    repository.save(fusion_result)
    stored_result = repository.get(fusion_result.run_id, fusion_result.entity_id)

    assert connection.commits == 1
    assert connection.statements[0][0] == _UPSERT_FUSION_RESULT
    assert connection.statements[0][1][:4] == (
        fusion_result.run_id,
        fusion_result.entity_id,
        "miss",
        None,
    )
    assert isinstance(connection.statements[0][1][4], Jsonb)
    assert connection.statements[1] == (
        _SELECT_FUSION_RESULT_PAYLOAD,
        (fusion_result.run_id, fusion_result.entity_id),
    )
    assert stored_result == fusion_result


def test_detection_repository_saves_and_rebuilds_result(
    detection_result: DetectionResult,
) -> None:
    connection = FakeConnection((detection_result.model_dump(mode="json"),))
    repository = DetectionResultRepository(connection)

    repository.save(detection_result)
    stored_result = repository.get(detection_result.run_id, detection_result.entity_id)

    assert connection.commits == 1
    assert connection.statements[0][0] == _UPSERT_DETECTION_RESULT
    assert connection.statements[0][1][:5] == (
        detection_result.run_id,
        detection_result.entity_id,
        "detected",
        datetime(2026, 9, 12, 1, tzinfo=UTC),
        "hayabusa",
    )
    assert isinstance(connection.statements[0][1][5], Jsonb)
    assert connection.statements[1] == (
        _SELECT_DETECTION_RESULT_PAYLOAD,
        (detection_result.run_id, detection_result.entity_id),
    )
    assert stored_result == detection_result


def test_decision_repository_inserts_and_rebuilds_immutable_result(
    decision_result: DecisionResult,
) -> None:
    connection = FakeConnection((decision_result.model_dump(mode="json"),))
    repository = DecisionRepository(connection)

    repository.save(decision_result)
    stored_result = repository.get(decision_result.decision_id)

    assert "ON CONFLICT" not in _INSERT_DECISION
    assert connection.commits == 1
    assert connection.statements[0][0] == _INSERT_DECISION
    assert connection.statements[0][1][:5] == (
        "DEC-001",
        "RUN-20260912-001",
        "WIN-01",
        "detected",
        "miss",
    )
    assert isinstance(connection.statements[0][1][10], Jsonb)
    assert connection.statements[1] == (_SELECT_DECISION_PAYLOAD, ("DEC-001",))
    assert stored_result == decision_result


@pytest.mark.parametrize(
    ("repository", "arguments"),
    [
        (FusionResultRepository(FakeConnection()), ("RUN-20260912-001", "WIN-01")),
        (DetectionResultRepository(FakeConnection()), ("RUN-20260912-001", "WIN-01")),
        (DecisionRepository(FakeConnection()), ("DEC-001",)),
    ],
)
def test_result_repositories_return_none_when_result_does_not_exist(
    repository: FusionResultRepository | DetectionResultRepository | DecisionRepository,
    arguments: tuple[str, ...],
) -> None:
    assert repository.get(*arguments) is None


@pytest.mark.parametrize(
    ("repository", "arguments", "table_name"),
    [
        (
            FusionResultRepository(FakeConnection(("invalid",))),
            ("RUN-20260912-001", "WIN-01"),
            "fusion_results",
        ),
        (
            DetectionResultRepository(FakeConnection(("invalid",))),
            ("RUN-20260912-001", "WIN-01"),
            "detection_results",
        ),
        (DecisionRepository(FakeConnection(("invalid",))), ("DEC-001",), "decisions"),
    ],
)
def test_result_repositories_reject_non_object_payloads(
    repository: FusionResultRepository | DetectionResultRepository | DecisionRepository,
    arguments: tuple[str, ...],
    table_name: str,
) -> None:
    with pytest.raises(TypeError, match=table_name):
        repository.get(*arguments)
