from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectorStatus,
    WinningPath,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api.service import get_run_detail
from incident_awareness.dashboard.decision_read_model import (
    CurrentDecisionReadModel,
    DashboardReadConsistencyError,
)

RUN_ID = "RUN-20261003-001"
ENTITY_ID = "WIN-01"


class FakeRunRepository:
    def __init__(self, results: list[RunMetadata | None]) -> None:
        self.results = list(results)
        self.get_calls: list[str] = []

    def get(self, run_id: str) -> RunMetadata | None:
        self.get_calls.append(run_id)
        if not self.results:
            raise AssertionError("unexpected RunRepository.get call")
        return self.results.pop(0)


class FakeDashboardDecisionReader:
    def __init__(
        self,
        *,
        current_results: list[CurrentDecisionReadModel | None],
        history_results: list[list[DecisionResult]],
    ) -> None:
        self.current_results = list(current_results)
        self.history_results = list(history_results)
        self.current_calls: list[tuple[str, str]] = []
        self.history_calls: list[tuple[str, str]] = []

    def get_current(self, run_id: str, entity_id: str) -> CurrentDecisionReadModel | None:
        self.current_calls.append((run_id, entity_id))
        return self.current_results.pop(0)

    def list_history(self, run_id: str, entity_id: str) -> list[DecisionResult]:
        self.history_calls.append((run_id, entity_id))
        return self.history_results.pop(0)


def test_get_run_detail_retries_mismatched_heads_and_returns_stable_view() -> None:
    # Given
    d1 = _decision("DEC-001")
    d2 = _decision("DEC-002", supersedes_decision_id=d1.decision_id)
    d3 = _decision("DEC-003", supersedes_decision_id=d2.decision_id)
    d4 = _decision("DEC-004", supersedes_decision_id=d3.decision_id)
    current_d3 = _current(d3)
    current_d4 = _current(d4)
    history = [d4, d3, d2, d1]
    reader = FakeDashboardDecisionReader(
        current_results=[current_d3, current_d4],
        history_results=[history, history],
    )
    run = _run_metadata()
    repository = FakeRunRepository([run, run, run, run])

    # When
    detail = get_run_detail(
        run_id=RUN_ID,
        run_repository=repository,
        reader=reader,
    )

    # Then
    assert detail is not None
    assert detail.run == run
    assert detail.current_decision == current_d4
    assert detail.decision_history == history
    assert repository.get_calls == [RUN_ID] * 4
    assert reader.current_calls == [(RUN_ID, ENTITY_ID), (RUN_ID, ENTITY_ID)]
    assert reader.history_calls == [(RUN_ID, ENTITY_ID), (RUN_ID, ENTITY_ID)]


def test_get_run_detail_raises_after_three_mismatched_views() -> None:
    # Given
    d1 = _decision("DEC-001")
    d2 = _decision("DEC-002", supersedes_decision_id=d1.decision_id)
    current = _current(d1)
    history = [d2, d1]
    reader = FakeDashboardDecisionReader(
        current_results=[current, current, current],
        history_results=[history, history, history],
    )
    run = _run_metadata()
    repository = FakeRunRepository([run] * 6)

    # When / Then
    with pytest.raises(DashboardReadConsistencyError, match="Current Decision and History"):
        get_run_detail(
            run_id=RUN_ID,
            run_repository=repository,
            reader=reader,
        )
    assert repository.get_calls == [RUN_ID] * 6
    assert len(reader.current_calls) == 3
    assert len(reader.history_calls) == 3


def test_get_run_detail_retries_changed_run_and_uses_new_entity_scope() -> None:
    # Given
    run_v1 = _run_metadata(scenario_id="scenario-v1", target_host="WIN-OLD")
    run_v2 = _run_metadata(scenario_id="scenario-v2", target_host="WIN-NEW")
    decision_v1 = _decision("DEC-OLD", entity_id=run_v1.target_host)
    decision_v2 = _decision("DEC-NEW", entity_id=run_v2.target_host)
    reader = FakeDashboardDecisionReader(
        current_results=[_current(decision_v1), _current(decision_v2)],
        history_results=[[decision_v1], [decision_v2]],
    )
    repository = FakeRunRepository([run_v1, run_v2, run_v2, run_v2])

    # When
    detail = get_run_detail(
        run_id=RUN_ID,
        run_repository=repository,
        reader=reader,
    )

    # Then
    assert detail is not None
    assert detail.run == run_v2
    assert detail.current_decision == _current(decision_v2)
    assert detail.decision_history == [decision_v2]
    assert reader.current_calls == [(RUN_ID, "WIN-OLD"), (RUN_ID, "WIN-NEW")]
    assert reader.history_calls == [(RUN_ID, "WIN-OLD"), (RUN_ID, "WIN-NEW")]


def test_get_run_detail_returns_none_when_run_is_deleted_during_read() -> None:
    # Given
    run = _run_metadata()
    decision = _decision("DEC-001")
    repository = FakeRunRepository([run, None, None])
    reader = FakeDashboardDecisionReader(
        current_results=[_current(decision)],
        history_results=[[decision]],
    )

    # When
    detail = get_run_detail(
        run_id=RUN_ID,
        run_repository=repository,
        reader=reader,
    )

    # Then
    assert detail is None
    assert repository.get_calls == [RUN_ID] * 3
    assert reader.current_calls == [(RUN_ID, ENTITY_ID)]
    assert reader.history_calls == [(RUN_ID, ENTITY_ID)]


def test_get_run_detail_raises_when_run_changes_for_all_three_attempts() -> None:
    # Given
    run_v1 = _run_metadata(scenario_id="scenario-v1")
    run_v2 = _run_metadata(scenario_id="scenario-v2")
    decision = _decision("DEC-001")
    repository = FakeRunRepository([run_v1, run_v2] * 3)
    reader = FakeDashboardDecisionReader(
        current_results=[_current(decision)] * 3,
        history_results=[[decision]] * 3,
    )

    # When / Then
    with pytest.raises(DashboardReadConsistencyError, match="Run Metadata"):
        get_run_detail(
            run_id=RUN_ID,
            run_repository=repository,
            reader=reader,
        )
    assert repository.get_calls == [RUN_ID] * 6
    assert len(reader.current_calls) == 3
    assert len(reader.history_calls) == 3


def _current(decision: DecisionResult) -> CurrentDecisionReadModel:
    return CurrentDecisionReadModel(
        decision=decision,
        latest_detection_result=None,
        latest_fusion_result=None,
        latest_fusion_stopping_trace=None,
    )


def _decision(
    decision_id: str,
    *,
    entity_id: str = ENTITY_ID,
    supersedes_decision_id: str | None = None,
) -> DecisionResult:
    return DecisionResult(
        run_id=RUN_ID,
        decision_id=decision_id,
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
        supersedes_decision_id=supersedes_decision_id,
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
        start_time=datetime(2026, 10, 3, 1, tzinfo=UTC),
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
