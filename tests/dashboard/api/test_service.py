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

    # When
    detail = get_run_detail(run=_run_metadata(), reader=reader)

    # Then
    assert detail.current_decision == current_d4
    assert detail.decision_history == history
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

    # When / Then
    with pytest.raises(DashboardReadConsistencyError, match="Current Decision and History"):
        get_run_detail(run=_run_metadata(), reader=reader)
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
