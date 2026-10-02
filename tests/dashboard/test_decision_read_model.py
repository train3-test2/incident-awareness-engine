from datetime import UTC, datetime

import pytest

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
from incident_awareness.common.models.runtime_snapshot import (
    DecisionRuntimeSnapshot,
    build_decision_runtime_snapshot,
)
from incident_awareness.dashboard.decision_read_model import (
    CurrentDecisionReadModel,
    DashboardDecisionReader,
    DashboardReadConsistencyError,
    HistoricalDecisionReadModel,
)

RUN_ID = "RUN-20261003-001"
ENTITY_ID = "WIN-01"
SCORING_CONFIG_VERSION = "fusion-config-v0.1"
BASE_TIME = datetime(2026, 10, 3, 1, tzinfo=UTC)


class FakeDecisionRepository:
    def __init__(
        self,
        *,
        current_head: DecisionResult | None = None,
        scoped_decisions: list[DecisionResult] | None = None,
        decisions_by_id: dict[str, DecisionResult] | None = None,
        fail_on_current_head: bool = False,
        current_heads: list[DecisionResult | None] | None = None,
    ) -> None:
        self.current_head = current_head
        self.scoped_decisions = scoped_decisions if scoped_decisions is not None else []
        self.decisions_by_id = decisions_by_id if decisions_by_id is not None else {}
        self.fail_on_current_head = fail_on_current_head
        self.current_heads = list(current_heads) if current_heads is not None else None
        self.current_head_calls: list[tuple[str, str]] = []
        self.list_by_scope_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []

    def get_current_head(self, run_id: str, entity_id: str) -> DecisionResult | None:
        if self.fail_on_current_head:
            raise AssertionError("list_history must not query get_current_head")
        self.current_head_calls.append((run_id, entity_id))
        if self.current_heads is not None:
            if not self.current_heads:
                raise AssertionError("unexpected get_current_head call")
            return self.current_heads.pop(0)
        return self.current_head

    def list_by_scope(self, run_id: str, entity_id: str) -> list[DecisionResult]:
        self.list_by_scope_calls.append((run_id, entity_id))
        return self.scoped_decisions

    def get(self, decision_id: str) -> DecisionResult | None:
        self.get_calls.append(decision_id)
        return self.decisions_by_id.get(decision_id)


class FakeScopeRepository[ScopeResult]:
    def __init__(self, result: ScopeResult | None) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def get(self, run_id: str, entity_id: str) -> ScopeResult | None:
        self.calls.append((run_id, entity_id))
        return self.result


class FakeSnapshotRepository:
    def __init__(
        self,
        snapshots: dict[str, DecisionRuntimeSnapshot] | None = None,
    ) -> None:
        self.snapshots = snapshots if snapshots is not None else {}
        self.calls: list[str] = []

    def get(self, decision_id: str) -> DecisionRuntimeSnapshot | None:
        self.calls.append(decision_id)
        return self.snapshots.get(decision_id)


def test_get_current_returns_none_without_querying_runtime_repositories() -> None:
    # Given
    decision_repository = FakeDecisionRepository()
    detection_repository = FakeScopeRepository[DetectionResult](None)
    fusion_repository = FakeScopeRepository[FusionResult](None)
    trace_repository = FakeScopeRepository[FusionStoppingTrace](None)
    snapshot_repository = FakeSnapshotRepository()
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=snapshot_repository,
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result is None
    assert decision_repository.current_head_calls == [(RUN_ID, ENTITY_ID)]
    assert detection_repository.calls == []
    assert fusion_repository.calls == []
    assert trace_repository.calls == []


def test_get_current_combines_head_with_latest_runtime_results() -> None:
    # Given
    head = _decision("DEC-003", supersedes_decision_id="DEC-002")
    detection = _detection_result(marker="runtime-2")
    fusion = _fusion_result(marker="runtime-2")
    trace = _fusion_stopping_trace(score=0.2)
    decision_repository = FakeDecisionRepository(current_head=head)
    detection_repository = FakeScopeRepository(detection)
    fusion_repository = FakeScopeRepository(fusion)
    trace_repository = FakeScopeRepository(trace)
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == CurrentDecisionReadModel(
        decision=head,
        latest_detection_result=detection,
        latest_fusion_result=fusion,
        latest_fusion_stopping_trace=trace,
    )
    assert decision_repository.current_head_calls == [
        (RUN_ID, ENTITY_ID),
        (RUN_ID, ENTITY_ID),
    ]
    assert detection_repository.calls == [(RUN_ID, ENTITY_ID)]
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)]
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)]


def test_get_current_preserves_missing_runtime_results_as_none() -> None:
    # Given
    head = _decision("DEC-003", supersedes_decision_id="DEC-002")
    decision_repository = FakeDecisionRepository(current_head=head)
    detection_repository = FakeScopeRepository[DetectionResult](None)
    fusion_repository = FakeScopeRepository[FusionResult](None)
    trace_repository = FakeScopeRepository[FusionStoppingTrace](None)
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == CurrentDecisionReadModel(
        decision=head,
        latest_detection_result=None,
        latest_fusion_result=None,
        latest_fusion_stopping_trace=None,
    )
    assert decision_repository.current_head_calls == [
        (RUN_ID, ENTITY_ID),
        (RUN_ID, ENTITY_ID),
    ]


def test_get_current_retries_all_runtime_reads_when_head_changes() -> None:
    # Given
    third = _decision("DEC-003", supersedes_decision_id="DEC-002")
    fourth = _decision("DEC-004", supersedes_decision_id="DEC-003")
    detection = _detection_result(marker="runtime-4")
    fusion = _fusion_result(marker="runtime-4")
    trace = _fusion_stopping_trace(score=0.9)
    decision_repository = FakeDecisionRepository(current_heads=[third, fourth, fourth, fourth])
    detection_repository = FakeScopeRepository(detection)
    fusion_repository = FakeScopeRepository(fusion)
    trace_repository = FakeScopeRepository(trace)
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == CurrentDecisionReadModel(
        decision=fourth,
        latest_detection_result=detection,
        latest_fusion_result=fusion,
        latest_fusion_stopping_trace=trace,
    )
    assert decision_repository.current_head_calls == [(RUN_ID, ENTITY_ID)] * 4
    assert detection_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 2


def test_get_current_raises_when_head_never_stabilizes() -> None:
    # Given
    first = _decision("DEC-001")
    second = _decision("DEC-002", supersedes_decision_id="DEC-001")
    third = _decision("DEC-003", supersedes_decision_id="DEC-002")
    fourth = _decision("DEC-004", supersedes_decision_id="DEC-003")
    decision_repository = FakeDecisionRepository(
        current_heads=[first, second, second, third, third, fourth]
    )
    detection_repository = FakeScopeRepository(_detection_result(marker="runtime"))
    fusion_repository = FakeScopeRepository(_fusion_result(marker="runtime"))
    trace_repository = FakeScopeRepository(_fusion_stopping_trace(score=0.5))
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    with pytest.raises(DashboardReadConsistencyError) as exc_info:
        reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert "3 attempts" in str(exc_info.value)
    assert decision_repository.current_head_calls == [(RUN_ID, ENTITY_ID)] * 6
    assert detection_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 3


def test_list_history_uses_lifecycle_builder_for_shuffled_decisions() -> None:
    # Given
    first = _decision("DEC-001")
    second = _decision("DEC-002", supersedes_decision_id="DEC-001")
    third = _decision("DEC-003", supersedes_decision_id="DEC-002")
    decision_repository = FakeDecisionRepository(
        scoped_decisions=[second, first, third],
        fail_on_current_head=True,
    )
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=FakeScopeRepository[DetectionResult](None),
        fusion_repository=FakeScopeRepository[FusionResult](None),
        stopping_trace_repository=FakeScopeRepository[FusionStoppingTrace](None),
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    history = reader.list_history(RUN_ID, ENTITY_ID)

    # Then
    assert history == [third, second, first]
    assert decision_repository.list_by_scope_calls == [(RUN_ID, ENTITY_ID)]
    assert decision_repository.current_head_calls == []


def test_list_history_returns_empty_scope() -> None:
    # Given
    decision_repository = FakeDecisionRepository(fail_on_current_head=True)
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=FakeScopeRepository[DetectionResult](None),
        fusion_repository=FakeScopeRepository[FusionResult](None),
        stopping_trace_repository=FakeScopeRepository[FusionStoppingTrace](None),
        snapshot_repository=FakeSnapshotRepository(),
    )

    # When
    history = reader.list_history(RUN_ID, ENTITY_ID)

    # Then
    assert history == []
    assert decision_repository.list_by_scope_calls == [(RUN_ID, ENTITY_ID)]
    assert decision_repository.current_head_calls == []


def test_get_historical_uses_decision_snapshot_without_latest_runtime() -> None:
    # Given
    decision = _decision("DEC-001")
    snapshot = _snapshot(decision, marker="runtime-1", score=0.1)
    current_detection = _detection_result(marker="runtime-2")
    current_fusion = _fusion_result(marker="runtime-2")
    current_trace = _fusion_stopping_trace(score=0.2)
    decision_repository = FakeDecisionRepository(decisions_by_id={decision.decision_id: decision})
    detection_repository = FakeScopeRepository(current_detection)
    fusion_repository = FakeScopeRepository(current_fusion)
    trace_repository = FakeScopeRepository(current_trace)
    snapshot_repository = FakeSnapshotRepository({decision.decision_id: snapshot})
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=snapshot_repository,
    )

    # When
    result = reader.get_historical(decision.decision_id)

    # Then
    assert result == HistoricalDecisionReadModel(
        decision=decision,
        runtime_snapshot=snapshot,
    )
    assert result.runtime_snapshot is not None
    assert result.runtime_snapshot.detection_result == snapshot.detection_result
    assert result.runtime_snapshot.fusion_result == snapshot.fusion_result
    assert result.runtime_snapshot.fusion_stopping_trace == snapshot.fusion_stopping_trace
    assert decision_repository.get_calls == [decision.decision_id]
    assert snapshot_repository.calls == [decision.decision_id]
    assert detection_repository.calls == []
    assert fusion_repository.calls == []
    assert trace_repository.calls == []


def test_get_historical_returns_legacy_decision_without_runtime_fallback() -> None:
    # Given
    decision = _decision("DEC-001")
    decision_repository = FakeDecisionRepository(decisions_by_id={decision.decision_id: decision})
    detection_repository = FakeScopeRepository(_detection_result(marker="runtime-2"))
    fusion_repository = FakeScopeRepository(_fusion_result(marker="runtime-2"))
    trace_repository = FakeScopeRepository(_fusion_stopping_trace(score=0.2))
    snapshot_repository = FakeSnapshotRepository()
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=snapshot_repository,
    )

    # When
    result = reader.get_historical(decision.decision_id)

    # Then
    assert result == HistoricalDecisionReadModel(
        decision=decision,
        runtime_snapshot=None,
    )
    assert snapshot_repository.calls == [decision.decision_id]
    assert detection_repository.calls == []
    assert fusion_repository.calls == []
    assert trace_repository.calls == []


def test_get_historical_returns_none_without_querying_snapshot() -> None:
    # Given
    decision_repository = FakeDecisionRepository()
    detection_repository = FakeScopeRepository[DetectionResult](None)
    fusion_repository = FakeScopeRepository[FusionResult](None)
    trace_repository = FakeScopeRepository[FusionStoppingTrace](None)
    snapshot_repository = FakeSnapshotRepository()
    reader = DashboardDecisionReader(
        decision_repository=decision_repository,
        detection_repository=detection_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        snapshot_repository=snapshot_repository,
    )

    # When
    result = reader.get_historical("DEC-MISSING")

    # Then
    assert result is None
    assert decision_repository.get_calls == ["DEC-MISSING"]
    assert snapshot_repository.calls == []
    assert detection_repository.calls == []
    assert fusion_repository.calls == []
    assert trace_repository.calls == []


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


def _detection_result(*, marker: str) -> DetectionResult:
    return DetectionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id=marker,
        rule_version="v0.1",
        severity=Severity.UNKNOWN,
    )


def _fusion_result(*, marker: str) -> FusionResult:
    return FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version=SCORING_CONFIG_VERSION,
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version=marker,
        fusion_episodes=[],
    )


def _fusion_stopping_trace(*, score: float) -> FusionStoppingTrace:
    return FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        scoring_config_version=SCORING_CONFIG_VERSION,
        points=[
            FusionStoppingTracePoint(
                timestamp=BASE_TIME,
                score=score,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )


def _snapshot(
    decision: DecisionResult,
    *,
    marker: str,
    score: float,
) -> DecisionRuntimeSnapshot:
    return build_decision_runtime_snapshot(
        decision_result=decision,
        detection_result=_detection_result(marker=marker),
        fusion_result=_fusion_result(marker=marker),
        fusion_stopping_trace=_fusion_stopping_trace(score=score),
    )
