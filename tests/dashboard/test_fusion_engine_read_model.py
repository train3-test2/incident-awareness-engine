from datetime import UTC, datetime

import pytest

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
from incident_awareness.dashboard.decision_read_model import DashboardReadConsistencyError
from incident_awareness.dashboard.fusion_engine_read_model import (
    DashboardFusionEngineReader,
    FusionEngineReadModel,
)

RUN_ID = "RUN-20261007-001"
ENTITY_ID = "WIN-01"
BASE_TIME = datetime(2026, 10, 7, 1, tzinfo=UTC)


class FakeDecisionRepository:
    def __init__(self, current_heads: list[DecisionResult | None]) -> None:
        self.current_heads = list(current_heads)
        self.calls: list[tuple[str, str]] = []

    def get_current_head(self, run_id: str, entity_id: str) -> DecisionResult | None:
        self.calls.append((run_id, entity_id))
        if not self.current_heads:
            raise AssertionError("unexpected get_current_head call")
        return self.current_heads.pop(0)


class FakeScopeRepository[ScopeResult]:
    def __init__(self, result: ScopeResult | None) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def get(self, run_id: str, entity_id: str) -> ScopeResult | None:
        self.calls.append((run_id, entity_id))
        return self.result


class FakeSequenceScopeRepository[ScopeResult]:
    def __init__(self, results: list[ScopeResult | None]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, str]] = []

    def get(self, run_id: str, entity_id: str) -> ScopeResult | None:
        self.calls.append((run_id, entity_id))
        if not self.results:
            raise AssertionError("unexpected scope repository get call")
        return self.results.pop(0)


def test_get_current_returns_stored_head_and_all_runtime_contracts() -> None:
    # Given
    decision = _decision("DEC-001")
    fusion = _fusion_result()
    trace = _stopping_trace()
    config = _runtime_config_snapshot()
    decision_repository = FakeDecisionRepository([decision, decision])
    fusion_repository = FakeScopeRepository(fusion)
    trace_repository = FakeScopeRepository(trace)
    config_repository = FakeScopeRepository(config)
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == FusionEngineReadModel(
        current_decision=decision,
        fusion_result=fusion,
        stopping_trace=trace,
        runtime_config_snapshot=config,
    )
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)]
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)]
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)]


def test_get_current_retries_all_runtime_reads_when_versions_do_not_match() -> None:
    # Given
    decision = _decision("DEC-001")
    first_fusion = _fusion_result(config_version="fusion-config-v1")
    second_fusion = _fusion_result(config_version="fusion-config-v2")
    trace = _stopping_trace(config_version="fusion-config-v2")
    config = _runtime_config_snapshot(config_version="fusion-config-v2")
    decision_repository = FakeDecisionRepository([decision, decision, decision, decision])
    fusion_repository = FakeSequenceScopeRepository([first_fusion, second_fusion])
    trace_repository = FakeSequenceScopeRepository([trace, trace])
    config_repository = FakeSequenceScopeRepository([config, config])
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == FusionEngineReadModel(
        current_decision=decision,
        fusion_result=second_fusion,
        stopping_trace=trace,
        runtime_config_snapshot=config,
    )
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 4
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)] * 2


def test_get_current_raises_when_runtime_versions_never_match() -> None:
    # Given
    decision = _decision("DEC-001")
    decision_repository = FakeDecisionRepository([decision, decision] * 3)
    fusion_repository = FakeScopeRepository(_fusion_result(config_version="fusion-config-v1"))
    trace_repository = FakeScopeRepository(_stopping_trace(config_version="fusion-config-v2"))
    config_repository = FakeScopeRepository(
        _runtime_config_snapshot(config_version="fusion-config-v2")
    )
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    with pytest.raises(DashboardReadConsistencyError, match="3 attempts"):
        reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 6
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)] * 3


def test_get_current_preserves_runtime_when_current_head_is_absent() -> None:
    # Given
    fusion = _fusion_result()
    trace = _stopping_trace()
    config = _runtime_config_snapshot()
    reader = DashboardFusionEngineReader(
        decision_repository=FakeDecisionRepository([None, None]),
        fusion_repository=FakeScopeRepository(fusion),
        stopping_trace_repository=FakeScopeRepository(trace),
        runtime_config_repository=FakeScopeRepository(config),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == FusionEngineReadModel(
        current_decision=None,
        fusion_result=fusion,
        stopping_trace=trace,
        runtime_config_snapshot=config,
    )


def test_get_current_accepts_matching_versions_for_partial_runtime() -> None:
    # Given
    trace = _stopping_trace(config_version="fusion-config-v1")
    config = _runtime_config_snapshot(config_version="fusion-config-v1")
    reader = DashboardFusionEngineReader(
        decision_repository=FakeDecisionRepository([None, None]),
        fusion_repository=FakeScopeRepository[FusionResult](None),
        stopping_trace_repository=FakeScopeRepository(trace),
        runtime_config_repository=FakeScopeRepository(config),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == FusionEngineReadModel(
        current_decision=None,
        fusion_result=None,
        stopping_trace=trace,
        runtime_config_snapshot=config,
    )


def test_get_current_raises_for_partial_runtime_versions_that_never_match() -> None:
    # Given
    decision_repository = FakeDecisionRepository([None, None] * 3)
    fusion_repository = FakeScopeRepository[FusionResult](None)
    trace_repository = FakeScopeRepository(_stopping_trace(config_version="fusion-config-v1"))
    config_repository = FakeScopeRepository(
        _runtime_config_snapshot(config_version="fusion-config-v2")
    )
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    with pytest.raises(DashboardReadConsistencyError, match="3 attempts"):
        reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 6
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)] * 3


@pytest.mark.parametrize("missing_runtime", ["fusion", "trace", "config"])
def test_get_current_preserves_each_missing_runtime_as_none(missing_runtime: str) -> None:
    # Given
    decision = _decision("DEC-001")
    fusion = None if missing_runtime == "fusion" else _fusion_result()
    trace = None if missing_runtime == "trace" else _stopping_trace()
    config = None if missing_runtime == "config" else _runtime_config_snapshot()
    reader = DashboardFusionEngineReader(
        decision_repository=FakeDecisionRepository([decision, decision]),
        fusion_repository=FakeScopeRepository(fusion),
        stopping_trace_repository=FakeScopeRepository(trace),
        runtime_config_repository=FakeScopeRepository(config),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result.fusion_result is fusion
    assert result.stopping_trace is trace
    assert result.runtime_config_snapshot is config


def test_get_current_preserves_all_missing_runtime_as_none() -> None:
    # Given
    reader = DashboardFusionEngineReader(
        decision_repository=FakeDecisionRepository([None, None]),
        fusion_repository=FakeScopeRepository[FusionResult](None),
        stopping_trace_repository=FakeScopeRepository[FusionStoppingTrace](None),
        runtime_config_repository=FakeScopeRepository[FusionRuntimeConfigSnapshot](None),
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result == FusionEngineReadModel(
        current_decision=None,
        fusion_result=None,
        stopping_trace=None,
        runtime_config_snapshot=None,
    )


def test_get_current_retries_all_runtime_reads_when_head_changes() -> None:
    # Given
    first = _decision("DEC-001")
    second = _decision("DEC-002", supersedes_decision_id=first.decision_id)
    decision_repository = FakeDecisionRepository([first, second, second, second])
    fusion_repository = FakeScopeRepository(_fusion_result())
    trace_repository = FakeScopeRepository(_stopping_trace())
    config_repository = FakeScopeRepository(_runtime_config_snapshot())
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    result = reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert result.current_decision == second
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 4
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 2
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)] * 2


def test_get_current_raises_when_head_never_stabilizes() -> None:
    # Given
    first = _decision("DEC-001")
    second = _decision("DEC-002", supersedes_decision_id=first.decision_id)
    third = _decision("DEC-003", supersedes_decision_id=second.decision_id)
    fourth = _decision("DEC-004", supersedes_decision_id=third.decision_id)
    decision_repository = FakeDecisionRepository([first, second, second, third, third, fourth])
    fusion_repository = FakeScopeRepository(_fusion_result())
    trace_repository = FakeScopeRepository(_stopping_trace())
    config_repository = FakeScopeRepository(_runtime_config_snapshot())
    reader = DashboardFusionEngineReader(
        decision_repository=decision_repository,
        fusion_repository=fusion_repository,
        stopping_trace_repository=trace_repository,
        runtime_config_repository=config_repository,
    )

    # When
    with pytest.raises(DashboardReadConsistencyError, match="3 attempts"):
        reader.get_current(RUN_ID, ENTITY_ID)

    # Then
    assert decision_repository.calls == [(RUN_ID, ENTITY_ID)] * 6
    assert fusion_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert trace_repository.calls == [(RUN_ID, ENTITY_ID)] * 3
    assert config_repository.calls == [(RUN_ID, ENTITY_ID)] * 3


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


def _fusion_result(*, config_version: str = "fusion-config-v1") -> FusionResult:
    return FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version=config_version,
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v1",
        fusion_episodes=[],
    )


def _stopping_trace(*, config_version: str = "fusion-config-v1") -> FusionStoppingTrace:
    return FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        scoring_config_version=config_version,
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
    config_version: str = "fusion-config-v1",
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        config_version=config_version,
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
