from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectorStatus,
    WinningPath,
)
from incident_awareness.dashboard.decision_history import build_decision_history
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


def make_decision(
    decision_id: str,
    *,
    supersedes_decision_id: str | None = None,
    run_id: str = "RUN-20260912-001",
    entity_id: str = "WIN-01",
) -> DecisionResult:
    decision_time = datetime(2026, 9, 12, 1, tzinfo=UTC)
    return DecisionResult(
        run_id=run_id,
        decision_id=decision_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.DETECTED,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=decision_time,
        t_e=decision_time,
        decision_path=DecisionPath.FAST,
        winning_path=WinningPath.FAST,
        decision_reason="Fast path detected",
        config_version="v0.2",
        supersedes_decision_id=supersedes_decision_id,
    )


def test_build_decision_history_returns_empty_history() -> None:
    # Given
    decisions: list[DecisionResult] = []

    # When
    history = build_decision_history(decisions, None)

    # Then
    assert history == []


def test_build_decision_history_returns_single_decision() -> None:
    # Given
    decision = make_decision("DEC-001")

    # When
    history = build_decision_history([decision], decision)

    # Then
    assert history == [decision]


def test_build_decision_history_orders_shuffled_chain_from_current_head() -> None:
    # Given
    first = make_decision("DEC-001")
    second = make_decision("DEC-002", supersedes_decision_id="DEC-001")
    third = make_decision("DEC-003", supersedes_decision_id="DEC-002")

    # When
    history = build_decision_history([first, third, second], third)

    # Then
    assert history == [third, second, first]


def test_build_decision_history_rejects_scope_mismatch() -> None:
    # Given
    head = make_decision("DEC-002", supersedes_decision_id="DEC-001")
    mismatched = make_decision("DEC-001", entity_id="WIN-02")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([mismatched, head], head)

    # Then
    assert "scope mismatch" in str(exc_info.value)


def test_build_decision_history_rejects_stored_decisions_without_head() -> None:
    # Given
    decision = make_decision("DEC-001")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([decision], None)

    # Then
    assert "no current Decision head" in str(exc_info.value)


def test_build_decision_history_rejects_head_missing_from_decisions() -> None:
    # Given
    stored = make_decision("DEC-001")
    missing_head = make_decision("DEC-002", supersedes_decision_id="DEC-001")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([stored], missing_head)

    # Then
    assert "missing from stored decisions" in str(exc_info.value)


def test_build_decision_history_rejects_missing_predecessor() -> None:
    # Given
    head = make_decision("DEC-002", supersedes_decision_id="DEC-001")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([head], head)

    # Then
    assert "DEC-002" in str(exc_info.value)
    assert "DEC-001" in str(exc_info.value)


def test_build_decision_history_rejects_cycle() -> None:
    # Given
    second = make_decision("DEC-002", supersedes_decision_id="DEC-003")
    third = make_decision("DEC-003", supersedes_decision_id="DEC-002")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([second, third], third)

    # Then
    assert "cycle" in str(exc_info.value)


def test_build_decision_history_rejects_multiple_heads() -> None:
    # Given
    first = make_decision("DEC-001")
    second = make_decision("DEC-002")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([first, second], second)

    # Then
    assert "multiple current Decision heads" in str(exc_info.value)


def test_build_decision_history_rejects_disconnected_component() -> None:
    # Given
    first = make_decision("DEC-001")
    head = make_decision("DEC-002", supersedes_decision_id="DEC-001")
    disconnected_first = make_decision("DEC-003", supersedes_decision_id="DEC-004")
    disconnected_second = make_decision("DEC-004", supersedes_decision_id="DEC-003")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history(
            [first, disconnected_first, head, disconnected_second],
            head,
        )

    # Then
    assert "disconnected" in str(exc_info.value)


def test_build_decision_history_rejects_duplicate_decision_id() -> None:
    # Given
    first = make_decision("DEC-001")
    duplicate = make_decision("DEC-001")

    # When
    with pytest.raises(DecisionIntegrityError) as exc_info:
        build_decision_history([first, duplicate], first)

    # Then
    assert "duplicate Decision" in str(exc_info.value)
