from datetime import UTC, datetime, timedelta
from typing import Literal

import pytest

from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
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

RUN_ID = "RUN-20261003-001"
OTHER_RUN_ID = "RUN-20261003-002"
ENTITY_ID = "WIN-01"
OTHER_ENTITY_ID = "WIN-02"
DECISION_ID = "DEC-001"
SCORING_CONFIG_VERSION = "fusion-config-v0.1"
BASE_TIME = datetime(2026, 10, 3, 1, tzinfo=UTC)
DETECTOR_TIME = BASE_TIME + timedelta(seconds=10)
FUSION_TIME = BASE_TIME + timedelta(seconds=20)


def test_builds_decision_runtime_snapshot_from_runtime_contracts() -> None:
    # Given
    detection_result = _detection_result()
    fusion_result = _fusion_result()
    fusion_stopping_trace = _fusion_stopping_trace()
    decision_result = _decision_result()

    # When
    snapshot = build_decision_runtime_snapshot(
        decision_result=decision_result,
        detection_result=detection_result,
        fusion_result=fusion_result,
        fusion_stopping_trace=fusion_stopping_trace,
        fusion_runtime_config_snapshot=_runtime_config_snapshot(),
    )

    # Then
    assert snapshot.decision_id == DECISION_ID
    assert snapshot.run_id == RUN_ID
    assert snapshot.entity_id == ENTITY_ID
    assert snapshot.detection_result is detection_result
    assert snapshot.fusion_result is fusion_result
    assert snapshot.fusion_stopping_trace is fusion_stopping_trace
    assert snapshot.fusion_runtime_config_snapshot == _runtime_config_snapshot()


@pytest.mark.parametrize(
    ("mismatched_contract", "expected_message"),
    [
        (
            "detection_result",
            "DetectionResult run_id must match DecisionRuntimeSnapshot run_id",
        ),
        (
            "fusion_result",
            "FusionResult run_id must match DecisionRuntimeSnapshot run_id",
        ),
        (
            "fusion_stopping_trace",
            "FusionStoppingTrace run_id must match DecisionRuntimeSnapshot run_id",
        ),
    ],
)
def test_rejects_runtime_contract_with_mismatched_run_id(
    mismatched_contract: str,
    expected_message: str,
) -> None:
    # Given
    detection_result = _detection_result(
        run_id=OTHER_RUN_ID if mismatched_contract == "detection_result" else RUN_ID
    )
    fusion_result = _fusion_result(
        run_id=OTHER_RUN_ID if mismatched_contract == "fusion_result" else RUN_ID
    )
    fusion_stopping_trace = _fusion_stopping_trace(
        run_id=OTHER_RUN_ID if mismatched_contract == "fusion_stopping_trace" else RUN_ID
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        _snapshot(
            detection_result=detection_result,
            fusion_result=fusion_result,
            fusion_stopping_trace=fusion_stopping_trace,
        )

    # Then
    assert expected_message in str(exc_info.value)


@pytest.mark.parametrize(
    ("mismatched_contract", "expected_message"),
    [
        (
            "detection_result",
            "DetectionResult entity_id must match DecisionRuntimeSnapshot entity_id",
        ),
        (
            "fusion_result",
            "FusionResult entity_id must match DecisionRuntimeSnapshot entity_id",
        ),
        (
            "fusion_stopping_trace",
            "FusionStoppingTrace entity_id must match DecisionRuntimeSnapshot entity_id",
        ),
    ],
)
def test_rejects_runtime_contract_with_mismatched_entity_id(
    mismatched_contract: str,
    expected_message: str,
) -> None:
    # Given
    detection_result = _detection_result(
        entity_id=OTHER_ENTITY_ID if mismatched_contract == "detection_result" else ENTITY_ID
    )
    fusion_result = _fusion_result(
        entity_id=OTHER_ENTITY_ID if mismatched_contract == "fusion_result" else ENTITY_ID
    )
    fusion_stopping_trace = _fusion_stopping_trace(
        entity_id=(OTHER_ENTITY_ID if mismatched_contract == "fusion_stopping_trace" else ENTITY_ID)
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        _snapshot(
            detection_result=detection_result,
            fusion_result=fusion_result,
            fusion_stopping_trace=fusion_stopping_trace,
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_mismatched_fusion_scoring_config_version() -> None:
    # Given
    fusion_stopping_trace = _fusion_stopping_trace(scoring_config_version="other-config")
    expected_message = (
        "FusionStoppingTrace scoring_config_version must match FusionResult scoring_config_version"
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        _snapshot(fusion_stopping_trace=fusion_stopping_trace)

    # Then
    assert expected_message in str(exc_info.value)


@pytest.mark.parametrize(
    ("fusion_status", "points_present"),
    [
        ("not_evaluated", False),
        ("miss", True),
        ("detected", True),
    ],
)
def test_accepts_fusion_status_with_expected_stopping_trace_presence(
    fusion_status: Literal["detected", "miss", "not_evaluated"],
    points_present: bool,
) -> None:
    # Given
    fusion_result = _fusion_result(fusion_status=fusion_status)
    fusion_stopping_trace = _fusion_stopping_trace(points_present=points_present)

    # When
    snapshot = _snapshot(
        fusion_result=fusion_result,
        fusion_stopping_trace=fusion_stopping_trace,
    )

    # Then
    assert snapshot.fusion_result is fusion_result
    assert snapshot.fusion_stopping_trace is fusion_stopping_trace


@pytest.mark.parametrize(
    ("fusion_status", "points_present", "expected_message"),
    [
        (
            "not_evaluated",
            True,
            "not_evaluated FusionResult requires an empty FusionStoppingTrace",
        ),
        (
            "miss",
            False,
            "miss FusionResult requires a non-empty FusionStoppingTrace",
        ),
        (
            "detected",
            False,
            "detected FusionResult requires a non-empty FusionStoppingTrace",
        ),
    ],
)
def test_rejects_fusion_status_with_invalid_stopping_trace_presence(
    fusion_status: Literal["detected", "miss", "not_evaluated"],
    points_present: bool,
    expected_message: str,
) -> None:
    # Given
    fusion_result = _fusion_result(fusion_status=fusion_status)
    fusion_stopping_trace = _fusion_stopping_trace(points_present=points_present)

    # When
    with pytest.raises(ValueError) as exc_info:
        _snapshot(
            fusion_result=fusion_result,
            fusion_stopping_trace=fusion_stopping_trace,
        )

    # Then
    assert expected_message in str(exc_info.value)


def test_rejects_decision_fast_status_mismatched_with_detection_result() -> None:
    # Given
    decision_result = _decision_result()
    detection_result = _detection_result(detector_status=DetectorStatus.NOT_EVALUATED)

    # When
    with pytest.raises(ValueError) as exc_info:
        build_decision_runtime_snapshot(
            decision_result=decision_result,
            detection_result=detection_result,
            fusion_result=_fusion_result(),
            fusion_stopping_trace=_fusion_stopping_trace(),
            fusion_runtime_config_snapshot=_runtime_config_snapshot(),
        )

    # Then
    assert "DecisionResult fast_status must match DetectionResult detector_status" in str(
        exc_info.value
    )


def test_rejects_decision_detector_time_mismatched_with_detection_result() -> None:
    # Given
    decision_result = _decision_result(
        fast_status=DetectorStatus.DETECTED,
        detector_time=DETECTOR_TIME,
    )
    detection_result = _detection_result(
        detector_status=DetectorStatus.DETECTED,
        detector_time=DETECTOR_TIME + timedelta(seconds=1),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        build_decision_runtime_snapshot(
            decision_result=decision_result,
            detection_result=detection_result,
            fusion_result=_fusion_result(),
            fusion_stopping_trace=_fusion_stopping_trace(),
            fusion_runtime_config_snapshot=_runtime_config_snapshot(),
        )

    # Then
    assert "DecisionResult detector_time must match DetectionResult detector_time" in str(
        exc_info.value
    )


def test_rejects_decision_fusion_status_mismatched_with_fusion_result() -> None:
    # Given
    decision_result = _decision_result()
    fusion_result = _fusion_result(fusion_status="not_evaluated")

    # When
    with pytest.raises(ValueError) as exc_info:
        build_decision_runtime_snapshot(
            decision_result=decision_result,
            detection_result=_detection_result(),
            fusion_result=fusion_result,
            fusion_stopping_trace=_fusion_stopping_trace(points_present=False),
            fusion_runtime_config_snapshot=_runtime_config_snapshot(),
        )

    # Then
    assert "DecisionResult fusion_status must match FusionResult fusion_status" in str(
        exc_info.value
    )


def test_rejects_decision_fusion_time_mismatched_with_fusion_result() -> None:
    # Given
    decision_result = _decision_result(
        fusion_status=DetectorStatus.DETECTED,
        fusion_time=FUSION_TIME,
    )
    fusion_result = _fusion_result(
        fusion_status="detected",
        fusion_time=FUSION_TIME + timedelta(seconds=1),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        build_decision_runtime_snapshot(
            decision_result=decision_result,
            detection_result=_detection_result(),
            fusion_result=fusion_result,
            fusion_stopping_trace=_fusion_stopping_trace(),
            fusion_runtime_config_snapshot=_runtime_config_snapshot(),
        )

    # Then
    assert "DecisionResult fusion_time must match FusionResult fusion_time" in str(exc_info.value)


def test_round_trips_decision_runtime_snapshot_through_json() -> None:
    # Given
    snapshot = build_decision_runtime_snapshot(
        decision_result=_decision_result(),
        detection_result=_detection_result(),
        fusion_result=_fusion_result(),
        fusion_stopping_trace=_fusion_stopping_trace(),
        fusion_runtime_config_snapshot=_runtime_config_snapshot(),
    )

    # When
    serialized = snapshot.model_dump_json()
    restored = DecisionRuntimeSnapshot.model_validate_json(serialized)

    # Then
    assert restored == snapshot


def test_rejects_extra_decision_runtime_snapshot_field() -> None:
    # Given
    values = _snapshot().model_dump(mode="python")
    values["unexpected"] = "value"

    # When
    with pytest.raises(ValueError) as exc_info:
        DecisionRuntimeSnapshot.model_validate(values)

    # Then
    assert "unexpected" in str(exc_info.value)


@pytest.mark.parametrize("field_name", ["decision_id", "run_id", "entity_id"])
def test_rejects_empty_decision_runtime_snapshot_identifier(field_name: str) -> None:
    # Given
    values = _snapshot().model_dump(mode="python")
    values[field_name] = ""

    # When
    with pytest.raises(ValueError) as exc_info:
        DecisionRuntimeSnapshot.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


def test_restores_legacy_snapshot_without_runtime_config_snapshot() -> None:
    # Given
    payload = _snapshot().model_dump(mode="json")
    del payload["fusion_runtime_config_snapshot"]

    # When
    restored = DecisionRuntimeSnapshot.model_validate(payload)

    # Then
    assert restored.fusion_runtime_config_snapshot is None


@pytest.mark.parametrize(
    ("field_name", "value", "expected_message"),
    [
        (
            "run_id",
            OTHER_RUN_ID,
            "FusionRuntimeConfigSnapshot run_id must match DecisionRuntimeSnapshot run_id",
        ),
        (
            "entity_id",
            OTHER_ENTITY_ID,
            "FusionRuntimeConfigSnapshot entity_id must match DecisionRuntimeSnapshot entity_id",
        ),
    ],
)
def test_rejects_runtime_config_snapshot_with_mismatched_scope(
    field_name: str,
    value: str,
    expected_message: str,
) -> None:
    # Given
    runtime_config = _runtime_config_snapshot().model_copy(update={field_name: value})

    # When
    with pytest.raises(ValueError, match=expected_message):
        _snapshot(fusion_runtime_config_snapshot=runtime_config)


def test_rejects_runtime_config_snapshot_with_mismatched_config_version() -> None:
    # Given
    runtime_config = _runtime_config_snapshot(config_version="other-config")

    # When
    with pytest.raises(
        ValueError,
        match=(
            "FusionRuntimeConfigSnapshot config_version must match "
            "FusionResult scoring_config_version"
        ),
    ):
        _snapshot(fusion_runtime_config_snapshot=runtime_config)


@pytest.mark.parametrize(
    ("fusion_field", "fusion_value", "expected_message"),
    [
        (
            "scoring_profile_id",
            "other-profile",
            "scoring profile_id must match FusionResult scoring_profile_id",
        ),
        (
            "scoring_method",
            "temporal_fusion",
            "scoring method must match FusionResult scoring_method",
        ),
        (
            "scorer_version",
            "other-scorer",
            "scoring scorer_version must match FusionResult scorer_version",
        ),
        (
            "model_version",
            "model-v1",
            "model_version must match FusionResult model_version",
        ),
    ],
)
def test_rejects_runtime_config_snapshot_with_mismatched_fusion_metadata(
    fusion_field: str,
    fusion_value: str,
    expected_message: str,
) -> None:
    # Given
    fusion_result = _fusion_result().model_copy(update={fusion_field: fusion_value})

    # When / Then
    with pytest.raises(ValueError, match=expected_message):
        _snapshot(fusion_result=fusion_result)


def _snapshot(
    *,
    detection_result: DetectionResult | None = None,
    fusion_result: FusionResult | None = None,
    fusion_stopping_trace: FusionStoppingTrace | None = None,
    fusion_runtime_config_snapshot: FusionRuntimeConfigSnapshot | None = None,
) -> DecisionRuntimeSnapshot:
    return DecisionRuntimeSnapshot(
        decision_id=DECISION_ID,
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detection_result=(
            detection_result if detection_result is not None else _detection_result()
        ),
        fusion_result=fusion_result if fusion_result is not None else _fusion_result(),
        fusion_stopping_trace=(
            fusion_stopping_trace if fusion_stopping_trace is not None else _fusion_stopping_trace()
        ),
        fusion_runtime_config_snapshot=(
            fusion_runtime_config_snapshot
            if fusion_runtime_config_snapshot is not None
            else _runtime_config_snapshot()
        ),
    )


def _runtime_config_snapshot(
    *,
    run_id: str = RUN_ID,
    entity_id: str = ENTITY_ID,
    config_version: str = SCORING_CONFIG_VERSION,
    profile_id: str = "s0-profile",
    method: Literal["simple_score"] = "simple_score",
    scorer_version: str = "simple-score-v0.1",
    model_version: str | None = None,
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=run_id,
        entity_id=entity_id,
        config_version=config_version,
        model_version=model_version,
        window=FusionRuntimeWindowSnapshot(window_size_sec=60.0),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10.0),
        scoring=FusionRuntimeScoringSnapshot(
            method=method,
            scorer_version=scorer_version,
            profile_id=profile_id,
            evidence_types=("process_start",),
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )


def _detection_result(
    *,
    run_id: str = RUN_ID,
    entity_id: str = ENTITY_ID,
    detector_status: DetectorStatus = DetectorStatus.MISS,
    detector_time: datetime | None = None,
) -> DetectionResult:
    return DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_time=detector_time,
        detector_status=detector_status,
        detector_id="hayabusa" if detector_status is DetectorStatus.DETECTED else None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )


def _fusion_result(
    *,
    run_id: str = RUN_ID,
    entity_id: str = ENTITY_ID,
    fusion_status: Literal["detected", "miss", "not_evaluated"] = "miss",
    fusion_time: datetime | None = None,
) -> FusionResult:
    if fusion_status == "detected":
        decision_time = fusion_time if fusion_time is not None else FUSION_TIME
        evidence_ids = ["ev-001"]
        episodes = [
            FusionEpisodeResult(
                episode_id="episode-001",
                run_id=run_id,
                entity_id=entity_id,
                start_time=decision_time,
                end_time=None,
                end_reason=None,
                score_at_start=0.8,
                peak_score=0.8,
                contributing_evidence_ids=evidence_ids,
            )
        ]
        score_at_decision = 0.8
    else:
        decision_time = None
        evidence_ids = []
        episodes = []
        score_at_decision = None

    return FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=decision_time,
        fusion_status=fusion_status,
        score_at_decision=score_at_decision,
        contributing_evidence_ids=evidence_ids,
        scoring_config_version=SCORING_CONFIG_VERSION,
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=episodes,
    )


def _fusion_stopping_trace(
    *,
    run_id: str = RUN_ID,
    entity_id: str = ENTITY_ID,
    scoring_config_version: str = SCORING_CONFIG_VERSION,
    points_present: bool = True,
) -> FusionStoppingTrace:
    points = (
        [
            FusionStoppingTracePoint(
                timestamp=BASE_TIME,
                score=0.5,
                persistence_count=None,
                policy_state="off",
            )
        ]
        if points_present
        else []
    )
    return FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=scoring_config_version,
        points=points,
    )


def _decision_result(
    *,
    fast_status: DetectorStatus = DetectorStatus.MISS,
    fusion_status: DetectorStatus = DetectorStatus.MISS,
    detector_time: datetime | None = None,
    fusion_time: datetime | None = None,
) -> DecisionResult:
    if DetectorStatus.NOT_EVALUATED in {fast_status, fusion_status}:
        t_e = None
        decision_path = None
        winning_path = None
    elif fast_status is DetectorStatus.DETECTED and fusion_status is DetectorStatus.DETECTED:
        assert detector_time is not None
        assert fusion_time is not None
        t_e = min(detector_time, fusion_time)
        decision_path = DecisionPath.FAST_AND_FUSION
        winning_path = (
            WinningPath.FAST
            if detector_time < fusion_time
            else WinningPath.FUSION
            if fusion_time < detector_time
            else WinningPath.TIE
        )
    elif fast_status is DetectorStatus.DETECTED:
        assert detector_time is not None
        t_e = detector_time
        decision_path = DecisionPath.FAST
        winning_path = WinningPath.FAST
    elif fusion_status is DetectorStatus.DETECTED:
        assert fusion_time is not None
        t_e = fusion_time
        decision_path = DecisionPath.FUSION
        winning_path = WinningPath.FUSION
    else:
        t_e = None
        decision_path = DecisionPath.NONE
        winning_path = WinningPath.NONE

    return DecisionResult(
        decision_id=DECISION_ID,
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fast_status=fast_status,
        fusion_status=fusion_status,
        detector_time=detector_time,
        fusion_time=fusion_time,
        t_e=t_e,
        decision_path=decision_path,
        winning_path=winning_path,
        decision_reason="Runtime paths evaluated",
        config_version="parallel-v0.2",
    )
