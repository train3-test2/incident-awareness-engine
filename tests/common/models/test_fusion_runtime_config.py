import math

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
    FusionRuntimeReplaySnapshot,
    FusionRuntimeScoringSnapshot,
    FusionRuntimeStoppingSnapshot,
    FusionRuntimeWindowSnapshot,
)


def test_builds_complete_fusion_runtime_config_snapshot() -> None:
    # Given
    expected_run_id = "RUN-20261004-001"

    # When
    snapshot = _snapshot()

    # Then
    assert snapshot.run_id == expected_run_id
    assert snapshot.entity_id == "WIN-01"
    assert snapshot.config_version == "fusion-config-v0.1"
    assert snapshot.model_version is None
    assert snapshot.window.window_size_sec == 300.0
    assert snapshot.replay.step_size_sec == 10.0
    assert snapshot.scoring.method == "simple_score"
    assert snapshot.scoring.scorer_version == "simple-score-v0.1"
    assert snapshot.scoring.profile_id == "s0-profile"
    assert snapshot.scoring.evidence_types == (
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    )
    assert snapshot.stopping.threshold_on == 0.8
    assert snapshot.stopping.threshold_off == 0.4
    assert snapshot.stopping.persistence_k == 2


def test_round_trips_snapshot_without_external_state() -> None:
    # Given
    snapshot = _snapshot(
        evidence_types=("historical_removed_type",),
        model_version="historical-model-v1",
    )

    # When
    restored = FusionRuntimeConfigSnapshot.model_validate_json(snapshot.model_dump_json())

    # Then
    assert restored == snapshot
    assert restored.scoring.evidence_types == ("historical_removed_type",)


def test_snapshot_models_are_frozen() -> None:
    # Given
    snapshot = _snapshot()

    # When
    with pytest.raises(ValidationError) as snapshot_error:
        snapshot.run_id = "RUN-20261004-002"
    with pytest.raises(ValidationError) as nested_error:
        snapshot.window.window_size_sec = 60.0

    # Then
    assert "frozen" in str(snapshot_error.value)
    assert "frozen" in str(nested_error.value)


@pytest.mark.parametrize(
    ("target", "field_name"),
    [
        pytest.param("top-level", "unexpected", id="top-level"),
        pytest.param("window", "unexpected", id="nested"),
    ],
)
def test_rejects_extra_snapshot_fields(target: str, field_name: str) -> None:
    # Given
    values = _snapshot().model_dump(mode="python")
    if target == "top-level":
        values[field_name] = "value"
    else:
        values[target][field_name] = "value"

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeConfigSnapshot.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("run_id", "", id="empty-run-id"),
        pytest.param("run_id", "   ", id="blank-run-id"),
        pytest.param("entity_id", "", id="empty-entity-id"),
        pytest.param("entity_id", "   ", id="blank-entity-id"),
        pytest.param("config_version", "", id="empty-config-version"),
        pytest.param("config_version", "   ", id="blank-config-version"),
        pytest.param("model_version", "", id="empty-model-version"),
        pytest.param("model_version", "   ", id="blank-model-version"),
    ],
)
def test_rejects_blank_snapshot_metadata(field_name: str, value: str) -> None:
    # Given
    values = _snapshot().model_dump(mode="python")
    values[field_name] = value

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeConfigSnapshot.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(0, id="zero"),
        pytest.param(-1, id="negative"),
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param(math.nan, id="nan"),
        pytest.param(math.inf, id="positive-infinity"),
        pytest.param(-math.inf, id="negative-infinity"),
    ],
)
def test_rejects_invalid_window_size(value: object) -> None:
    # Given
    invalid_value = value

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeWindowSnapshot(window_size_sec=invalid_value)

    # Then
    assert exc_info.value.errors()


@pytest.mark.parametrize("value", [300, 300.0])
def test_accepts_numeric_window_size(value: float) -> None:
    # Given
    window_size_sec = value

    # When
    snapshot = FusionRuntimeWindowSnapshot(window_size_sec=window_size_sec)

    # Then
    assert snapshot.window_size_sec == 300.0


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(0, id="zero"),
        pytest.param(-1, id="negative"),
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param(math.nan, id="nan"),
        pytest.param(math.inf, id="positive-infinity"),
        pytest.param(-math.inf, id="negative-infinity"),
        pytest.param(0.0001, id="sub-millisecond"),
    ],
)
def test_rejects_invalid_replay_step(value: object) -> None:
    # Given
    invalid_value = value

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeReplaySnapshot(step_size_sec=invalid_value)

    # Then
    assert exc_info.value.errors()


@pytest.mark.parametrize("value", [10, 0.001, 1.234])
def test_accepts_millisecond_aligned_replay_step(value: float) -> None:
    # Given
    step_size_sec = value

    # When
    snapshot = FusionRuntimeReplaySnapshot(step_size_sec=step_size_sec)

    # Then
    assert snapshot.step_size_sec == float(value)


@pytest.mark.parametrize("field_name", ["scorer_version", "profile_id"])
def test_rejects_blank_scoring_metadata(field_name: str) -> None:
    # Given
    values = _snapshot().scoring.model_dump(mode="python")
    values[field_name] = "   "

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeScoringSnapshot.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


def test_rejects_unsupported_scoring_method() -> None:
    # Given
    values = _snapshot().scoring.model_dump(mode="python")
    values["method"] = "other_score"

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeScoringSnapshot.model_validate(values)

    # Then
    assert "method" in str(exc_info.value)


@pytest.mark.parametrize(
    "evidence_types",
    [
        pytest.param((), id="empty"),
        pytest.param(("",), id="empty-item"),
        pytest.param(("   ",), id="blank-item"),
        pytest.param((" evidence",), id="leading-whitespace"),
        pytest.param(("evidence ",), id="trailing-whitespace"),
        pytest.param(("evidence", "evidence"), id="duplicate"),
    ],
)
def test_rejects_invalid_evidence_types(evidence_types: tuple[str, ...]) -> None:
    # Given
    values = _snapshot().scoring.model_dump(mode="python")
    values["evidence_types"] = evidence_types

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeScoringSnapshot.model_validate(values)

    # Then
    assert "evidence_types" in str(exc_info.value)


def test_preserves_evidence_type_order_without_current_vocabulary_lookup() -> None:
    # Given
    historical_types = ("historical_removed_type", "another_historical_type")

    # When
    scoring = FusionRuntimeScoringSnapshot(
        method="simple_score",
        scorer_version="historical-scorer",
        profile_id="historical-profile",
        evidence_types=historical_types,
    )

    # Then
    assert scoring.evidence_types == historical_types


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("threshold_on", -0.1, id="threshold-on-below-range"),
        pytest.param("threshold_on", 1.1, id="threshold-on-above-range"),
        pytest.param("threshold_off", -0.1, id="threshold-off-below-range"),
        pytest.param("threshold_off", 1.1, id="threshold-off-above-range"),
        pytest.param("threshold_on", True, id="threshold-on-boolean"),
        pytest.param("threshold_off", False, id="threshold-off-boolean"),
        pytest.param("threshold_on", math.nan, id="threshold-on-nan"),
        pytest.param("threshold_off", math.inf, id="threshold-off-infinity"),
        pytest.param("persistence_k", 0, id="zero-persistence"),
        pytest.param("persistence_k", -1, id="negative-persistence"),
        pytest.param("persistence_k", True, id="boolean-persistence"),
    ],
)
def test_rejects_invalid_stopping_value(field_name: str, value: object) -> None:
    # Given
    values = _snapshot().stopping.model_dump(mode="python")
    values[field_name] = value

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeStoppingSnapshot.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


def test_rejects_invalid_stopping_threshold_order() -> None:
    # Given
    threshold_on = 0.4
    threshold_off = 0.4

    # When
    with pytest.raises(ValidationError) as exc_info:
        FusionRuntimeStoppingSnapshot(
            threshold_on=threshold_on,
            threshold_off=threshold_off,
            persistence_k=1,
        )

    # Then
    assert "threshold_off must be less than threshold_on" in str(exc_info.value)


def _snapshot(
    *,
    evidence_types: tuple[str, ...] = (
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    ),
    model_version: str | None = None,
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id="RUN-20261004-001",
        entity_id="WIN-01",
        config_version="fusion-config-v0.1",
        model_version=model_version,
        window=FusionRuntimeWindowSnapshot(window_size_sec=300),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10),
        scoring=FusionRuntimeScoringSnapshot(
            method="simple_score",
            scorer_version="simple-score-v0.1",
            profile_id="s0-profile",
            evidence_types=evidence_types,
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )
