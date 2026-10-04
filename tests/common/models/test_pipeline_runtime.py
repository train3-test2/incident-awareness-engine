import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)

_STARTED_AT = datetime(2026, 10, 4, 1, 0, 0, 123000, tzinfo=UTC)
_STAGE_STARTED_AT = datetime(2026, 10, 4, 1, 0, 1, 234000, tzinfo=UTC)
_UPDATED_AT = datetime(2026, 10, 4, 1, 0, 2, 345000, tzinfo=UTC)
_COMPLETED_AT = datetime(2026, 10, 4, 1, 0, 3, 456000, tzinfo=UTC)


def _running_values() -> dict[str, object]:
    return {
        "execution_id": "execution-001",
        "run_id": "RUN-20261004-001",
        "entity_id": "WIN-01",
        "status": PipelineRuntimeState.RUNNING,
        "current_stage": PipelineStage.NORMALIZATION,
        "input_total": 3,
        "normalization_processed_count": 1,
        "started_at": _STARTED_AT,
        "stage_started_at": _STAGE_STARTED_AT,
        "updated_at": _UPDATED_AT,
        "completed_at": None,
        "failed_stage": None,
    }


def _completed_values() -> dict[str, object]:
    return {
        **_running_values(),
        "status": PipelineRuntimeState.COMPLETED,
        "current_stage": None,
        "normalization_processed_count": 3,
        "stage_started_at": None,
        "updated_at": _COMPLETED_AT,
        "completed_at": _COMPLETED_AT,
    }


def _failed_values() -> dict[str, object]:
    return {
        **_running_values(),
        "status": PipelineRuntimeState.FAILED,
        "current_stage": None,
        "stage_started_at": None,
        "completed_at": None,
        "failed_stage": PipelineStage.NORMALIZATION,
    }


def test_defines_runtime_state_and_stage_vocabularies() -> None:
    # Given
    expected_states = {"running", "completed", "failed"}
    expected_stages = {
        "artifact_validation",
        "normalization",
        "fusion",
        "fast_handoff",
        "hybrid",
        "persistence",
    }

    # When
    states = {state.value for state in PipelineRuntimeState}
    stages = {stage.value for stage in PipelineStage}

    # Then
    assert states == expected_states
    assert stages == expected_stages


@pytest.mark.parametrize(
    "values",
    [
        pytest.param(_running_values(), id="running"),
        pytest.param(_completed_values(), id="completed"),
        pytest.param(_failed_values(), id="failed"),
    ],
)
def test_accepts_valid_runtime_status(values: dict[str, object]) -> None:
    # Given
    expected_status = values["status"]

    # When
    runtime_status = PipelineRuntimeStatus.model_validate(values)

    # Then
    assert runtime_status.status is expected_status
    assert runtime_status.execution_id == "execution-001"
    assert runtime_status.run_id == "RUN-20261004-001"
    assert runtime_status.entity_id == "WIN-01"


def test_accepts_completed_status_updated_after_completion() -> None:
    # Given
    values = {
        **_completed_values(),
        "updated_at": _COMPLETED_AT + timedelta(milliseconds=1),
    }

    # When
    runtime_status = PipelineRuntimeStatus.model_validate(values)

    # Then
    assert runtime_status.updated_at > runtime_status.completed_at


def test_accepts_failed_status_after_all_normalization_records_were_processed() -> None:
    # Given
    values = {
        **_failed_values(),
        "normalization_processed_count": 3,
        "failed_stage": PipelineStage.FUSION,
    }

    # When
    runtime_status = PipelineRuntimeStatus.model_validate(values)

    # Then
    assert runtime_status.normalization_processed_count == runtime_status.input_total
    assert runtime_status.failed_stage is PipelineStage.FUSION


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("execution_id", "", id="empty-execution-id"),
        pytest.param("run_id", "", id="empty-run-id"),
        pytest.param("entity_id", "", id="empty-entity-id"),
        pytest.param("execution_id", "   ", id="blank-execution-id"),
        pytest.param("run_id", "   ", id="blank-run-id"),
        pytest.param("entity_id", "   ", id="blank-entity-id"),
        pytest.param("execution_id", " execution-001", id="leading-whitespace"),
        pytest.param("run_id", "RUN-20261004-001 ", id="trailing-whitespace"),
        pytest.param("entity_id", " WIN-01 ", id="surrounding-whitespace"),
    ],
)
def test_rejects_invalid_identifier(field_name: str, value: str) -> None:
    # Given
    values = {**_running_values(), field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("input_total", 0, id="zero-input-total"),
        pytest.param("input_total", -1, id="negative-input-total"),
        pytest.param("normalization_processed_count", -1, id="negative-processed"),
        pytest.param("normalization_processed_count", 4, id="processed-exceeds-input"),
        pytest.param("input_total", True, id="boolean-input-total"),
        pytest.param("normalization_processed_count", False, id="boolean-processed"),
    ],
)
def test_rejects_invalid_count(field_name: str, value: object) -> None:
    # Given
    values = {**_running_values(), field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("current_stage", None, id="missing-current-stage"),
        pytest.param("stage_started_at", None, id="missing-stage-started-at"),
        pytest.param("completed_at", _COMPLETED_AT, id="includes-completed-at"),
        pytest.param("failed_stage", PipelineStage.NORMALIZATION, id="includes-failed-stage"),
    ],
)
def test_rejects_invalid_running_contract(field_name: str, value: object) -> None:
    # Given
    values = {**_running_values(), field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("completed_at", None, id="missing-completed-at"),
        pytest.param("current_stage", PipelineStage.PERSISTENCE, id="includes-current-stage"),
        pytest.param("stage_started_at", _STAGE_STARTED_AT, id="includes-stage-started-at"),
        pytest.param("failed_stage", PipelineStage.PERSISTENCE, id="includes-failed-stage"),
        pytest.param(
            "normalization_processed_count",
            2,
            id="normalization-not-complete",
        ),
    ],
)
def test_rejects_invalid_completed_contract(field_name: str, value: object) -> None:
    # Given
    values = {**_completed_values(), field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("failed_stage", None, id="missing-failed-stage"),
        pytest.param("completed_at", _COMPLETED_AT, id="includes-completed-at"),
        pytest.param("current_stage", PipelineStage.FUSION, id="includes-current-stage"),
        pytest.param("stage_started_at", _STAGE_STARTED_AT, id="includes-stage-started-at"),
    ],
)
def test_rejects_invalid_failed_contract(field_name: str, value: object) -> None:
    # Given
    values = {**_failed_values(), field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    ("values", "field_name"),
    [
        pytest.param(
            {**_failed_values(), "updated_at": _STARTED_AT - timedelta(milliseconds=1)},
            "updated_at",
            id="updated-before-started",
        ),
        pytest.param(
            {
                **_running_values(),
                "stage_started_at": _STARTED_AT - timedelta(milliseconds=1),
            },
            "stage_started_at",
            id="stage-before-started",
        ),
        pytest.param(
            {**_running_values(), "updated_at": _STAGE_STARTED_AT - timedelta(milliseconds=1)},
            "updated_at",
            id="updated-before-stage",
        ),
        pytest.param(
            {**_completed_values(), "completed_at": _STARTED_AT - timedelta(milliseconds=1)},
            "completed_at",
            id="completed-before-started",
        ),
        pytest.param(
            {**_completed_values(), "updated_at": _COMPLETED_AT - timedelta(milliseconds=1)},
            "updated_at",
            id="updated-before-completed",
        ),
    ],
)
def test_rejects_invalid_timestamp_order(
    values: dict[str, object],
    field_name: str,
) -> None:
    # Given
    invalid_values = values

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(invalid_values)

    # Then
    assert field_name in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(datetime(2026, 10, 4, 1, tzinfo=UTC).replace(tzinfo=None), id="naive"),
        pytest.param(
            datetime(2026, 10, 4, 1, tzinfo=timezone(timedelta(hours=9))),
            id="non-utc-offset",
        ),
        pytest.param(1_780_536_000, id="integer"),
        pytest.param(1_780_536_000.5, id="float"),
        pytest.param(True, id="boolean"),
        pytest.param("1780536000", id="numeric-string"),
        pytest.param(datetime(2026, 10, 4, 1, 0, 0, 123456, tzinfo=UTC), id="sub-millisecond"),
        pytest.param("2026-10-04T01:00:00.123456Z", id="sub-millisecond-string"),
    ],
)
def test_rejects_invalid_datetime(value: object) -> None:
    # Given
    values = {**_running_values(), "started_at": value}

    # When
    with pytest.raises((TypeError, ValidationError)) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert "started_at" in str(exc_info.value)


@pytest.mark.parametrize(
    "field_name",
    ["started_at", "stage_started_at", "updated_at", "completed_at"],
)
def test_rejects_numeric_value_for_every_datetime_field(field_name: str) -> None:
    # Given
    values = _completed_values() if field_name == "completed_at" else _running_values()
    values = {**values, field_name: 1_780_536_000}

    # When
    with pytest.raises((TypeError, ValidationError)) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)


def test_rejects_unknown_extra_field() -> None:
    # Given
    values = {**_running_values(), "unexpected": "value"}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert "unexpected" in str(exc_info.value)


def test_runtime_status_is_frozen() -> None:
    # Given
    runtime_status = PipelineRuntimeStatus.model_validate(_running_values())

    # When
    with pytest.raises(ValidationError) as exc_info:
        runtime_status.normalization_processed_count = 2

    # Then
    assert "frozen" in str(exc_info.value)


@pytest.mark.parametrize(
    ("values", "expected_remaining_count", "expected_has_error"),
    [
        pytest.param(_running_values(), 2, False, id="running"),
        pytest.param(_completed_values(), 0, False, id="completed"),
        pytest.param(_failed_values(), 2, True, id="failed"),
    ],
)
def test_exposes_derived_runtime_properties(
    values: dict[str, object],
    expected_remaining_count: int,
    expected_has_error: bool,
) -> None:
    # Given
    runtime_status = PipelineRuntimeStatus.model_validate(values)

    # When
    dumped = runtime_status.model_dump(mode="json")

    # Then
    assert runtime_status.remaining_count == expected_remaining_count
    assert runtime_status.has_error is expected_has_error
    assert "remaining_count" not in dumped
    assert "has_error" not in dumped


def test_serializes_utc_datetimes_with_millisecond_precision() -> None:
    # Given
    runtime_status = PipelineRuntimeStatus.model_validate(_running_values())

    # When
    serialized = runtime_status.model_dump_json()
    payload = json.loads(serialized)
    restored = PipelineRuntimeStatus.model_validate_json(serialized)

    # Then
    assert payload["started_at"] == "2026-10-04T01:00:00.123Z"
    assert payload["stage_started_at"] == "2026-10-04T01:00:01.234Z"
    assert payload["updated_at"] == "2026-10-04T01:00:02.345Z"
    assert payload["completed_at"] is None
    assert "remaining_count" not in payload
    assert "has_error" not in payload
    assert restored == runtime_status


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("status", "queued", id="runtime-state"),
        pytest.param("current_stage", "detect", id="current-stage"),
        pytest.param("failed_stage", "integrate", id="failed-stage"),
    ],
)
def test_rejects_values_outside_enum_vocabulary(field_name: str, value: str) -> None:
    # Given
    values = _failed_values() if field_name == "failed_stage" else _running_values()
    values = {**values, field_name: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineRuntimeStatus.model_validate(values)

    # Then
    assert field_name in str(exc_info.value)
