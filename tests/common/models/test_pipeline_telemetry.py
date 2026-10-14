from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_telemetry import (
    PipelineTelemetryBucket,
    PipelineTelemetrySnapshot,
)

START = datetime(2026, 10, 14, 1, tzinfo=UTC)


def _bucket_values() -> dict[str, object]:
    return {
        "bucket_start": START,
        "bucket_end": START + timedelta(seconds=1),
        "first_observed_at": START + timedelta(milliseconds=123),
        "last_observed_at": START + timedelta(milliseconds=124),
        "revision": 2,
        "input_accepted_count": 2,
        "processing_completed_count": 1,
        "latency_sample_count": 1,
        "latency_sum_ns": 7,
    }


def _snapshot_values() -> dict[str, object]:
    return {
        "snapshot_id": "pipeline-telemetry:execution-001",
        "execution_id": "execution-001",
        "run_id": "RUN-20261014-001",
        "entity_id": "WIN-01",
        "revision": 2,
        "input_total": 2,
        "input_accepted_at": START + timedelta(milliseconds=123),
        "last_observed_at": START + timedelta(milliseconds=124),
        "observation_status": "observed",
        "buckets": (PipelineTelemetryBucket(**_bucket_values()),),
    }


def test_snapshot_json_round_trip_preserves_nanoseconds_and_utc_milliseconds() -> None:
    # Given
    snapshot = PipelineTelemetrySnapshot(**_snapshot_values())

    # When
    serialized = snapshot.model_dump_json()
    restored = PipelineTelemetrySnapshot.model_validate_json(serialized)

    # Then
    assert restored == snapshot
    assert restored.buckets[0].latency_sum_ns == 7
    assert '"input_accepted_at":"2026-10-14T01:00:00.123Z"' in serialized
    assert isinstance(restored.buckets, tuple)


@pytest.mark.parametrize(
    "value",
    [
        START.replace(tzinfo=None),
        START.astimezone(timezone(timedelta(hours=9))),
        START.replace(microsecond=123456),
        "2026-10-14T01:00:00.123456Z",
        "123",
        123,
        True,
    ],
)
def test_rejects_invalid_observation_timestamps(value: object) -> None:
    # Given
    values = {**_bucket_values(), "first_observed_at": value}

    # When
    with pytest.raises((TypeError, ValidationError)):
        PipelineTelemetryBucket(**values)

    # Then
    assert _bucket_values()["first_observed_at"] == START + timedelta(milliseconds=123)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_accepted_count", -1),
        ("processing_completed_count", True),
        ("processing_failed_count", 1.5),
        ("latency_sample_count", -1),
        ("latency_sum_ns", 1.5),
        ("revision", 0),
    ],
)
def test_requires_strict_nonnegative_counts_and_positive_bucket_revision(
    field: str, value: object
) -> None:
    # Given
    values = {**_bucket_values(), field: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineTelemetryBucket(**values)

    # Then
    assert field in str(exc_info.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"bucket_start": START + timedelta(milliseconds=1)},
        {"bucket_end": START + timedelta(seconds=2)},
        {"last_observed_at": START + timedelta(seconds=1)},
        {"first_observed_at": START + timedelta(milliseconds=125)},
        {"latency_sample_count": 2},
        {"latency_sample_count": 0, "latency_sum_ns": 7},
        {
            "input_accepted_count": 0,
            "processing_completed_count": 0,
            "latency_sample_count": 0,
            "latency_sum_ns": 0,
        },
    ],
)
def test_rejects_invalid_bucket_relationships(changes: dict[str, object]) -> None:
    # Given
    values = {**_bucket_values(), **changes}

    # When
    with pytest.raises(ValidationError):
        PipelineTelemetryBucket(**values)

    # Then
    assert PipelineTelemetryBucket(**_bucket_values()).latency_sum_ns == 7


@pytest.mark.parametrize("field", ["execution_id", "run_id", "entity_id"])
@pytest.mark.parametrize("value", ["", "   ", " leading", "trailing "])
def test_rejects_invalid_scope_identifiers(field: str, value: str) -> None:
    # Given
    values = {**_snapshot_values(), field: value}

    # When
    with pytest.raises(ValidationError) as exc_info:
        PipelineTelemetrySnapshot(**values)

    # Then
    assert field in str(exc_info.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"snapshot_id": "unrelated"},
        {"input_total": 1},
        {"input_total": None},
        {"input_accepted_at": None},
        {"input_accepted_at": START + timedelta(seconds=1)},
        {"last_observed_at": START},
        {"revision": 1},
        {"observation_status": "partial"},
        {"collection_disabled": True},
        {"buckets": (PipelineTelemetryBucket(**_bucket_values()),) * 2},
        {"extra": "not allowed"},
    ],
)
def test_rejects_inconsistent_snapshots(changes: dict[str, object]) -> None:
    # Given
    values = {**_snapshot_values(), **changes}

    # When
    with pytest.raises(ValidationError):
        PipelineTelemetrySnapshot(**values)

    # Then
    assert PipelineTelemetrySnapshot(**_snapshot_values()).observation_status == "observed"


def test_unavailable_snapshot_does_not_fabricate_observations() -> None:
    # Given
    values = {
        "snapshot_id": "pipeline-telemetry:execution-001",
        "execution_id": "execution-001",
        "run_id": "RUN-20261014-001",
        "entity_id": "WIN-01",
        "revision": 0,
        "observation_status": "unavailable",
    }

    # When
    snapshot = PipelineTelemetrySnapshot(**values)

    # Then
    assert snapshot.buckets == ()
    assert snapshot.input_total is None
    assert snapshot.last_observed_at is None
