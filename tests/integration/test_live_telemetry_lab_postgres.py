"""Explicitly gated real PostgreSQL tests; only newly owned UUID lab DBs are written."""

import os
import time
from datetime import timedelta

import psycopg
import pytest

from incident_awareness.dashboard.telemetry_read_model import (
    DashboardTelemetryReader,
    TelemetryQuery,
)
from incident_awareness.devtools import live_telemetry_lab as lab
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    create_database,
    drop_database,
    local_admin_dsn,
    reset_observations,
)
from incident_awareness.pipeline.runtime_telemetry import utc_now_milliseconds
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("LIVE_TELEMETRY_LAB_TEST") != "1", reason="Requires explicit owned-lab DB gate"
)


@pytest.fixture
def owned_database(monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(lab.ROOT / "configs/event_types_v0.2.yaml")
    )
    admin = local_admin_dsn()
    identity, migrations = create_database(admin)
    assert len(migrations) == 15
    try:
        yield admin, identity
    finally:
        drop_database(admin, identity)


def test_real_fixture_processing_persists_exact_counts_and_real_latency_without_business_rows(
    owned_database,
):
    # Given
    admin, identity = owned_database
    # When
    result = lab.process_batch(admin, identity, separate_first_second=True)
    with connect_lab(admin, identity, readonly=True) as connection:
        snapshot = PipelineTelemetryRepository(connection).get_execution(result.execution_id)
        business = [
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "runs",
                "events",
                "decisions",
                "r1_archive_publications",
                "pipeline_runtime_status",
            )
        ]
    # Then
    assert result.completed == result.evidences_in_memory == 2
    assert sum(b.input_accepted_count for b in snapshot.buckets) == 2
    assert sum(b.processing_completed_count for b in snapshot.buckets) == 2
    assert sum(b.latency_sample_count for b in snapshot.buckets) == 2
    assert result.latency_sum_ns > 0
    assert result.latency_sum_ns == sum(b.latency_sum_ns for b in snapshot.buckets)
    assert len(snapshot.buckets) == 2
    assert snapshot.buckets[0].processing_completed_count == 0
    assert snapshot.buckets[1].input_accepted_count == 0
    assert snapshot.input_identity is not None
    assert business == [0, 0, 0, 0, 0]


def test_duplicate_snapshot_and_bucket_revisions_do_not_add_counters(owned_database):
    # Given
    admin, identity = owned_database
    result = lab.process_batch(admin, identity)
    # When
    with connect_lab(admin, identity) as connection:
        repository = PipelineTelemetryRepository(connection)
        snapshot = repository.get_execution(result.execution_id)
        assert repository.save_snapshot(snapshot) is False
        assert repository.save_snapshot(snapshot) is False
    # Then
    with connect_lab(admin, identity, readonly=True) as connection:
        assert (
            connection.execute(
                "SELECT sum(processing_completed_count) FROM pipeline_telemetry_buckets"
            ).fetchone()[0]
            == 2
        )
        assert (
            connection.execute("SELECT count(*) FROM pipeline_telemetry_executions").fetchone()[0]
            == 1
        )


def test_repeated_actual_processing_uses_new_execution_with_same_verified_input_identity(
    owned_database,
):
    # Given
    admin, identity = owned_database
    # When
    first, second = lab.process_batch(admin, identity), lab.process_batch(admin, identity)
    with connect_lab(admin, identity, readonly=True) as connection:
        repository = PipelineTelemetryRepository(connection)
        a, b = (
            repository.get_execution(first.execution_id),
            repository.get_execution(second.execution_id),
        )
    # Then
    assert a.execution_id != b.execution_id
    assert a.input_identity == b.input_identity
    assert a.revision == b.revision == 3


def test_dashboard_connection_rejects_writes_and_reset_only_clears_owned_telemetry(owned_database):
    # Given
    admin, identity = owned_database
    lab.process_batch(admin, identity)
    # When / Then
    with connect_lab(admin, identity, readonly=True) as connection:
        assert connection.execute("SHOW transaction_read_only").fetchone()[0] == "on"
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection.execute("UPDATE pipeline_telemetry_executions SET revision=revision")
        connection.rollback()
    reset_observations(admin, identity)
    with connect_lab(admin, identity, readonly=True) as connection:
        assert (
            connection.execute("SELECT count(*) FROM pipeline_telemetry_executions").fetchone()[0]
            == 0
        )
        assert (
            connection.execute("SELECT count(*) FROM pipeline_telemetry_buckets").fetchone()[0] == 0
        )


def test_current_window_and_explicit_later_boundary_keep_null_distinct_from_observed_zero(
    owned_database,
):
    # Given
    admin, identity = owned_database
    lab.process_batch(admin, identity, separate_first_second=True)
    time.sleep(1.05)  # Complete the current real UTC bucket; no injected measurement clock.
    # When
    with connect_lab(admin, identity, readonly=True) as connection:
        reader = DashboardTelemetryReader(PipelineTelemetryRepository(connection))
        current = reader.get_telemetry(TelemetryQuery())
        # Read-clock fixture only: stored observations/measurement clocks remain real.
        future = utc_now_milliseconds() + timedelta(seconds=301)
        later = DashboardTelemetryReader(
            PipelineTelemetryRepository(connection), clock=lambda: future
        ).get_telemetry(TelemetryQuery())
    # Then
    assert len(current.points) == 2
    assert current.points[0].processing_completed_count == 0
    assert current.recent_60s_summary.missing_bucket_count == 58
    assert later.points == ()
    assert later.recent_60s_summary.processing_completed_count is None
