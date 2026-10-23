"""Opt-in real full Pipeline tests; each case creates and drops only its owned new DB."""

import os
from types import SimpleNamespace

import pytest

from incident_awareness.devtools import continuous_e2e_qa as qa
from incident_awareness.devtools.continuous_qa_database import create_continuous_database
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    drop_database,
    local_admin_dsn,
)
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("CONTINUOUS_E2E_QA_TEST") != "1", reason="Explicit owned disposable DB gate"
)


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(qa.ROOT / "configs/event_types_v0.2.yaml")
    )
    admin = local_admin_dsn()
    identity, migrations = create_continuous_database(admin)
    assert len(migrations) == 15
    try:
        yield admin, identity
    finally:
        drop_database(admin, identity)


def make_runner(environment, tmp_path):
    admin, identity = environment
    counts = iter([3, 6, 9, 3])
    runner = qa.ContinuousRunner(
        admin,
        identity,
        output_dir=tmp_path,
        rng=SimpleNamespace(choice=lambda _: next(counts), uniform=lambda *_: 0),
    )
    actual_observations = runner.backend.observations

    def observe_and_stop(job):
        actual = actual_observations(job)
        if len(runner.jobs) % 2 == 0:
            runner.stop()
        return actual

    runner.backend.observations = observe_and_stop
    return runner


def test_real_variable_batches_full_results_identity_and_restart_no_replay(environment, tmp_path):
    # Given
    admin, identity = environment
    runner = make_runner(environment, tmp_path)
    try:
        # When: real operation clocks, real observers, real business commits, no fake stage results.
        runner.start()
        runner.thread.join(60)
        # Then
        assert not runner.thread.is_alive() and runner.phase == "stopped"
        assert [job["records"] for job in runner.jobs] == [3, 6]
        assert [job["summary"]["fusion_status"] for job in runner.jobs] == ["miss", "detected"]
        assert (
            runner.status()["input_accepted_count"]
            == runner.status()["processing_completed_count"]
            == 9
        )
        with connect_lab(admin, identity, readonly=True) as connection:
            assert connection.execute("SHOW transaction_read_only").fetchone()[0] == "on"
            assert connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 2
            assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 9
            assert connection.execute("SELECT count(*) FROM decisions").fetchone()[0] == 2
            assert (
                connection.execute("SELECT count(*) FROM r1_archive_publications").fetchone()[0]
                == 0
            )
            for job in runner.jobs:
                timing, _, known = PipelineStageTimingRepository(connection).read_execution(
                    job["execution_id"]
                )
                assert (
                    known
                    and timing.run_id == job["run_id"]
                    and timing.entity_id == job["entity_id"]
                )
                assert len(timing.records) == 5 and all(
                    record.duration_ns >= 0 for record in timing.records
                )
                assert job["runtime_history"][-1]["status"] == "completed"
                assert job["observations"]["latency_sample_count"] == job["records"]
                assert job["observations"]["latency_sum_ns"] > 0
                assert job["summary"]["detector_status"] == "not_evaluated"
        previous = [job["execution_id"] for job in runner.jobs]
        runner.close()
        # When: same owned DB resumes stopped, not rerunning committed/reserved jobs.
        runner = make_runner(environment, tmp_path)
        assert runner.thread is None and runner.phase == "stopped" and len(runner.jobs) == 2
        runner.start("random")
        runner.thread.join(60)
        # Then
        assert len(runner.jobs) == 4 and len({job["run_id"] for job in runner.jobs}) == 4
        assert len({job["execution_id"] for job in runner.jobs}) == 4
        assert [job["execution_id"] for job in runner.jobs[:2]] == previous
    finally:
        runner.close()


def test_real_advisory_lease_refuses_duplicate_controller(environment, tmp_path):
    # Given
    runner = make_runner(environment, tmp_path)
    try:
        # When / Then
        with pytest.raises(ValueError, match="Another continuous QA owner"):
            qa.ContinuousBackend(*environment)
        assert runner.phase == "stopped" and runner.jobs == []
    finally:
        runner.close()


@pytest.mark.parametrize("failure", ["lost_database_connection", "invalid_input"])
def test_real_environment_errors_stop_without_creating_a_business_run(
    environment, tmp_path, monkeypatch, failure
):
    # Given
    runner = make_runner(environment, tmp_path)
    if failure == "lost_database_connection":
        runner.backend.lease.close()  # Only our new isolated test connection, not the server/DB.
    else:
        monkeypatch.setattr(qa, "FIXTURE_HASHES", {"normal": "wrong"})
    try:
        # When
        runner.start()
        runner.thread.join(20)
        # Then
        assert runner.phase == "failed" and runner.reason == "safe_stop"
        assert runner.jobs == []
        with connect_lab(*environment, readonly=True) as connection:
            assert connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0
    finally:
        runner.close()
