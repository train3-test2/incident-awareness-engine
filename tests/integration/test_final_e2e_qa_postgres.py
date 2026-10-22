"""Full real Standalone Pipeline on newly owned, disposable QA PostgreSQL only."""

import os

import pytest

from incident_awareness.devtools.e2e_qa_database import create_qa_database
from incident_awareness.devtools.final_e2e_qa import QaRunner
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    drop_database,
    local_admin_dsn,
)
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("FINAL_E2E_QA_TEST") != "1", reason="Explicit new QA DB gate required"
)


@pytest.mark.parametrize(
    "kind,expected", [("normal", "miss"), ("attack", "detected"), ("failure", None)]
)
def test_real_full_pipeline_identity_results_and_observers(kind, expected, tmp_path, monkeypatch):
    # Given
    import incident_awareness.devtools.final_e2e_qa as qa

    monkeypatch.setattr(qa, "OUT", tmp_path)
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(qa.ROOT / "configs/event_types_v0.2.yaml")
    )
    admin = local_admin_dsn()
    identity, _ = create_qa_database(admin)
    runner = QaRunner(admin, identity)
    job = {
        "run_id": "RUN-20261018-798",
        "kind": kind,
        "records": 3,
        "phase": "starting",
        "runtime_history": [],
    }
    runner.jobs.append(job)
    try:
        # When: no operation/clock is mocked; actual persistence and all three observers run.
        runner._execute(job)
        with connect_lab(admin, identity, readonly=True) as connection:
            timing, _, known = PipelineStageTimingRepository(connection).read_execution(
                job["execution_id"]
            )
            telemetry = PipelineTelemetryRepository(connection).get_execution(job["execution_id"])
            fusion = connection.execute(
                "SELECT payload FROM fusion_results WHERE run_id=%s", (job["run_id"],)
            ).fetchone()
            archive_count = connection.execute(
                "SELECT count(*) FROM r1_archive_publications"
            ).fetchone()[0]
        # Then
        assert known and timing.execution_id == telemetry.execution_id == job["execution_id"]
        assert timing.run_id == telemetry.run_id == job["run_id"]
        assert timing.entity_id == telemetry.entity_id == job["entity_id"]
        assert telemetry.observation_status == "observed"
        assert sum(bucket.processing_completed_count for bucket in telemetry.buckets) == 3
        assert all(
            record.duration_ns is not None and record.duration_ns >= 0 for record in timing.records
        )
        assert archive_count == 0  # Never pretend a local output was published.
        if expected is None:
            assert job["phase"] == "failed" and fusion is None
            assert (
                timing.records[-1].stage.value == "fusion"
                and timing.records[-1].outcome == "failed"
            )
            assert job["runtime_history"][-1]["status"] == "failed"
        else:
            assert job["phase"] == "completed"
            assert fusion[0]["fusion_status"] == job["summary"]["fusion_status"] == expected
            assert job["summary"]["detector_status"] == "not_evaluated"
            assert len(timing.records) == 5
            assert job["runtime_history"][-1]["status"] == "completed"
    finally:
        drop_database(admin, identity)
