"""Runtime read fixture snapshots live only in a newly owned, disposable test DB."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.pipeline_runtime import PipelineRuntimeStatus
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.devtools.continuous_qa_database import create_continuous_database
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    drop_database,
    local_admin_dsn,
    target_dsn,
)
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("QA_FOLLOWUP_DATABASE_TEST") != "1", reason="Explicit disposable DB gate"
)


@pytest.mark.parametrize("terminal", [False, True])
def test_real_twenty_scopes_older_than_recent_five_and_global_target(terminal, monkeypatch):
    # Given: test-only model snapshots, not operational Pipeline measurements.
    admin = local_admin_dsn()
    identity, _ = create_continuous_database(admin)
    now = datetime.now(UTC).replace(microsecond=0)
    try:
        with connect_lab(admin, identity) as connection:
            repository = PipelineRuntimeStatusRepository(connection)
            for index in range(22):
                status = PipelineRuntimeStatus(
                    execution_id=f"fixture-execution-{index}",
                    run_id=f"fixture-run-{index}",
                    entity_id="HOST-A",
                    status="completed",
                    current_stage=None,
                    input_total=3,
                    normalization_processed_count=3,
                    started_at=now - timedelta(minutes=60),
                    updated_at=now - timedelta(seconds=index + 1),
                    stage_started_at=None,
                    completed_at=now - timedelta(seconds=index + 1),
                    failed_stage=None,
                )
                assert repository.save(status)
            newest = PipelineRuntimeStatus.model_validate(
                {
                    **status.model_dump(),
                    "run_id": "same-run",
                    "entity_id": "HOST-B",
                    "execution_id": "special",
                    "status": "failed" if terminal else "running",
                    "current_stage": None if terminal else "fusion",
                    "updated_at": now if terminal else now - timedelta(minutes=10),
                    "completed_at": None,
                    "failed_stage": "fusion" if terminal else None,
                    "stage_started_at": None if terminal else now - timedelta(minutes=10),
                }
            )
            assert repository.save(newest)
        monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", target_dsn(admin, identity))
        query = "&".join(f"run_id=fixture-run-{i}&entity_id=HOST-A" for i in range(20))
        # When: actual API dependency opens its own explicit read-only session.
        response = TestClient(create_app()).get("/operations/runtime-context?" + query)
        # Then
        assert response.status_code == 200
        body = response.json()
        assert len(body["scopes"]) == 20 and all(
            s["runtime"]["normalization_processed_count"] == 3 for s in body["scopes"]
        )
        assert body["scopes"][19]["runtime"]["run_id"] == "fixture-run-19"
        assert body["pipeline"]["execution_id"] == "special"
        assert body["pipeline"]["status"] == ("failed" if terminal else "running")
        assert body["pipeline"]["is_stale"] is (not terminal)
        with connect_lab(admin, identity, readonly=True) as connection:
            rows = PipelineRuntimeStatusRepository(connection).list_for_scopes(
                (("same-run", "HOST-A"), ("same-run", "HOST-B"))
            )
            assert [r.entity_id for r in rows] == ["HOST-B"]
    finally:
        drop_database(admin, identity)
