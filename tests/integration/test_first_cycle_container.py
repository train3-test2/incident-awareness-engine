"""Opt-in Docker E2E verification for the mounted First Cycle fixture."""

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "pipeline" / "first_cycle"
IMAGE_ENV = "INCIDENT_AWARENESS_CONTAINER_IMAGE"
DATABASE_URL_ENV = "INCIDENT_AWARENESS_CONTAINER_DATABASE_URL"
RUN_ENV = "INCIDENT_AWARENESS_RUN_CONTAINER_E2E"


@pytest.mark.skipif(
    os.getenv(RUN_ENV) != "1",
    reason=f"set {RUN_ENV}=1 after starting local PostgreSQL to run Docker E2E",
)
def test_first_cycle_fixture_runs_inside_container() -> None:
    if shutil.which("docker") is None:
        pytest.fail("Docker CLI is required for the container E2E test")

    database_url = os.getenv(DATABASE_URL_ENV)
    if not database_url:
        pytest.fail(f"{DATABASE_URL_ENV} must point to PostgreSQL from inside Docker")

    image = os.getenv(IMAGE_ENV, "incident-awareness-engine:local")
    decision_id = f"D-CONTAINER-{uuid.uuid4().hex}"
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{FIXTURE_ROOT.resolve()}:/inputs:ro",
        "-e",
        f"INCIDENT_AWARENESS_DATABASE_URL={database_url}",
        image,
        "python",
        "-m",
        "incident_awareness.pipeline",
        "--run-metadata",
        "/inputs/run_metadata.json",
        "--manifest",
        "/inputs/manifest.json",
        "--sysmon-jsonl",
        "/inputs/sysmon-0001.jsonl",
        "--fast-hits",
        "/inputs/fast/hits.jsonl",
        "--fast-trace",
        "/inputs/fast/trace.json",
        "--fast-selection",
        "/inputs/fast/selection.json",
        "--fusion-config",
        "/app/configs/fusion/fusion_config_s0_pair_v0.1.yaml",
        "--entity-id",
        "WIN-01",
        "--decision-id",
        decision_id,
        "--decision-config-version",
        "parallel-v0.2",
    ]

    completed = subprocess.run(command, check=False, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stderr
    assert "First Cycle pipeline completed" in completed.stderr
    assert "fusion_status=detected" in completed.stderr
