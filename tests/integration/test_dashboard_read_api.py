import os
from urllib.parse import unquote, urlparse
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from test_postgres_repositories import _decision_read_model_persistence_case

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.pipeline.persistence import persist_s0_results
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.result_repository import DecisionRepository

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"


@pytest.fixture
def database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_DATABASE_URL_ENV} is required for PostgreSQL integration tests")

    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})

    database_name = unquote(urlparse(url).path).strip("/").lower()
    explicitly_marked = os.environ.get(TEST_DATABASE_MARKER_ENV, "").lower() == "true"
    if "test" not in database_name and not explicitly_marked:
        pytest.skip(
            "PostgreSQL integration requires a database containing 'test' in its name or "
            f"{TEST_DATABASE_MARKER_ENV}=true"
        )

    return url


def test_dashboard_read_api_against_postgres(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id = _unique_run_id(UUID(suffix))
    entity_id = f"WIN-{suffix}"
    d1_id = f"DEC-D1-{suffix}"
    d2_id = f"DEC-D2-{suffix}"
    d3_id = f"DEC-D3-{suffix}"
    legacy_id = f"DEC-LEGACY-{suffix}"
    d1_case = _decision_read_model_persistence_case(
        run_id,
        entity_id,
        d1_id,
        runtime_version=1,
        trace_score=0.1,
    )
    d2_case = _decision_read_model_persistence_case(
        run_id,
        entity_id,
        d2_id,
        runtime_version=2,
        trace_score=0.5,
        supersedes_decision_id=d1_id,
    )
    d3_case = _decision_read_model_persistence_case(
        run_id,
        entity_id,
        d3_id,
        runtime_version=3,
        trace_score=0.9,
        supersedes_decision_id=d2_id,
    )
    cases = (d1_case, d2_case, d3_case)
    unknown_run_id = _unique_run_id(uuid4())
    unknown_decision_id = f"DEC-UNKNOWN-{uuid4().hex}"

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        try:
            for case in cases:
                persist_s0_results(*case, connection=connection)

            expected_total_runs = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            expected_recent_ids = [
                row[0]
                for row in connection.execute(
                    "SELECT run_id FROM runs ORDER BY start_time DESC, run_id DESC LIMIT 5"
                ).fetchall()
            ]
            monkeypatch.setenv(DATABASE_URL_ENV, database_url)
            app = create_app()

            # When
            with TestClient(app) as client:
                runs_response = client.get("/runs")
                overview_response = client.get("/overview")
                detail_response = client.get(f"/runs/{run_id}")
                historical_d1_response = client.get(f"/decisions/{d1_id}")
                historical_d3_response = client.get(f"/decisions/{d3_id}")
                unknown_run_response = client.get(f"/runs/{unknown_run_id}")
                unknown_decision_response = client.get(f"/decisions/{unknown_decision_id}")

                legacy_decision = d3_case[5].model_copy(
                    update={
                        "decision_id": legacy_id,
                        "decision_reason": "Legacy Decision without Runtime snapshot",
                        "supersedes_decision_id": d3_id,
                    }
                )
                DecisionRepository(connection).save(legacy_decision)
                connection.commit()
                legacy_response = client.get(f"/decisions/{legacy_id}")

            # Then
            assert runs_response.status_code == 200
            run_items = runs_response.json()["runs"]
            stored_run = next(item for item in run_items if item["run_id"] == run_id)
            assert stored_run["scenario_id"] == "postgres-decision-read-model"
            assert stored_run["target_host"] == entity_id

            assert overview_response.status_code == 200
            assert overview_response.json()["total_runs"] == expected_total_runs
            assert [
                run["run_id"] for run in overview_response.json()["recent_runs"]
            ] == expected_recent_ids
            assert len(overview_response.json()["recent_runs"]) <= 5

            assert detail_response.status_code == 200
            detail = detail_response.json()
            assert detail["run"]["run_id"] == run_id
            assert detail["current_decision"]["decision"]["decision_id"] == d3_id
            assert [item["decision_id"] for item in detail["decision_history"]] == [
                d3_id,
                d2_id,
                d1_id,
            ]
            current_runtime = detail["current_decision"]
            assert (
                current_runtime["latest_detection_result"]["detector_time"]
                == d3_case[4].detection_result.model_dump(mode="json")["detector_time"]
            )
            assert (
                current_runtime["latest_fusion_result"]["scoring_config_version"]
                == d3_case[2].scoring_config_version
            )
            assert current_runtime["latest_fusion_stopping_trace"]["points"][0]["score"] == 0.9

            assert historical_d1_response.status_code == 200
            historical_d1 = historical_d1_response.json()
            assert historical_d1["decision"]["decision_id"] == d1_id
            assert historical_d1["runtime_snapshot"]["decision_id"] == d1_id
            assert (
                historical_d1["runtime_snapshot"]["detection_result"]["detector_time"]
                == d1_case[4].detection_result.model_dump(mode="json")["detector_time"]
            )
            assert (
                historical_d1["runtime_snapshot"]["fusion_result"]["scoring_config_version"]
                == d1_case[2].scoring_config_version
            )
            assert (
                historical_d1["runtime_snapshot"]["fusion_stopping_trace"]["points"][0]["score"]
                == 0.1
            )
            assert (
                historical_d1["runtime_snapshot"]["detection_result"]["detector_time"]
                != current_runtime["latest_detection_result"]["detector_time"]
            )
            assert (
                historical_d1["runtime_snapshot"]["fusion_result"]["scoring_config_version"]
                != current_runtime["latest_fusion_result"]["scoring_config_version"]
            )
            assert (
                historical_d1["runtime_snapshot"]["fusion_stopping_trace"]["points"][0]["score"]
                != current_runtime["latest_fusion_stopping_trace"]["points"][0]["score"]
            )

            assert historical_d3_response.status_code == 200
            assert historical_d3_response.json()["decision"]["decision_id"] == d3_id
            assert historical_d3_response.json()["runtime_snapshot"]["decision_id"] == d3_id

            assert legacy_response.status_code == 200
            assert legacy_response.json()["decision"]["decision_id"] == legacy_id
            assert legacy_response.json()["runtime_snapshot"] is None

            assert unknown_run_response.status_code == 404
            assert unknown_run_response.json() == {"detail": "Run not found"}
            assert unknown_decision_response.status_code == 404
            assert unknown_decision_response.json() == {"detail": "Decision not found"}

            responses = (
                runs_response,
                overview_response,
                detail_response,
                historical_d1_response,
                historical_d3_response,
                legacy_response,
                unknown_run_response,
                unknown_decision_response,
            )
            parsed_url = urlparse(database_url)
            secret_markers = {
                DATABASE_URL_ENV,
                TEST_DATABASE_URL_ENV,
                "postgresql://",
                "password",
                "Traceback",
                "SELECT ",
                database_url,
                parsed_url.password,
                parsed_url.hostname,
            }
            for response in responses:
                for marker in secret_markers:
                    if marker:
                        assert marker not in response.text
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def _unique_run_id(value: UUID) -> str:
    integer = value.int
    year = 2027 + integer % 50
    month = 1 + (integer >> 8) % 12
    day = 1 + (integer >> 16) % 28
    sequence = (integer >> 24) % 1000
    return f"RUN-{year:04d}{month:02d}{day:02d}-{sequence:03d}"
