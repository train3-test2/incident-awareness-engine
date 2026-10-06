import os
from urllib.parse import unquote, urlparse
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb
from test_postgres_repositories import _decision_read_model_persistence_case

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.pipeline.persistence import persist_s0_results
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    FusionRuntimeConfigSnapshotRepository,
)

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
    embedded_legacy_id = f"DEC-EMBEDDED-LEGACY-{suffix}"
    row_absent_legacy_id = f"DEC-ROW-ABSENT-LEGACY-{suffix}"
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
                fusion_engine_response = client.get(f"/runs/{run_id}/fusion-engine")
                historical_d1_response = client.get(f"/decisions/{d1_id}")
                historical_d2_response = client.get(f"/decisions/{d2_id}")
                historical_d3_response = client.get(f"/decisions/{d3_id}")
                unknown_run_response = client.get(f"/runs/{unknown_run_id}")
                unknown_fusion_engine_response = client.get(f"/runs/{unknown_run_id}/fusion-engine")
                unknown_decision_response = client.get(f"/decisions/{unknown_decision_id}")

                embedded_legacy_decision = d3_case[6].model_copy(
                    update={
                        "decision_id": embedded_legacy_id,
                        "decision_reason": "Legacy Decision with embedded Runtime snapshot",
                        "supersedes_decision_id": d3_id,
                    }
                )
                row_absent_legacy_decision = d3_case[6].model_copy(
                    update={
                        "decision_id": row_absent_legacy_id,
                        "decision_reason": "Legacy Decision without Runtime snapshot row",
                        "supersedes_decision_id": embedded_legacy_id,
                    }
                )
                DecisionRepository(connection).save(embedded_legacy_decision)
                DecisionRepository(connection).save(row_absent_legacy_decision)
                stored_snapshot_row = connection.execute(
                    "SELECT payload FROM decision_runtime_snapshots WHERE decision_id = %s",
                    (d3_id,),
                ).fetchone()
                assert stored_snapshot_row is not None
                embedded_legacy_payload = dict(stored_snapshot_row[0])
                embedded_legacy_payload["decision_id"] = embedded_legacy_id
                del embedded_legacy_payload["fusion_runtime_config_snapshot"]
                # Direct SQL intentionally reproduces a pre-Issue #164 stored payload.
                connection.execute(
                    """
                    INSERT INTO decision_runtime_snapshots (
                        decision_id,
                        run_id,
                        entity_id,
                        payload
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        embedded_legacy_id,
                        run_id,
                        entity_id,
                        Jsonb(embedded_legacy_payload),
                    ),
                )
                connection.commit()
                embedded_legacy_response = client.get(f"/decisions/{embedded_legacy_id}")
                row_absent_legacy_response = client.get(f"/decisions/{row_absent_legacy_id}")
                latest_runtime_config = FusionRuntimeConfigSnapshotRepository(connection).get(
                    run_id,
                    entity_id,
                )

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
            assert set(current_runtime) == {
                "decision",
                "latest_detection_result",
                "latest_fusion_result",
                "latest_fusion_stopping_trace",
            }
            assert "fusion_runtime_config_snapshot" not in detail_response.text
            assert (
                current_runtime["latest_detection_result"]["detector_time"]
                == d3_case[5].detection_result.model_dump(mode="json")["detector_time"]
            )
            assert (
                current_runtime["latest_fusion_result"]["scoring_config_version"]
                == d3_case[2].scoring_config_version
            )
            assert current_runtime["latest_fusion_stopping_trace"]["points"][0]["score"] == 0.9

            assert fusion_engine_response.status_code == 200
            fusion_engine = fusion_engine_response.json()
            assert set(fusion_engine) == {
                "run",
                "current_decision",
                "fusion_result",
                "stopping_trace",
                "runtime_config_snapshot",
            }
            assert fusion_engine["run"]["run_id"] == run_id
            assert fusion_engine["current_decision"] == d3_case[6].model_dump(mode="json")
            assert fusion_engine["fusion_result"] == d3_case[2].model_dump(mode="json")
            assert fusion_engine["stopping_trace"] == d3_case[3].model_dump(mode="json")
            assert fusion_engine["runtime_config_snapshot"] == d3_case[4].model_dump(mode="json")

            assert historical_d1_response.status_code == 200
            historical_d1 = historical_d1_response.json()
            assert historical_d1["decision"]["decision_id"] == d1_id
            assert historical_d1["runtime_snapshot"]["decision_id"] == d1_id
            assert historical_d1["runtime_snapshot"]["fusion_runtime_config_snapshot"] == (
                d1_case[4].model_dump(mode="json")
            )
            assert (
                historical_d1["runtime_snapshot"]["detection_result"]["detector_time"]
                == d1_case[5].detection_result.model_dump(mode="json")["detector_time"]
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

            assert historical_d2_response.status_code == 200
            historical_d2 = historical_d2_response.json()
            assert historical_d2["decision"]["decision_id"] == d2_id
            assert historical_d2["runtime_snapshot"]["fusion_runtime_config_snapshot"] == (
                d2_case[4].model_dump(mode="json")
            )

            assert historical_d3_response.status_code == 200
            assert historical_d3_response.json()["decision"]["decision_id"] == d3_id
            assert historical_d3_response.json()["runtime_snapshot"]["decision_id"] == d3_id

            assert embedded_legacy_response.status_code == 200
            embedded_legacy = embedded_legacy_response.json()
            assert embedded_legacy["decision"]["decision_id"] == embedded_legacy_id
            assert embedded_legacy["runtime_snapshot"] is not None
            assert latest_runtime_config == d3_case[4]
            assert embedded_legacy["runtime_snapshot"]["fusion_runtime_config_snapshot"] is None

            assert row_absent_legacy_response.status_code == 200
            assert row_absent_legacy_response.json()["decision"]["decision_id"] == (
                row_absent_legacy_id
            )
            assert row_absent_legacy_response.json()["runtime_snapshot"] is None

            assert unknown_run_response.status_code == 404
            assert unknown_run_response.json() == {"detail": "Run not found"}
            assert unknown_fusion_engine_response.status_code == 404
            assert unknown_fusion_engine_response.json() == {"detail": "Run not found"}
            assert unknown_decision_response.status_code == 404
            assert unknown_decision_response.json() == {"detail": "Decision not found"}

            responses = (
                runs_response,
                overview_response,
                detail_response,
                fusion_engine_response,
                historical_d1_response,
                historical_d2_response,
                historical_d3_response,
                embedded_legacy_response,
                row_absent_legacy_response,
                unknown_run_response,
                unknown_fusion_engine_response,
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
