from dataclasses import replace
from datetime import UTC, datetime
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from incident_awareness.common.models.fusion import FusionEpisodeResult, FusionResult
from incident_awareness.common.models.result import (
    DecisionResult,
    DetectorStatus,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api import analysis_summaries as api
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError

BASE_TIME = datetime(2026, 10, 3, 0, tzinfo=UTC)


class FakeRuns:
    def __init__(self, runs: dict[str, RunMetadata]) -> None:
        self.runs = runs
        self.calls: list[str] = []

    def get(self, run_id: str) -> RunMetadata | None:
        self.calls.append(run_id)
        return self.runs.get(run_id)


class FakeDecisions:
    def __init__(self, heads: dict[str, DecisionResult | Exception | None]) -> None:
        self.heads = heads
        self.calls: list[tuple[str, str]] = []

    def get_current_head(self, run_id: str, entity_id: str) -> DecisionResult | None:
        self.calls.append((run_id, entity_id))
        head = self.heads.get(run_id)
        if isinstance(head, Exception):
            raise head
        return head


class FakeFusionResults:
    def __init__(self, results: dict[str, FusionResult | None]) -> None:
        self.results = results
        self.calls: list[tuple[str, str]] = []

    def get(self, run_id: str, entity_id: str) -> FusionResult | None:
        self.calls.append((run_id, entity_id))
        return self.results.get(run_id)


def test_read_summaries_preserves_order_and_distinct_missing_states() -> None:
    # Given: a Fusion-only incomplete Decision, a Run without results, an unknown Run and a broken chain.
    repositories = _repositories()
    run_ids = ("RUN-20261003-001", "RUN-20261003-002", "RUN-20261003-003", "RUN-20261003-004")

    # When
    response = api.read_summaries(repositories, run_ids, now=BASE_TIME)

    # Then
    assert [item.run_id for item in response.items] == list(run_ids)
    assert [item.status for item in response.items] == [
        "available",
        "available",
        "run_not_found",
        "integrity_error",
    ]
    first = response.items[0]
    assert first.entity_id == "WIN-01"
    assert first.decision is not None and first.decision.fast_status == DetectorStatus.NOT_EVALUATED
    assert first.decision.t_e is None and first.decision.decision_path is None
    assert first.fusion_result is not None
    assert first.fusion_result.contributing_evidence_ids == ["E-A", "E-B"]
    assert response.items[1].decision is None and response.items[1].fusion_result is None
    assert response.items[2].entity_id is None
    assert response.items[3].decision is None and response.items[3].entity_id == "WIN-03"


def test_read_summaries_is_bounded_to_three_reads_per_run_without_detail_reads() -> None:
    # Given
    repositories = _repositories()

    # When
    api.read_summaries(
        repositories, ("RUN-20261003-001", "RUN-20261003-002", "RUN-20261003-003"), now=BASE_TIME
    )

    # Then: metadata for every Run, then one Decision head and one Fusion read per existing Run.
    assert repositories.runs.calls == ["RUN-20261003-001", "RUN-20261003-002", "RUN-20261003-003"]
    assert repositories.decisions.calls == [
        ("RUN-20261003-001", "WIN-01"),
        ("RUN-20261003-002", "WIN-02"),
    ]
    assert repositories.fusion_results.calls == [
        ("RUN-20261003-001", "WIN-01"),
        ("RUN-20261003-002", "WIN-02"),
    ]


def test_endpoint_returns_versioned_snapshot_of_requested_runs() -> None:
    # Given
    client, _ = _client()

    # When
    response = client.get(
        "/analysis-summaries",
        params=[("run_id", "RUN-20261003-001"), ("run_id", "RUN-20261003-003")],
    )

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "dashboard_analysis_summaries_v1"
    assert [item["run_id"] for item in payload["items"]] == ["RUN-20261003-001", "RUN-20261003-003"]
    assert (
        payload["items"][0]["decision"]["decision_reason"]
        == "Required parallel evaluation was not completed"
    )
    assert payload["items"][0]["fusion_result"]["fusion_time"] == "2026-10-03T00:00:20.000Z"
    assert payload["items"][1] == {
        "run_id": "RUN-20261003-003",
        "status": "run_not_found",
        "entity_id": None,
        "decision": None,
        "fusion_result": None,
        "observations": None,
    }


@pytest.mark.parametrize(
    "params",
    [
        [],
        [("run_id", f"RUN-{index}") for index in range(21)],
        [("run_id", "RUN-20261003-001"), ("run_id", "RUN-20261003-001")],
        [("run_id", " RUN-A")],
        [("run_id", "")],
        [("run_id", "RUN-\nA")],
    ],
)
def test_endpoint_rejects_unbounded_or_ambiguous_scopes_before_database(params) -> None:
    # Given
    client, opened = _client()

    # When
    response = client.get("/analysis-summaries", params=params)

    # Then
    assert response.status_code == 422
    assert opened == []


def test_endpoint_reports_unavailable_database_without_secrets(monkeypatch) -> None:
    # Given
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_DATABASE_URL", "postgresql://test:secret@127.0.0.1:1/test"
    )

    # When
    response = TestClient(create_app()).get(
        "/analysis-summaries", params={"run_id": "RUN-20261003-001"}
    )

    # Then
    assert response.status_code == 503
    assert "secret" not in response.text


def test_run_detail_route_is_not_shadowed_by_the_summary_route() -> None:
    # Given / When
    paths = create_app().openapi()["paths"]

    # Then: the summary path is top-level, so /runs/{run_id} keeps its meaning.
    assert "/analysis-summaries" in paths
    assert "/runs/analysis-summaries" not in paths
    assert "/runs/{run_id}" in paths


def _client() -> tuple[TestClient, list[bool]]:
    opened: list[bool] = []
    app = create_app()

    # Mirrors the real dependency: an invalid scope never reaches the repository factory.
    def repositories(_query: Annotated[api.AnalysisSummaryQuery, Depends(api.query_runs)]):
        opened.append(True)
        yield _repositories()

    app.dependency_overrides[api.summary_repositories] = repositories
    return TestClient(app), opened


def _repositories() -> api.SummaryRepositories:
    return api.SummaryRepositories(
        runs=FakeRuns(
            {
                "RUN-20261003-001": _run("RUN-20261003-001", "WIN-01"),
                "RUN-20261003-002": _run("RUN-20261003-002", "WIN-02"),
                "RUN-20261003-004": _run("RUN-20261003-004", "WIN-03"),
            }
        ),
        decisions=FakeDecisions(
            {
                "RUN-20261003-001": _incomplete_decision(),
                "RUN-20261003-002": None,
                "RUN-20261003-004": DecisionIntegrityError("multiple heads"),
            }
        ),
        fusion_results=FakeFusionResults(
            {"RUN-20261003-001": _fusion_result(), "RUN-20261003-002": None}
        ),
    )


def _incomplete_decision() -> DecisionResult:
    return DecisionResult(
        run_id="RUN-20261003-001",
        decision_id="DEC-A",
        entity_id="WIN-01",
        fast_status=DetectorStatus.NOT_EVALUATED,
        fusion_status=DetectorStatus.DETECTED,
        fusion_time=datetime(2026, 10, 3, 0, 0, 20, tzinfo=UTC),
        detector_time=None,
        t_e=None,
        decision_path=None,
        winning_path=None,
        decision_reason="Required parallel evaluation was not completed",
        config_version="parallel-v0.2",
    )


def _fusion_result() -> FusionResult:
    return FusionResult(
        run_id="RUN-20261003-001",
        entity_id="WIN-01",
        fusion_time=datetime(2026, 10, 3, 0, 0, 20, tzinfo=UTC),
        fusion_status="detected",
        score_at_decision=1.0,
        contributing_evidence_ids=["E-A", "E-B"],
        scoring_config_version="fusion-config-v1",
        scoring_profile_id="s0-profile",
        model_version=None,
        scoring_method="simple_score",
        scorer_version="simple-score-v1",
        fusion_episodes=[
            FusionEpisodeResult(
                episode_id="FEP-001",
                run_id="RUN-20261003-001",
                entity_id="WIN-01",
                start_time=datetime(2026, 10, 3, 0, 0, 20, tzinfo=UTC),
                end_time=datetime(2026, 10, 3, 0, 5, 20, tzinfo=UTC),
                end_reason="released",
                score_at_start=1.0,
                peak_score=1.0,
            )
        ],
    )


def _run(run_id: str, target_host: str) -> RunMetadata:
    return RunMetadata(
        run_id=run_id,
        scenario_id="scenario-001",
        run_type=RunType.ATTACK,
        target_host=target_host,
        start_time=BASE_TIME,
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.2",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


class ObservationConnection:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def cursor(self, **_kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, parameters):
        self.calls.append((statement, parameters))
        return self

    def fetchall(self):
        return self.rows


def test_observations_use_one_target_scoped_grouped_read_for_the_whole_batch() -> None:
    # Given: the SQL result includes two Event types and an existing target with no Events.
    connection = ObservationConnection(
        [
            {
                "run_id": "R1",
                "target_host": "HOST1",
                "event_type": "network_connection",
                "event_count": 2,
            },
            {
                "run_id": "R1",
                "target_host": "HOST1",
                "event_type": "process_create",
                "event_count": 1,
            },
            {"run_id": "R2", "target_host": "HOST2", "event_type": None, "event_count": 0},
        ]
    )

    # When
    result = api.StoredObservationReader(connection).read(("R1", "R2", "MISSING"))

    # Then: one parameterized SELECT joins both the Run and target host, not a query per row.
    assert len(connection.calls) == 1
    statement, parameters = connection.calls[0]
    assert "LEFT JOIN events" in statement
    assert "e.run_id=r.run_id AND e.host_id=r.target_host" in statement
    assert "GROUP BY r.run_id,r.target_host,e.event_type" in statement
    assert parameters == (["R1", "R2", "MISSING"],)
    assert result[("R1", "HOST1")].model_dump() == {
        "source": "stored_events",
        "entity_id": "HOST1",
        "event_count": 3,
        "event_type_counts": {"network_connection": 2, "process_create": 1},
    }
    assert result[("R2", "HOST2")].event_count == 0
    assert result[("R2", "HOST2")].event_type_counts == {}
    assert ("MISSING", "HOST1") not in result


def test_observations_do_not_cross_target_scope_or_replace_absent_analysis() -> None:
    # Given: metadata selects WIN-01; a different target has counts in the same batch.
    repositories = _repositories()
    connection = ObservationConnection(
        [
            {
                "run_id": "RUN-20261003-001",
                "target_host": "OTHER",
                "event_type": "process_create",
                "event_count": 9,
            },
            {
                "run_id": "RUN-20261003-002",
                "target_host": "WIN-02",
                "event_type": "process_create",
                "event_count": 1,
            },
        ]
    )
    repositories = replace(repositories, observations=api.StoredObservationReader(connection))

    # When
    result = api.read_summaries(
        repositories, ("RUN-20261003-001", "RUN-20261003-002"), now=BASE_TIME
    )

    # Then: stored Event presence does not create a Decision or Fusion result.
    assert len(connection.calls) == 1
    assert result.items[0].observations is None
    assert result.items[0].decision.t_e is None
    assert result.items[1].observations.event_count == 1
    assert result.items[1].decision is None
    assert result.items[1].fusion_result is None


def test_observations_endpoint_exposes_counts_with_the_actual_decision_fields() -> None:
    # Given: the real route and serialization, with only repositories replaced by fixtures.
    app = create_app()
    repositories = replace(
        _repositories(),
        observations=api.StoredObservationReader(
            ObservationConnection(
                [
                    {
                        "run_id": "RUN-20261003-001",
                        "target_host": "WIN-01",
                        "event_type": "network_connection",
                        "event_count": 2,
                    }
                ]
            )
        ),
    )
    app.dependency_overrides[api.summary_repositories] = lambda: repositories

    # When
    response = TestClient(app).get("/analysis-summaries", params={"run_id": "RUN-20261003-001"})

    # Then
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["observations"]["event_type_counts"] == {"network_connection": 2}
    assert item["decision"]["fast_status"] == "not_evaluated"
    assert item["decision"]["t_e"] is None
    assert item["decision"]["fusion_time"] is not None


@pytest.mark.parametrize("invalid_count", [-1, 0, "2"])
def test_invalid_stored_counts_are_a_server_error_not_an_empty_result(invalid_count) -> None:
    # Given
    app = create_app()
    repositories = replace(
        _repositories(),
        observations=api.StoredObservationReader(
            ObservationConnection(
                [
                    {
                        "run_id": "RUN-20261003-001",
                        "target_host": "WIN-01",
                        "event_type": "process_create",
                        "event_count": invalid_count,
                    }
                ]
            )
        ),
    )
    app.dependency_overrides[api.summary_repositories] = lambda: repositories

    # When
    response = TestClient(app).get("/analysis-summaries", params={"run_id": "RUN-20261003-001"})

    # Then
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored analysis summary invalid"}
