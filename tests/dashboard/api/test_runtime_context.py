"""Bounded exact scopes and latest persisted Pipeline selection, not host liveness."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.runtime_context import (
    RuntimeContextQuery,
    context_repository,
    read_context,
)
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)

from .test_pipeline_runtime import _completed_status, _failed_status, _running_status


class Repository:
    def __init__(self, running=None, terminal=None, scopes=()):
        self.running, self.terminal, self.scopes = running, terminal, list(scopes)
        self.calls = []

    def list_recent(self, *, limit, status=None):
        self.calls.append(("recent", limit, status))
        return (
            [self.running]
            if self.running and status
            else []
            if status
            else [self.terminal]
            if self.terminal
            else []
        )

    def list_for_scopes(self, scopes):
        self.calls.append(("scopes", scopes))
        return self.scopes


@pytest.mark.parametrize("status", ["running", "stale", "completed", "failed", "empty"])
def test_pipeline_prefers_actual_running_even_stale_else_latest_terminal(status):
    # Given
    now = datetime(2026, 10, 4, 1, 1, tzinfo=UTC)
    running = _running_status() if status in {"running", "stale"} else None
    if status == "stale":
        now += timedelta(hours=1)
    terminal = (
        _failed_status()
        if status == "failed"
        else _completed_status()
        if status != "empty"
        else None
    )
    repository = Repository(running=running, terminal=terminal)
    # When
    result = read_context(repository, (), now=now)
    # Then
    assert (
        result.pipeline is None
        if status == "empty"
        else result.pipeline.status.value == ("running" if running else status)
    )
    if running:
        assert result.pipeline.is_stale == (status == "stale")
        assert len(repository.calls) == 2  # running lookup + bounded scopes (no terminal lookup)


def test_twenty_exact_scopes_use_one_bounded_lookup_and_keep_missing_distinct():
    # Given
    stored = _completed_status()
    scopes = ((stored.run_id, stored.entity_id),) + tuple((f"RUN-{i}", "HOST") for i in range(19))
    repository = Repository(terminal=stored, scopes=[stored])
    # When
    result = read_context(repository, scopes, now=datetime.now(UTC))
    # Then
    assert len(result.scopes) == 20 and result.scopes[0].runtime.execution_id == stored.execution_id
    assert all(item.runtime is None for item in result.scopes[1:])
    assert len(repository.calls) == 3 and repository.calls[-1] == ("scopes", scopes)


@pytest.mark.parametrize(
    "query",
    [
        "run_id=R",
        "run_id=R&entity_id=H&entity_id=OTHER",
        "run_id=%20R&entity_id=H",
        "run_id=R&entity_id=H&run_id=R&entity_id=H",
        "&".join(f"run_id=R{i}&entity_id=H" for i in range(22)),
    ],
)
def test_invalid_scopes_are_rejected_before_opening_a_connection(query, monkeypatch):
    # Given
    app = create_app()
    calls = []
    monkeypatch.setattr(
        "incident_awareness.dashboard.api.runtime_context.psycopg.connect",
        lambda *a, **k: calls.append(True),
    )
    # When
    response = TestClient(app).get("/operations/runtime-context?" + query)
    # Then: Depends override doesn't validate; route's own query still rejects.
    assert response.status_code == 422
    assert calls == []


def test_context_route_returns_exact_scopes_without_affecting_existing_runtime_route():
    # Given
    stored = _completed_status()
    app = create_app()
    app.dependency_overrides[context_repository] = lambda: Repository(
        terminal=stored, scopes=[stored]
    )
    # When
    response = TestClient(app).get(
        f"/operations/runtime-context?run_id={stored.run_id}&entity_id={stored.entity_id}"
    )
    # Then
    assert response.status_code == 200
    assert response.json()["pipeline"]["execution_id"] == stored.execution_id


def test_repository_scope_sql_is_one_pk_join_without_commit_or_entity_cartesian_product():
    # Given
    stored = _completed_status()

    class Connection:
        def __init__(self):
            self.queries = []

        def execute(self, query, params):
            self.queries.append((query, params))
            return type("Cursor", (), {"fetchall": lambda _: [(stored.model_dump(mode="json"),)]})()

    connection = Connection()
    scopes = ((stored.run_id, stored.entity_id), ("RUN-OTHER", "HOST-OTHER"))
    # When
    result = PipelineRuntimeStatusRepository(connection).list_for_scopes(scopes)
    # Then
    assert result == [stored] and len(connection.queries) == 1
    sql, params = connection.queries[0]
    assert "unnest(%s::text[], %s::text[])" in sql and "runtime.entity_id = scope.entity_id" in sql
    assert params == ([scopes[0][0], scopes[1][0]], [scopes[0][1], scopes[1][1]])
    assert PipelineRuntimeStatusRepository(connection).list_for_scopes(()) == []
    assert len(connection.queries) == 1


def test_query_accepts_same_run_distinct_entities_not_a_run_only_lookup():
    # Given / When
    query = RuntimeContextQuery(run_id=["R", "R"], entity_id=["A", "B"])
    # Then
    assert query.entity_id == ["A", "B"]
