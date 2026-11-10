"""Evidence Read API against an owned disposable PostgreSQL database (fixture data only)."""

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.dashboard.api import dependencies
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.pipeline.r1_production import (
    R1ProductionConfig,
    generate_r1_production_archive,
)
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublicationRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

FIXTURE = Path(__file__).parents[1] / "fixtures" / "evidence" / "r1_pair004_selector_events.jsonl"
CONFIG = R1ProductionConfig(
    family_id="remote_management",
    approved_policy_id="r1-remote-management-approved-lineage",
    approved_policy_version="v0.3",
    approved_policy_config_hash="b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2",
    archive_bucket="fixture-bucket",
)


@pytest.fixture
def database_url() -> str:
    value = os.environ.get("EVIDENCE_DISPOSABLE_DATABASE_URL")
    if not value:
        pytest.skip("An explicitly provisioned disposable Evidence DB is required")
    info = conninfo_to_dict(value)
    if not re.fullmatch(r"iae_evidence_test_[a-f0-9]{32}", info.get("dbname", "")):
        pytest.fail("Refusing Evidence writes outside an owned disposable database", pytrace=False)
    if info.get("host") != "127.0.0.1" or info.get("port") != "54329":
        pytest.fail("Refusing nonlocal PostgreSQL test target", pytrace=False)
    return value


@pytest.fixture
def connection(database_url):
    schema = "evidence_test_" + uuid4().hex
    with psycopg.connect(database_url, autocommit=False, connect_timeout=2) as conn:
        assert conn.info.dbname.startswith("iae_evidence_test_")
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        assert apply_migrations(conn)[-1] == "015_raw_artifact_retention"
        conn.commit()
        try:
            yield conn
        finally:
            conn.rollback()
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
            conn.commit()


def _run(run_id: str, target_host: str) -> RunMetadata:
    return RunMetadata(
        run_id=run_id,
        scenario_id="dashboard-evidence-integration",
        run_type=RunType.ATTACK,
        target_host=target_host,
        start_time=datetime(2026, 10, 8, 17, tzinfo=UTC),
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.3",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def _store_fixture_run(conn, tmp_path, *, status="published"):
    """Real Role2 writer output from the repository fixture, stored through real repositories."""
    events = tuple(
        NormalizedEvent.model_validate(json.loads(line))
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
    )
    run_id = events[0].run_id
    RunRepository(conn).save(_run(run_id, events[0].host_id))
    for event in events:
        EventRepository(conn).save(event)
    generated = generate_r1_production_archive(
        events, run_id=run_id, output_directory=tmp_path / "r1", config=CONFIG
    )
    archives = R1ArchivePublicationRepository(conn)
    archives.save_pending(generated.to_publication())
    if status != "pending":
        archives.update_status(run_id, status=status)
    conn.commit()
    return run_id, events


class Api:
    """TestClient plus the schema the real dependency's own connection is pointed at."""

    def __init__(self, schema: str) -> None:
        self.schema = schema
        self.sessions: list[tuple[psycopg.Connection, tuple[object, ...]]] = []
        self.client = TestClient(create_app())

    def get(self, path: str):
        return self.client.get(path)


@pytest.fixture
def api(connection, database_url, monkeypatch):
    """The real dependency on its own read-only connection, scoped to the test schema."""
    state = Api(connection.execute("SELECT current_schema()").fetchone()[0])
    original_connect = psycopg.connect
    monkeypatch.setattr(
        dependencies.DatabaseConfig, "from_environment", lambda: DatabaseConfig(database_url)
    )

    def connect(url, **kwargs):
        kwargs["options"] += f" -c search_path={state.schema}"
        conn = original_connect(url, **kwargs)
        state.sessions.append(
            (
                conn,
                conn.execute(
                    "SELECT current_setting('transaction_read_only'),"
                    " current_setting('statement_timeout'), current_setting('TimeZone')"
                ).fetchone(),
            )
        )
        return conn

    monkeypatch.setattr(dependencies.psycopg, "connect", connect)
    return state


def test_published_archive_round_trips_through_real_sql_read_only(connection, api, tmp_path):
    # Given
    run_id, events = _store_fixture_run(connection, tmp_path)
    # When
    response = api.get(f"/runs/{run_id}/evidences")
    # Then
    body = response.json()
    assert response.status_code == 200
    assert (body["availability"], body["total"]) == ("published", 2)
    stored_ids = {event.event_id for event in events}
    for item in body["items"]:
        assert all(ref["stored"] and ref["event_id"] in stored_ids for ref in item["events"])
        assert item["entity_id"] == events[0].host_id
    session, settings = api.sessions[0]
    assert settings == ("on", "5s", "UTC")
    assert session.closed
    assert "fixture-bucket" not in response.text


@pytest.mark.parametrize("status", ["pending", "retryable", "failed"])
def test_unpublished_archive_is_withheld(connection, api, tmp_path, status):
    # Given
    run_id, _ = _store_fixture_run(connection, tmp_path, status=status)
    # When
    body = api.get(f"/runs/{run_id}/evidences").json()
    # Then
    assert (body["availability"], body["archive_status"], body["items"]) == (
        "not_published",
        status,
        [],
    )


def test_run_without_archive_and_unknown_run_are_distinct(connection, api):
    # Given
    RunRepository(connection).save(_run("RUN-20261018-001", "HOST-A"))
    connection.commit()
    # When
    no_archive = api.get("/runs/RUN-20261018-001/evidences")
    unknown = api.get("/runs/RUN-20261018-999/evidences")
    # Then
    assert no_archive.json()["availability"] == "no_archive"
    assert (unknown.status_code, unknown.json()) == (404, {"detail": "Run not found"})


def test_bytes_changed_in_storage_fail_closed(connection, api, tmp_path):
    # Given
    run_id, _ = _store_fixture_run(connection, tmp_path)
    connection.execute(
        "UPDATE r1_archive_publications SET evidence_content = evidence_content || '\\x0a'::bytea"
        " WHERE run_id = %s",
        (run_id,),
    )
    connection.commit()
    # When
    response = api.get(f"/runs/{run_id}/evidences")
    # Then
    assert (response.status_code, response.json()) == (
        500,
        {"detail": "Stored Evidence archive is invalid"},
    )


def test_stored_event_host_contradicting_evidence_entity_fails_closed(connection, api, tmp_path):
    # Given
    run_id, events = _store_fixture_run(connection, tmp_path)
    connection.execute(
        "UPDATE events SET host_id = 'OTHER-HOST' WHERE event_id = %s", (events[-1].event_id,)
    )
    connection.commit()
    # When
    response = api.get(f"/runs/{run_id}/evidences")
    # Then
    assert response.json() == {"detail": "Stored Evidence provenance is inconsistent"}


def test_unstored_event_reference_is_flagged(connection, api, tmp_path):
    # Given
    run_id, events = _store_fixture_run(connection, tmp_path)
    connection.execute("DELETE FROM events WHERE event_id = %s", (events[-1].event_id,))
    connection.commit()
    # When
    body = api.get(f"/runs/{run_id}/evidences").json()
    # Then
    assert body["unstored_event_reference_count"] == 1
    flagged = [ref for item in body["items"] for ref in item["events"] if not ref["stored"]]
    assert flagged == [{"event_id": events[-1].event_id, "stored": False}]


def test_missing_archive_table_is_reported_as_not_provisioned(connection, api):
    # Given: a schema where no migrations were applied.
    empty_schema = "evidence_empty_" + uuid4().hex
    connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(empty_schema)))
    connection.commit()
    api.schema = empty_schema
    try:
        # When
        response = api.get("/runs/RUN-20261018-001/evidences")
        # Then
        assert (response.status_code, response.json()) == (
            503,
            {"detail": "Evidence archive storage is not provisioned"},
        )
    finally:
        connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(empty_schema)))
        connection.commit()
