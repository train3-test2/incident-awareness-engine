"""Real PostgreSQL run of the Role3 -> Role2 -> Role1 wiring with synthetic v0.2 inputs."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest
import test_r1_candidate_generation_seal as seal_fixture
import test_r1_incremental_availability_v02 as fixture
from psycopg import sql
from test_r1_operational_wiring import _Harness, _Ledger

from incident_awareness.common.models.r1_stream import R1SourceWatermark
from incident_awareness.pipeline import r1_stream_wiring as wiring
from incident_awareness.pipeline.persistence import R1RunRegistrationError
from incident_awareness.pipeline.r1_fusion_handoff import consume_published_r1_evidence
from incident_awareness.pipeline.r1_incremental_consumer import R1IncrementalConsumerError
from incident_awareness.storage import migrate
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1StreamDeliveryRepository,
)
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
    FusionStoppingTraceRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository


@pytest.fixture
def connection() -> Iterator[psycopg.Connection]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for real PostgreSQL R1 wiring tests")
    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})
    database_name = unquote(urlparse(url).path).strip("/").lower()
    if (
        "test" not in database_name
        and os.environ.get("INCIDENT_AWARENESS_TEST_DATABASE", "").lower() != "true"
    ):
        pytest.skip("a test database or INCIDENT_AWARENESS_TEST_DATABASE=true is required")
    schema = sql.Identifier(f"r1_wiring_test_{uuid4().hex}")
    database = psycopg.connect(url, autocommit=False, connect_timeout=2)
    try:
        database.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        database.execute(sql.SQL("SET search_path TO {}").format(schema))
        migrate.apply_migrations(database)
        database.commit()
        yield database
    finally:
        database.rollback()
        database.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
        database.commit()
        database.close()


def _count(connection: psycopg.Connection, table: str) -> int:
    row = connection.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table)))
    return row.fetchone()[0]


def test_real_ledger_feeds_role2_and_role1_persists_r1_results(
    connection: psycopg.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: Role3 commits the chunks in real PostgreSQL. The real watermark save fails
    # (see the strict xfail below), so only the synthetic watermark/close admission uses
    # the in-memory Role3 double. Role2 and Role1 still use the real ledger and tables.
    harness = _Harness(tmp_path, monkeypatch, connection=connection)
    harness.consume_all_chunks()
    # The Run owner registers the Run; the R1 runtime below must not rewrite it.
    RunRepository(connection).save(fixture._run_metadata())
    connection.commit()
    registered = connection.execute("SELECT metadata, created_at FROM runs").fetchall()
    close_ledger = _Ledger()
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda _conn: close_ledger)
    export = harness.publish_close_through_role3()
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", R1StreamDeliveryRepository)

    # When
    harness.consumer().consume_available()
    _, published = harness.finalize(tmp_path, export)
    result = consume_published_r1_evidence(
        harness.state_root,
        output_directory=harness.fusion_output,
        run_metadata=fixture._run_metadata(),
        trust=harness.handoff_trust(export),
        config=fixture._config(),
        connection=connection,
        availability_clock=harness.clock,
    )
    retry = consume_published_r1_evidence(
        harness.state_root,
        output_directory=harness.fusion_output,
        run_metadata=fixture._run_metadata(),
        trust=harness.handoff_trust(export),
        config=fixture._config(),
        connection=connection,
        availability_clock=harness.clock,
    )

    # Then: the real ledger held every chunk once and Role2 replays did not add rows.
    assert _count(connection, "r1_stream_chunks") == len(harness.chunks)
    assert _count(connection, "r1_stream_run_closes") == 0
    assert published.snapshot.status == "finalized"

    # Then: results are readable through the existing repositories.
    stored_fusion = FusionResultRepository(connection).get(fixture._RUN_ID, fixture._HOST_ID)
    stored_trace = FusionStoppingTraceRepository(connection).get(fixture._RUN_ID, fixture._HOST_ID)
    stored_fast = DetectionResultRepository(connection).get(fixture._RUN_ID, fixture._HOST_ID)
    stored_decision = DecisionRepository(connection).get(result.decision_result.decision_id)
    assert stored_fusion == result.fusion_result
    assert stored_fusion.fusion_status == "detected"
    assert stored_trace is not None and stored_trace.points
    assert stored_fast is not None and stored_fast.detector_status.value == "not_evaluated"
    assert stored_decision == result.decision_result
    assert stored_decision.t_e is None
    assert retry.already_consumed is True
    assert connection.execute("SELECT metadata, created_at FROM runs").fetchall() == registered
    assert _count(connection, "decisions") == 1
    assert _count(connection, "decision_runtime_snapshots") == 1


def test_real_ledger_rejects_acked_chunk_without_commit_and_rolls_back(
    connection: psycopg.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: an ack exists, but Role3 never committed the chunk.
    harness = _Harness(tmp_path, monkeypatch, connection=connection)
    harness.write_run_started()
    harness.write_ack(harness.publish_chunk(harness.chunks[0]))
    consumer = harness.consumer()

    # When / Then
    with pytest.raises(R1IncrementalConsumerError, match="no committed Role3 ledger entry"):
        consumer.consume_available()
    assert _count(connection, "r1_stream_chunks") == 0
    assert _count(connection, "r1_stream_events") == 0
    assert not consumer.checkpoint_path.exists()


@pytest.mark.xfail(
    raises=psycopg.errors.IndeterminateDatatype,
    strict=True,
    reason="Role3 watermark lock passes untyped parameters to concat_ws",
)
def test_real_role3_watermark_save(connection: psycopg.Connection) -> None:
    # Given
    final = seal_fixture._run_closed().final_watermarks[0]
    watermark = R1SourceWatermark(
        schema="r1-incremental-stream",
        contract_version="v0.1",
        message_type="source_watermark",
        emitted_at=seal_fixture._run_closed().emitted_at,
        **final.model_dump(),
    )

    # When / Then
    R1StreamDeliveryRepository(connection).save_watermark(watermark, content_sha256="a" * 64)


def test_real_r1_persistence_refuses_unregistered_run(
    connection: psycopg.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: no owner-registered Run row exists.
    harness = _Harness(tmp_path, monkeypatch, connection=connection)
    harness.consume_all_chunks()
    connection.commit()
    close_ledger = _Ledger()
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", lambda _conn: close_ledger)
    export = harness.publish_close_through_role3()
    monkeypatch.setattr(wiring, "R1StreamDeliveryRepository", R1StreamDeliveryRepository)
    harness.finalize(tmp_path, export)

    # When / Then
    with pytest.raises(R1RunRegistrationError):
        consume_published_r1_evidence(
            harness.state_root,
            output_directory=harness.fusion_output,
            run_metadata=fixture._run_metadata(),
            trust=harness.handoff_trust(export),
            config=fixture._config(),
            connection=connection,
            availability_clock=harness.clock,
        )
    assert _count(connection, "runs") == 0
    assert _count(connection, "fusion_results") == 0
    assert _count(connection, "decisions") == 0
