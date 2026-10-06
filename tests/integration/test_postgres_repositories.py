import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.errors import ForeignKeyViolation, UniqueViolation

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
    FusionRuntimeReplaySnapshot,
    FusionRuntimeScoringSnapshot,
    FusionRuntimeStoppingSnapshot,
    FusionRuntimeWindowSnapshot,
)
from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
    PipelineStage,
)
from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectionResult,
    DetectorStatus,
    Severity,
    WinningPath,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.common.models.runtime_snapshot import (
    DecisionRuntimeSnapshot,
    build_decision_runtime_snapshot,
)
from incident_awareness.dashboard.decision_read_model import DashboardDecisionReader
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.persistence import DecisionConflictError, persist_s0_results
from incident_awareness.pipeline.runtime_telemetry import (
    PipelineRuntimeTracker,
    PostgresPipelineRuntimeObserver,
)
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.pipeline.sqs_worker import (
    S3SysmonInput,
    _PostgresSuccessfulReceiptStore,
    _receipt_lock_key,
)
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_migrations
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.result_repository import (
    DecisionIntegrityError,
    DecisionRepository,
    DecisionRuntimeSnapshotRepository,
    DetectionResultRepository,
    FusionResultRepository,
    FusionRuntimeConfigSnapshotRepository,
    FusionStoppingTraceRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"

type _PersistenceCase = tuple[
    S0PipelineArtifacts,
    NormalizedEvidenceArtifacts,
    FusionResult,
    FusionStoppingTrace,
    FusionRuntimeConfigSnapshot,
    FastDetectionAdapterResult,
    DecisionResult,
]


@pytest.fixture
def database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_DATABASE_URL_ENV}이 설정된 PostgreSQL에서만 실행합니다.")

    DatabaseConfig.from_environment({DATABASE_URL_ENV: url})

    database_name = unquote(urlparse(url).path).strip("/").lower()
    is_explicitly_marked = os.environ.get(TEST_DATABASE_MARKER_ENV, "").lower() == "true"
    if "test" not in database_name and not is_explicitly_marked:
        pytest.skip(
            "통합 테스트는 이름에 'test'가 포함된 DB 또는 "
            f"{TEST_DATABASE_MARKER_ENV}=true가 필요합니다."
        )

    return url


def test_postgres_receipt_lock_accepts_safe_object_identity(database_url: str) -> None:
    schema = sql.Identifier(f"sqs_worker_receipt_lock_{uuid4().hex}")
    input_object = S3SysmonInput(
        bucket="worker-inputs",
        key="incoming/first-cycle/sysmon/ING-550e8400-e29b-41d4-a716-446655440000/sysmon.jsonl",
        ingest_id="ING-550e8400-e29b-41d4-a716-446655440000",
        e_tag="worker-object-version",
        sequencer="001",
    )

    with psycopg.connect(database_url) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        connection.commit()
        try:
            connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            apply_migrations(connection)
            connection.commit()

            lock_key = _receipt_lock_key(input_object)
            assert "\x00" not in lock_key
            assert (
                _PostgresSuccessfulReceiptStore(connection).acquire_execution(input_object) is None
            )
        finally:
            connection.rollback()
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
            connection.commit()


def test_postgres_repositories_store_and_restore_first_cycle_contracts(database_url: str) -> None:
    run_id = "RUN-20260912-999"
    event_id = f"evt-{uuid4().hex}"
    decision_id = f"DEC-{uuid4().hex}"
    timestamp = datetime(2026, 9, 12, 1, tzinfo=UTC)

    run = RunMetadata(
        run_id=run_id,
        scenario_id="postgres-integration",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=timestamp,
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
    event = NormalizedEvent(
        event_id=event_id,
        run_id=run_id,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id="WIN-01",
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="153",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            segment_no=1,
            record_no=153,
        ),
    )
    fusion_result = FusionResult(
        run_id=run_id,
        entity_id="WIN-01",
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="v0.2",
        scoring_profile_id="S0",
        scoring_method="temporal_fusion",
        scorer_version="v0.2",
        fusion_episodes=[],
    )
    detection_result = DetectionResult(
        run_id=run_id,
        entity_id="WIN-01",
        detector_time=timestamp,
        detector_status=DetectorStatus.DETECTED,
        detector_id="hayabusa",
        rule_id="RULE-001",
        rule_version="v0.2",
        severity=Severity.HIGH,
    )
    decision_result = DecisionResult(
        run_id=run_id,
        decision_id=decision_id,
        entity_id="WIN-01",
        fast_status=DetectorStatus.DETECTED,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=timestamp,
        t_e=timestamp,
        decision_path=DecisionPath.FAST,
        winning_path=WinningPath.FAST,
        decision_reason="Fast 경로 탐지",
        config_version="v0.2",
    )

    with psycopg.connect(database_url) as connection:
        run_repository = RunRepository(connection)
        event_repository = EventRepository(connection)
        fusion_repository = FusionResultRepository(connection)
        detection_repository = DetectionResultRepository(connection)
        decision_repository = DecisionRepository(connection)

        try:
            run_repository.save(run)
            event_repository.save(event)
            fusion_repository.save(fusion_result)
            detection_repository.save(detection_result)
            decision_repository.save(decision_result)

            assert run_repository.get(run_id) == run
            assert event_repository.get(event_id) == event
            assert fusion_repository.get(run_id, "WIN-01") == fusion_result
            assert detection_repository.get(run_id, "WIN-01") == detection_result
            assert decision_repository.get(decision_id) == decision_result
            assert decision_repository.get_current_head(run_id, "WIN-01") == decision_result
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_stores_updates_and_cascades_fusion_stopping_trace(
    database_url: str,
) -> None:
    # Given
    run_id = "RUN-20260912-995"
    entity_id = "WIN-01"
    timestamp = datetime(2026, 9, 12, 1, tzinfo=UTC)
    run = RunMetadata(
        run_id=run_id,
        scenario_id="postgres-stopping-trace",
        run_type=RunType.ATTACK,
        target_host=entity_id,
        start_time=timestamp,
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
    first_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="v1",
        points=[
            FusionStoppingTracePoint(
                timestamp=timestamp,
                score=0.8,
                persistence_count=1,
                policy_state="off",
            )
        ],
    )
    second_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="v2",
        points=[
            FusionStoppingTracePoint(
                timestamp=timestamp,
                score=0.9,
                persistence_count=1,
                policy_state="off",
            ),
            FusionStoppingTracePoint(
                timestamp=timestamp.replace(second=10),
                score=1.0,
                persistence_count=2,
                policy_state="on",
            ),
        ],
    )

    with psycopg.connect(database_url) as connection:
        run_repository = RunRepository(connection)
        trace_repository = FusionStoppingTraceRepository(connection)

        try:
            # When
            apply_migrations(connection)
            run_repository.save(run)
            trace_repository.save(first_trace)
            stored_first_trace = trace_repository.get(run_id, entity_id)
            trace_repository.save(second_trace)
            stored_second_trace = trace_repository.get(run_id, entity_id)

            # Then
            assert stored_first_trace == first_trace
            assert stored_second_trace == second_trace
            assert stored_second_trace.scoring_config_version == "v2"

            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            assert trace_repository.get(run_id, entity_id) is None
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_runtime_config_repository_round_trip_and_latest_upsert(
    database_url: str,
) -> None:
    # Given
    run_id = "RUN-20261003-909"
    entity_id = f"WIN-{uuid4().hex}"
    decision_id = f"DEC-{uuid4().hex}"
    case = _persistence_case(run_id, entity_id, decision_id)
    artifacts = case[0]
    snapshot_a = case[4].model_copy(
        update={"config_version": "config-a", "model_version": "fusion-model-a"}
    )
    snapshot_b = snapshot_a.model_copy(
        update={
            "config_version": "config-b",
            "model_version": "fusion-model-b",
            "scoring": snapshot_a.scoring.model_copy(
                update={"evidence_types": ("historical_sentinel", "network_connection")}
            ),
            "stopping": snapshot_a.stopping.model_copy(update={"threshold_on": 0.9}),
        }
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        repository = FusionRuntimeConfigSnapshotRepository(connection)
        try:
            RunRepository(connection).save(artifacts.run_metadata)
            repository.save(snapshot_a)
            stored_a = repository.get(run_id, entity_id)

            # When
            repository.save(snapshot_b)
            stored_b = repository.get(run_id, entity_id)
            row_count = connection.execute(
                """
                SELECT count(*)
                FROM fusion_runtime_config_snapshots
                WHERE run_id = %s AND entity_id = %s
                """,
                (run_id, entity_id),
            ).fetchone()

            # Then
            assert stored_a == snapshot_a
            assert stored_b == snapshot_b
            assert row_count == (1,)
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_pipeline_runtime_repository_enforces_latest_state_without_run_row(
    database_url: str,
) -> None:
    # Given
    schema_name = f"pipeline_runtime_repository_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    run_id = "RUN-20261004-901"
    base_time = datetime(2026, 10, 4, 1, tzinfo=UTC)

    with psycopg.connect(database_url) as connection:
        try:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
            connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            apply_migrations(connection)
            repository = PipelineRuntimeStatusRepository(connection)
            assert connection.execute(
                "SELECT count(*) FROM runs WHERE run_id = %s",
                (run_id,),
            ).fetchone() == (0,)

            execution_a_10 = _pipeline_running_status(
                execution_id="execution-a",
                run_id=run_id,
                entity_id="WIN-STALE",
                started_at=base_time,
                updated_at=base_time + timedelta(seconds=10),
                processed_count=1,
            )
            execution_a_20 = execution_a_10.model_copy(
                update={
                    "updated_at": base_time + timedelta(seconds=20),
                    "normalization_processed_count": 2,
                }
            )
            execution_a_15 = execution_a_10.model_copy(
                update={"updated_at": base_time + timedelta(seconds=15)}
            )
            execution_b = _pipeline_running_status(
                execution_id="execution-b",
                run_id=run_id,
                entity_id="WIN-STALE",
                started_at=base_time + timedelta(seconds=30),
                updated_at=base_time + timedelta(seconds=40),
                processed_count=1,
            )
            execution_a_late = execution_a_20.model_copy(
                update={"updated_at": base_time + timedelta(seconds=50)}
            )
            equal_start_execution = execution_b.model_copy(
                update={
                    "execution_id": "execution-c",
                    "updated_at": base_time + timedelta(seconds=45),
                }
            )

            # When
            inserted = repository.save(execution_a_10)
            connection.commit()
            round_tripped = repository.get(run_id, "WIN-STALE")
            newer_same_execution = repository.save(execution_a_20)
            stale_same_execution = repository.save(execution_a_15)
            newer_execution = repository.save(execution_b)
            stale_old_execution = repository.save(execution_a_late)
            equal_start_different_execution = repository.save(equal_start_execution)

            completed_running = _pipeline_running_status(
                execution_id="execution-completed",
                run_id=run_id,
                entity_id="WIN-COMPLETED",
                started_at=base_time,
                updated_at=base_time + timedelta(seconds=10),
            )
            completed = _pipeline_completed_status(
                completed_running,
                updated_at=base_time + timedelta(seconds=20),
            )
            completed_applied = repository.save(completed_running) and repository.save(completed)
            completed_regression = repository.save(
                completed_running.model_copy(
                    update={"updated_at": base_time + timedelta(seconds=30)}
                )
            )

            failed_running = _pipeline_running_status(
                execution_id="execution-failed",
                run_id=run_id,
                entity_id="WIN-FAILED",
                started_at=base_time,
                updated_at=base_time + timedelta(seconds=10),
            )
            failed = _pipeline_failed_status(
                failed_running,
                updated_at=base_time + timedelta(seconds=20),
            )
            failed_applied = repository.save(failed_running) and repository.save(failed)
            failed_regression = repository.save(
                _pipeline_completed_status(
                    failed_running,
                    updated_at=base_time + timedelta(seconds=30),
                )
            )
            connection.commit()

            # Then
            assert inserted is True
            assert round_tripped == execution_a_10
            assert newer_same_execution is True
            assert stale_same_execution is False
            assert newer_execution is True
            assert stale_old_execution is False
            assert equal_start_different_execution is False
            assert repository.get(run_id, "WIN-STALE") == execution_b
            assert completed_applied is True
            assert completed_regression is False
            assert repository.get(run_id, "WIN-COMPLETED") == completed
            assert failed_applied is True
            assert failed_regression is False
            assert repository.get(run_id, "WIN-FAILED") == failed
            assert connection.execute(
                "SELECT count(*) FROM runs WHERE run_id = %s",
                (run_id,),
            ).fetchone() == (0,)
        finally:
            connection.rollback()
            connection.execute("SET search_path TO public")
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
            connection.commit()


def test_postgres_pipeline_runtime_repository_lists_operational_latest_state(
    database_url: str,
) -> None:
    # Given
    schema_name = f"pipeline_runtime_list_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    base_time = datetime(2026, 10, 4, 2, tzinfo=UTC)

    with psycopg.connect(database_url) as connection:
        try:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
            connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            apply_migrations(connection)
            repository = PipelineRuntimeStatusRepository(connection)
            running_b = _pipeline_running_status(
                execution_id="execution-running-b",
                run_id="RUN-20261004-912",
                entity_id="WIN-B",
                started_at=base_time,
                updated_at=base_time + timedelta(seconds=20),
            )
            running_a = _pipeline_running_status(
                execution_id="execution-running-a",
                run_id="RUN-20261004-911",
                entity_id="WIN-A",
                started_at=base_time,
                updated_at=base_time + timedelta(seconds=20),
            )
            failed_newer = _pipeline_failed_status(
                _pipeline_running_status(
                    execution_id="execution-failed-newer",
                    run_id="RUN-20261004-914",
                    entity_id="WIN-D",
                    started_at=base_time,
                    updated_at=base_time + timedelta(seconds=10),
                ),
                updated_at=base_time + timedelta(seconds=40),
            )
            completed_older = _pipeline_completed_status(
                _pipeline_running_status(
                    execution_id="execution-completed-older",
                    run_id="RUN-20261004-913",
                    entity_id="WIN-C",
                    started_at=base_time,
                    updated_at=base_time + timedelta(seconds=10),
                ),
                updated_at=base_time + timedelta(seconds=30),
            )
            for status in (failed_newer, running_b, completed_older, running_a):
                assert repository.save(status) is True
            connection.commit()

            # When
            recent = repository.list_recent(limit=4)
            failed_only = repository.list_recent(
                limit=1,
                status=PipelineRuntimeState.FAILED,
            )
            limited = repository.list_recent(limit=2)

            # Then
            assert [(status.run_id, status.entity_id) for status in recent] == [
                ("RUN-20261004-911", "WIN-A"),
                ("RUN-20261004-912", "WIN-B"),
                ("RUN-20261004-914", "WIN-D"),
                ("RUN-20261004-913", "WIN-C"),
            ]
            assert failed_only == [failed_newer]
            assert limited == [running_a, running_b]
        finally:
            connection.rollback()
            connection.execute("SET search_path TO public")
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
            connection.commit()


def test_postgres_pipeline_runtime_repository_orders_by_running_freshness(
    database_url: str,
) -> None:
    # Given
    schema_name = f"pipeline_runtime_freshness_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    fresh_after = datetime(2026, 10, 4, 4, 10, tzinfo=UTC)
    started_at = fresh_after - timedelta(minutes=20)

    with psycopg.connect(database_url) as connection:
        try:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
            connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            apply_migrations(connection)
            repository = PipelineRuntimeStatusRepository(connection)
            fresh_running = _pipeline_running_status(
                execution_id="execution-active",
                run_id="RUN-20261004-921",
                entity_id="WIN-FRESHNESS",
                started_at=started_at,
                updated_at=fresh_after + timedelta(seconds=30),
            )
            boundary_running = _pipeline_running_status(
                execution_id="execution-boundary",
                run_id="RUN-20261004-922",
                entity_id="WIN-FRESHNESS",
                started_at=started_at,
                updated_at=fresh_after,
            )
            completed_recent = _pipeline_completed_status(
                _pipeline_running_status(
                    execution_id="execution-completed",
                    run_id="RUN-20261004-923",
                    entity_id="WIN-FRESHNESS",
                    started_at=started_at,
                    updated_at=started_at + timedelta(minutes=1),
                ),
                updated_at=fresh_after + timedelta(minutes=1),
            )
            failed_old = _pipeline_failed_status(
                _pipeline_running_status(
                    execution_id="execution-failed",
                    run_id="RUN-20261004-924",
                    entity_id="WIN-FRESHNESS",
                    started_at=started_at,
                    updated_at=started_at + timedelta(minutes=1),
                ),
                updated_at=fresh_after - timedelta(minutes=5),
            )
            stale_running = _pipeline_running_status(
                execution_id="execution-stale",
                run_id="RUN-20261004-925",
                entity_id="WIN-FRESHNESS",
                started_at=started_at,
                updated_at=fresh_after - timedelta(milliseconds=1),
            )
            stale_running_old = _pipeline_running_status(
                execution_id="execution-stale-old",
                run_id="RUN-20261004-926",
                entity_id="WIN-FRESHNESS",
                started_at=started_at,
                updated_at=fresh_after - timedelta(minutes=10),
            )
            for status in (
                stale_running_old,
                failed_old,
                fresh_running,
                stale_running,
                completed_recent,
                boundary_running,
            ):
                assert repository.save(status) is True
            connection.commit()
            snapshot_query = """
                SELECT run_id, entity_id, execution_id, status, updated_at, payload
                FROM pipeline_runtime_status
                ORDER BY run_id, entity_id
                """
            rows_before = connection.execute(snapshot_query).fetchall()

            # When
            recent = repository.list_recent(limit=100, running_fresh_after=fresh_after)
            limited = repository.list_recent(limit=4, running_fresh_after=fresh_after)
            limited_without_cutoff = repository.list_recent(limit=4)
            running_only = repository.list_recent(
                limit=100,
                status=PipelineRuntimeState.RUNNING,
                running_fresh_after=fresh_after,
            )
            completed_only = repository.list_recent(
                limit=100,
                status=PipelineRuntimeState.COMPLETED,
                running_fresh_after=fresh_after,
            )
            failed_only = repository.list_recent(
                limit=100,
                status=PipelineRuntimeState.FAILED,
                running_fresh_after=fresh_after,
            )
            persisted_states = connection.execute(
                """
                SELECT status, count(*)
                FROM pipeline_runtime_status
                GROUP BY status
                ORDER BY status
                """
            ).fetchall()
            rows_after = connection.execute(snapshot_query).fetchall()

            # Then
            assert recent == [
                fresh_running,
                boundary_running,
                completed_recent,
                failed_old,
                stale_running,
                stale_running_old,
            ]
            assert limited == [fresh_running, boundary_running, completed_recent, failed_old]
            assert limited_without_cutoff == [
                fresh_running,
                boundary_running,
                stale_running,
                stale_running_old,
            ]
            assert running_only == [
                fresh_running,
                boundary_running,
                stale_running,
                stale_running_old,
            ]
            assert completed_only == [completed_recent]
            assert failed_only == [failed_old]
            assert persisted_states == [("completed", 1), ("failed", 1), ("running", 4)]
            assert rows_after == rows_before
            assert repository.get(stale_running.run_id, stale_running.entity_id) == stale_running
        finally:
            connection.rollback()
            connection.execute("SET search_path TO public")
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
            connection.commit()


def test_postgres_pipeline_runtime_observer_commits_completed_status(
    database_url: str,
) -> None:
    # Given
    schema_name = f"pipeline_runtime_observer_{uuid4().hex}"
    schema = sql.Identifier(schema_name)
    started_at = datetime(2026, 10, 4, 3, tzinfo=UTC)
    timestamps = iter(
        (
            started_at,
            started_at + timedelta(seconds=1),
            started_at + timedelta(seconds=2),
            started_at + timedelta(seconds=3),
        )
    )

    with psycopg.connect(database_url) as setup_connection:
        setup_connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        setup_connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        apply_migrations(setup_connection)
        setup_connection.commit()

    def connect_telemetry(url: str):
        connection = psycopg.connect(url)
        connection.execute(sql.SQL("SET search_path TO {}").format(schema))
        return connection

    try:
        # When
        with PostgresPipelineRuntimeObserver(
            database_config_factory=lambda: DatabaseConfig(database_url),
            connection_factory=connect_telemetry,
            progress_write_interval_seconds=0.0,
        ) as observer:
            tracker = PipelineRuntimeTracker(
                execution_id=f"execution-{uuid4().hex}",
                run_id="RUN-20261004-915",
                entity_id="WIN-OBSERVER",
                input_total=1,
                started_at=started_at,
                observer=observer,
                clock=lambda: next(timestamps),
            )
            tracker.start_stage(PipelineStage.NORMALIZATION)
            tracker.record_normalization_progress(1)
            tracker.start_stage(PipelineStage.FUSION)
            expected = tracker.complete()

        # Then
        with psycopg.connect(database_url) as verification_connection:
            verification_connection.execute(sql.SQL("SET search_path TO {}").format(schema))
            stored = PipelineRuntimeStatusRepository(verification_connection).get(
                expected.run_id,
                expected.entity_id,
            )
        assert stored == expected
        assert stored is not None
        assert stored.status is PipelineRuntimeState.COMPLETED
        assert stored.normalization_processed_count == stored.input_total
    finally:
        with psycopg.connect(database_url) as cleanup_connection:
            cleanup_connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema))
            cleanup_connection.commit()


def test_postgres_decision_runtime_snapshot_round_trip(database_url: str) -> None:
    # Given
    run, decision, snapshot = _runtime_snapshot_case(
        "RUN-20261003-901",
        f"WIN-{uuid4().hex}",
        f"DEC-{uuid4().hex}",
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        run_repository = RunRepository(connection)
        decision_repository = DecisionRepository(connection)
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)

        try:
            run_repository.save(run)
            decision_repository.save(decision)

            # When
            snapshot_repository.save(snapshot)
            stored_snapshot = snapshot_repository.get(snapshot.decision_id)
            stored_with_decision = snapshot_repository.get_with_decision(snapshot.decision_id)

            # Then
            assert stored_snapshot == snapshot
            assert stored_snapshot is not None
            assert stored_snapshot.detection_result == snapshot.detection_result
            assert stored_snapshot.fusion_result == snapshot.fusion_result
            assert stored_snapshot.fusion_stopping_trace == snapshot.fusion_stopping_trace
            assert stored_with_decision == (decision, snapshot)
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run.run_id,))
            connection.commit()


def test_postgres_rejects_overwriting_decision_runtime_snapshot(database_url: str) -> None:
    # Given
    run_id = "RUN-20261003-902"
    entity_id = f"WIN-{uuid4().hex}"
    decision_id = f"DEC-{uuid4().hex}"
    run, decision, first_snapshot = _runtime_snapshot_case(run_id, entity_id, decision_id)
    _, _, second_snapshot = _runtime_snapshot_case(
        run_id,
        entity_id,
        decision_id,
        trace_score=0.5,
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        run_repository = RunRepository(connection)
        decision_repository = DecisionRepository(connection)
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)

        try:
            run_repository.save(run)
            decision_repository.save(decision)
            snapshot_repository.save(first_snapshot)
            connection.commit()

            # When
            with pytest.raises(UniqueViolation):
                snapshot_repository.save(second_snapshot)
            connection.rollback()

            # Then
            assert second_snapshot != first_snapshot
            assert snapshot_repository.get(decision_id) == first_snapshot
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_rejects_snapshot_for_missing_decision(database_url: str) -> None:
    # Given
    _, _, snapshot = _runtime_snapshot_case(
        "RUN-20261003-903",
        f"WIN-{uuid4().hex}",
        f"DEC-{uuid4().hex}",
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        repository = DecisionRuntimeSnapshotRepository(connection)

        # When
        with pytest.raises(ForeignKeyViolation):
            repository.save(snapshot)
        connection.rollback()

        # Then
        assert repository.get(snapshot.decision_id) is None


def test_postgres_deleting_decision_cascades_runtime_snapshot(database_url: str) -> None:
    # Given
    run, decision, snapshot = _runtime_snapshot_case(
        "RUN-20261003-904",
        f"WIN-{uuid4().hex}",
        f"DEC-{uuid4().hex}",
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)

        try:
            RunRepository(connection).save(run)
            DecisionRepository(connection).save(decision)
            snapshot_repository.save(snapshot)

            # When
            connection.execute(
                "DELETE FROM decisions WHERE decision_id = %s",
                (decision.decision_id,),
            )
            connection.commit()

            # Then
            assert snapshot_repository.get_with_decision(snapshot.decision_id) is None
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run.run_id,))
            connection.commit()


def test_postgres_deleting_run_cascades_runtime_snapshot(database_url: str) -> None:
    # Given
    run, decision, snapshot = _runtime_snapshot_case(
        "RUN-20261003-905",
        f"WIN-{uuid4().hex}",
        f"DEC-{uuid4().hex}",
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)
        RunRepository(connection).save(run)
        DecisionRepository(connection).save(decision)
        snapshot_repository.save(snapshot)

        # When
        connection.execute("DELETE FROM runs WHERE run_id = %s", (run.run_id,))

        # Then
        assert snapshot_repository.get(snapshot.decision_id) is None


def test_postgres_preserves_historical_runtime_snapshot_after_reprocessing(
    database_url: str,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id = "RUN-20261003-906"
    entity_id = f"WIN-{suffix}"
    d1_id = f"DEC-D1-{suffix}"
    d2_id = f"DEC-D2-{suffix}"
    d1_case, d2_case = _historical_persistence_cases(
        run_id,
        entity_id,
        d1_id,
        d2_id,
    )
    _, _, d1_fusion, d1_trace, d1_config, d1_fast, d1_decision = d1_case
    _, _, d2_fusion, d2_trace, d2_config, d2_fast, d2_decision = d2_case

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)
        fusion_repository = FusionResultRepository(connection)
        trace_repository = FusionStoppingTraceRepository(connection)
        config_repository = FusionRuntimeConfigSnapshotRepository(connection)
        detection_repository = DetectionResultRepository(connection)
        decision_repository = DecisionRepository(connection)

        try:
            persist_s0_results(*d1_case, connection=connection)
            snapshot_d1 = snapshot_repository.get(d1_id)
            latest_config_after_d1 = config_repository.get(run_id, entity_id)
            d1_table_counts = _first_cycle_table_counts(connection, run_id)

            # When
            persist_s0_results(*d2_case, connection=connection)
            snapshot_d2 = snapshot_repository.get(d2_id)
            latest_fusion = fusion_repository.get(run_id, entity_id)
            latest_trace = trace_repository.get(run_id, entity_id)
            latest_config = config_repository.get(run_id, entity_id)
            latest_detection = detection_repository.get(run_id, entity_id)
            current_head = decision_repository.get_current_head(run_id, entity_id)
            snapshot_d1_after_reprocessing = snapshot_repository.get(d1_id)

            # Then
            assert snapshot_d1 is not None
            assert snapshot_d1.decision_id == d1_id
            assert snapshot_d1.run_id == run_id
            assert snapshot_d1.entity_id == entity_id
            assert snapshot_d1.detection_result == d1_fast.detection_result
            assert snapshot_d1.fusion_result == d1_fusion
            assert snapshot_d1.fusion_stopping_trace == d1_trace
            assert snapshot_d1.fusion_runtime_config_snapshot == d1_config
            assert latest_config_after_d1 == d1_config
            assert d1_table_counts == (1, 1, 1, 1, 1, 1, 1, 1)

            assert snapshot_d2 is not None
            assert snapshot_d2.decision_id == d2_id
            assert snapshot_d2.detection_result == d2_fast.detection_result
            assert snapshot_d2.fusion_result == d2_fusion
            assert snapshot_d2.fusion_stopping_trace == d2_trace
            assert snapshot_d2.fusion_runtime_config_snapshot == d2_config
            assert snapshot_d1 != snapshot_d2

            assert latest_fusion == d2_fusion
            assert latest_trace == d2_trace
            assert latest_config == d2_config
            assert latest_detection == d2_fast.detection_result
            assert decision_repository.get(d1_id) == d1_decision
            assert decision_repository.get(d2_id) == d2_decision
            assert current_head is not None
            assert current_head.decision_id == d2_id
            assert current_head.supersedes_decision_id == d1_id
            assert snapshot_d1_after_reprocessing == snapshot_d1
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_rolls_back_first_cycle_writes_when_snapshot_write_fails(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id = "RUN-20261003-910"
    entity_id = f"WIN-{suffix}"
    d1_case, _ = _historical_persistence_cases(
        run_id,
        entity_id,
        f"DEC-D1-{suffix}",
        f"DEC-D2-{suffix}",
    )

    def fail_snapshot_save(
        _repository: DecisionRuntimeSnapshotRepository,
        _snapshot: DecisionRuntimeSnapshot,
    ) -> None:
        raise RuntimeError("injected Decision Runtime snapshot write failure")

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        connection.commit()
        try:
            # When
            with monkeypatch.context() as patch:
                patch.setattr(DecisionRuntimeSnapshotRepository, "save", fail_snapshot_save)
                with pytest.raises(RuntimeError, match="injected Decision Runtime snapshot"):
                    persist_s0_results(*d1_case, connection=connection)
            counts_after_failure = _first_cycle_table_counts(connection, run_id)
            persist_s0_results(*d1_case, connection=connection)
            counts_after_retry = _first_cycle_table_counts(connection, run_id)

            # Then
            assert counts_after_failure == (0, 0, 0, 0, 0, 0, 0, 0)
            assert counts_after_retry == (1, 1, 1, 1, 1, 1, 1, 1)
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_dashboard_reader_preserves_current_history_and_snapshots(
    database_url: str,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id = "RUN-20261003-907"
    entity_id = f"WIN-{suffix}"
    d1_id = f"DEC-D1-{suffix}"
    d2_id = f"DEC-D2-{suffix}"
    d3_id = f"DEC-D3-{suffix}"
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
    expected_snapshots = tuple(
        build_decision_runtime_snapshot(
            decision_result=case[6],
            detection_result=case[5].detection_result,
            fusion_result=case[2],
            fusion_stopping_trace=case[3],
            fusion_runtime_config_snapshot=case[4],
        )
        for case in cases
    )

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        reader = DashboardDecisionReader(
            decision_repository=DecisionRepository(connection),
            detection_repository=DetectionResultRepository(connection),
            fusion_repository=FusionResultRepository(connection),
            stopping_trace_repository=FusionStoppingTraceRepository(connection),
            snapshot_repository=DecisionRuntimeSnapshotRepository(connection),
        )

        try:
            for case in cases:
                persist_s0_results(*case, connection=connection)

            # When
            current = reader.get_current(run_id, entity_id)
            history = reader.list_history(run_id, entity_id)
            historical_d1 = reader.get_historical(d1_id)
            historical_d2 = reader.get_historical(d2_id)
            historical_d3 = reader.get_historical(d3_id)

            # Then
            assert current is not None
            assert current.decision == d3_case[6]
            assert current.latest_detection_result == d3_case[5].detection_result
            assert current.latest_fusion_result == d3_case[2]
            assert current.latest_fusion_stopping_trace == d3_case[3]

            assert [decision.decision_id for decision in history] == [d3_id, d2_id, d1_id]

            assert historical_d1 is not None
            assert historical_d1.decision == d1_case[6]
            assert historical_d1.runtime_snapshot == expected_snapshots[0]
            assert historical_d1.runtime_snapshot.detection_result == d1_case[5].detection_result
            assert historical_d1.runtime_snapshot.fusion_result == d1_case[2]
            assert historical_d1.runtime_snapshot.fusion_stopping_trace == d1_case[3]

            assert historical_d2 is not None
            assert historical_d2.decision == d2_case[6]
            assert historical_d2.runtime_snapshot == expected_snapshots[1]
            assert historical_d2.runtime_snapshot.detection_result == d2_case[5].detection_result
            assert historical_d2.runtime_snapshot.fusion_result == d2_case[2]
            assert historical_d2.runtime_snapshot.fusion_stopping_trace == d2_case[3]

            assert historical_d3 is not None
            assert historical_d3.decision == d3_case[6]
            assert historical_d3.runtime_snapshot == expected_snapshots[2]
            assert historical_d3.runtime_snapshot.detection_result == d3_case[5].detection_result
            assert historical_d3.runtime_snapshot.fusion_result == d3_case[2]
            assert historical_d3.runtime_snapshot.fusion_stopping_trace == d3_case[3]

            assert historical_d1.runtime_snapshot.detection_result != d3_case[5].detection_result
            assert historical_d1.runtime_snapshot.fusion_result != d3_case[2]
            assert historical_d1.runtime_snapshot.fusion_stopping_trace != d3_case[3]
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_dashboard_reader_does_not_fallback_for_legacy_decision(
    database_url: str,
) -> None:
    # Given
    suffix = uuid4().hex
    run_id = "RUN-20261003-908"
    entity_id = f"WIN-{suffix}"
    decision_id = f"DEC-LEGACY-{suffix}"
    case = _decision_read_model_persistence_case(
        run_id,
        entity_id,
        decision_id,
        runtime_version=4,
        trace_score=0.7,
    )
    (
        artifacts,
        _,
        fusion_result,
        stopping_trace,
        _,
        fast_result,
        decision_result,
    ) = case

    with psycopg.connect(database_url) as connection:
        apply_migrations(connection)
        decision_repository = DecisionRepository(connection)
        detection_repository = DetectionResultRepository(connection)
        fusion_repository = FusionResultRepository(connection)
        trace_repository = FusionStoppingTraceRepository(connection)
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)
        reader = DashboardDecisionReader(
            decision_repository=decision_repository,
            detection_repository=detection_repository,
            fusion_repository=fusion_repository,
            stopping_trace_repository=trace_repository,
            snapshot_repository=snapshot_repository,
        )

        try:
            RunRepository(connection).save(artifacts.run_metadata)
            detection_repository.save(fast_result.detection_result)
            fusion_repository.save(fusion_result)
            trace_repository.save(stopping_trace)
            decision_repository.save(decision_result)
            connection.commit()

            # When
            current = reader.get_current(run_id, entity_id)
            historical = reader.get_historical(decision_id)
            stored_with_decision = snapshot_repository.get_with_decision(decision_id)

            # Then
            assert current is not None
            assert current.decision == decision_result
            assert current.latest_detection_result == fast_result.detection_result
            assert current.latest_fusion_result == fusion_result
            assert current.latest_fusion_stopping_trace == stopping_trace

            assert historical is not None
            assert historical.decision == decision_result
            assert historical.runtime_snapshot is None
            assert stored_with_decision == (decision_result, None)
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_decision_retry_keeps_runtime_a_until_d2_supersedes_with_b(
    database_url: str,
) -> None:
    # Given
    run_id = "RUN-20260912-994"
    entity_id = f"WIN-{uuid4().hex}"
    decision_id = f"DEC-{uuid4().hex}"
    case = _persistence_case(run_id, entity_id, decision_id)
    (
        artifacts,
        normalized_artifacts,
        fusion_result,
        first_trace,
        runtime_config_snapshot,
        fast_result,
        decision_result,
    ) = case
    fusion_result = fusion_result.model_copy(
        update={
            "scoring_config_version": "config-a",
            "scoring_profile_id": "profile-a",
            "scorer_version": "scorer-a",
        }
    )
    first_trace = first_trace.model_copy(update={"scoring_config_version": "config-a"})
    runtime_config_snapshot = runtime_config_snapshot.model_copy(
        update={
            "config_version": "config-a",
            "scoring": runtime_config_snapshot.scoring.model_copy(
                update={"profile_id": "profile-a", "scorer_version": "scorer-a"}
            ),
        }
    )
    case = (
        artifacts,
        normalized_artifacts,
        fusion_result,
        first_trace,
        runtime_config_snapshot,
        fast_result,
        decision_result,
    )
    second_fusion = fusion_result.model_copy(
        update={
            "scoring_config_version": "config-b",
            "scoring_profile_id": "profile-b",
            "scorer_version": "scorer-b",
        }
    )
    second_trace = first_trace.model_copy(
        update={
            "scoring_config_version": "config-b",
            "points": [
                FusionStoppingTracePoint(
                    timestamp=datetime(2026, 9, 12, 1, tzinfo=UTC),
                    score=0.9,
                    persistence_count=1,
                    policy_state="off",
                )
            ],
        }
    )
    second_config = runtime_config_snapshot.model_copy(
        update={
            "config_version": "config-b",
            "scoring": runtime_config_snapshot.scoring.model_copy(
                update={
                    "scorer_version": "scorer-b",
                    "profile_id": "profile-b",
                    "evidence_types": ("historical_sentinel", "process_start"),
                }
            ),
            "stopping": runtime_config_snapshot.stopping.model_copy(update={"threshold_on": 0.9}),
        }
    )
    retry_fast_result = FastDetectionAdapterResult(
        detection_result=fast_result.detection_result.model_copy(
            update={"rule_version": "retry-v2"}
        ),
        source_hit_ids=fast_result.source_hit_ids,
        selected_source_hit_id=fast_result.selected_source_hit_id,
    )
    d2_decision = decision_result.model_copy(
        update={
            "decision_id": f"DEC-D2-{uuid4().hex}",
            "decision_reason": "D2 supersedes D1 with Runtime bundle B",
            "supersedes_decision_id": decision_id,
        }
    )

    with psycopg.connect(database_url) as connection:
        trace_repository = FusionStoppingTraceRepository(connection)
        detection_repository = DetectionResultRepository(connection)
        fusion_repository = FusionResultRepository(connection)
        config_repository = FusionRuntimeConfigSnapshotRepository(connection)
        snapshot_repository = DecisionRuntimeSnapshotRepository(connection)
        decision_repository = DecisionRepository(connection)
        try:
            apply_migrations(connection)
            persist_s0_results(*case, connection=connection)
            first_snapshot = snapshot_repository.get(decision_id)

            # When
            persist_s0_results(
                artifacts,
                normalized_artifacts,
                second_fusion,
                second_trace,
                second_config,
                retry_fast_result,
                decision_result,
                connection=connection,
            )
            stored_trace = trace_repository.get(run_id, entity_id)
            stored_detection = detection_repository.get(run_id, entity_id)
            stored_fusion = fusion_repository.get(run_id, entity_id)
            stored_config = config_repository.get(run_id, entity_id)
            stored_snapshot = snapshot_repository.get(decision_id)
            snapshot_count = connection.execute(
                "SELECT count(*) FROM decision_runtime_snapshots WHERE decision_id = %s",
                (decision_id,),
            ).fetchone()

            # Then
            assert second_trace != first_trace
            assert second_fusion != fusion_result
            assert second_config != runtime_config_snapshot
            assert retry_fast_result.detection_result != fast_result.detection_result
            assert stored_trace == first_trace
            assert stored_detection == fast_result.detection_result
            assert stored_fusion == fusion_result
            assert stored_config == runtime_config_snapshot
            assert first_snapshot is not None
            assert first_snapshot == build_decision_runtime_snapshot(
                decision_result=decision_result,
                detection_result=fast_result.detection_result,
                fusion_result=fusion_result,
                fusion_stopping_trace=first_trace,
                fusion_runtime_config_snapshot=runtime_config_snapshot,
            )
            assert stored_snapshot == first_snapshot
            assert snapshot_count == (1,)

            # When
            persist_s0_results(
                artifacts,
                normalized_artifacts,
                second_fusion,
                second_trace,
                second_config,
                retry_fast_result,
                d2_decision,
                connection=connection,
            )
            latest_fusion = fusion_repository.get(run_id, entity_id)
            latest_trace = trace_repository.get(run_id, entity_id)
            latest_config = config_repository.get(run_id, entity_id)
            latest_detection = detection_repository.get(run_id, entity_id)
            d1_snapshot_after_d2 = snapshot_repository.get(decision_id)
            d2_snapshot = snapshot_repository.get(d2_decision.decision_id)
            current_head = decision_repository.get_current_head(run_id, entity_id)

            # Then
            assert latest_fusion == second_fusion
            assert latest_trace == second_trace
            assert latest_config == second_config
            assert latest_detection == retry_fast_result.detection_result
            assert d1_snapshot_after_d2 == first_snapshot
            assert d2_snapshot == build_decision_runtime_snapshot(
                decision_result=d2_decision,
                detection_result=retry_fast_result.detection_result,
                fusion_result=second_fusion,
                fusion_stopping_trace=second_trace,
                fusion_runtime_config_snapshot=second_config,
            )
            assert current_head == d2_decision
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def test_postgres_serializes_same_decision_id_across_scopes(database_url: str) -> None:
    suffix = uuid4().hex
    decision_id = f"DEC-{suffix}"
    first_run_id = "RUN-20260912-997"
    second_run_id = "RUN-20260912-998"
    cases = (
        _persistence_case(first_run_id, "WIN-A", decision_id),
        _persistence_case(second_run_id, "WIN-B", decision_id),
    )
    start_barrier = Barrier(len(cases))

    def persist_case(case: _PersistenceCase) -> DecisionIntegrityError | None:
        with psycopg.connect(database_url) as connection:
            start_barrier.wait(timeout=10)
            try:
                persist_s0_results(*case, connection=connection)
            except DecisionIntegrityError as error:
                return error
        return None

    try:
        with ThreadPoolExecutor(max_workers=len(cases)) as executor:
            results = list(executor.map(persist_case, cases))

        errors = [result for result in results if result is not None]
        assert len(errors) == 1
        assert isinstance(errors[0], DecisionIntegrityError)
        assert "different scope" in str(errors[0])
    finally:
        with psycopg.connect(database_url) as connection:
            connection.execute(
                "DELETE FROM runs WHERE run_id IN (%s, %s)",
                (first_run_id, second_run_id),
            )


def test_postgres_serializes_competing_decisions_in_same_scope(database_url: str) -> None:
    suffix = uuid4().hex
    run_id = "RUN-20260912-996"
    entity_id = f"WIN-{suffix}"
    base_decision_id = f"DEC-D1-{suffix}"
    candidate_decision_ids = (f"DEC-D2-{suffix}", f"DEC-D3-{suffix}")
    base_case = _persistence_case(run_id, entity_id, base_decision_id)
    cases = tuple(
        _persistence_case(
            run_id,
            entity_id,
            decision_id,
            supersedes_decision_id=base_decision_id,
        )
        for decision_id in candidate_decision_ids
    )
    start_barrier = Barrier(len(cases))

    def persist_case(case: _PersistenceCase) -> DecisionConflictError | None:
        with psycopg.connect(database_url) as connection:
            start_barrier.wait(timeout=10)
            try:
                persist_s0_results(*case, connection=connection)
            except DecisionConflictError as error:
                return error
        return None

    try:
        with psycopg.connect(database_url) as connection:
            persist_s0_results(*base_case, connection=connection)
            head = DecisionRepository(connection).get_current_head(run_id, entity_id)
            assert head is not None
            assert head.decision_id == base_decision_id

        with ThreadPoolExecutor(max_workers=len(cases)) as executor:
            results = list(executor.map(persist_case, cases))

        errors = [result for result in results if result is not None]
        assert results.count(None) == 1
        assert len(errors) == 1
        assert isinstance(errors[0], DecisionConflictError)
        assert "current Decision head changed" in str(errors[0])

        with psycopg.connect(database_url) as connection:
            head = DecisionRepository(connection).get_current_head(run_id, entity_id)
            assert head is not None
            assert head.decision_id in candidate_decision_ids
            assert head.supersedes_decision_id == base_decision_id
    finally:
        with psycopg.connect(database_url) as connection:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()


def _persistence_case(
    run_id: str,
    entity_id: str,
    decision_id: str,
    *,
    supersedes_decision_id: str | None = None,
) -> _PersistenceCase:
    timestamp = datetime(2026, 9, 12, 1, tzinfo=UTC)
    run = RunMetadata(
        run_id=run_id,
        scenario_id="postgres-concurrency",
        run_type=RunType.ATTACK,
        target_host=entity_id,
        start_time=timestamp,
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
    artifacts = S0PipelineArtifacts(
        run_metadata=run,
        sysmon_records=(SysmonJsonlRecord(record_no=1, data={}),),
        normalization_context=SysmonNormalizationContext(
            run_id=run_id,
            raw_log_id="RAW-CONCURRENCY",
            segment_no=1,
        ),
    )
    fusion_result = FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="v0.2",
        scoring_profile_id="S0",
        scoring_method="simple_score",
        scorer_version="v0.2",
        fusion_episodes=[],
    )
    stopping_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=fusion_result.scoring_config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=timestamp,
                score=0.0,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )
    detection_result = DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )
    fast_result = FastDetectionAdapterResult(
        detection_result=detection_result,
        source_hit_ids=(),
        selected_source_hit_id=None,
    )
    decision_result = DecisionResult(
        run_id=run_id,
        decision_id=decision_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.MISS,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=None,
        t_e=None,
        decision_path=DecisionPath.NONE,
        winning_path=WinningPath.NONE,
        decision_reason="Both evaluated paths missed",
        config_version="parallel-v0.2",
        supersedes_decision_id=supersedes_decision_id,
    )
    return (
        artifacts,
        NormalizedEvidenceArtifacts(events=(), evidences=()),
        fusion_result,
        stopping_trace,
        _runtime_config_snapshot_for(fusion_result),
        fast_result,
        decision_result,
    )


def _decision_read_model_persistence_case(
    run_id: str,
    entity_id: str,
    decision_id: str,
    *,
    runtime_version: int,
    trace_score: float,
    supersedes_decision_id: str | None = None,
) -> _PersistenceCase:
    timestamp = datetime(2026, 10, 3, 1, 0, runtime_version, tzinfo=UTC)
    version = f"read-model-v{runtime_version}"
    artifacts = S0PipelineArtifacts(
        run_metadata=RunMetadata(
            run_id=run_id,
            scenario_id="postgres-decision-read-model",
            run_type=RunType.ATTACK,
            target_host=entity_id,
            start_time=datetime(2026, 10, 3, 1, tzinfo=UTC),
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
        ),
        sysmon_records=(SysmonJsonlRecord(record_no=1, data={}),),
        normalization_context=SysmonNormalizationContext(
            run_id=run_id,
            raw_log_id="RAW-READ-MODEL",
            segment_no=1,
        ),
    )
    fusion_result = FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version=version,
        scoring_profile_id=version,
        scoring_method="simple_score",
        scorer_version=version,
        fusion_episodes=[],
    )
    stopping_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=version,
        points=[
            FusionStoppingTracePoint(
                timestamp=timestamp,
                score=trace_score,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )
    hit_id = f"hit-{runtime_version}-{uuid4().hex}"
    fast_result = _detected_fast_result(
        run_id,
        entity_id,
        timestamp,
        hit_id=hit_id,
    )
    decision_result = DecisionResult(
        run_id=run_id,
        decision_id=decision_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.DETECTED,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=timestamp,
        t_e=timestamp,
        decision_path=DecisionPath.FAST,
        winning_path=WinningPath.FAST,
        decision_reason=f"Runtime {runtime_version} Fast path detected",
        config_version="parallel-v0.2",
        contributing_evidence_ids=[],
        rule_version=fast_result.detection_result.rule_version,
        source_hit_ids=list(fast_result.source_hit_ids),
        selected_source_hit_id=fast_result.selected_source_hit_id,
        supersedes_decision_id=supersedes_decision_id,
    )
    return (
        artifacts,
        NormalizedEvidenceArtifacts(events=(), evidences=()),
        fusion_result,
        stopping_trace,
        _runtime_config_snapshot_for(fusion_result),
        fast_result,
        decision_result,
    )


def _runtime_snapshot_case(
    run_id: str,
    entity_id: str,
    decision_id: str,
    *,
    trace_score: float = 0.0,
) -> tuple[RunMetadata, DecisionResult, DecisionRuntimeSnapshot]:
    timestamp = datetime(2026, 10, 3, 1, tzinfo=UTC)
    run = RunMetadata(
        run_id=run_id,
        scenario_id="postgres-runtime-snapshot",
        run_type=RunType.ATTACK,
        target_host=entity_id,
        start_time=timestamp,
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
    detection_result = DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )
    fusion_result = FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="snapshot-v0.1",
        scoring_profile_id="S0",
        scoring_method="simple_score",
        scorer_version="v0.2",
        fusion_episodes=[],
    )
    fusion_stopping_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=fusion_result.scoring_config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=timestamp,
                score=trace_score,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )
    decision_result = DecisionResult(
        run_id=run_id,
        decision_id=decision_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.MISS,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=None,
        t_e=None,
        decision_path=DecisionPath.NONE,
        winning_path=WinningPath.NONE,
        decision_reason="Both evaluated paths missed",
        config_version="parallel-v0.2",
    )
    snapshot = build_decision_runtime_snapshot(
        decision_result=decision_result,
        detection_result=detection_result,
        fusion_result=fusion_result,
        fusion_stopping_trace=fusion_stopping_trace,
        fusion_runtime_config_snapshot=_runtime_config_snapshot_for(fusion_result),
    )
    return run, decision_result, snapshot


def _historical_persistence_cases(
    run_id: str,
    entity_id: str,
    d1_id: str,
    d2_id: str,
) -> tuple[_PersistenceCase, _PersistenceCase]:
    d1_time = datetime(2026, 10, 3, 1, tzinfo=UTC)
    d2_detector_time = datetime(2026, 10, 3, 1, 0, 10, tzinfo=UTC)
    d2_fusion_time = datetime(2026, 10, 3, 1, 0, 20, tzinfo=UTC)
    artifacts = S0PipelineArtifacts(
        run_metadata=RunMetadata(
            run_id=run_id,
            scenario_id="postgres-historical-runtime-snapshot",
            run_type=RunType.ATTACK,
            target_host=entity_id,
            start_time=d1_time,
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
        ),
        sysmon_records=(SysmonJsonlRecord(record_no=1, data={}),),
        normalization_context=SysmonNormalizationContext(
            run_id=run_id,
            raw_log_id="RAW-HISTORICAL",
            segment_no=1,
        ),
    )
    event_time = d1_time
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(
            NormalizedEvent(
                event_id=f"evt-{uuid4().hex}",
                run_id=run_id,
                timestamp=event_time,
                timestamp_source="event_time",
                event_time=event_time,
                host_id=entity_id,
                source="sysmon",
                source_layer="raw_telemetry",
                source_event_id="1",
                event_type="process_create",
                raw_ref=RawLogReference(
                    raw_log_id="RAW-HISTORICAL",
                    segment_no=1,
                    record_no=1,
                ),
            ),
        ),
        evidences=(),
    )

    d1_fusion = FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="historical-v1",
        scoring_profile_id="historical-profile-v1",
        scoring_method="simple_score",
        scorer_version="historical-scorer-v1",
        fusion_episodes=[],
    )
    d1_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=d1_fusion.scoring_config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=d1_time,
                score=0.1,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )
    d1_detection = DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_time=None,
        detector_status=DetectorStatus.MISS,
        detector_id=None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )
    d1_fast = FastDetectionAdapterResult(
        detection_result=d1_detection,
        source_hit_ids=(),
        selected_source_hit_id=None,
    )
    d1_decision = DecisionResult(
        run_id=run_id,
        decision_id=d1_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.MISS,
        fusion_status=DetectorStatus.MISS,
        fusion_time=None,
        detector_time=None,
        t_e=None,
        decision_path=DecisionPath.NONE,
        winning_path=WinningPath.NONE,
        decision_reason="D1 Runtime paths missed",
        config_version="parallel-v0.2",
        contributing_evidence_ids=[],
        source_hit_ids=[],
        supersedes_decision_id=None,
    )

    d2_evidence_ids = [f"evidence-{uuid4().hex}"]
    d2_hit_id = f"hit-{uuid4().hex}"
    d2_fast = _detected_fast_result(
        run_id,
        entity_id,
        d2_detector_time,
        hit_id=d2_hit_id,
    )
    d2_fusion = FusionResult(
        run_id=run_id,
        entity_id=entity_id,
        fusion_time=d2_fusion_time,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=d2_evidence_ids,
        scoring_config_version="historical-v2",
        scoring_profile_id="historical-profile-v2",
        scoring_method="simple_score",
        scorer_version="historical-scorer-v2",
        fusion_episodes=[
            FusionEpisodeResult(
                episode_id=f"episode-{uuid4().hex}",
                run_id=run_id,
                entity_id=entity_id,
                start_time=d2_fusion_time,
                end_time=None,
                end_reason=None,
                score_at_start=0.8,
                peak_score=0.9,
                contributing_evidence_ids=d2_evidence_ids,
            )
        ],
    )
    d2_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version=d2_fusion.scoring_config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=d2_detector_time,
                score=0.4,
                persistence_count=None,
                policy_state="off",
            ),
            FusionStoppingTracePoint(
                timestamp=d2_fusion_time,
                score=0.8,
                persistence_count=2,
                policy_state="on",
            ),
        ],
    )
    d2_decision = DecisionResult(
        run_id=run_id,
        decision_id=d2_id,
        entity_id=entity_id,
        fast_status=DetectorStatus.DETECTED,
        fusion_status=DetectorStatus.DETECTED,
        fusion_time=d2_fusion_time,
        detector_time=d2_detector_time,
        t_e=d2_detector_time,
        decision_path=DecisionPath.FAST_AND_FUSION,
        winning_path=WinningPath.FAST,
        decision_reason="D2 Fast and Fusion paths detected",
        config_version="parallel-v0.2",
        contributing_evidence_ids=d2_evidence_ids,
        rule_version=d2_fast.detection_result.rule_version,
        source_hit_ids=list(d2_fast.source_hit_ids),
        selected_source_hit_id=d2_fast.selected_source_hit_id,
        supersedes_decision_id=d1_id,
    )

    d1_case: _PersistenceCase = (
        artifacts,
        normalized_artifacts,
        d1_fusion,
        d1_trace,
        _runtime_config_snapshot_for(d1_fusion),
        d1_fast,
        d1_decision,
    )
    d2_case: _PersistenceCase = (
        artifacts,
        normalized_artifacts,
        d2_fusion,
        d2_trace,
        _runtime_config_snapshot_for(d2_fusion),
        d2_fast,
        d2_decision,
    )
    return d1_case, d2_case


def _runtime_config_snapshot_for(
    fusion_result: FusionResult,
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=fusion_result.run_id,
        entity_id=fusion_result.entity_id,
        config_version=fusion_result.scoring_config_version,
        model_version=fusion_result.model_version,
        window=FusionRuntimeWindowSnapshot(window_size_sec=60.0),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10.0),
        scoring=FusionRuntimeScoringSnapshot(
            method="simple_score",
            scorer_version=fusion_result.scorer_version,
            profile_id=fusion_result.scoring_profile_id,
            evidence_types=("process_start",),
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )


def _detected_fast_result(
    run_id: str,
    entity_id: str,
    detector_time: datetime,
    *,
    hit_id: str,
) -> FastDetectionAdapterResult:
    detection_result = DetectionResult(
        run_id=run_id,
        entity_id=entity_id,
        detector_time=detector_time,
        detector_status=DetectorStatus.DETECTED,
        detector_id="hayabusa",
        rule_id="RULE-HISTORICAL",
        rule_version="v0.2",
        severity=Severity.HIGH,
    )
    return FastDetectionAdapterResult(
        detection_result=detection_result,
        source_hit_ids=(hit_id,),
        selected_source_hit_id=hit_id,
    )


def _first_cycle_table_counts(
    connection: psycopg.Connection[tuple[object, ...]],
    run_id: str,
) -> tuple[object, ...] | None:
    return connection.execute(
        """
        SELECT
            (SELECT count(*) FROM runs WHERE run_id = %s),
            (SELECT count(*) FROM events WHERE run_id = %s),
            (SELECT count(*) FROM fusion_results WHERE run_id = %s),
            (SELECT count(*) FROM fusion_stopping_traces WHERE run_id = %s),
            (SELECT count(*) FROM fusion_runtime_config_snapshots WHERE run_id = %s),
            (SELECT count(*) FROM detection_results WHERE run_id = %s),
            (SELECT count(*) FROM decisions WHERE run_id = %s),
            (SELECT count(*) FROM decision_runtime_snapshots WHERE run_id = %s)
        """,
        (run_id,) * 8,
    ).fetchone()


def _pipeline_running_status(
    *,
    execution_id: str,
    run_id: str,
    entity_id: str,
    started_at: datetime,
    updated_at: datetime,
    processed_count: int = 1,
) -> PipelineRuntimeStatus:
    return PipelineRuntimeStatus(
        execution_id=execution_id,
        run_id=run_id,
        entity_id=entity_id,
        status=PipelineRuntimeState.RUNNING,
        current_stage=PipelineStage.NORMALIZATION,
        input_total=3,
        normalization_processed_count=processed_count,
        started_at=started_at,
        stage_started_at=started_at,
        updated_at=updated_at,
        completed_at=None,
        failed_stage=None,
    )


def _pipeline_completed_status(
    running: PipelineRuntimeStatus,
    *,
    updated_at: datetime,
) -> PipelineRuntimeStatus:
    return running.model_copy(
        update={
            "status": PipelineRuntimeState.COMPLETED,
            "current_stage": None,
            "normalization_processed_count": running.input_total,
            "stage_started_at": None,
            "updated_at": updated_at,
            "completed_at": updated_at,
            "failed_stage": None,
        }
    )


def _pipeline_failed_status(
    running: PipelineRuntimeStatus,
    *,
    updated_at: datetime,
) -> PipelineRuntimeStatus:
    return running.model_copy(
        update={
            "status": PipelineRuntimeState.FAILED,
            "current_stage": None,
            "stage_started_at": None,
            "updated_at": updated_at,
            "completed_at": None,
            "failed_stage": PipelineStage.FUSION,
        }
    )
