import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import (
    DecisionPath,
    DecisionResult,
    DetectionResult,
    DetectorStatus,
    Severity,
    WinningPath,
)
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.persistence import DecisionConflictError, persist_s0_results
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.result_repository import (
    DecisionIntegrityError,
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"

type _PersistenceCase = tuple[
    S0PipelineArtifacts,
    NormalizedEvidenceArtifacts,
    FusionResult,
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


def test_postgres_serializes_same_decision_id_across_scopes(database_url: str) -> None:
    suffix = uuid4().hex
    decision_id = f"DEC-{suffix}"
    first_run_id = f"RUN-A-{suffix}"
    second_run_id = f"RUN-B-{suffix}"
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
    run_id = f"RUN-{suffix}"
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
        scoring_method="temporal_fusion",
        scorer_version="v0.2",
        fusion_episodes=[],
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
        fast_result,
        decision_result,
    )
