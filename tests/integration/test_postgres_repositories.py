import os
from datetime import UTC, datetime
from urllib.parse import unquote, urlparse
from uuid import uuid4

import psycopg
import pytest

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
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"


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
            fusion_result="v0.2",
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
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))
            connection.commit()
