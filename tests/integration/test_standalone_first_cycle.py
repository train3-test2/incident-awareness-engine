"""PostgreSQL E2E coverage for generated standalone Sysmon artifacts."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse

import psycopg
import pytest

from incident_awareness.common.models.run import RunType
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.fusion import run_s0_fusion
from incident_awareness.pipeline.hybrid import combine_parallel_decision
from incident_awareness.pipeline.persistence import persist_s0_results
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts
from incident_awareness.pipeline.standalone import (
    build_default_standalone_fast_detection,
    build_run_metadata_from_sysmon_jsonl,
    build_sysmon_artifacts_from_jsonl,
    select_standalone_execution_config,
)
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig
from incident_awareness.storage.migrate import apply_first_cycle_migration

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
TEST_DATABASE_MARKER_ENV = "INCIDENT_AWARENESS_TEST_DATABASE"
RUN_ID = "RUN-20261003-901"
ENTITY_ID = "WIN-01"


@pytest.fixture
def database_url() -> str:
    """Require an explicitly designated PostgreSQL test database."""
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


def test_generated_standalone_artifacts_flow_through_pipeline_and_postgres(
    tmp_path: Path,
    database_url: str,
) -> None:
    source_jsonl = tmp_path / "source.jsonl"
    _write_sysmon_jsonl(source_jsonl)
    output_root = tmp_path / RUN_ID
    telemetry_dir = output_root / "telemetry"
    telemetry_dir.mkdir(parents=True)
    sysmon_jsonl = telemetry_dir / "sysmon-0001.jsonl"
    sysmon_jsonl.write_bytes(source_jsonl.read_bytes())

    metadata = build_run_metadata_from_sysmon_jsonl(
        source_jsonl,
        run_id=RUN_ID,
        scenario_id="S0",
        run_type=RunType.ATTACK,
        target_host=ENTITY_ID,
    )
    generated = build_sysmon_artifacts_from_jsonl(sysmon_jsonl, run_id=RUN_ID)
    metadata_path = output_root / "run_metadata.json"
    manifest_path = output_root / "manifest.json"
    metadata_path.write_text(metadata.model_dump_json(), encoding="utf-8")
    manifest_path.write_text(json.dumps(generated.manifest), encoding="utf-8")

    execution_config = select_standalone_execution_config()
    inputs = PipelineInputs(
        run_metadata_path=metadata_path,
        manifest_path=manifest_path,
        sysmon_jsonl_path=sysmon_jsonl,
        fast_hits_path=output_root / "unused-fast-hits.jsonl",
        fast_trace_path=output_root / "unused-fast-trace.json",
        fast_selection_path=output_root / "unused-fast-selection.json",
        fusion_config_path=execution_config.fusion_config_path,
        entity_id=ENTITY_ID,
        decision_id=f"DEC-{RUN_ID}",
        decision_config_version=execution_config.decision_config_version,
    )

    artifacts = load_s0_pipeline_artifacts(inputs)
    normalized = normalize_sysmon_and_extract_evidence(artifacts)
    fusion = run_s0_fusion(inputs, artifacts, normalized)
    fast = build_default_standalone_fast_detection(run_id=RUN_ID, entity_id=ENTITY_ID)
    decision = combine_parallel_decision(inputs, fast, fusion)

    with psycopg.connect(database_url, autocommit=False) as connection:
        apply_first_cycle_migration(connection)
        connection.commit()
        connection.execute("DELETE FROM runs WHERE run_id = %s", (RUN_ID,))
        connection.commit()
        try:
            persist_s0_results(artifacts, normalized, fusion, fast, decision, connection=connection)

            assert _table_count(connection, "runs") == 1
            assert _table_count(connection, "events") == 3
            assert _table_count(connection, "fusion_results") == 1
            assert _table_count(connection, "detection_results") == 1
            assert _table_count(connection, "decisions") == 1
            assert fusion.fusion_status == "detected"
            assert fast.detection_result.detector_status == "not_evaluated"
            assert decision.decision_path is None
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (RUN_ID,))
            connection.commit()


def _table_count(connection: psycopg.Connection[tuple[object, ...]], table_name: str) -> int:
    return connection.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE run_id = %s", (RUN_ID,)
    ).fetchone()[0]


def _write_sysmon_jsonl(path: Path) -> None:
    start = datetime(2026, 10, 3, tzinfo=UTC)
    records = [
        {
            "RecordId": 1,
            "EventId": 1,
            "TimeCreated": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "Computer": ENTITY_ID,
            "EventData": {
                "UtcTime": "2026-10-03 00:00:00.000",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": "4242",
                "CommandLine": "powershell.exe -EncodedCommand VwByAGkAdABlAA==",
            },
        },
        {
            "RecordId": 2,
            "EventId": 3,
            "TimeCreated": (start + timedelta(seconds=10))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "Computer": ENTITY_ID,
            "EventData": {
                "UtcTime": "2026-10-03 00:00:10.000",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": "4242",
                "Protocol": "tcp",
                "SourceIp": "192.168.1.10",
                "SourcePort": "50000",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "443",
            },
        },
        {
            "RecordId": 3,
            "EventId": 3,
            "TimeCreated": (start + timedelta(seconds=660))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "Computer": ENTITY_ID,
            "EventData": {
                "UtcTime": "2026-10-03 00:11:00.000",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": "4242",
                "DestinationPort": "443",
            },
        },
    ]
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
