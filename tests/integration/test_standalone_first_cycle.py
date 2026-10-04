"""PostgreSQL E2E coverage for generated standalone Sysmon artifacts."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlparse

import psycopg
import pytest

from incident_awareness.pipeline.standalone import (
    prepare_standalone_run,
    run_prepared_standalone_run,
)
from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig

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
    output_dir = tmp_path / RUN_ID
    prepared = prepare_standalone_run(
        sysmon_jsonl_path=source_jsonl,
        output_dir=output_dir,
        run_id=RUN_ID,
        decision_id=f"DEC-{RUN_ID}",
        scenario_id="S0",
        target_host=ENTITY_ID,
    )

    assert prepared.inputs.run_metadata_path.is_file()
    assert prepared.inputs.manifest_path.is_file()
    assert prepared.inputs.sysmon_jsonl_path.is_file()

    with psycopg.connect(database_url, autocommit=False) as connection:
        _require_first_cycle_schema(connection)
        connection.execute("DELETE FROM runs WHERE run_id = %s", (RUN_ID,))
        connection.commit()
        try:
            summary = run_prepared_standalone_run(prepared, connection=connection)

            assert _table_count(connection, "runs") == 1
            assert _table_count(connection, "events") == 3
            assert _table_count(connection, "fusion_results") == 1
            assert _table_count(connection, "fusion_stopping_traces") == 1
            assert _table_count(connection, "fusion_runtime_config_snapshots") == 1
            assert _table_count(connection, "detection_results") == 1
            assert _table_count(connection, "decisions") == 1
            assert summary.fusion_status == "detected"
            assert summary.detector_status == "not_evaluated"
            assert summary.decision_path is None
        finally:
            connection.execute("DELETE FROM runs WHERE run_id = %s", (RUN_ID,))
            connection.commit()


def _table_count(connection: psycopg.Connection[tuple[object, ...]], table_name: str) -> int:
    return connection.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE run_id = %s", (RUN_ID,)
    ).fetchone()[0]


def _require_first_cycle_schema(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    required_tables = (
        "runs",
        "fusion_stopping_traces",
        "fusion_runtime_config_snapshots",
    )
    missing_tables = [
        table_name
        for table_name in required_tables
        if connection.execute("SELECT to_regclass(%s)", (f"public.{table_name}",)).fetchone()[0]
        is None
    ]
    if missing_tables:
        pytest.skip(
            "최신 First Cycle migration이 적용된 PostgreSQL에서만 실행합니다: "
            + ", ".join(missing_tables)
        )


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
