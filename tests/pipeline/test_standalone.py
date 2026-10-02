import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.common.models.run import RunType
from incident_awareness.pipeline.standalone import build_run_metadata_from_sysmon_jsonl


def test_builds_run_metadata_from_sysmon_event_time_range(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:10.123456", time_created="2026-10-03T01:00:00.000Z"),
            _record("2026-10-03 00:00:00.001", time_created="2026-10-03T00:00:00.000Z"),
        ],
    )

    metadata = build_run_metadata_from_sysmon_jsonl(
        jsonl_path,
        run_id="RUN-20261003-001",
        scenario_id="S0",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
    )

    assert metadata.start_time == datetime(2026, 10, 3, 0, 0, 0, 1000, tzinfo=UTC)
    assert metadata.end_time == datetime(2026, 10, 3, 0, 0, 10, 123000, tzinfo=UTC)
    assert metadata.schema_versions.event == "v0.3"
    assert metadata.schema_versions.fusion_result == "v0.3"


def test_rejects_empty_sysmon_jsonl(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    jsonl_path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain at least one record"):
        build_run_metadata_from_sysmon_jsonl(
            jsonl_path,
            run_id="RUN-20261003-001",
            scenario_id="S0",
            run_type=RunType.ATTACK,
            target_host="WIN-01",
        )


def test_rejects_missing_sysmon_event_time(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(jsonl_path, [{"EventData": {}}])

    with pytest.raises(ValueError, match="EventData.UtcTime must be non-blank"):
        build_run_metadata_from_sysmon_jsonl(
            jsonl_path,
            run_id="RUN-20261003-001",
            scenario_id="S0",
            run_type=RunType.ATTACK,
            target_host="WIN-01",
        )


def _record(utc_time: str, *, time_created: str) -> dict[str, object]:
    return {
        "RecordId": 1,
        "EventId": 1,
        "TimeCreated": time_created,
        "Computer": "WIN-01",
        "EventData": {"UtcTime": utc_time},
    }


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
