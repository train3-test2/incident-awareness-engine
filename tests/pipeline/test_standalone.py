import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.common.models.run import RunType
from incident_awareness.pipeline.standalone import (
    DEFAULT_STANDALONE_DECISION_CONFIG_VERSION,
    DEFAULT_STANDALONE_FAST_MODE,
    DEFAULT_STANDALONE_FUSION_CONFIG_PATH,
    build_default_standalone_fast_detection,
    build_run_metadata_from_sysmon_jsonl,
    build_sysmon_artifacts_from_jsonl,
    select_standalone_execution_config,
    validate_standalone_sysmon_jsonl,
)


def _record(utc_time: str, *, time_created: str) -> dict[str, object]:
    return {
        "RecordId": 1,
        "EventId": 1,
        "TimeCreated": time_created,
        "Computer": "WIN-01",
        "EventData": {
            "UtcTime": utc_time,
            "Image": "C:\\Windows\\System32\\cmd.exe",
        },
    }


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
    _write_jsonl(
        jsonl_path,
        [
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventData": {"Image": "C:\\Windows\\System32\\cmd.exe"},
            }
        ],
    )

    with pytest.raises(ValueError, match="EventData.UtcTime must be non-blank"):
        build_run_metadata_from_sysmon_jsonl(
            jsonl_path,
            run_id="RUN-20261003-001",
            scenario_id="S0",
            run_type=RunType.ATTACK,
            target_host="WIN-01",
        )


def test_builds_manifest_sha256_and_raw_log_provenance(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "uploaded-sysmon.jsonl"
    _write_jsonl(
        jsonl_path, [_record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z")]
    )

    artifacts = build_sysmon_artifacts_from_jsonl(jsonl_path, run_id="RUN-20261003-001")

    jsonl_item = artifacts.manifest["items"][1]
    assert artifacts.manifest["run_id"] == "RUN-20261003-001"
    assert jsonl_item == {
        "raw_log_id": "RAW-RUN-20261003-001-SYSMON-001",
        "path": "generated/raw/RUN-20261003-001/telemetry/sysmon-0001.jsonl",
        "sha256": _sha256(jsonl_path),
        "layer": "raw_telemetry",
        "source": "sysmon",
        "derived_from": "generated/raw/RUN-20261003-001/telemetry/sysmon-0001.evtx",
    }
    assert artifacts.normalization_context.run_id == "RUN-20261003-001"
    assert artifacts.normalization_context.raw_log_id == jsonl_item["raw_log_id"]
    assert artifacts.normalization_context.segment_no == 1


def test_builds_not_evaluated_fast_result_without_fast_artifacts() -> None:
    result = build_default_standalone_fast_detection(
        run_id="RUN-20261003-001",
        entity_id="WIN-01",
    )

    assert DEFAULT_STANDALONE_FAST_MODE == "not_evaluated"
    assert result.detection_result.run_id == "RUN-20261003-001"
    assert result.detection_result.entity_id == "WIN-01"
    assert result.detection_result.detector_status == "not_evaluated"
    assert result.detection_result.detector_time is None
    assert result.source_hit_ids == ()
    assert result.selected_source_hit_id is None


def test_selects_default_s0_fusion_and_parallel_hybrid_config() -> None:
    config = select_standalone_execution_config()

    assert config.fusion_config_path == DEFAULT_STANDALONE_FUSION_CONFIG_PATH
    assert config.fusion_config.config_version == "fusion-config-s0-pair-v0.1"
    assert config.decision_config_version == DEFAULT_STANDALONE_DECISION_CONFIG_VERSION


def test_rejects_unsupported_standalone_hybrid_config() -> None:
    with pytest.raises(ValueError, match="supports only decision config"):
        select_standalone_execution_config(decision_config_version="optional-v1")


def test_accepts_supported_sysmon_event_ids(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _record("2026-10-03 00:00:00.000", time_created="2026-10-03T00:00:00Z"),
            {
                "RecordId": 2,
                "EventId": 3,
                "TimeCreated": "2026-10-03T00:00:10Z",
                "Computer": "WIN-01",
                "EventData": {
                    "UtcTime": "2026-10-03 00:00:10.000",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ProcessId": "4242",
                    "DestinationPort": "443",
                },
            },
        ],
    )

    records = validate_standalone_sysmon_jsonl(jsonl_path)

    assert [record.data["EventId"] for record in records] == [1, 3]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventId": 7,
            },
            "unsupported",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventId": True,
            },
            "EventId must be an integer",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "TimeCreated": "2026-10-03T00:00:00",
            },
            "must include timezone",
        ),
        (
            {
                **_record(
                    "2026-10-03 00:00:00.000",
                    time_created="2026-10-03T00:00:00Z",
                ),
                "EventData": {"UtcTime": "2026-10-03 00:00:00.000"},
            },
            "Image must be a non-blank string",
        ),
    ],
)
def test_rejects_unsupported_or_malformed_sysmon_input(
    tmp_path: Path,
    record: dict[str, object],
    message: str,
) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(jsonl_path, [record])

    with pytest.raises((TypeError, ValueError), match=message):
        validate_standalone_sysmon_jsonl(jsonl_path)


def test_rejects_network_port_outside_contract_range(tmp_path: Path) -> None:
    jsonl_path = tmp_path / "sysmon.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            {
                "RecordId": 1,
                "EventId": 3,
                "TimeCreated": "2026-10-03T00:00:00Z",
                "Computer": "WIN-01",
                "EventData": {
                    "UtcTime": "2026-10-03 00:00:00.000",
                    "DestinationPort": "65536",
                },
            }
        ],
    )

    with pytest.raises(ValueError, match="between 0 and 65535"):
        validate_standalone_sysmon_jsonl(jsonl_path)


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
