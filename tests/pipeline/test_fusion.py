from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.fusion import run_s0_fusion
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

RUN_ID = "RUN-20260920-001"
ENTITY_ID = "WIN-01"
FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")


def test_runs_existing_fusion_pipeline_and_returns_fusion_result() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(start_time=start_time, end_time=start_time + timedelta(seconds=660))
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(
            _encoded_command_event("evt-001", start_time),
            _network_event("evt-002", start_time + timedelta(seconds=10)),
        ),
        evidences=(),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.run_id == RUN_ID
    assert fusion_result.entity_id == ENTITY_ID
    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == start_time + timedelta(seconds=20)
    assert len(fusion_result.contributing_evidence_ids) == 2


def test_rejects_fusion_for_run_that_has_not_ended() -> None:
    artifacts = _artifacts(start_time=datetime(2026, 9, 20, tzinfo=UTC), end_time=None)

    with pytest.raises(ValueError, match="completed RunMetadata end_time"):
        run_s0_fusion(_inputs(), artifacts, NormalizedEvidenceArtifacts(events=(), evidences=()))


def test_uses_official_replay_end_and_excludes_events_after_it() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(
        start_time=start_time,
        end_time=start_time + timedelta(seconds=660, milliseconds=1),
    )
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(
            _encoded_command_event("evt-001", start_time + timedelta(seconds=640)),
            _network_event("evt-002", start_time + timedelta(seconds=650)),
            _encoded_command_event("evt-003", start_time + timedelta(seconds=660, milliseconds=1)),
        ),
        evidences=(),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == start_time + timedelta(seconds=660)
    assert fusion_result.contributing_evidence_ids
    assert fusion_result.fusion_episodes[0].end_time == start_time + timedelta(seconds=660)
    assert fusion_result.fusion_episodes[0].end_reason == "replay_end"


def test_sorts_evidence_by_timestamp_before_running_fusion() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(start_time=start_time, end_time=start_time + timedelta(seconds=660))
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(
            _network_event("evt-002", start_time + timedelta(seconds=10)),
            _encoded_command_event("evt-001", start_time),
        ),
        evidences=(),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.fusion_status == "detected"
    assert len(fusion_result.contributing_evidence_ids) == 2


def test_returns_not_evaluated_before_official_replay_window_is_covered() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(
        start_time=start_time,
        end_time=start_time + timedelta(seconds=659, milliseconds=999),
    )

    fusion_result = run_s0_fusion(
        _inputs(),
        artifacts,
        NormalizedEvidenceArtifacts(events=(), evidences=()),
    )

    assert fusion_result.fusion_status == "not_evaluated"


def _inputs() -> PipelineInputs:
    unused_path = Path("unused")
    return PipelineInputs(
        run_metadata_path=unused_path,
        manifest_path=unused_path,
        sysmon_jsonl_path=unused_path,
        fast_hits_path=unused_path,
        fast_trace_path=unused_path,
        fast_selection_path=unused_path,
        fusion_config_path=FUSION_CONFIG_PATH,
        entity_id=ENTITY_ID,
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )


def _artifacts(*, start_time: datetime, end_time: datetime | None) -> S0PipelineArtifacts:
    return S0PipelineArtifacts(
        run_metadata=RunMetadata.model_validate(
            {
                "run_id": RUN_ID,
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": ENTITY_ID,
                "start_time": start_time,
                "end_time": end_time,
                "schema_versions": {
                    "run_metadata": "v0.2",
                    "event": "v0.2",
                    "evidence": "v0.2",
                    "fast_hit": "v0.2",
                    "detection_result": "v0.2",
                    "fusion_result": "v0.2",
                    "decision_result": "v0.2",
                    "execution_record": "v0.1",
                    "evaluation_input": "v0.1",
                },
            }
        ),
        sysmon_records=(),
        normalization_context=SysmonNormalizationContext(
            run_id=RUN_ID,
            raw_log_id="RAW-002",
            segment_no=1,
        ),
    )


def _encoded_command_event(event_id: str, timestamp: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        run_id=RUN_ID,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id=ENTITY_ID,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=event_id,
        event_type="process_create",
        raw_ref=RawLogReference(raw_log_id="RAW-002", segment_no=1, record_no=1),
        process=ProcessInfo(name="powershell.exe", command_line="powershell.exe -enc SQBFAFgA"),
    )


def _network_event(event_id: str, timestamp: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        run_id=RUN_ID,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id=ENTITY_ID,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=event_id,
        event_type="network_connection",
        raw_ref=RawLogReference(raw_log_id="RAW-002", segment_no=1, record_no=2),
        process=ProcessInfo(name="powershell.exe", command_line="powershell.exe -enc SQBFAFgA"),
        network=NetworkInfo(protocol="tcp", dst_ip="1.1.1.1", dst_port=443),
    )
