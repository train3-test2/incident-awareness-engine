from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.evidence import Evidence
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
    artifacts = _artifacts(start_time=start_time, end_time=start_time + timedelta(seconds=20))
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(),
        evidences=(
            _evidence("E-001", "encoded_powershell_command", start_time),
            _evidence(
                "E-002",
                "script_interpreter_external_connection",
                start_time + timedelta(seconds=10),
            ),
        ),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.run_id == RUN_ID
    assert fusion_result.entity_id == ENTITY_ID
    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == start_time + timedelta(seconds=20)
    assert fusion_result.contributing_evidence_ids == ["E-001", "E-002"]


def test_rejects_fusion_for_run_that_has_not_ended() -> None:
    artifacts = _artifacts(start_time=datetime(2026, 9, 20, tzinfo=UTC), end_time=None)

    with pytest.raises(ValueError, match="completed RunMetadata end_time"):
        run_s0_fusion(_inputs(), artifacts, NormalizedEvidenceArtifacts(events=(), evidences=()))


def test_uses_last_cadence_tick_for_a_measured_end_time_between_ticks() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(
        start_time=start_time,
        end_time=start_time + timedelta(seconds=20, milliseconds=1),
    )
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(),
        evidences=(
            _evidence("E-001", "encoded_powershell_command", start_time),
            _evidence(
                "E-002",
                "script_interpreter_external_connection",
                start_time + timedelta(seconds=10),
            ),
        ),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == start_time + timedelta(seconds=20)


def test_sorts_evidence_by_timestamp_before_running_fusion() -> None:
    start_time = datetime(2026, 9, 20, tzinfo=UTC)
    artifacts = _artifacts(start_time=start_time, end_time=start_time + timedelta(seconds=20))
    normalized_artifacts = NormalizedEvidenceArtifacts(
        events=(),
        evidences=(
            _evidence(
                "E-002",
                "script_interpreter_external_connection",
                start_time + timedelta(seconds=10),
            ),
            _evidence("E-001", "encoded_powershell_command", start_time),
        ),
    )

    fusion_result = run_s0_fusion(_inputs(), artifacts, normalized_artifacts)

    assert fusion_result.fusion_status == "detected"
    assert fusion_result.contributing_evidence_ids == ["E-001", "E-002"]


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


def _evidence(evidence_id: str, evidence_type: str, timestamp: datetime) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=RUN_ID,
        timestamp=timestamp,
        entity_id=ENTITY_ID,
        evidence_type=evidence_type,
        event_ids=[f"evt-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="test-v0.1",
    )
