import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.fast import load_s0_fast_detection
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

RUN_ID = "RUN-20260920-001"
ENTITY_ID = "WIN-01"
FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"


def test_reads_fast_handoff_and_adapts_detection_result(tmp_path: Path) -> None:
    inputs = _inputs_with_handoff(tmp_path)
    inputs.fast_selection_path.write_text(
        json.dumps(
            {
                "detector_status": "detected",
                "selected_hit_id": f"{RUN_ID}-hit-2",
                "severity": "high",
            }
        ),
        encoding="utf-8",
    )

    result = load_s0_fast_detection(inputs, _artifacts())

    assert result.detection_result.model_dump(mode="json") == {
        "run_id": RUN_ID,
        "entity_id": ENTITY_ID,
        "detector_time": "2026-09-13T00:00:01.123Z",
        "detector_status": "detected",
        "detector_id": "hayabusa",
        "rule_id": "mock-rule",
        "rule_version": "mock-v1",
        "severity": "high",
    }
    assert result.source_hit_ids == (f"{RUN_ID}-hit-2",)
    assert result.selected_source_hit_id == f"{RUN_ID}-hit-2"


def test_maps_fast_native_host_to_canonical_entity_without_losing_provenance(
    tmp_path: Path,
) -> None:
    inputs = _inputs_with_handoff(tmp_path, entity_id="endpoint-01")
    inputs.fast_selection_path.write_text(
        json.dumps(
            {
                "detector_status": "detected",
                "selected_hit_id": f"{RUN_ID}-hit-2",
            }
        ),
        encoding="utf-8",
    )

    result = load_s0_fast_detection(
        inputs,
        _artifacts(),
        entity_mapper=lambda native_host_id: {"WIN-01": "endpoint-01"}.get(native_host_id),
    )

    assert result.detection_result.entity_id == "endpoint-01"
    assert result.source_hit_ids == (f"{RUN_ID}-hit-2",)
    assert result.selected_source_hit_id == f"{RUN_ID}-hit-2"


def test_rejects_invalid_fast_detection_selection(tmp_path: Path) -> None:
    inputs = _inputs_with_handoff(tmp_path)
    inputs.fast_selection_path.write_text('{"detector_status":"detected"}', encoding="utf-8")

    with pytest.raises(ValueError, match="FastDetectionSelection"):
        load_s0_fast_detection(inputs, _artifacts())


def _inputs_with_handoff(tmp_path: Path, *, entity_id: str = ENTITY_ID) -> PipelineInputs:
    fast_hits_path = tmp_path / "fast-hits.jsonl"
    fast_trace_path = tmp_path / "fast-trace.json"
    run_fast_handoff(
        csv_path=FIXTURES / "handoff.csv",
        config_path=FIXTURES / "handoff_config.json",
        run_id=RUN_ID,
        output_path=fast_hits_path,
        trace_path=fast_trace_path,
    )
    fast_selection_path = tmp_path / "fast-selection.json"
    unused_path = tmp_path / "unused"
    return PipelineInputs(
        run_metadata_path=unused_path,
        manifest_path=unused_path,
        sysmon_jsonl_path=unused_path,
        fast_hits_path=fast_hits_path,
        fast_trace_path=fast_trace_path,
        fast_selection_path=fast_selection_path,
        fusion_config_path=unused_path,
        entity_id=entity_id,
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )


def _artifacts() -> S0PipelineArtifacts:
    return S0PipelineArtifacts(
        run_metadata=RunMetadata.model_validate(
            {
                "run_id": RUN_ID,
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": ENTITY_ID,
                "start_time": datetime(2026, 9, 20, tzinfo=UTC),
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
