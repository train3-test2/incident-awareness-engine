from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

RUN_ID = "RUN-20260920-001"
SAMPLE_PATH = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"


def test_normalizes_sysmon_records_and_extracts_s0_evidence() -> None:
    artifacts = _artifacts_for_record_ids(3391, 3395)

    result = normalize_sysmon_and_extract_evidence(artifacts)

    assert [event.event_type for event in result.events] == [
        "process_create",
        "network_connection",
    ]
    assert [event.raw_ref.raw_log_id for event in result.events] == ["RAW-002", "RAW-002"]
    assert [event.raw_ref.record_no for event in result.events] == [3, 7]
    assert [evidence.evidence_type for evidence in result.evidences] == [
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    ]
    assert [evidence.event_ids for evidence in result.evidences] == [
        [result.events[0].event_id],
        [result.events[1].event_id],
    ]


def test_rejects_sysmon_event_type_outside_s0_normalizer_contract() -> None:
    record = next(read_sysmon_jsonl(SAMPLE_PATH))
    invalid_record = record.__class__(
        record_no=record.record_no, data={**record.data, "EventId": 2}
    )
    artifacts = _artifacts((invalid_record,))

    with pytest.raises(ValueError, match="unsupported EventId 2"):
        normalize_sysmon_and_extract_evidence(artifacts)


def _artifacts_for_record_ids(*record_ids: int) -> S0PipelineArtifacts:
    records = tuple(
        record for record in read_sysmon_jsonl(SAMPLE_PATH) if record.data["RecordId"] in record_ids
    )
    return _artifacts(records)


def _artifacts(records: tuple[SysmonJsonlRecord, ...]) -> S0PipelineArtifacts:
    return S0PipelineArtifacts(
        run_metadata=RunMetadata.model_validate(
            {
                "run_id": RUN_ID,
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": "WIN-01",
                "start_time": datetime(2026, 9, 20, tzinfo=UTC),
                "schema_versions": {
                    "run_metadata": "v0.2",
                    "event": "v0.2",
                    "evidence": "v0.2",
                    "fast_hit": "v0.2",
                    "detection_result": "v0.2",
                    "fusion_result": "v0.3",
                    "decision_result": "v0.2",
                    "execution_record": "v0.1",
                    "evaluation_input": "v0.1",
                },
            }
        ),
        sysmon_records=records,
        normalization_context=SysmonNormalizationContext(
            run_id=RUN_ID,
            raw_log_id="RAW-002",
            segment_no=1,
        ),
    )
