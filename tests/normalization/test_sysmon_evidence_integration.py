from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)
from incident_awareness.evidence.extractor import extract_evidence
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)

_SAMPLE_PATH = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"
_CONTEXT = SysmonNormalizationContext(
    run_id="RUN-20260912-001",
    raw_log_id="RAW-SYSMON-SAMPLE-001",
    segment_no=1,
)


def test_normalized_encoded_powershell_event_is_extracted_as_evidence() -> None:
    event = normalize_sysmon_process_create(_sample_record(3391), context=_CONTEXT)

    evidences = extract_evidence(event)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "encoded_powershell_command"
    assert evidence.run_id == event.run_id
    assert evidence.timestamp == event.timestamp
    assert evidence.event_ids == [event.event_id]


def test_normalized_external_connection_is_extracted_as_evidence() -> None:
    event = normalize_sysmon_network_connection(_sample_record(3395), context=_CONTEXT)

    evidences = extract_evidence(event)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.evidence_type == "script_interpreter_external_connection"
    assert evidence.run_id == event.run_id
    assert evidence.timestamp == event.timestamp
    assert evidence.event_ids == [event.event_id]


def _sample_record(record_id: int) -> SysmonJsonlRecord:
    return next(
        record for record in read_sysmon_jsonl(_SAMPLE_PATH) if record.data["RecordId"] == record_id
    )
