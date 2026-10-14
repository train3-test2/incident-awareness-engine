from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline import event_evidence
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector

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


def test_reports_progress_after_each_fully_processed_record() -> None:
    # Given
    artifacts = _artifacts_for_record_ids(3391, 3395)
    progress: list[int] = []

    # When
    result = normalize_sysmon_and_extract_evidence(
        artifacts,
        progress_callback=progress.append,
    )

    # Then
    assert len(result.events) == 2
    assert progress == [1, 2]


def test_does_not_report_a_record_when_evidence_extraction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    artifacts = _artifacts_for_record_ids(3391, 3395)
    original_extract_evidence = event_evidence.extract_evidence
    expected_error = RuntimeError("evidence extraction failed")
    calls = 0
    progress: list[int] = []

    def extract_with_second_failure(event):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise expected_error
        return original_extract_evidence(event)

    monkeypatch.setattr(event_evidence, "extract_evidence", extract_with_second_failure)

    # When
    with pytest.raises(RuntimeError) as exc_info:
        normalize_sysmon_and_extract_evidence(
            artifacts,
            progress_callback=progress.append,
        )

    # Then
    assert exc_info.value is expected_error
    assert progress == [1]


def _artifacts_for_record_ids(*record_ids: int) -> S0PipelineArtifacts:
    records = tuple(
        record for record in read_sysmon_jsonl(SAMPLE_PATH) if record.data["RecordId"] in record_ids
    )
    return _artifacts(records)


def test_real_normalization_measures_evidence_before_progress_callback(monkeypatch) -> None:
    # Given
    artifacts = _artifacts_for_record_ids(3391, 3395)
    expected = normalize_sysmon_and_extract_evidence(artifacts)
    elapsed = [0]
    collector = PipelineTelemetryCollector(
        execution_id="shared",
        run_id=RUN_ID,
        entity_id="WIN-01",
        clock=lambda: datetime(2026, 10, 14, 1, tzinfo=UTC),
        monotonic_clock=lambda: elapsed[0],
    )
    collector.accept_batch(2)
    extract = event_evidence.extract_evidence

    def measured_extract(event):
        elapsed[0] += 7
        return extract(event)

    def progress(count):
        assert collector.snapshot().buckets[0].processing_completed_count == count
        elapsed[0] += 1_000_000  # Progress/DB I/O must not enter the record duration.

    monkeypatch.setattr(event_evidence, "extract_evidence", measured_extract)

    # When
    actual = normalize_sysmon_and_extract_evidence(
        artifacts,
        progress_callback=progress,
        telemetry_collector=collector,
    )

    # Then
    assert actual == expected
    bucket = collector.snapshot().buckets[0]
    assert bucket.processing_completed_count == bucket.latency_sample_count == 2
    assert bucket.latency_sum_ns == 14
    assert bucket.processing_failed_count == 0


def test_evidence_failure_is_counted_separately_and_preserves_exception(monkeypatch) -> None:
    # Given
    artifacts = _artifacts_for_record_ids(3391, 3395)
    collector = PipelineTelemetryCollector(
        execution_id="shared",
        run_id=RUN_ID,
        entity_id="WIN-01",
        clock=lambda: datetime(2026, 10, 14, 1, tzinfo=UTC),
    )
    collector.accept_batch(2)
    original = event_evidence.extract_evidence
    calls = [0]
    error = RuntimeError("Evidence failed")

    def extract(event):
        calls[0] += 1
        if calls[0] == 2:
            raise error
        return original(event)

    monkeypatch.setattr(event_evidence, "extract_evidence", extract)
    progress = []

    # When
    with pytest.raises(RuntimeError) as exc_info:
        normalize_sysmon_and_extract_evidence(
            artifacts,
            telemetry_collector=collector,
            progress_callback=progress.append,
        )

    # Then
    assert exc_info.value is error
    assert progress == [1]
    bucket = collector.snapshot().buckets[0]
    assert bucket.processing_completed_count == bucket.processing_failed_count == 1
    assert bucket.latency_sample_count == 1


def test_failing_measurement_callbacks_cannot_replace_business_error(monkeypatch) -> None:
    # Given
    artifacts = _artifacts_for_record_ids(3391)
    business_error = RuntimeError("original Evidence failure")
    collector = PipelineTelemetryCollector(execution_id="shared", run_id=RUN_ID, entity_id="WIN-01")
    collector.accept_batch(1)

    def fail(*args):
        raise RuntimeError("measurement failed")

    def fail_evidence(event):
        raise business_error

    monkeypatch.setattr(collector, "begin_record", fail)
    monkeypatch.setattr(collector, "record_failure", fail)
    monkeypatch.setattr(event_evidence, "extract_evidence", fail_evidence)

    # When
    with pytest.raises(RuntimeError) as exc_info:
        normalize_sysmon_and_extract_evidence(artifacts, telemetry_collector=collector)

    # Then
    assert exc_info.value is business_error


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
