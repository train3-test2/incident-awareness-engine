import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.r1_multi_event import (
    REMOTE_PROCESS_NETWORK_FOLLOW_ON,
    REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION,
    ApprovedLineagePolicy,
)
from incident_awareness.pipeline.r1_artifacts import (
    R1_EVIDENCE_FILENAME,
    R1_EXTRACTION_SUMMARY_FILENAME,
    R1SelectorProvenance,
    load_r1_evidence_artifacts,
    load_r1_extraction_summary,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_evidence import R1LineageInput

_BASE_TIME = datetime(2026, 10, 6, 1, 0, tzinfo=UTC)
_RUN_ID = "RUN-20261006-001"
_HOST_ID = "TARGET-A"
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str | None,
    process_name: str | None,
    parent_process_guid: str | None = None,
    run_id: str = _RUN_ID,
) -> NormalizedEvent:
    is_network_event = event_type == "network_connection"
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": run_id,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": timestamp,
            "ingest_time": timestamp,
            "host_id": _HOST_ID,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-ARTIFACT",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 4 if is_network_event else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}" if process_name else None,
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
                "parent_name": None,
            },
            "network": (
                {
                    "protocol": "tcp",
                    "src_ip": "10.0.0.10",
                    "src_port": 52132,
                    "dst_ip": "10.0.0.20",
                    "dst_port": 5985,
                }
                if is_network_event
                else None
            ),
        }
    )


def _events() -> tuple[NormalizedEvent, ...]:
    return (
        _event(
            event_id="evt-anchor",
            event_type="process_create",
            timestamp=_BASE_TIME,
            process_guid=_ANCHOR_GUID,
            process_name="anchor.exe",
        ),
        _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="runtime-hop.exe",
            parent_process_guid=_ANCHOR_GUID,
        ),
        _event(
            event_id="evt-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
        _event(
            event_id="evt-network",
            event_type="network_connection",
            timestamp=_BASE_TIME + timedelta(seconds=3),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
        ),
    )


def _policy(
    approved_lineage: tuple[str, ...] = (
        "anchor.exe",
        "approved-hop.exe",
        "terminal.exe",
    ),
    *,
    policy_id: str = "r1-target-a-lineage",
    version: str = "v1",
    config_hash: str = "sha256:approved-policy-v1",
) -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id=policy_id,
        version=version,
        config_hash=config_hash,
        approved_lineage=approved_lineage,
    )


def _lineage_input(policy: ApprovedLineagePolicy | None = None) -> R1LineageInput:
    return R1LineageInput(
        anchor_event_id="evt-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=policy or _policy(),
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _read_summary_payload(output_directory: Path) -> dict[str, object]:
    path = output_directory / R1_EXTRACTION_SUMMARY_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _write_summary_payload(
    output_directory: Path,
    payload: dict[str, object],
) -> None:
    path = output_directory / R1_EXTRACTION_SUMMARY_FILENAME
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _replace_evidence_content(
    output_directory: Path,
    content: bytes,
    *,
    synchronize_hash: bool,
) -> None:
    evidence_path = output_directory / R1_EVIDENCE_FILENAME
    evidence_path.write_bytes(content)
    if synchronize_hash:
        summary = _read_summary_payload(output_directory)
        summary["evidence_artifact_sha256"] = hashlib.sha256(content).hexdigest()
        _write_summary_payload(output_directory, summary)


def _replace_evidence_records(
    output_directory: Path,
    records: list[dict[str, object]],
) -> None:
    content = "".join(f"{json.dumps(record)}\n" for record in records).encode("utf-8")
    _replace_evidence_content(output_directory, content, synchronize_hash=True)
    summary = _read_summary_payload(output_directory)
    summary["evidence_count"] = len(records)
    _write_summary_payload(output_directory, summary)


def _diagnostic_events(diagnostic: str) -> tuple[NormalizedEvent, ...]:
    anchor, middle, terminal, _ = _events()
    if diagnostic == "missing_process_guid":
        terminal = _event(
            event_id="evt-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=None,
            process_name="terminal.exe",
            parent_process_guid=_MIDDLE_GUID,
        )
        return anchor, middle, terminal
    if diagnostic == "truncated_lineage":
        return anchor, terminal
    if diagnostic == "lineage_cycle":
        middle = _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="runtime-hop.exe",
            parent_process_guid=_TERMINAL_GUID,
        )
        return anchor, middle, terminal
    if diagnostic == "duplicate_process_guid":
        duplicate_terminal = _event(
            event_id="evt-duplicate-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
            parent_process_guid=_MIDDLE_GUID,
        )
        return anchor, middle, terminal, duplicate_terminal
    if diagnostic == "missing_or_blank_process_name":
        middle = _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="   ",
            parent_process_guid=_ANCHOR_GUID,
        )
        return anchor, middle, terminal
    raise AssertionError(f"unsupported test diagnostic: {diagnostic}")


def test_writes_completed_evidence_and_summary_artifacts(tmp_path: Path) -> None:
    # Given
    events = _events()

    # When
    result = run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )

    # Then
    evidence_path = tmp_path / R1_EVIDENCE_FILENAME
    summary_path = tmp_path / R1_EXTRACTION_SUMMARY_FILENAME
    records = _read_jsonl(evidence_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert result.evidence_path == evidence_path
    assert result.summary_path == summary_path
    assert summary["status"] == "completed"
    assert summary["run_id"] == _RUN_ID
    assert summary["extractor_version"] == "r1-v0.1"
    assert summary["input_event_count"] == len(events)
    assert summary["evidence_count"] == len(records) == 2
    assert summary["telemetry_completeness"] == "not_provided"
    assert summary["error_type"] is None
    assert summary["error_message"] is None
    assert (
        summary["evidence_artifact_sha256"]
        == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    )

    required_fields = {
        "evidence_id",
        "run_id",
        "timestamp",
        "entity_id",
        "evidence_type",
        "event_ids",
        "feature_channel_group",
        "extractor_version",
        "features",
    }
    assert all(required_fields <= record.keys() for record in records)
    assert len([Evidence.model_validate(record) for record in records]) == len(records)


def test_completed_extraction_with_no_evidence_is_not_failed(tmp_path: Path) -> None:
    # Given
    anchor, middle, terminal, _ = _events()
    matching_policy = _policy(approved_lineage=("anchor.exe", "runtime-hop.exe", "terminal.exe"))

    # When
    result = run_and_write_r1_evidence_artifacts(
        [anchor, middle, terminal],
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input(matching_policy)],
    )

    # Then
    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert result.evidences == ()
    assert result.evidence_path.read_bytes() == b""
    assert summary["status"] == "completed"
    assert summary["evidence_count"] == 0
    assert summary["diagnostics"] == []
    assert summary["lineage_inputs"] == [
        {
            "anchor_event_id": "evt-anchor",
            "terminal_event_id": "evt-terminal",
            "policy_id": "r1-target-a-lineage",
            "policy_version": "v1",
            "policy_config_hash": "sha256:approved-policy-v1",
        }
    ]
    assert summary["error_type"] is None
    assert summary["error_message"] is None


def test_rejects_selected_selector_without_lineage_before_publication(
    tmp_path: Path,
) -> None:
    # Given
    selector_provenance = R1SelectorProvenance(
        policy_id="r1-selector-policy",
        version="v0.1",
        config_hash="sha256:selector-policy",
        status="selected",
        diagnostics=(),
    )

    # When
    with pytest.raises(
        ValueError,
        match="selected selector provenance requires a lineage input",
    ):
        run_and_write_r1_evidence_artifacts(
            _events(),
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=(),
            selector_provenance=selector_provenance,
        )

    # Then
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert not (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).exists()


def test_rejects_invalid_selector_status_before_artifact_publication(
    tmp_path: Path,
) -> None:
    # Given
    evidence_path = tmp_path / R1_EVIDENCE_FILENAME
    summary_path = tmp_path / R1_EXTRACTION_SUMMARY_FILENAME

    # When
    with pytest.raises(ValueError, match="status must be selected or failed"):
        selector_provenance = R1SelectorProvenance(
            policy_id="r1-selector-policy",
            version="v0.1",
            config_hash="sha256:selector-policy",
            status="unknown",
            diagnostics=(),
        )
        run_and_write_r1_evidence_artifacts(
            _events(),
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[_lineage_input()],
            selector_provenance=selector_provenance,
        )

    # Then
    assert not evidence_path.exists()
    assert not summary_path.exists()


def test_rejects_invalid_selector_diagnostic() -> None:
    # Given
    invalid_diagnostic = "not_a_real_diagnostic"

    # When
    with pytest.raises(ValueError) as error_info:
        R1SelectorProvenance(
            policy_id="r1-selector-policy",
            version="v0.1",
            config_hash="sha256:selector-policy",
            status="failed",
            diagnostics=(invalid_diagnostic,),
        )

    # Then
    assert str(error_info.value) == "diagnostics must contain valid R1 selector diagnostics"


def test_rejects_non_tuple_selector_diagnostics() -> None:
    # Given
    diagnostics = ["ambiguous_terminal_candidate"]

    # When
    with pytest.raises(ValueError) as error_info:
        R1SelectorProvenance(
            policy_id="r1-selector-policy",
            version="v0.1",
            config_hash="sha256:selector-policy",
            status="failed",
            diagnostics=diagnostics,
        )

    # Then
    assert str(error_info.value) == "diagnostics must contain valid R1 selector diagnostics"


def test_accepts_selected_selector_without_diagnostics() -> None:
    # Given
    diagnostics = ()

    # When
    provenance = R1SelectorProvenance(
        policy_id="r1-selector-policy",
        version="v0.1",
        config_hash="sha256:selector-policy",
        status="selected",
        diagnostics=diagnostics,
    )

    # Then
    assert provenance.status == "selected"
    assert provenance.diagnostics == ()


def test_rejects_selected_selector_with_diagnostic() -> None:
    # Given
    diagnostic = "ambiguous_terminal_candidate"

    # When
    with pytest.raises(ValueError) as error_info:
        R1SelectorProvenance(
            policy_id="r1-selector-policy",
            version="v0.1",
            config_hash="sha256:selector-policy",
            status="selected",
            diagnostics=(diagnostic,),
        )

    # Then
    assert str(error_info.value) == ("selected selector provenance must not contain diagnostics")


def test_accepts_failed_selector_with_valid_diagnostic() -> None:
    # Given
    diagnostic = "ambiguous_terminal_candidate"

    # When
    provenance = R1SelectorProvenance(
        policy_id="r1-selector-policy",
        version="v0.1",
        config_hash="sha256:selector-policy",
        status="failed",
        diagnostics=(diagnostic,),
    )

    # Then
    assert provenance.status == "failed"
    assert provenance.diagnostics == ("ambiguous_terminal_candidate",)


def test_loads_completed_artifact_with_valid_selector_provenance(
    tmp_path: Path,
) -> None:
    # Given
    selector_provenance = R1SelectorProvenance(
        policy_id="r1-selector-policy",
        version="v0.1",
        config_hash="sha256:selector-policy",
        status="selected",
        diagnostics=(),
    )

    # When
    written = run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
        selector_provenance=selector_provenance,
    )
    loaded = load_r1_evidence_artifacts(tmp_path)

    # Then
    assert written.summary.selector == selector_provenance
    assert loaded.summary.selector == selector_provenance
    assert loaded.evidences == written.evidences


def test_lineage_provenance_is_deterministic_and_preserves_inputs(tmp_path: Path) -> None:
    # Given
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    anchor, middle, terminal, _ = _events()
    approved_lineage = ("anchor.exe", "runtime-hop.exe", "terminal.exe")
    first_input = _lineage_input(
        _policy(
            approved_lineage,
            policy_id="policy-a",
            version="v1",
            config_hash="sha256:policy-a",
        )
    )
    second_input = _lineage_input(
        _policy(
            approved_lineage,
            policy_id="policy-b",
            version="v2",
            config_hash="sha256:policy-b",
        )
    )

    # When
    first_result = run_and_write_r1_evidence_artifacts(
        [anchor, middle, terminal],
        run_id=_RUN_ID,
        output_directory=first_directory,
        lineage_inputs=[second_input, first_input, first_input],
    )
    second_result = run_and_write_r1_evidence_artifacts(
        [anchor, middle, terminal],
        run_id=_RUN_ID,
        output_directory=second_directory,
        lineage_inputs=[first_input, second_input, first_input],
    )

    # Then
    first_summary = json.loads(first_result.summary_path.read_text(encoding="utf-8"))
    second_summary = json.loads(second_result.summary_path.read_text(encoding="utf-8"))
    expected_provenance = [
        {
            "anchor_event_id": "evt-anchor",
            "terminal_event_id": "evt-terminal",
            "policy_id": "policy-a",
            "policy_version": "v1",
            "policy_config_hash": "sha256:policy-a",
        },
        {
            "anchor_event_id": "evt-anchor",
            "terminal_event_id": "evt-terminal",
            "policy_id": "policy-a",
            "policy_version": "v1",
            "policy_config_hash": "sha256:policy-a",
        },
        {
            "anchor_event_id": "evt-anchor",
            "terminal_event_id": "evt-terminal",
            "policy_id": "policy-b",
            "policy_version": "v2",
            "policy_config_hash": "sha256:policy-b",
        },
    ]
    assert first_summary["evidence_count"] == 0
    assert first_summary["lineage_inputs"] == expected_provenance
    assert second_summary["lineage_inputs"] == expected_provenance
    assert first_result.summary_path.read_bytes() == second_result.summary_path.read_bytes()


def test_empty_lineage_inputs_record_no_fail_closed_diagnostic(tmp_path: Path) -> None:
    # Given
    events = _events()

    # When
    result = run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=(),
    )

    # Then
    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert result.evidences == ()
    assert summary["lineage_inputs"] == []
    assert summary["evidence_count"] == 0
    assert summary["diagnostics"] == []


@pytest.mark.parametrize(
    "diagnostic",
    [
        "missing_process_guid",
        "truncated_lineage",
        "lineage_cycle",
        "duplicate_process_guid",
        "missing_or_blank_process_name",
    ],
)
def test_completed_fail_closed_extraction_records_diagnostic(
    tmp_path: Path,
    diagnostic: str,
) -> None:
    # Given
    events = _diagnostic_events(diagnostic)

    # When
    result = run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )

    # Then
    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert result.evidences == ()
    assert summary["status"] == "completed"
    assert summary["evidence_count"] == 0
    assert summary["diagnostics"] == [diagnostic]
    assert summary["error_type"] is None
    assert summary["error_message"] is None


def test_failed_extraction_writes_summary_and_reraises(tmp_path: Path) -> None:
    # Given
    events = _events()
    invalid_input = R1LineageInput(
        anchor_event_id="evt-missing-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=_policy(),
    )

    # When
    with pytest.raises(ValueError, match="anchor_event_id"):
        run_and_write_r1_evidence_artifacts(
            events,
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[invalid_input],
        )

    # Then
    summary_path = tmp_path / R1_EXTRACTION_SUMMARY_FILENAME
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert summary["status"] == "failed"
    assert summary["evidence_count"] is None
    assert summary["input_event_count"] == len(events)
    assert summary["evidence_artifact_sha256"] is None
    assert summary["diagnostics"] == []
    assert summary["error_type"] == "ValueError"
    assert summary["error_message"] == (
        "anchor_event_id does not reference an Event in the batch: evt-missing-anchor"
    )


def test_failed_summary_publication_does_not_replace_extraction_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    invalid_input = R1LineageInput(
        anchor_event_id="evt-missing-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=_policy(),
    )

    def fail_publication(_: tuple[tuple[Path, bytes], ...]) -> None:
        raise OSError("summary storage unavailable")

    monkeypatch.setattr(
        "incident_awareness.pipeline.r1_artifacts._publish_files",
        fail_publication,
    )

    # When
    with pytest.raises(ValueError, match="anchor_event_id") as error_info:
        run_and_write_r1_evidence_artifacts(
            _events(),
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[invalid_input],
        )

    # Then
    assert str(error_info.value) == (
        "anchor_event_id does not reference an Event in the batch: evt-missing-anchor"
    )
    assert error_info.value.__notes__ == [
        "R1 failed summary publication also failed: OSError: summary storage unavailable"
    ]
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert not (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).exists()


def test_run_id_mismatch_writes_failed_summary_without_evidence(tmp_path: Path) -> None:
    # Given
    anchor, middle, terminal, _ = _events()
    other_run_network = _event(
        event_id="evt-network",
        event_type="network_connection",
        timestamp=_BASE_TIME + timedelta(seconds=3),
        process_guid=_TERMINAL_GUID,
        process_name="terminal.exe",
        run_id="RUN-20261006-002",
    )

    # When
    with pytest.raises(ValueError, match="requested run_id"):
        run_and_write_r1_evidence_artifacts(
            [anchor, middle, terminal, other_run_network],
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[_lineage_input()],
        )

    # Then
    summary = json.loads((tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_text(encoding="utf-8"))
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert summary["status"] == "failed"
    assert summary["evidence_count"] is None
    assert summary["diagnostics"] == []
    assert summary["error_type"] == "ValueError"
    assert summary["error_message"] == (
        "all events must belong to the requested run_id: evt-network belongs to RUN-20261006-002"
    )


def test_event_materialization_failure_writes_failed_summary(tmp_path: Path) -> None:
    # Given
    first_event = _events()[0]

    def failing_events():
        yield first_event
        raise RuntimeError("event stream failed")

    # When
    with pytest.raises(RuntimeError, match="event stream failed"):
        run_and_write_r1_evidence_artifacts(
            failing_events(),
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[_lineage_input()],
        )

    # Then
    summary = json.loads((tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_text(encoding="utf-8"))
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert summary["status"] == "failed"
    assert summary["input_event_count"] is None
    assert summary["lineage_inputs"] is None
    assert summary["diagnostics"] == []
    assert summary["error_type"] == "RuntimeError"
    assert summary["error_message"] == "event stream failed"


def test_lineage_input_materialization_failure_writes_failed_summary(tmp_path: Path) -> None:
    # Given
    events = _events()

    def failing_lineage_inputs():
        yield _lineage_input()
        raise RuntimeError("lineage input stream failed")

    # When
    with pytest.raises(RuntimeError, match="lineage input stream failed"):
        run_and_write_r1_evidence_artifacts(
            events,
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=failing_lineage_inputs(),
        )

    # Then
    summary = json.loads((tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_text(encoding="utf-8"))
    assert not (tmp_path / R1_EVIDENCE_FILENAME).exists()
    assert summary["status"] == "failed"
    assert summary["input_event_count"] == len(events)
    assert summary["lineage_inputs"] is None
    assert summary["diagnostics"] == []
    assert summary["error_type"] == "RuntimeError"
    assert summary["error_message"] == "lineage input stream failed"


def test_failed_artifact_requires_a_new_output_directory_for_retry(tmp_path: Path) -> None:
    # Given
    failed_directory = tmp_path / "failed-attempt"
    retry_directory = tmp_path / "retry-attempt"
    failed_directory.mkdir()
    retry_directory.mkdir()
    events = _events()
    invalid_input = R1LineageInput(
        anchor_event_id="evt-missing-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=_policy(),
    )
    with pytest.raises(ValueError, match="anchor_event_id"):
        run_and_write_r1_evidence_artifacts(
            events,
            run_id=_RUN_ID,
            output_directory=failed_directory,
            lineage_inputs=[invalid_input],
        )

    # When
    with pytest.raises(FileExistsError, match="must not already exist"):
        run_and_write_r1_evidence_artifacts(
            events,
            run_id=_RUN_ID,
            output_directory=failed_directory,
            lineage_inputs=[_lineage_input()],
        )

    retry_result = run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=retry_directory,
        lineage_inputs=[_lineage_input()],
    )

    # Then
    assert retry_result.summary.status == "completed"
    assert retry_result.evidence_path.exists()


def test_evidence_artifact_preserves_only_event_id_provenance(tmp_path: Path) -> None:
    # Given
    events = _events()
    events_by_id = {event.event_id: event for event in events}

    # When
    run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)

    # Then
    assert all(event_id in events_by_id for record in records for event_id in record["event_ids"])
    assert all("source_event_id" not in record for record in records)
    assert all("raw_ref" not in record for record in records)


def test_same_inputs_produce_identical_artifacts(tmp_path: Path) -> None:
    # Given
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    events = _events()
    lineage_input = _lineage_input()

    # When
    first = run_and_write_r1_evidence_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=first_directory,
        lineage_inputs=[lineage_input],
    )
    second = run_and_write_r1_evidence_artifacts(
        reversed(events),
        run_id=_RUN_ID,
        output_directory=second_directory,
        lineage_inputs=[lineage_input],
    )

    # Then
    assert first.evidence_path.read_bytes() == second.evidence_path.read_bytes()
    assert first.summary_path.read_bytes() == second.summary_path.read_bytes()
    assert [evidence.evidence_id for evidence in first.evidences] == [
        evidence.evidence_id for evidence in second.evidences
    ]


def test_loads_writer_artifacts_round_trip(tmp_path: Path) -> None:
    # Given
    written = run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )

    # When
    loaded = load_r1_evidence_artifacts(tmp_path)

    # Then
    assert loaded.evidences == written.evidences
    assert loaded.summary == written.summary
    assert loaded.evidence_path == written.evidence_path
    assert loaded.summary_path == written.summary_path
    assert [evidence.model_dump() for evidence in loaded.evidences] == [
        evidence.model_dump() for evidence in written.evidences
    ]


def test_loads_completed_empty_evidence_artifact(tmp_path: Path) -> None:
    # Given
    written = run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=(),
    )

    # When
    loaded = load_r1_evidence_artifacts(tmp_path)

    # Then
    assert written.evidences == loaded.evidences == ()
    assert loaded.summary.status == "completed"
    assert loaded.summary.evidence_count == 0
    assert loaded.summary.diagnostics == ()
    assert loaded.summary.lineage_inputs == ()


def test_rejects_failed_artifact_but_preserves_readable_summary(tmp_path: Path) -> None:
    # Given
    invalid_input = R1LineageInput(
        anchor_event_id="evt-missing-anchor",
        terminal_event_id="evt-terminal",
        approved_policy=_policy(),
    )
    with pytest.raises(ValueError, match="anchor_event_id"):
        run_and_write_r1_evidence_artifacts(
            _events(),
            run_id=_RUN_ID,
            output_directory=tmp_path,
            lineage_inputs=[invalid_input],
        )

    # When
    summary = load_r1_extraction_summary(tmp_path)
    with pytest.raises(ValueError, match="failed R1 extraction artifact") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert summary.status == "failed"
    assert summary.error_type == "ValueError"
    assert summary.error_message == (
        "anchor_event_id does not reference an Event in the batch: evt-missing-anchor"
    )
    assert "failed R1 extraction artifact" in str(error_info.value)


def test_rejects_missing_summary_file(tmp_path: Path) -> None:
    # Given
    (tmp_path / R1_EVIDENCE_FILENAME).write_bytes(b"")

    # When
    with pytest.raises(ValueError, match="summary is not valid JSON"):
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert not (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).exists()


def test_rejects_missing_evidence_file(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    (tmp_path / R1_EVIDENCE_FILENAME).unlink()

    # When
    with pytest.raises(ValueError, match="Evidence JSONL is not readable"):
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).exists()


def test_rejects_malformed_summary_json(tmp_path: Path) -> None:
    # Given
    (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).write_text("{", encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="summary is not valid JSON") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "summary is not valid JSON" in str(error_info.value)


def test_rejects_summary_schema_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    summary = _read_summary_payload(tmp_path)
    summary.pop("diagnostics")
    _write_summary_payload(tmp_path, summary)

    # When
    with pytest.raises(ValueError, match="writer contract") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "writer contract" in str(error_info.value)


def test_rejects_damaged_lineage_provenance(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    summary = _read_summary_payload(tmp_path)
    lineage_inputs = summary["lineage_inputs"]
    assert isinstance(lineage_inputs, list)
    assert isinstance(lineage_inputs[0], dict)
    lineage_inputs[0].pop("policy_config_hash")
    _write_summary_payload(tmp_path, summary)

    # When
    with pytest.raises(ValueError, match="writer contract") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "writer contract" in str(error_info.value)


def test_rejects_noncanonical_lineage_provenance_order(tmp_path: Path) -> None:
    # Given
    first_input = _lineage_input(_policy(policy_id="policy-a"))
    second_input = _lineage_input(_policy(policy_id="policy-b"))
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[second_input, first_input],
    )
    summary = _read_summary_payload(tmp_path)
    lineage_inputs = summary["lineage_inputs"]
    assert isinstance(lineage_inputs, list)
    lineage_inputs.reverse()
    _write_summary_payload(tmp_path, summary)

    # When
    with pytest.raises(ValueError, match="writer contract") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "writer contract" in str(error_info.value)


def test_rejects_malformed_evidence_jsonl(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    _replace_evidence_content(tmp_path, b"{not-json\n", synchronize_hash=True)

    # When
    with pytest.raises(ValueError, match="invalid Evidence JSON at line 1") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "invalid Evidence JSON at line 1" in str(error_info.value)


def test_rejects_evidence_schema_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records[0].pop("entity_id")
    content = "".join(f"{json.dumps(record)}\n" for record in records).encode("utf-8")
    _replace_evidence_content(tmp_path, content, synchronize_hash=True)

    # When
    with pytest.raises(ValueError, match="invalid Evidence JSON at line 1") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "invalid Evidence JSON at line 1" in str(error_info.value)


def test_rejects_evidence_sha256_mismatch_without_rewriting_artifacts(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    evidence_path = tmp_path / R1_EVIDENCE_FILENAME
    summary_path = tmp_path / R1_EXTRACTION_SUMMARY_FILENAME
    _replace_evidence_content(
        tmp_path,
        evidence_path.read_bytes() + b" ",
        synchronize_hash=False,
    )
    evidence_before = evidence_path.read_bytes()
    summary_before = summary_path.read_bytes()

    # When
    with pytest.raises(ValueError, match="SHA-256"):
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert evidence_path.read_bytes() == evidence_before
    assert summary_path.read_bytes() == summary_before


def test_rejects_evidence_count_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    summary = _read_summary_payload(tmp_path)
    assert isinstance(summary["evidence_count"], int)
    summary["evidence_count"] += 1
    _write_summary_payload(tmp_path, summary)

    # When
    with pytest.raises(ValueError, match="Evidence count") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "Evidence count" in str(error_info.value)


def test_rejects_noncanonical_evidence_order_with_matching_integrity(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records.reverse()
    _replace_evidence_records(tmp_path, records)

    # When
    with pytest.raises(ValueError, match="canonical ordering") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "canonical ordering" in str(error_info.value)


def test_rejects_unsupported_candidate_type_with_matching_integrity(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records[0]["evidence_type"] = "unsupported_r1_candidate"
    _replace_evidence_records(tmp_path, records)

    # When
    with pytest.raises(ValueError, match="not supported") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "evidence_type" in str(error_info.value)


def test_rejects_managed_s0_type_outside_r1_artifact_scope(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records[0]["evidence_type"] = "encoded_powershell_command"
    _replace_evidence_records(tmp_path, records)

    # When
    with pytest.raises(ValueError, match="not supported") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "evidence_type" in str(error_info.value)


def test_rejects_lineage_policy_provenance_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    lineage_record = next(
        record
        for record in records
        if record["evidence_type"] == REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION
    )
    features = lineage_record["features"]
    assert isinstance(features, dict)
    features["config_hash"] = "sha256:different-policy"
    _replace_evidence_records(tmp_path, records)

    # When
    with pytest.raises(ValueError, match="lineage/policy provenance") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "lineage/policy provenance" in str(error_info.value)


def test_rejects_lineage_anchor_provenance_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    summary = _read_summary_payload(tmp_path)
    lineage_inputs = summary["lineage_inputs"]
    assert isinstance(lineage_inputs, list)
    assert isinstance(lineage_inputs[0], dict)
    lineage_inputs[0]["anchor_event_id"] = "evt-unrelated-anchor"
    _write_summary_payload(tmp_path, summary)

    # When
    with pytest.raises(ValueError, match="lineage/policy provenance") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "lineage/policy provenance" in str(error_info.value)


def test_rejects_network_terminal_provenance_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    network_record = next(
        record for record in records if record["evidence_type"] == REMOTE_PROCESS_NETWORK_FOLLOW_ON
    )
    event_ids = network_record["event_ids"]
    assert isinstance(event_ids, list)
    event_ids[0] = "evt-unrelated-terminal"
    _replace_evidence_records(tmp_path, records)

    # When
    with pytest.raises(ValueError, match="terminal provenance") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "terminal provenance" in str(error_info.value)


def test_accepts_evidence_matching_one_of_multiple_lineage_inputs(tmp_path: Path) -> None:
    # Given
    matching_runtime_policy = _policy(
        approved_lineage=("anchor.exe", "runtime-hop.exe", "terminal.exe"),
        policy_id="policy-a-no-deviation",
        config_hash="sha256:policy-a",
    )
    deviation_policy = _policy(
        policy_id="policy-z-deviation",
        config_hash="sha256:policy-z",
    )
    written = run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[
            _lineage_input(matching_runtime_policy),
            _lineage_input(deviation_policy),
        ],
    )

    # When
    loaded = load_r1_evidence_artifacts(tmp_path)

    # Then
    assert loaded.evidences == written.evidences
    lineage_evidence = next(
        evidence
        for evidence in loaded.evidences
        if evidence.evidence_type == REMOTE_SESSION_PROCESS_LINEAGE_DEVIATION
    )
    assert lineage_evidence.features["policy_id"] == "policy-z-deviation"


def test_rejects_identical_duplicate_evidence_id_with_matching_integrity(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records.insert(1, records[0].copy())
    _replace_evidence_records(tmp_path, records)
    evidence_content = (tmp_path / R1_EVIDENCE_FILENAME).read_bytes()
    summary = _read_summary_payload(tmp_path)
    assert summary["evidence_count"] == len(records)
    assert summary["evidence_artifact_sha256"] == hashlib.sha256(evidence_content).hexdigest()

    # When
    with pytest.raises(ValueError, match="duplicate evidence_id") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "duplicate evidence_id" in str(error_info.value)


def test_rejects_duplicate_evidence_id_collision_with_matching_integrity(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    collision = records[0].copy()
    collision["entity_id"] = "TARGET-B"
    records.insert(1, collision)
    _replace_evidence_records(tmp_path, records)
    evidence_content = (tmp_path / R1_EVIDENCE_FILENAME).read_bytes()
    summary = _read_summary_payload(tmp_path)
    assert summary["evidence_count"] == len(records)
    assert summary["evidence_artifact_sha256"] == hashlib.sha256(evidence_content).hexdigest()

    # When
    with pytest.raises(ValueError, match="duplicate evidence_id") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "duplicate evidence_id" in str(error_info.value)


def test_rejects_evidence_run_id_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records[0]["run_id"] = "RUN-20261006-002"
    content = "".join(f"{json.dumps(record)}\n" for record in records).encode("utf-8")
    _replace_evidence_content(tmp_path, content, synchronize_hash=True)

    # When
    with pytest.raises(ValueError, match="run_id") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "run_id" in str(error_info.value)


def test_rejects_evidence_extractor_version_mismatch(tmp_path: Path) -> None:
    # Given
    run_and_write_r1_evidence_artifacts(
        _events(),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=[_lineage_input()],
    )
    records = _read_jsonl(tmp_path / R1_EVIDENCE_FILENAME)
    records[0]["extractor_version"] = "r1-v9.9"
    content = "".join(f"{json.dumps(record)}\n" for record in records).encode("utf-8")
    _replace_evidence_content(tmp_path, content, synchronize_hash=True)

    # When
    with pytest.raises(ValueError, match="extractor_version") as error_info:
        load_r1_evidence_artifacts(tmp_path)

    # Then
    assert "extractor_version" in str(error_info.value)
