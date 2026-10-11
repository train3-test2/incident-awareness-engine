import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

import incident_awareness.pipeline.r1_causal_availability as causal_availability
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1_EVIDENCE_FILENAME,
    R1_EXTRACTION_SUMMARY_FILENAME,
    R1SelectorProvenance,
    load_r1_evidence_artifacts,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalAvailabilityEnvelope,
    R1CausalEvidenceAvailability,
    build_r1_causal_availability_envelope,
    r1_causal_availability_sort_key,
)
from incident_awareness.pipeline.r1_evidence import R1LineageInput

_RUN_ID = "RUN-20261011-001"
_HOST_ID = "TARGET-A"
_RUN_START = datetime(2026, 10, 11, 1, 0, tzinfo=UTC)
_RUN_END = _RUN_START + timedelta(seconds=10)
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    process_name: str,
    parent_process_guid: str | None = None,
) -> NormalizedEvent:
    is_network = event_type == "network_connection"
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": _RUN_ID,
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
                "raw_log_id": "RAW-R1-CAUSAL",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 4 if is_network else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
                "parent_name": None,
            },
            "network": (
                {
                    "protocol": "tcp",
                    "src_ip": "192.0.2.10",
                    "src_port": 50000,
                    "dst_ip": "192.0.2.20",
                    "dst_port": 443,
                }
                if is_network
                else None
            ),
        }
    )


def _events(*, with_pre_run_context: bool = False) -> tuple[NormalizedEvent, ...]:
    anchor_time = _RUN_START - timedelta(seconds=1) if with_pre_run_context else _RUN_START
    return (
        _event(
            event_id="evt-anchor",
            event_type="process_create",
            timestamp=anchor_time,
            process_guid=_ANCHOR_GUID,
            process_name="anchor.exe",
        ),
        _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_RUN_START + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="runtime-hop.exe",
            parent_process_guid=_ANCHOR_GUID,
        ),
        _event(
            event_id="evt-terminal",
            event_type="process_create",
            timestamp=_RUN_START + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
        _event(
            event_id="evt-network",
            event_type="network_connection",
            timestamp=_RUN_START + timedelta(seconds=3),
            process_guid=_TERMINAL_GUID,
            process_name="terminal.exe",
        ),
    )


def _selector_policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="selector-hash-v0.1",
        lineage_event_count=3,
    )


def _approved_policy() -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="r1-approved-lineage",
        version="v0.1",
        config_hash="approved-hash-v0.1",
        approved_lineage=("anchor.exe", "approved-hop.exe", "terminal.exe"),
    )


def _run_metadata(
    *,
    run_id: str = _RUN_ID,
    target_host: str = _HOST_ID,
    start_time: datetime = _RUN_START,
    end_time: datetime | None = _RUN_END,
) -> RunMetadata:
    return RunMetadata(
        run_id=run_id,
        scenario_id="R1",
        run_type=RunType.ATTACK,
        target_host=target_host,
        start_time=start_time,
        end_time=end_time,
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.3",
            evidence="v0.2",
            fast_hit="v0.1",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.1",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def _write_artifacts(
    output_directory: Path,
    *,
    with_selector: bool = True,
    with_pre_run_context: bool = False,
) -> None:
    policy = _approved_policy()
    context_event_ids = ("evt-anchor",) if with_pre_run_context else ()
    selector_policy = _selector_policy()
    run_and_write_r1_evidence_artifacts(
        _events(with_pre_run_context=with_pre_run_context),
        run_id=_RUN_ID,
        output_directory=output_directory,
        lineage_inputs=(
            R1LineageInput(
                anchor_event_id="evt-anchor",
                terminal_event_id="evt-terminal",
                approved_policy=policy,
                context_event_ids=context_event_ids,
            ),
        ),
        selector_provenance=(
            R1SelectorProvenance(
                policy_id=selector_policy.policy_id,
                version=selector_policy.version,
                config_hash=selector_policy.config_hash,
                status="selected",
                diagnostics=(),
            )
            if with_selector
            else None
        ),
    )


def _build(output_directory: Path, *, run_metadata: RunMetadata | None = None):
    return build_r1_causal_availability_envelope(
        output_directory,
        run_metadata=run_metadata or _run_metadata(),
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
    )


def _availability_payload() -> dict[str, object]:
    return {
        "evidence_id": "E-causal-time-validation",
        "timestamp": _RUN_START + timedelta(seconds=2),
        "available_at": _RUN_END,
        "event_ids": ("evt-terminal",),
        "context_event_ids": (),
    }


def _envelope_payload() -> dict[str, object]:
    return {
        "contract_version": "v0.1",
        "run_id": _RUN_ID,
        "entity_id": _HOST_ID,
        "run_start": _RUN_START,
        "run_end": _RUN_END,
        "watermark_at": _RUN_END,
        "watermark_basis": "authoritative_run_end",
        "selector_policy_identity": {
            "policy_id": "r1-selector",
            "version": "v0.1",
            "config_hash": "selector-hash",
        },
        "approved_policy_identity": {
            "policy_id": "r1-approved-lineage",
            "version": "v0.1",
            "config_hash": "approved-hash",
        },
        "source_extractor_version": "r1-v0.1",
        "source_evidence_count": 0,
        "source_evidence_artifact_sha256": "a" * 64,
        "source_extraction_summary_sha256": "b" * 64,
        "evidences": (),
    }


@pytest.mark.parametrize("numeric_timestamp", [1791676800, 1791676800.5, "1791676800"])
@pytest.mark.parametrize("field_name", ["timestamp", "available_at"])
def test_rejects_numeric_epoch_for_evidence_availability_times(
    field_name: str,
    numeric_timestamp: object,
) -> None:
    # Given
    payload = _availability_payload()
    payload[field_name] = numeric_timestamp

    # When / Then
    with pytest.raises(ValueError, match="숫자형 Unix timestamp"):
        R1CausalEvidenceAvailability.model_validate(payload)


@pytest.mark.parametrize("numeric_timestamp", [1791676800, 1791676800.5, "1791676800"])
@pytest.mark.parametrize("field_name", ["run_start", "run_end", "watermark_at"])
def test_rejects_numeric_epoch_for_envelope_times(
    field_name: str,
    numeric_timestamp: object,
) -> None:
    # Given
    payload = _envelope_payload()
    payload[field_name] = numeric_timestamp

    # When / Then
    with pytest.raises(ValueError, match="숫자형 Unix timestamp"):
        R1CausalAvailabilityEnvelope.model_validate(payload)


def test_accepts_aware_utc_datetime_and_iso_8601_string_times() -> None:
    # Given
    evidence_payload = _availability_payload()
    evidence_payload["available_at"] = _RUN_END.isoformat().replace("+00:00", "Z")
    envelope_payload = _envelope_payload()
    envelope_payload["run_start"] = _RUN_START.isoformat().replace("+00:00", "Z")
    envelope_payload["run_end"] = _RUN_END.isoformat().replace("+00:00", "Z")
    envelope_payload["watermark_at"] = _RUN_END.isoformat().replace("+00:00", "Z")

    # When
    evidence_availability = R1CausalEvidenceAvailability.model_validate(evidence_payload)
    envelope = R1CausalAvailabilityEnvelope.model_validate(envelope_payload)

    # Then
    assert evidence_availability.timestamp == _RUN_START + timedelta(seconds=2)
    assert evidence_availability.available_at == _RUN_END
    assert envelope.run_start == _RUN_START
    assert envelope.run_end == envelope.watermark_at == _RUN_END


@pytest.mark.parametrize(
    "invalid_time",
    [
        _RUN_START.replace(tzinfo=None),
        datetime(2026, 10, 11, 10, 0, tzinfo=timezone(timedelta(hours=9))),
    ],
    ids=["naive", "non-utc"],
)
def test_rejects_non_utc_evidence_and_envelope_times(invalid_time: datetime) -> None:
    # Given
    evidence_payload = _availability_payload()
    evidence_payload["timestamp"] = invalid_time
    envelope_payload = _envelope_payload()
    envelope_payload["run_start"] = invalid_time

    # When / Then
    with pytest.raises(ValueError, match="timezone information|must be UTC"):
        R1CausalEvidenceAvailability.model_validate(evidence_payload)
    with pytest.raises(ValueError, match="timezone information|must be UTC"):
        R1CausalAvailabilityEnvelope.model_validate(envelope_payload)


def test_builds_whole_episode_availability_without_changing_evidence_timestamps(
    tmp_path: Path,
) -> None:
    # Given
    _write_artifacts(tmp_path)

    # When
    envelope = _build(tmp_path)

    # Then
    loaded = load_r1_evidence_artifacts(tmp_path)
    availability_by_id = {item.evidence_id: item for item in envelope.evidences}
    by_type = {
        evidence.evidence_type: availability_by_id[evidence.evidence_id]
        for evidence in loaded.evidences
    }
    lineage = by_type["remote_session_process_lineage_deviation"]
    network = by_type["remote_process_network_follow_on"]
    assert lineage.timestamp == _RUN_START + timedelta(seconds=2)
    assert network.timestamp == _RUN_START + timedelta(seconds=3)
    assert lineage.available_at == _RUN_END
    assert network.available_at == _RUN_END
    assert envelope.watermark_at == _RUN_END
    assert envelope.watermark_basis == "authoritative_run_end"


def test_preserves_source_artifact_provenance_and_round_trips(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)

    # When
    envelope = _build(tmp_path)
    loaded = load_r1_evidence_artifacts(tmp_path)
    restored = R1CausalAvailabilityEnvelope.model_validate_json(envelope.model_dump_json())

    # Then
    assert restored == envelope
    assert envelope.source_evidence_artifact_sha256 == loaded.summary.evidence_artifact_sha256
    assert envelope.source_extraction_summary_sha256 == loaded.summary_artifact_sha256
    assert (
        loaded.summary_artifact_sha256
        == hashlib.sha256((tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_bytes()).hexdigest()
    )


def test_uses_loader_validated_hashes_without_rereading_replaced_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    _write_artifacts(tmp_path)
    real_load = causal_availability.load_r1_evidence_artifacts
    loaded_runs = []

    def load_then_replace(output_directory: Path):
        loaded = real_load(output_directory)
        loaded_runs.append(loaded)
        loaded.evidence_path.write_bytes(b"replaced after validation\n")
        loaded.summary_path.write_bytes(b'{"replaced": true}\n')
        return loaded

    monkeypatch.setattr(
        causal_availability,
        "load_r1_evidence_artifacts",
        load_then_replace,
    )

    # When
    envelope = _build(tmp_path)

    # Then
    loaded = loaded_runs[0]
    assert envelope.source_evidence_artifact_sha256 == loaded.summary.evidence_artifact_sha256
    assert envelope.source_extraction_summary_sha256 == loaded.summary_artifact_sha256
    assert (
        envelope.source_evidence_artifact_sha256
        != hashlib.sha256(loaded.evidence_path.read_bytes()).hexdigest()
    )
    assert (
        envelope.source_extraction_summary_sha256
        != hashlib.sha256(loaded.summary_path.read_bytes()).hexdigest()
    )


def test_rejects_evidence_timestamp_after_authoritative_run_end(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    metadata = _run_metadata(end_time=_RUN_START + timedelta(seconds=2))

    # When / Then
    with pytest.raises(ValueError, match="timestamp must not exceed"):
        _build(tmp_path, run_metadata=metadata)


def test_rejects_evidence_timestamp_before_authoritative_run_start(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    metadata = _run_metadata(start_time=_RUN_START + timedelta(milliseconds=2500))

    # When / Then
    with pytest.raises(ValueError, match="timestamp must not be earlier"):
        _build(tmp_path, run_metadata=metadata)


def test_rejects_run_id_mismatch(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    metadata = _run_metadata(run_id="RUN-20261011-002")

    # When / Then
    with pytest.raises(ValueError, match="run_id must match"):
        _build(tmp_path, run_metadata=metadata)


def test_rejects_entity_mismatch(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    metadata = _run_metadata(target_host="TARGET-B")

    # When / Then
    with pytest.raises(ValueError, match="entity_id must match"):
        _build(tmp_path, run_metadata=metadata)


def test_rejects_selector_provenance_mismatch(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    selector_policy = replace(_selector_policy(), config_hash="different-selector-hash")

    # When / Then
    with pytest.raises(ValueError, match="selector provenance"):
        build_r1_causal_availability_envelope(
            tmp_path,
            run_metadata=_run_metadata(),
            selector_policy=selector_policy,
            approved_policy=_approved_policy(),
        )


def test_rejects_approved_policy_provenance_mismatch(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    policy = replace(_approved_policy(), config_hash="different-approved-hash")

    # When / Then
    with pytest.raises(ValueError, match="approved policy provenance"):
        build_r1_causal_availability_envelope(
            tmp_path,
            run_metadata=_run_metadata(),
            selector_policy=_selector_policy(),
            approved_policy=policy,
        )


def test_rejects_missing_authoritative_run_end(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)

    # When / Then
    with pytest.raises(ValueError, match="authoritative RunMetadata.end_time"):
        _build(tmp_path, run_metadata=_run_metadata(end_time=None))


def test_rejects_manual_artifact_without_selector_provenance(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path, with_selector=False)

    # When / Then
    with pytest.raises(ValueError, match="manual or legacy artifact"):
        _build(tmp_path)


def test_pre_run_context_does_not_advance_availability(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path, with_pre_run_context=True)

    # When
    envelope = _build(tmp_path)

    # Then
    assert envelope.evidences
    assert all(item.context_event_ids == ("evt-anchor",) for item in envelope.evidences)
    assert all(item.available_at == _RUN_END for item in envelope.evidences)
    lineage = next(item for item in envelope.evidences if item.event_ids[-1] == "evt-terminal")
    assert "evt-anchor" not in lineage.event_ids


def test_uses_available_at_timestamp_and_evidence_id_as_deterministic_ordering_key(
    tmp_path: Path,
) -> None:
    # Given
    _write_artifacts(tmp_path)

    # When
    envelope = _build(tmp_path)

    # Then
    assert envelope.evidences == tuple(
        sorted(envelope.evidences, key=r1_causal_availability_sort_key)
    )
    assert [r1_causal_availability_sort_key(item) for item in envelope.evidences] == [
        (item.available_at, item.timestamp, item.evidence_id) for item in envelope.evidences
    ]


def test_does_not_change_existing_evidence_or_two_artifact_contract(tmp_path: Path) -> None:
    # Given
    _write_artifacts(tmp_path)
    evidence_bytes_before = (tmp_path / R1_EVIDENCE_FILENAME).read_bytes()
    summary_bytes_before = (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_bytes()

    # When
    _build(tmp_path)

    # Then
    assert (tmp_path / R1_EVIDENCE_FILENAME).read_bytes() == evidence_bytes_before
    assert (tmp_path / R1_EXTRACTION_SUMMARY_FILENAME).read_bytes() == summary_bytes_before
    assert {path.name for path in tmp_path.iterdir()} == {
        R1_EVIDENCE_FILENAME,
        R1_EXTRACTION_SUMMARY_FILENAME,
    }
    assert all(
        "available_at" not in json.loads(line) for line in evidence_bytes_before.splitlines()
    )
