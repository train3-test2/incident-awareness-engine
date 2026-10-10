import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_reference_policy import R1WmiActionResult
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline import r1_automated
from incident_awareness.pipeline.r1_artifacts import (
    R1_COLLECTION_PROVENANCE_FILENAME,
    load_r1_collection_provenance,
    load_r1_evidence_artifacts,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_automated import (
    run_and_write_r1_evidence_artifacts_from_policy,
    run_and_write_r1_wmi_collection_artifacts,
    run_r1_evidence_pipeline_from_policy,
)
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    R1SelectedEvidencePipelineResult,
    run_r1_evidence_pipeline_with_selector,
)

_RUN_ID = "RUN-20261005-001"
_HOST_ID = "TARGET-A"
_BASE_TIME = datetime(2026, 10, 5, 19, 0, tzinfo=UTC)
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
_POLICY_ID = "r1-v02-development-connection"
_POLICY_VERSION = "v0.1"
_FAMILY_POLICY_ID = "r1-remote-management-approved-lineage"
_FAMILY_POLICY_VERSION = "v0.2"
_FROZEN_POLICY_VERSION = "v0.3"
_WMI_POLICY_ID = "r1-wmi-management-approved-lineage"
_WMI_POLICY_VERSION = "v0.1"
_WMI_REFERENCE_POLICY_ID = "r1-wmi-a01-reference"
_WMI_REFERENCE_POLICY_VERSION = "wmi-ref-v0.1"
_PAIR004_SELECTOR_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "evidence" / "r1_pair004_selector_events.jsonl"
)


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    process_name: str | None,
    parent_process_guid: str | None = None,
    source_record_id: str | None = None,
) -> NormalizedEvent:
    is_network = event_type == "network_connection"
    canonical_source_record_id = source_record_id or f"record-{event_id}"
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
            "source_event_id": canonical_source_record_id,
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-AUTOMATED",
                "source_record_id": canonical_source_record_id,
                "segment_no": 1,
                "record_no": 4 if is_network else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": process_name,
                "path": None if process_name is None else rf"C:\Windows\System32\{process_name}",
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
                if is_network
                else None
            ),
        }
    )


def _events(*, middle_process_name: str | None = "cscript.exe") -> tuple[NormalizedEvent, ...]:
    return (
        _event(
            event_id="evt-anchor",
            event_type="process_create",
            timestamp=_BASE_TIME,
            process_guid=_ANCHOR_GUID,
            process_name="wsmprovhost.exe",
        ),
        _event(
            event_id="evt-middle",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name=middle_process_name,
            parent_process_guid=_ANCHOR_GUID,
        ),
        _event(
            event_id="evt-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="powershell.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
        _event(
            event_id="evt-network",
            event_type="network_connection",
            timestamp=_BASE_TIME + timedelta(seconds=3),
            process_guid=_TERMINAL_GUID,
            process_name="powershell.exe",
        ),
    )


def _wmi_events() -> tuple[NormalizedEvent, ...]:
    return (
        _event(
            event_id="evt-wmi-context",
            event_type="process_create",
            timestamp=_BASE_TIME - timedelta(seconds=1),
            process_guid=_ANCHOR_GUID,
            process_name="WmiPrvSE.exe",
        ),
        _event(
            event_id="evt-wmi-reference",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=1),
            process_guid=_MIDDLE_GUID,
            process_name="cmd.exe",
            parent_process_guid=_ANCHOR_GUID,
            source_record_id="42001",
        ),
        _event(
            event_id="evt-wmi-terminal",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=2),
            process_guid=_TERMINAL_GUID,
            process_name="powershell.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
        _event(
            event_id="evt-wmi-network",
            event_type="network_connection",
            timestamp=_BASE_TIME + timedelta(seconds=3),
            process_guid=_TERMINAL_GUID,
            process_name="powershell.exe",
        ),
    )


def _selector_policy(*, lineage_event_count: int = 3) -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=lineage_event_count,
    )


def _output_directory(tmp_path: Path, name: str) -> Path:
    output_directory = tmp_path / name
    output_directory.mkdir()
    return output_directory


def _pair004_selector_events() -> tuple[NormalizedEvent, ...]:
    return tuple(
        NormalizedEvent.model_validate(json.loads(line))
        for line in _PAIR004_SELECTOR_FIXTURE.read_text(encoding="utf-8").splitlines()
    )


def _derived_pair004_event(
    event: NormalizedEvent,
    *,
    event_id: str,
    process_guid: str | None = None,
) -> NormalizedEvent:
    payload = event.model_dump(mode="json")
    payload["event_id"] = event_id
    payload["source_event_id"] = f"derived-{event_id}"
    payload["raw_ref"]["source_record_id"] = f"derived-{event_id}"
    payload["raw_ref"]["record_no"] += 1000
    if process_guid is not None:
        payload["process"]["process_guid"] = process_guid
    return NormalizedEvent.model_validate(payload)


def _run_pair004_derived_selector(
    events: tuple[NormalizedEvent, ...],
) -> R1SelectedEvidencePipelineResult:
    return run_r1_evidence_pipeline_from_policy(
        events,
        selector_policy=_selector_policy(),
        approved_policy_id=_FAMILY_POLICY_ID,
        approved_policy_version=_FROZEN_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="remote_management",
    )


def test_pair004_derived_fixture_preserves_verified_selection() -> None:
    # Given
    events = _pair004_selector_events()

    # When
    result = _run_pair004_derived_selector(events)

    # Then
    assert result.selector_result.selection is not None
    assert result.selector_result.selection.anchor_event_id == events[0].event_id
    assert result.selector_result.selection.terminal_event_id == events[2].event_id
    assert result.selector_result.diagnostics == ()
    assert {evidence.evidence_type for evidence in result.evidences} == {
        "remote_process_network_follow_on",
        "remote_session_process_lineage_deviation",
    }


def test_pair004_derived_duplicate_guid_publishes_failed_selector_summary(
    tmp_path: Path,
) -> None:
    # Given
    events = _pair004_selector_events()
    duplicate_terminal = _derived_pair004_event(
        events[2],
        event_id="evt-pair004-derived-terminal-duplicate",
    )
    output_directory = _output_directory(tmp_path, "pair004-duplicate")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        (*events, duplicate_terminal),
        run_id=events[0].run_id,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_FAMILY_POLICY_ID,
        approved_policy_version=_FROZEN_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="remote_management",
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.pipeline_result.selector_result.selection is None
    assert result.pipeline_result.selector_result.diagnostics == ("duplicate_process_guid",)
    assert result.pipeline_result.lineage_input is None
    assert result.pipeline_result.evidences == ()
    assert result.artifact_run.evidences == ()
    assert result.artifact_run.evidence_path.is_file()
    assert result.artifact_run.evidence_path.read_bytes() == b""
    assert result.artifact_run.summary_path.is_file()
    assert result.artifact_run.summary.status == "completed"
    assert result.artifact_run.summary.evidence_count == 0
    assert result.artifact_run.summary.lineage_inputs == ()
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.status == "failed"
    assert result.artifact_run.summary.selector.diagnostics == ("duplicate_process_guid",)
    assert loaded.evidences == ()
    assert loaded.summary == result.artifact_run.summary


def test_pair004_derived_truncated_lineage_publishes_failed_selector_summary(
    tmp_path: Path,
) -> None:
    # Given
    anchor, _, terminal, network = _pair004_selector_events()
    output_directory = _output_directory(tmp_path, "pair004-truncated")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        (anchor, terminal, network),
        run_id=anchor.run_id,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_FAMILY_POLICY_ID,
        approved_policy_version=_FROZEN_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="remote_management",
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.pipeline_result.selector_result.selection is None
    assert result.pipeline_result.selector_result.diagnostics == ("truncated_lineage",)
    assert result.pipeline_result.lineage_input is None
    assert result.pipeline_result.evidences == ()
    assert result.artifact_run.evidences == ()
    assert result.artifact_run.evidence_path.is_file()
    assert result.artifact_run.evidence_path.read_bytes() == b""
    assert result.artifact_run.summary_path.is_file()
    assert result.artifact_run.summary.status == "completed"
    assert result.artifact_run.summary.evidence_count == 0
    assert result.artifact_run.summary.lineage_inputs == ()
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.status == "failed"
    assert result.artifact_run.summary.selector.diagnostics == ("truncated_lineage",)
    assert loaded.evidences == ()
    assert loaded.summary == result.artifact_run.summary


def test_pair004_derived_ambiguous_terminal_publishes_failed_selector_summary(
    tmp_path: Path,
) -> None:
    # Given
    events = _pair004_selector_events()
    second_terminal_guid = "{2bf90845-ce86-6ac7-9901-000000000800}"
    second_terminal = _derived_pair004_event(
        events[2],
        event_id="evt-pair004-derived-terminal-ambiguous",
        process_guid=second_terminal_guid,
    )
    second_network = _derived_pair004_event(
        events[3],
        event_id="evt-pair004-derived-network-ambiguous",
        process_guid=second_terminal_guid,
    )
    output_directory = _output_directory(tmp_path, "pair004-ambiguous")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        (*events, second_terminal, second_network),
        run_id=events[0].run_id,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_FAMILY_POLICY_ID,
        approved_policy_version=_FROZEN_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="remote_management",
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.pipeline_result.selector_result.selection is None
    assert result.pipeline_result.selector_result.diagnostics == ("ambiguous_terminal_candidate",)
    assert result.pipeline_result.lineage_input is None
    assert result.pipeline_result.evidences == ()
    assert result.artifact_run.evidences == ()
    assert result.artifact_run.evidence_path.is_file()
    assert result.artifact_run.evidence_path.read_bytes() == b""
    assert result.artifact_run.summary_path.is_file()
    assert result.artifact_run.summary.status == "completed"
    assert result.artifact_run.summary.evidence_count == 0
    assert result.artifact_run.summary.lineage_inputs == ()
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.status == "failed"
    assert result.artifact_run.summary.selector.diagnostics == ("ambiguous_terminal_candidate",)
    assert loaded.evidences == ()
    assert loaded.summary == result.artifact_run.summary


def test_runs_selector_with_loaded_policy_and_matches_manual_path() -> None:
    # Given
    events = _events()
    selector_policy = _selector_policy()
    approved_policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)
    manual = run_r1_evidence_pipeline_with_selector(
        events,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
    )

    # When
    automatic = run_r1_evidence_pipeline_from_policy(
        events,
        selector_policy=selector_policy,
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )

    # Then
    assert automatic == manual
    assert automatic.lineage_input is not None
    assert automatic.lineage_input.approved_policy == approved_policy
    assert {evidence.evidence_type for evidence in automatic.evidences} == {
        "remote_process_network_follow_on",
        "remote_session_process_lineage_deviation",
    }


def test_normal_lineage_creates_only_network_follow_on() -> None:
    # Given
    events = _events(middle_process_name="cmd.exe")

    # When
    result = run_r1_evidence_pipeline_from_policy(
        events,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )

    # Then
    assert [evidence.evidence_type for evidence in result.evidences] == [
        "remote_process_network_follow_on"
    ]
    assert result.selector_result.diagnostics == ()


def test_selector_failure_preserves_diagnostics_and_writes_no_evidence(tmp_path: Path) -> None:
    # Given
    events = (*_events(), *_second_terminal_events())
    output_directory = _output_directory(tmp_path, "selector-failure")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.pipeline_result.selector_result.diagnostics == ("ambiguous_terminal_candidate",)
    assert result.pipeline_result.evidences == ()
    assert result.artifact_run.evidences == ()
    assert result.artifact_run.summary.evidence_count == 0
    assert result.artifact_run.summary.lineage_inputs == ()
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.status == "failed"
    assert result.artifact_run.summary.selector.diagnostics == ("ambiguous_terminal_candidate",)
    assert loaded.summary.selector == result.artifact_run.summary.selector


def test_writes_existing_artifact_contract_with_policy_provenance(tmp_path: Path) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "artifacts")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        _events(),
        run_id=_RUN_ID,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.artifact_run.evidence_path.name == "r1_evidence.jsonl"
    assert result.artifact_run.summary_path.name == "r1_extraction_summary.json"
    assert result.artifact_run.summary.evidence_count == 2
    assert result.artifact_run.summary.lineage_inputs is not None
    provenance = result.artifact_run.summary.lineage_inputs[0]
    assert provenance.anchor_event_id == "evt-anchor"
    assert provenance.terminal_event_id == "evt-terminal"
    assert provenance.policy_id == _POLICY_ID
    assert provenance.policy_version == _POLICY_VERSION
    assert provenance.policy_config_hash == (
        result.pipeline_result.lineage_input.approved_policy.config_hash
    )
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.policy_id == ("r1-structural-lineage-selector")
    assert result.artifact_run.summary.selector.version == "v0.1"
    assert result.artifact_run.summary.selector.config_hash == _selector_policy().config_hash
    assert result.artifact_run.summary.selector.status == "selected"
    assert result.artifact_run.summary.selector.diagnostics == ()
    assert loaded.evidences == result.artifact_run.evidences
    assert loaded.summary == result.artifact_run.summary


def test_extraction_diagnostic_is_preserved_in_runtime_and_summary(tmp_path: Path) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "extraction-diagnostic")

    # When
    result = run_and_write_r1_evidence_artifacts_from_policy(
        _events(middle_process_name=None),
        run_id=_RUN_ID,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )

    # Then
    assert result.pipeline_result.extraction_diagnostics == ("missing_or_blank_process_name",)
    assert result.artifact_run.summary.diagnostics == ("missing_or_blank_process_name",)
    assert [evidence.evidence_type for evidence in result.artifact_run.evidences] == [
        "remote_process_network_follow_on"
    ]
    assert result.artifact_run.summary.selector is not None
    assert result.artifact_run.summary.selector.status == "selected"


def test_manual_zero_evidence_is_distinct_from_selector_failure(tmp_path: Path) -> None:
    # Given
    anchor, middle, terminal, _ = _events(middle_process_name="cmd.exe")
    approved_policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)
    lineage_input = R1LineageInput(
        anchor_event_id=anchor.event_id,
        terminal_event_id=terminal.event_id,
        approved_policy=approved_policy,
    )
    output_directory = _output_directory(tmp_path, "manual-zero")

    # When
    result = run_and_write_r1_evidence_artifacts(
        (anchor, middle, terminal),
        run_id=_RUN_ID,
        output_directory=output_directory,
        lineage_inputs=(lineage_input,),
    )
    loaded = load_r1_evidence_artifacts(output_directory)
    summary_payload = json.loads(result.summary_path.read_text(encoding="utf-8"))

    # Then
    assert result.evidences == ()
    assert result.summary.selector is None
    assert loaded.summary.selector is None
    assert "selector" not in summary_payload


def test_unknown_policy_fails_before_artifact_creation(tmp_path: Path) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "unknown-policy")

    # When
    with pytest.raises(ValueError, match="was not found"):
        run_and_write_r1_evidence_artifacts_from_policy(
            _events(),
            run_id=_RUN_ID,
            output_directory=output_directory,
            selector_policy=_selector_policy(),
            approved_policy_id="unknown-policy",
            approved_policy_version=_POLICY_VERSION,
        )

    # Then
    assert tuple(output_directory.iterdir()) == ()


def test_invalid_policy_config_fails_before_artifact_creation(tmp_path: Path) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "invalid-policy")
    config_path = tmp_path / "invalid-policy.yaml"
    config_path.write_text("config_version: v0.1\npolicies: []\n", encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        run_and_write_r1_evidence_artifacts_from_policy(
            _events(),
            run_id=_RUN_ID,
            output_directory=output_directory,
            selector_policy=_selector_policy(),
            approved_policy_id=_POLICY_ID,
            approved_policy_version=_POLICY_VERSION,
            approved_policy_config_path=config_path,
        )

    # Then
    assert tuple(output_directory.iterdir()) == ()


def test_depth_mismatch_preserves_existing_failure_before_artifact_creation(
    tmp_path: Path,
) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "depth-mismatch")

    # When
    with pytest.raises(
        ValueError,
        match="selector lineage_event_count must match approved_lineage length",
    ):
        run_and_write_r1_evidence_artifacts_from_policy(
            _events(),
            run_id=_RUN_ID,
            output_directory=output_directory,
            selector_policy=_selector_policy(lineage_event_count=2),
            approved_policy_id=_POLICY_ID,
            approved_policy_version=_POLICY_VERSION,
        )

    # Then
    assert tuple(output_directory.iterdir()) == ()


def test_shuffled_input_produces_identical_evidence_and_artifacts(tmp_path: Path) -> None:
    # Given
    events = _events()
    first_output = _output_directory(tmp_path, "first")
    second_output = _output_directory(tmp_path, "second")

    # When
    first = run_and_write_r1_evidence_artifacts_from_policy(
        events,
        run_id=_RUN_ID,
        output_directory=first_output,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )
    second = run_and_write_r1_evidence_artifacts_from_policy(
        reversed(events),
        run_id=_RUN_ID,
        output_directory=second_output,
        selector_policy=_selector_policy(),
        approved_policy_id=_POLICY_ID,
        approved_policy_version=_POLICY_VERSION,
    )

    # Then
    assert first.pipeline_result == second.pipeline_result
    assert first.artifact_run.evidences == second.artifact_run.evidences
    assert first.artifact_run.evidence_path.read_bytes() == (
        second.artifact_run.evidence_path.read_bytes()
    )
    assert first.artifact_run.summary_path.read_bytes() == (
        second.artifact_run.summary_path.read_bytes()
    )


def test_family_bound_policy_runs_for_matching_scenario_family() -> None:
    # Given
    events = _events()

    # When
    result = run_r1_evidence_pipeline_from_policy(
        events,
        selector_policy=_selector_policy(),
        approved_policy_id=_FAMILY_POLICY_ID,
        approved_policy_version=_FAMILY_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="remote_management",
    )

    # Then
    assert result.lineage_input is not None
    assert result.lineage_input.approved_policy.family_id == "remote_management"
    assert result.lineage_input.approved_policy.lifecycle == "development"


def test_family_mismatch_fails_before_selector_and_artifact_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    output_directory = _output_directory(tmp_path, "family-mismatch")
    selector_calls: list[object] = []
    monkeypatch.setattr(
        r1_automated,
        "run_r1_evidence_pipeline_with_selector",
        lambda *args, **kwargs: selector_calls.append((args, kwargs)),
    )

    # When
    with pytest.raises(ValueError, match="does not match approved policy family_id"):
        run_and_write_r1_evidence_artifacts_from_policy(
            _events(),
            run_id=_RUN_ID,
            output_directory=output_directory,
            selector_policy=_selector_policy(),
            approved_policy_id=_FAMILY_POLICY_ID,
            approved_policy_version=_FAMILY_POLICY_VERSION,
            approved_policy_config_path=(DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH),
            scenario_family_id="other_family",
        )

    # Then
    assert selector_calls == []
    assert tuple(output_directory.iterdir()) == ()


def test_family_bound_policy_requires_scenario_family_before_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    selector_calls: list[object] = []
    monkeypatch.setattr(
        r1_automated,
        "run_r1_evidence_pipeline_with_selector",
        lambda *args, **kwargs: selector_calls.append((args, kwargs)),
    )

    # When
    with pytest.raises(ValueError, match="scenario_family_id is required"):
        run_r1_evidence_pipeline_from_policy(
            _events(),
            selector_policy=_selector_policy(),
            approved_policy_id=_FAMILY_POLICY_ID,
            approved_policy_version=_FAMILY_POLICY_VERSION,
            approved_policy_config_path=(DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH),
        )

    # Then
    assert selector_calls == []


def test_wmi_collection_path_publishes_reference_provenance_artifact(
    tmp_path: Path,
) -> None:
    # Given
    events = _wmi_events()
    output_directory = _output_directory(tmp_path, "wmi-collection")
    action_result = R1WmiActionResult(
        action_id="A01",
        action_type="wmi_process_create",
        invocation_method="Win32_Process.Create",
        invoked_at_utc=_BASE_TIME + timedelta(milliseconds=500),
        return_value=0,
        process_id=4200,
    )

    # When
    result = run_and_write_r1_wmi_collection_artifacts(
        events,
        run_id=_RUN_ID,
        output_directory=output_directory,
        selector_policy=_selector_policy(),
        approved_policy_id=_WMI_POLICY_ID,
        approved_policy_version=_WMI_POLICY_VERSION,
        approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        scenario_family_id="wmi_management",
        reference_policy_id=_WMI_REFERENCE_POLICY_ID,
        reference_policy_version=_WMI_REFERENCE_POLICY_VERSION,
        evaluation_horizon_sec=600,
        action_result=action_result,
        action_attributed_event_ids=("evt-wmi-reference",),
        lineage_process_guids=(_ANCHOR_GUID, _MIDDLE_GUID, _TERMINAL_GUID),
        scenario_identifier="scenarios/R1/wmi-v01.json",
        scenario_version="v1",
        execution_commit="0123456789abcdef",
        run_start=_BASE_TIME,
    )
    loaded_provenance = load_r1_collection_provenance(output_directory)
    loaded_evidence = load_r1_evidence_artifacts(output_directory)

    # Then
    assert result.collection_provenance_path == (
        output_directory / R1_COLLECTION_PROVENANCE_FILENAME
    )
    assert result.collection_provenance_path.is_file()
    assert loaded_provenance == result.collection_provenance
    assert loaded_provenance.run_id == _RUN_ID
    assert loaded_provenance.reference_policy_id == _WMI_REFERENCE_POLICY_ID
    assert loaded_provenance.reference_policy_version == _WMI_REFERENCE_POLICY_VERSION
    assert loaded_provenance.horizon_matches is True
    assert loaded_evidence == result.evidence_run.artifact_run


def test_wmi_collection_reference_failure_publishes_no_artifact(tmp_path: Path) -> None:
    # Given
    events = _wmi_events()
    output_directory = _output_directory(tmp_path, "wmi-reference-failure")
    failed_action_result = R1WmiActionResult(
        action_id="A01",
        action_type="wmi_process_create",
        invocation_method="Win32_Process.Create",
        invoked_at_utc=_BASE_TIME + timedelta(milliseconds=500),
        return_value=1,
        process_id=4200,
    )

    # When
    with pytest.raises(ValueError, match="WMI A01 did not succeed"):
        run_and_write_r1_wmi_collection_artifacts(
            events,
            run_id=_RUN_ID,
            output_directory=output_directory,
            selector_policy=_selector_policy(),
            approved_policy_id=_WMI_POLICY_ID,
            approved_policy_version=_WMI_POLICY_VERSION,
            approved_policy_config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
            scenario_family_id="wmi_management",
            reference_policy_id=_WMI_REFERENCE_POLICY_ID,
            reference_policy_version=_WMI_REFERENCE_POLICY_VERSION,
            evaluation_horizon_sec=600,
            action_result=failed_action_result,
            action_attributed_event_ids=("evt-wmi-reference",),
            lineage_process_guids=(_ANCHOR_GUID, _MIDDLE_GUID, _TERMINAL_GUID),
            scenario_identifier="scenarios/R1/wmi-v01.json",
            scenario_version="v1",
            execution_commit="0123456789abcdef",
            run_start=_BASE_TIME,
        )

    # Then
    assert tuple(output_directory.iterdir()) == ()


def _second_terminal_events() -> tuple[NormalizedEvent, NormalizedEvent]:
    second_guid = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
    return (
        _event(
            event_id="evt-terminal-2",
            event_type="process_create",
            timestamp=_BASE_TIME + timedelta(seconds=4),
            process_guid=second_guid,
            process_name="alternate.exe",
            parent_process_guid=_MIDDLE_GUID,
        ),
        _event(
            event_id="evt-network-2",
            event_type="network_connection",
            timestamp=_BASE_TIME + timedelta(seconds=5),
            process_guid=second_guid,
            process_name="alternate.exe",
        ),
    )
