import json
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_reference_policy import (
    DEFAULT_R1_REFERENCE_POLICIES_PATH,
    R1_REFERENCE_POLICY_LOADER_VERSION,
    R1WmiActionResult,
    load_r1_reference_policies,
    load_r1_reference_policy,
    resolve_r1_wmi_reference,
    validate_normal_reference_fields,
)
from incident_awareness.pipeline.r1_artifacts import (
    R1_COLLECTION_PROVENANCE_CONTRACT_VERSION,
    R1_COLLECTION_PROVENANCE_FILENAME,
    build_r1_collection_provenance,
    load_r1_collection_provenance,
)
from incident_awareness.pipeline.r1_artifacts import (
    write_r1_collection_provenance as _write_r1_collection_provenance,
)

_POLICY_ID = "r1-wmi-a01-reference"
_POLICY_VERSION = "wmi-ref-v0.1"
_ACTUAL_POLICY_HASH = "ddce36c637226b1a31033591973f64c819fe3f3240ea4c369d6343582445e2d8"
_REFERENCE_TIME = datetime(2026, 10, 10, 1, 0, 1, tzinfo=UTC)
_REFERENCE_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_CONTEXT_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"


def write_r1_collection_provenance(selection, *, run_id: str, output_directory: Path):
    return _write_r1_collection_provenance(
        selection,
        run_id=run_id,
        output_directory=output_directory,
        scenario_identifier="scenarios/R1/wmi-v01.json",
        scenario_version="v1",
        execution_commit="0123456789abcdef",
    )


def _policy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "policy_id": _POLICY_ID,
        "version": _POLICY_VERSION,
        "family_id": "wmi_management",
        "reference_action_id": "A01",
        "action_type": "wmi_process_create",
        "invocation_method": "Win32_Process.Create",
        "success_return_value": 0,
        "require_process_id": True,
        "reference_source": "sysmon",
        "reference_source_layer": "raw_telemetry",
        "reference_event_type": "process_create",
        "reference_process_name": "cmd.exe",
        "candidate_start_offset_sec": 0,
        "candidate_window_sec": 2,
        "expected_evaluation_horizon_sec": 600,
    }
    payload.update(overrides)
    return payload


def _write_registry(
    path: Path,
    *,
    policies: object,
    config_version: object = "v0.1",
) -> None:
    path.write_text(
        json.dumps(
            {
                "config_version": config_version,
                "policies": policies,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _reference_event(
    *,
    event_id: str = "evt-reference",
    process_guid: str = _REFERENCE_GUID,
    process_name: str = "cmd.exe",
    pid: int = 4100,
    parent_process_guid: str = _CONTEXT_GUID,
    run_id: str = "RUN-20261010-001",
    host_id: str = "TARGET-A",
    reference_time: datetime = _REFERENCE_TIME,
    source_event_id: str = "42001",
    source_record_id: str | None = "42001",
) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": run_id,
            "timestamp": reference_time,
            "timestamp_source": "event_time",
            "event_time": reference_time,
            "record_time": reference_time,
            "ingest_time": reference_time,
            "host_id": host_id,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": source_event_id,
            "event_type": "process_create",
            "raw_ref": {
                "raw_log_id": "RAW-R1-WMI-REFERENCE",
                "source_record_id": source_record_id,
                "segment_no": 1,
                "record_no": 10,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": pid,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
                "parent_name": None,
            },
            "network": None,
        }
    )


def _context_event(
    *,
    event_id: str = "evt-context",
    process_guid: str = _CONTEXT_GUID,
    run_id: str = "RUN-20261010-001",
    host_id: str = "TARGET-A",
) -> NormalizedEvent:
    return _reference_event(
        event_id=event_id,
        process_guid=process_guid,
        process_name="WmiPrvSE.exe",
        pid=4000,
        parent_process_guid="{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}",
        run_id=run_id,
        host_id=host_id,
        reference_time=_REFERENCE_TIME - timedelta(seconds=1),
    )


def _action_result(
    *,
    action_id: str = "A01",
    action_type: str = "wmi_process_create",
    invocation_method: str = "Win32_Process.Create",
    invoked_at_utc: datetime = _REFERENCE_TIME - timedelta(milliseconds=1),
    return_value: int = 0,
    process_id: int | None = 4100,
) -> R1WmiActionResult:
    return R1WmiActionResult(
        action_id=action_id,
        action_type=action_type,
        invocation_method=invocation_method,
        invoked_at_utc=invoked_at_utc,
        return_value=return_value,
        process_id=process_id,
    )


def _resolve(
    events: tuple[NormalizedEvent, ...],
    *,
    action_result: R1WmiActionResult | None = None,
    a01_started_at_utc: datetime | None = None,
    context_event: NormalizedEvent | None = None,
    action_attributed_event_ids: tuple[str, ...] = ("evt-reference",),
    lineage_process_guids: tuple[str, ...] = (_CONTEXT_GUID, _REFERENCE_GUID),
    expected_run_id: str = "RUN-20261010-001",
    target_host: str = "TARGET-A",
    family_id: str = "wmi_management",
    reference_policy_version: str = _POLICY_VERSION,
    evaluation_horizon_sec: int = 600,
):
    policy = load_r1_reference_policy(_POLICY_ID, _POLICY_VERSION)
    selected_action_result = action_result or _action_result()
    return resolve_r1_wmi_reference(
        (context_event or _context_event(), *events),
        policy=policy,
        expected_run_id=expected_run_id,
        target_host=target_host,
        scenario_family_id=family_id,
        reference_policy_version=reference_policy_version,
        evaluation_horizon_sec=evaluation_horizon_sec,
        action_result=selected_action_result,
        a01_started_at_utc=a01_started_at_utc or selected_action_result.invoked_at_utc,
        action_attributed_event_ids=action_attributed_event_ids,
        lineage_process_guids=lineage_process_guids,
    )


def test_loads_managed_wmi_reference_policy() -> None:
    # Given
    config_path = DEFAULT_R1_REFERENCE_POLICIES_PATH

    # When
    policy = load_r1_reference_policy(_POLICY_ID, _POLICY_VERSION)

    # Then
    assert config_path.is_file()
    assert policy.policy_id == _POLICY_ID
    assert policy.version == _POLICY_VERSION
    assert policy.family_id == "wmi_management"
    assert policy.reference_action_id == "A01"
    assert policy.expected_evaluation_horizon_sec == 600
    assert policy.config_hash == _ACTUAL_POLICY_HASH
    assert policy.candidate_start_offset_sec == 0
    assert policy.candidate_window_sec == 2


def test_semantically_identical_config_has_same_canonical_hash(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "reordered.yaml"
    config_path.write_text(
        """policies:
  - expected_evaluation_horizon_sec: 600
    candidate_start_offset_sec: 0
    candidate_window_sec: 2
    reference_process_name: cmd.exe
    reference_event_type: process_create
    reference_source_layer: raw_telemetry
    reference_source: sysmon
    require_process_id: true
    success_return_value: 0
    action_type: wmi_process_create
    invocation_method: Win32_Process.Create
    reference_action_id: A01
    family_id: wmi_management
    version: wmi-ref-v0.1
    policy_id: r1-wmi-a01-reference
config_version: v0.1
""",
        encoding="utf-8",
    )

    # When
    policy = load_r1_reference_policy(_POLICY_ID, _POLICY_VERSION, config_path=config_path)

    # Then
    assert policy.config_hash == _ACTUAL_POLICY_HASH
    assert policy.canonical_path == (
        f"external-policy:{_POLICY_ID}/{_POLICY_VERSION}@{_ACTUAL_POLICY_HASH}"
    )
    assert str(tmp_path) not in policy.canonical_path


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("policy_id", "r1-wmi-a01-reference-next"),
        ("version", "wmi-ref-v0.2"),
        ("family_id", "remote_management"),
        ("expected_evaluation_horizon_sec", 601),
    ],
)
def test_policy_identity_and_binding_changes_change_hash(
    tmp_path: Path,
    changed_field: str,
    changed_value: object,
) -> None:
    # Given
    base_path = tmp_path / "base.yaml"
    changed_path = tmp_path / "changed.yaml"
    _write_registry(base_path, policies=[_policy_payload()])
    _write_registry(
        changed_path,
        policies=[_policy_payload(**{changed_field: changed_value})],
    )

    # When
    base = load_r1_reference_policies(base_path)[0]
    changed = load_r1_reference_policies(changed_path)[0]

    # Then
    assert changed.config_hash != base.config_hash


@pytest.mark.parametrize(
    "invalid_policy",
    [
        {**_policy_payload(), "unknown": "value"},
        {key: value for key, value in _policy_payload().items() if key != "family_id"},
        {**_policy_payload(), "expected_evaluation_horizon_sec": "600"},
        {**_policy_payload(), "require_process_id": 1},
    ],
)
def test_rejects_malformed_policy_config(
    tmp_path: Path,
    invalid_policy: dict[str, object],
) -> None:
    # Given
    config_path = tmp_path / "invalid.yaml"
    _write_registry(config_path, policies=[invalid_policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_reference_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_duplicate_policy_identity(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "duplicate.yaml"
    _write_registry(config_path, policies=[_policy_payload(), _policy_payload()])

    # When
    with pytest.raises(ValueError, match="identities must be unique"):
        load_r1_reference_policies(config_path)

    # Then
    assert config_path.is_file()


def test_selects_single_a01_attributed_lineage_event() -> None:
    # Given
    reference_event = _reference_event()

    # When
    selection = _resolve((reference_event,))

    # Then
    assert selection.reference_action_id == "A01"
    assert selection.run_id == reference_event.run_id
    assert selection.entity_id == reference_event.host_id
    assert selection.target_host == reference_event.host_id
    assert selection.reference_time == _REFERENCE_TIME
    assert selection.reference_source_event_id == "42001"
    assert selection.reference_event_id == "evt-reference"
    assert selection.policy_id == _POLICY_ID
    assert selection.reference_policy_version == _POLICY_VERSION
    assert selection.policy_config_hash == _ACTUAL_POLICY_HASH
    assert selection.policy_config_path == "configs/r1_reference_policies_v0.1.yaml"
    assert selection.scenario_evaluation_horizon_sec == 600
    assert selection.expected_evaluation_horizon_sec == 600
    assert selection.horizon_matches is True


def test_writes_and_loads_reference_policy_runtime_provenance(tmp_path: Path) -> None:
    # Given
    reference_event = _reference_event()
    selection = _resolve((reference_event,))

    # When
    written, provenance_path = write_r1_collection_provenance(
        selection,
        run_id=reference_event.run_id,
        output_directory=tmp_path,
    )
    loaded = load_r1_collection_provenance(tmp_path)
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))

    # Then
    assert provenance_path == tmp_path / R1_COLLECTION_PROVENANCE_FILENAME
    assert loaded == written
    assert payload["reference_policy_canonical_path"] == ("configs/r1_reference_policies_v0.1.yaml")
    assert payload["selected_target_host"] == reference_event.host_id
    assert payload["reference_policy_id"] == _POLICY_ID
    assert payload["reference_policy_version"] == _POLICY_VERSION
    assert payload["reference_policy_config_hash"] == _ACTUAL_POLICY_HASH
    assert payload["loader_selected_policy_identity"] == {
        "config_hash": _ACTUAL_POLICY_HASH,
        "policy_id": _POLICY_ID,
        "version": _POLICY_VERSION,
    }
    assert payload["scenario_evaluation_horizon_sec"] == 600
    assert payload["policy_expected_evaluation_horizon_sec"] == 600
    assert payload["horizon_matches"] is True
    assert payload["scenario_identifier"] == "scenarios/R1/wmi-v01.json"
    assert payload["scenario_version"] == "v1"
    assert payload["reference_action_id"] == "A01"
    assert payload["reference_time"] == "2026-10-10T01:00:01Z"
    assert payload["reference_source_event_id"] == "42001"
    assert payload["reference_event_id"] == "evt-reference"
    assert payload["action_process_id"] == 4100
    assert payload["execution_commit"] == "0123456789abcdef"
    assert payload["loader_version"] == R1_REFERENCE_POLICY_LOADER_VERSION
    assert payload["contract_version"] == R1_COLLECTION_PROVENANCE_CONTRACT_VERSION


def test_collection_provenance_serialization_is_deterministic(tmp_path: Path) -> None:
    # Given
    selection = _resolve((_reference_event(),))
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()

    # When
    _, first_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=first_directory,
    )
    _, second_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=second_directory,
    )

    # Then
    assert first_path.read_bytes() == second_path.read_bytes()


def test_collection_provenance_does_not_overwrite_existing_artifact(tmp_path: Path) -> None:
    # Given
    selection = _resolve((_reference_event(),))
    _, provenance_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=tmp_path,
    )
    original_content = provenance_path.read_bytes()

    # When
    with pytest.raises(FileExistsError, match=R1_COLLECTION_PROVENANCE_FILENAME):
        write_r1_collection_provenance(
            selection,
            run_id=selection.run_id,
            output_directory=tmp_path,
        )

    # Then
    assert provenance_path.read_bytes() == original_content


def test_collection_provenance_loader_rejects_unknown_fields(tmp_path: Path) -> None:
    # Given
    selection = _resolve((_reference_event(),))
    _, provenance_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=tmp_path,
    )
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    payload["unknown"] = "value"
    provenance_path.write_text(json.dumps(payload), encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="does not match the writer contract"):
        load_r1_collection_provenance(tmp_path)

    # Then
    assert payload["unknown"] == "value"


def test_collection_provenance_loader_requires_selected_target_host(tmp_path: Path) -> None:
    # Given
    selection = _resolve((_reference_event(),))
    _, provenance_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=tmp_path,
    )
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    del payload["selected_target_host"]
    provenance_path.write_text(json.dumps(payload), encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="does not match the writer contract"):
        load_r1_collection_provenance(tmp_path)

    # Then
    assert "selected_target_host" not in payload


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("contract_version", "v9.9"),
        ("contract_version", None),
        ("loader_version", "spoofed-loader"),
        ("loader_version", None),
    ],
)
def test_collection_provenance_loader_rejects_wrong_or_missing_implementation_versions(
    tmp_path: Path,
    field_name: str,
    invalid_value: str | None,
) -> None:
    # Given
    selection = _resolve((_reference_event(),))
    _, provenance_path = write_r1_collection_provenance(
        selection,
        run_id=selection.run_id,
        output_directory=tmp_path,
    )
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    if invalid_value is None:
        del payload[field_name]
    else:
        payload[field_name] = invalid_value
    provenance_path.write_text(json.dumps(payload), encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="does not match the writer contract"):
        load_r1_collection_provenance(tmp_path)

    # Then
    assert payload.get(field_name) != (
        R1_COLLECTION_PROVENANCE_CONTRACT_VERSION
        if field_name == "contract_version"
        else R1_REFERENCE_POLICY_LOADER_VERSION
    )


def test_collection_provenance_versions_are_not_caller_controlled() -> None:
    # Given
    writer_parameters = signature(_write_r1_collection_provenance).parameters
    builder_parameters = signature(build_r1_collection_provenance).parameters

    # When
    caller_controlled_parameters = {
        "contract_version",
        "loader_version",
    } & (writer_parameters.keys() | builder_parameters.keys())

    # Then
    assert caller_controlled_parameters == set()


def test_process_name_alone_does_not_select_reference() -> None:
    # Given
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,), action_attributed_event_ids=())

    # Then
    assert reference_event.process is not None
    assert reference_event.process.name == "cmd.exe"


def test_reference_requires_process_guid_lineage_membership() -> None:
    # Given
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,), lineage_process_guids=("{OTHER-GUID}",))

    # Then
    assert reference_event.process is not None
    assert reference_event.process.pid == 4100


@pytest.mark.parametrize(
    "event_overrides",
    [
        {"pid": 4101},
        {"parent_process_guid": "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"},
        {"host_id": "TARGET-B"},
        {"run_id": "RUN-20261010-002"},
    ],
)
def test_reference_requires_a01_pid_and_same_scope_wmi_parent(
    event_overrides: dict[str, object],
) -> None:
    # Given
    reference_event = _reference_event(**event_overrides)

    # When / Then
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,))


@pytest.mark.parametrize(
    ("expected_run_id", "target_host"),
    [
        ("RUN-20261010-002", "TARGET-A"),
        ("RUN-20261010-001", "TARGET-B"),
    ],
)
def test_reference_fails_closed_when_expected_identity_does_not_match(
    expected_run_id: str,
    target_host: str,
) -> None:
    # Given
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve(
            (reference_event,),
            expected_run_id=expected_run_id,
            target_host=target_host,
        )

    # Then
    assert reference_event.run_id == "RUN-20261010-001"
    assert reference_event.host_id == "TARGET-A"


@pytest.mark.parametrize(
    ("other_run_id", "other_host_id"),
    [
        ("RUN-20261010-002", "TARGET-A"),
        ("RUN-20261010-001", "TARGET-B"),
    ],
)
def test_reference_rejects_candidate_and_context_outside_expected_scope(
    other_run_id: str,
    other_host_id: str,
) -> None:
    # Given
    context = _context_event(run_id=other_run_id, host_id=other_host_id)
    reference_event = _reference_event(run_id=other_run_id, host_id=other_host_id)

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,), context_event=context)

    # Then
    assert reference_event.run_id == context.run_id
    assert reference_event.host_id == context.host_id


def test_reference_rejects_context_on_another_host() -> None:
    # Given
    context = _context_event(host_id="TARGET-B")
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,), context_event=context)

    # Then
    assert reference_event.host_id != context.host_id


def test_reference_selects_only_expected_host_pair_from_mixed_batch() -> None:
    # Given
    other_context_guid = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
    other_reference_guid = "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"
    target_reference = _reference_event()
    other_context = _context_event(
        event_id="evt-other-context",
        process_guid=other_context_guid,
        host_id="TARGET-B",
    )
    other_reference = _reference_event(
        event_id="evt-other-reference",
        process_guid=other_reference_guid,
        parent_process_guid=other_context_guid,
        host_id="TARGET-B",
        source_event_id="42002",
        source_record_id="42002",
    )

    # When
    selection = _resolve(
        (target_reference, other_context, other_reference),
        action_attributed_event_ids=(target_reference.event_id, other_reference.event_id),
        lineage_process_guids=(
            _CONTEXT_GUID,
            _REFERENCE_GUID,
            other_context_guid,
            other_reference_guid,
        ),
    )

    # Then
    assert selection.reference_event_id == target_reference.event_id
    assert selection.target_host == "TARGET-A"


@pytest.mark.parametrize("offset_seconds", [0, 2])
def test_reference_candidate_window_includes_boundaries(offset_seconds: int) -> None:
    # Given
    event = _reference_event(reference_time=_REFERENCE_TIME + timedelta(seconds=offset_seconds))

    # When
    selection = _resolve((event,), action_result=_action_result(invoked_at_utc=_REFERENCE_TIME))

    # Then
    assert selection.reference_event_id == event.event_id


@pytest.mark.parametrize("offset_seconds", [-1, 3])
def test_reference_candidate_window_rejects_outside(offset_seconds: int) -> None:
    # Given
    event = _reference_event(reference_time=_REFERENCE_TIME + timedelta(seconds=offset_seconds))

    # When / Then
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((event,), action_result=_action_result(invoked_at_utc=_REFERENCE_TIME))


def test_reference_rejects_mismatched_action_and_execution_anchor_times() -> None:
    # Given
    reference_event = _reference_event()
    action_result = _action_result(invoked_at_utc=_REFERENCE_TIME)

    # When
    with pytest.raises(ValueError, match="must match the A01 execution record start time"):
        _resolve(
            (reference_event,),
            action_result=action_result,
            a01_started_at_utc=_REFERENCE_TIME + timedelta(milliseconds=1),
        )

    # Then
    assert action_result.invoked_at_utc == _REFERENCE_TIME


def test_candidate_cardinality_is_evaluated_after_time_filtering() -> None:
    # Given
    inside = _reference_event()
    outside_guid = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
    outside = _reference_event(
        event_id="evt-outside",
        process_guid=outside_guid,
        reference_time=_REFERENCE_TIME + timedelta(seconds=3),
        source_event_id="42002",
        source_record_id="42002",
    )

    # When
    selection = _resolve(
        (inside, outside),
        action_attributed_event_ids=(inside.event_id, outside.event_id),
        lineage_process_guids=(_CONTEXT_GUID, _REFERENCE_GUID, outside_guid),
        action_result=_action_result(invoked_at_utc=_REFERENCE_TIME),
    )

    # Then
    assert selection.reference_event_id == inside.event_id


@pytest.mark.parametrize(
    ("source_event_id", "source_record_id"),
    [
        ("42001", None),
        ("42001", "not-an-integer"),
        ("42001", "042001"),
        ("42001", "+42001"),
        ("42001", " 42001"),
        ("42001", "42002"),
    ],
)
def test_reference_requires_matching_canonical_sysmon_record_id(
    source_event_id: str,
    source_record_id: str | None,
) -> None:
    # Given
    event = _reference_event(
        source_event_id=source_event_id,
        source_record_id=source_record_id,
    )

    # When / Then
    with pytest.raises(ValueError, match="source_record_id|source_event_id"):
        _resolve((event,))


def test_rejects_multiple_reference_candidates() -> None:
    # Given
    first = _reference_event()
    second_guid = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
    second = _reference_event(event_id="evt-reference-2", process_guid=second_guid)

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 2"):
        _resolve(
            (first, second),
            action_attributed_event_ids=(first.event_id, second.event_id),
            lineage_process_guids=(_CONTEXT_GUID, _REFERENCE_GUID, second_guid),
        )

    # Then
    assert first.source_event_id == second.source_event_id


@pytest.mark.parametrize(
    "action_result",
    [
        _action_result(return_value=1),
        _action_result(process_id=None),
        _action_result(process_id=0),
    ],
)
def test_rejects_failed_or_processless_a01(action_result: R1WmiActionResult) -> None:
    # Given
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match="WMI A01"):
        _resolve((reference_event,), action_result=action_result)

    # Then
    assert action_result.action_id == "A01"


@pytest.mark.parametrize(
    ("action_result", "message"),
    [
        (_action_result(action_type="Win32_Process.Create"), "action_type"),
        (_action_result(action_type="process_create"), "action_type"),
        (_action_result(invocation_method="PowerShell.InvokeMethod"), "invocation_method"),
    ],
)
def test_rejects_noncanonical_action_type_or_invocation_method(
    action_result: R1WmiActionResult,
    message: str,
) -> None:
    # Given
    reference_event = _reference_event()

    # When / Then
    with pytest.raises(ValueError, match=message):
        _resolve((reference_event,), action_result=action_result)


def test_rejects_reference_event_before_candidate_window() -> None:
    # Given
    reference_event = _reference_event()
    action_result = _action_result(invoked_at_utc=_REFERENCE_TIME + timedelta(seconds=3))

    # When
    with pytest.raises(ValueError, match="candidate count must be exactly 1, found 0"):
        _resolve((reference_event,), action_result=action_result)

    # Then
    assert reference_event.event_time == _REFERENCE_TIME


def test_malformed_sysmon_utc_time_fails_before_reference_selection() -> None:
    # Given
    payload = _reference_event().model_dump(mode="json")
    payload["timestamp"] = "not-a-time"
    payload["event_time"] = "not-a-time"

    # When
    with pytest.raises(ValidationError):
        NormalizedEvent.model_validate(payload)

    # Then
    assert payload["timestamp_source"] == "event_time"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"family_id": "remote_management"}, "family_id"),
        ({"reference_policy_version": "wmi-ref-v9.9"}, "reference_policy_version"),
        ({"evaluation_horizon_sec": 601}, "evaluation_horizon_sec"),
    ],
)
def test_policy_binding_mismatch_fails_closed(
    overrides: dict[str, object],
    message: str,
) -> None:
    # Given
    reference_event = _reference_event()

    # When
    with pytest.raises(ValueError, match=message):
        _resolve((reference_event,), **overrides)

    # Then
    assert reference_event.event_id == "evt-reference"


def test_unknown_policy_identity_fails_closed() -> None:
    # Given
    config_path = DEFAULT_R1_REFERENCE_POLICIES_PATH

    # When
    with pytest.raises(ValueError, match="was not found"):
        load_r1_reference_policy("unknown", _POLICY_VERSION, config_path=config_path)

    # Then
    assert config_path.is_file()


def test_normal_reference_fields_are_all_null() -> None:
    # Given
    fields = {
        "reference_action_id": None,
        "reference_time": None,
        "reference_source_event_id": None,
    }

    # When
    result = validate_normal_reference_fields(**fields)

    # Then
    assert result is None


@pytest.mark.parametrize(
    "fields",
    [
        {
            "reference_action_id": "A01",
            "reference_time": None,
            "reference_source_event_id": None,
        },
        {
            "reference_action_id": None,
            "reference_time": _REFERENCE_TIME,
            "reference_source_event_id": None,
        },
        {
            "reference_action_id": None,
            "reference_time": None,
            "reference_source_event_id": "42001",
        },
    ],
)
def test_normal_reference_rejects_any_non_null_field(fields: dict[str, object]) -> None:
    # Given
    reference_fields = fields

    # When
    with pytest.raises(ValueError, match="must all be null"):
        validate_normal_reference_fields(**reference_fields)

    # Then
    assert any(value is not None for value in reference_fields.values())


def test_remote_management_frozen_policy_hash_is_unchanged() -> None:
    # Given
    expected_hash = "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"

    # When
    policy = load_r1_approved_lineage_policy(
        "r1-remote-management-approved-lineage",
        "v0.3",
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )

    # Then
    assert policy.config_hash == expected_hash
