import json
from datetime import UTC, datetime, timedelta
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
    R1WmiActionResult,
    load_r1_reference_policies,
    load_r1_reference_policy,
    resolve_r1_wmi_reference,
    validate_normal_reference_fields,
)

_POLICY_ID = "r1-wmi-a01-reference"
_POLICY_VERSION = "wmi-ref-v0.1"
_ACTUAL_POLICY_HASH = "4144a6e2857fad7e834d819d5393eb03343398df83e5727470e9b97a24e495ba"
_REFERENCE_TIME = datetime(2026, 10, 10, 1, 0, 1, tzinfo=UTC)
_REFERENCE_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"


def _policy_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "policy_id": _POLICY_ID,
        "version": _POLICY_VERSION,
        "family_id": "wmi_management",
        "reference_action_id": "A01",
        "action_type": "Win32_Process.Create",
        "success_return_value": 0,
        "require_process_id": True,
        "reference_source": "sysmon",
        "reference_source_layer": "raw_telemetry",
        "reference_event_type": "process_create",
        "reference_process_name": "cmd.exe",
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
) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": "RUN-20261010-001",
            "timestamp": _REFERENCE_TIME,
            "timestamp_source": "event_time",
            "event_time": _REFERENCE_TIME,
            "record_time": _REFERENCE_TIME,
            "ingest_time": _REFERENCE_TIME,
            "host_id": "TARGET-A",
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": "42001",
            "event_type": "process_create",
            "raw_ref": {
                "raw_log_id": "RAW-R1-WMI-REFERENCE",
                "source_record_id": "42001",
                "segment_no": 1,
                "record_no": 10,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4100,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
                "parent_name": None,
            },
            "network": None,
        }
    )


def _action_result(
    *,
    action_id: str = "A01",
    action_type: str = "Win32_Process.Create",
    invoked_at_utc: datetime = _REFERENCE_TIME - timedelta(milliseconds=1),
    return_value: int = 0,
    process_id: int | None = 4100,
) -> R1WmiActionResult:
    return R1WmiActionResult(
        action_id=action_id,
        action_type=action_type,
        invoked_at_utc=invoked_at_utc,
        return_value=return_value,
        process_id=process_id,
    )


def _resolve(
    events: tuple[NormalizedEvent, ...],
    *,
    action_result: R1WmiActionResult | None = None,
    action_attributed_event_ids: tuple[str, ...] = ("evt-reference",),
    lineage_process_guids: tuple[str, ...] = (_REFERENCE_GUID,),
    family_id: str = "wmi_management",
    reference_policy_version: str = _POLICY_VERSION,
    evaluation_horizon_sec: int = 600,
):
    policy = load_r1_reference_policy(_POLICY_ID, _POLICY_VERSION)
    return resolve_r1_wmi_reference(
        events,
        policy=policy,
        scenario_family_id=family_id,
        reference_policy_version=reference_policy_version,
        evaluation_horizon_sec=evaluation_horizon_sec,
        action_result=action_result or _action_result(),
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


def test_semantically_identical_config_has_same_canonical_hash(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "reordered.yaml"
    config_path.write_text(
        """policies:
  - expected_evaluation_horizon_sec: 600
    reference_process_name: cmd.exe
    reference_event_type: process_create
    reference_source_layer: raw_telemetry
    reference_source: sysmon
    require_process_id: true
    success_return_value: 0
    action_type: Win32_Process.Create
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
    assert selection.reference_time == _REFERENCE_TIME
    assert selection.reference_source_event_id == "42001"
    assert selection.reference_event_id == "evt-reference"
    assert selection.policy_id == _POLICY_ID
    assert selection.reference_policy_version == _POLICY_VERSION
    assert selection.policy_config_hash == _ACTUAL_POLICY_HASH
    assert selection.scenario_evaluation_horizon_sec == 600
    assert selection.expected_evaluation_horizon_sec == 600
    assert selection.horizon_matches is True


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
            lineage_process_guids=(_REFERENCE_GUID, second_guid),
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


def test_rejects_reference_event_before_a01_invocation() -> None:
    # Given
    reference_event = _reference_event()
    action_result = _action_result(invoked_at_utc=_REFERENCE_TIME + timedelta(milliseconds=1))

    # When
    with pytest.raises(ValueError, match="predates the A01 invocation"):
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
