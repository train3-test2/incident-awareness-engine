import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policies,
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import (
    ApprovedLineagePolicy,
    extract_remote_session_process_lineage_deviation,
)
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import run_and_write_r1_evidence_artifacts
from incident_awareness.pipeline.r1_evidence import (
    R1LineageInput,
    run_r1_evidence_pipeline_with_selector,
)

_BASE_TIME = datetime(2026, 10, 5, 1, 0, tzinfo=UTC)
_RUN_ID = "RUN-20261005-001"
_HOST_ID = "TARGET-A"
_ANCHOR_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
_POLICY_ID = "r1-v02-development-connection"
_POLICY_VERSION = "v0.1"
_POLICY_HASH = "59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78"
_APPROVED_LINEAGE = ("wsmprovhost.exe", "cmd.exe", "powershell.exe")
_FAMILY_POLICY_ID = "r1-remote-management-approved-lineage"
_FAMILY_POLICY_VERSION = "v0.2"
_FAMILY_POLICY_HASH = "6d4235ccc33fcc2484a679d6b6b9b8972cf67f45ff8de35d02eb402380e7f788"
_FROZEN_POLICY_VERSION = "v0.3"
_FROZEN_POLICY_HASH = "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"


def _policy_payload(
    *,
    policy_id: object = _POLICY_ID,
    version: object = _POLICY_VERSION,
    approved_lineage: object = _APPROVED_LINEAGE,
) -> dict[str, object]:
    return {
        "policy_id": policy_id,
        "version": version,
        "approved_lineage": list(approved_lineage)
        if isinstance(approved_lineage, tuple)
        else approved_lineage,
    }


def _family_policy_payload(
    *,
    policy_id: object = _FAMILY_POLICY_ID,
    version: object = _FAMILY_POLICY_VERSION,
    family_id: object = "remote_management",
    lifecycle: object = "development",
    approved_lineage: object = _APPROVED_LINEAGE,
) -> dict[str, object]:
    return {
        "policy_id": policy_id,
        "version": version,
        "family_id": family_id,
        "lifecycle": lifecycle,
        "approved_lineage": list(approved_lineage)
        if isinstance(approved_lineage, tuple)
        else approved_lineage,
    }


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


def _load_single(path: Path) -> ApprovedLineagePolicy:
    return load_r1_approved_lineage_policy(
        _POLICY_ID,
        _POLICY_VERSION,
        config_path=path,
    )


def _event(
    *,
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    process_name: str,
    parent_process_guid: str | None = None,
) -> NormalizedEvent:
    is_network_event = event_type == "network_connection"
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
                "raw_log_id": "RAW-R1-POLICY",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 2 if is_network_event else 1,
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
                    "src_port": 52132,
                    "dst_ip": "192.0.2.20",
                    "dst_port": 5985,
                }
                if is_network_event
                else None
            ),
        }
    )


def _r1_events() -> tuple[NormalizedEvent, ...]:
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
            process_name="cscript.exe",
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


def _selector_policy(*, lineage_event_count: int = 3) -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=lineage_event_count,
    )


def test_loads_repository_managed_development_policy() -> None:
    # Given
    config_path = DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH

    # When
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)

    # Then
    assert config_path.is_file()
    assert policy.policy_id == _POLICY_ID
    assert policy.version == _POLICY_VERSION
    assert policy.approved_lineage == _APPROVED_LINEAGE
    assert policy.config_hash == _POLICY_HASH


def test_loads_repository_managed_family_bound_development_policy() -> None:
    # Given
    config_path = DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH

    # When
    policy = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FAMILY_POLICY_VERSION,
        config_path=config_path,
    )

    # Then
    assert policy.policy_id == _FAMILY_POLICY_ID
    assert policy.version == _FAMILY_POLICY_VERSION
    assert policy.family_id == "remote_management"
    assert policy.lifecycle == "development"
    assert policy.approved_lineage == _APPROVED_LINEAGE
    assert policy.config_hash == _FAMILY_POLICY_HASH


def test_loads_repository_managed_frozen_evaluation_policy() -> None:
    # Given
    config_path = DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH

    # When
    legacy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)
    development = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FAMILY_POLICY_VERSION,
        config_path=config_path,
    )
    frozen = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FROZEN_POLICY_VERSION,
        config_path=config_path,
    )

    # Then
    assert legacy.config_hash == _POLICY_HASH
    assert development.config_hash == _FAMILY_POLICY_HASH
    assert frozen.policy_id == _FAMILY_POLICY_ID
    assert frozen.version == _FROZEN_POLICY_VERSION
    assert frozen.family_id == "remote_management"
    assert frozen.lifecycle == "frozen"
    assert frozen.approved_lineage == _APPROVED_LINEAGE
    assert frozen.config_hash == _FROZEN_POLICY_HASH
    assert (frozen.policy_id, frozen.version) != (
        development.policy_id,
        development.version,
    )
    assert frozen.config_hash != development.config_hash


def test_semantically_identical_configs_have_the_same_hash(tmp_path: Path) -> None:
    # Given
    first_path = tmp_path / "first.yaml"
    second_path = tmp_path / "second.yaml"
    first_path.write_text(
        """config_version: v0.1
policies:
  - policy_id: r1-v02-development-connection
    version: v0.1
    approved_lineage:
      - wsmprovhost.exe
      - cmd.exe
      - powershell.exe
""",
        encoding="utf-8",
    )
    second_path.write_text(
        """# 표현 형식과 key 순서는 hash 의미에 포함되지 않는다.
policies:
  - approved_lineage: [wsmprovhost.exe, cmd.exe, powershell.exe]
    version: v0.1
    policy_id: r1-v02-development-connection
config_version: v0.1
""",
        encoding="utf-8",
    )

    # When
    first = _load_single(first_path)
    second = _load_single(second_path)

    # Then
    assert first == second
    assert first.config_hash == _POLICY_HASH


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("policy_id", "r1-v02-development-connection-next"),
        ("version", "v0.2"),
        ("approved_lineage", ("wsmprovhost.exe", "powershell.exe")),
    ],
)
def test_semantic_policy_changes_change_the_hash(
    tmp_path: Path,
    changed_field: str,
    changed_value: object,
) -> None:
    # Given
    base_path = tmp_path / "base.yaml"
    changed_path = tmp_path / "changed.yaml"
    base_payload = _policy_payload()
    changed_payload = {**base_payload, changed_field: changed_value}
    _write_registry(base_path, policies=[base_payload])
    _write_registry(changed_path, policies=[changed_payload])

    # When
    base_policy = load_r1_approved_lineage_policies(base_path)[0]
    changed_policy = load_r1_approved_lineage_policies(changed_path)[0]

    # Then
    assert changed_policy.config_hash != base_policy.config_hash


def test_rejects_malformed_config(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "malformed.yaml"
    config_path.write_text("config_version: [", encoding="utf-8")

    # When
    with pytest.raises(ValueError, match="not valid YAML"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.read_text(encoding="utf-8") == "config_version: ["


@pytest.mark.parametrize("missing_field", ["policy_id", "version", "approved_lineage"])
def test_rejects_missing_required_policy_fields(tmp_path: Path, missing_field: str) -> None:
    # Given
    config_path = tmp_path / f"missing-{missing_field}.yaml"
    policy = _policy_payload()
    policy.pop(missing_field)
    _write_registry(config_path, policies=[policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize("field_name", ["policy_id", "version"])
@pytest.mark.parametrize("blank_value", ["", "   "])
def test_rejects_blank_policy_identity(
    tmp_path: Path,
    field_name: str,
    blank_value: str,
) -> None:
    # Given
    config_path = tmp_path / "blank-identity.yaml"
    policy = {**_policy_payload(), field_name: blank_value}
    _write_registry(config_path, policies=[policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_empty_approved_lineage(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "empty-lineage.yaml"
    _write_registry(config_path, policies=[_policy_payload(approved_lineage=())])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize("process_name", ["", "   ", " cmd.exe "])
def test_rejects_blank_or_padded_lineage_elements(
    tmp_path: Path,
    process_name: str,
) -> None:
    # Given
    config_path = tmp_path / "invalid-lineage-element.yaml"
    _write_registry(
        config_path,
        policies=[
            _policy_payload(approved_lineage=("wsmprovhost.exe", process_name, "powershell.exe"))
        ],
    )

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_duplicate_policy_identity(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "duplicate-policy.yaml"
    _write_registry(
        config_path,
        policies=[
            _policy_payload(),
            _policy_payload(approved_lineage=("one.exe", "two.exe")),
        ],
    )

    # When
    with pytest.raises(ValueError, match="identities must be unique"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_preserves_repeated_lineage_names_and_original_case(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "repeated-lineage.yaml"
    approved_lineage = ("PowerShell.exe", "helper.exe", "PowerShell.exe")
    _write_registry(
        config_path,
        policies=[_policy_payload(approved_lineage=approved_lineage)],
    )

    # When
    policy = load_r1_approved_lineage_policies(config_path)[0]

    # Then
    assert policy.approved_lineage == approved_lineage


def test_rejects_unknown_config_fields(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "unknown-field.yaml"
    policy = {**_policy_payload(), "scope": "production"}
    _write_registry(config_path, policies=[policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_unknown_config_version(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "unknown-version.yaml"
    _write_registry(
        config_path,
        config_version="v9.9",
        policies=[_policy_payload()],
    )

    # When
    with pytest.raises(ValueError, match="does not match v0.1 or v0.2"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_empty_policy_registry(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "empty-registry.yaml"
    _write_registry(config_path, policies=[])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_duplicate_yaml_mapping_keys(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "duplicate-key.yaml"
    config_path.write_text(
        """config_version: v0.1
config_version: v0.1
policies: []
""",
        encoding="utf-8",
    )

    # When
    with pytest.raises(ValueError, match="not valid YAML"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_rejects_unknown_policy_identity(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "known-policy.yaml"
    _write_registry(config_path, policies=[_policy_payload()])

    # When
    with pytest.raises(ValueError, match="was not found"):
        load_r1_approved_lineage_policy(
            "unknown-policy",
            "v0.1",
            config_path=config_path,
        )

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize(
    "policy",
    [
        _policy_payload(policy_id=1),
        _policy_payload(version=1),
        _policy_payload(approved_lineage="powershell.exe"),
        _policy_payload(approved_lineage=("wsmprovhost.exe", 1, "powershell.exe")),
    ],
)
def test_rejects_wrong_policy_field_types(
    tmp_path: Path,
    policy: dict[str, object],
) -> None:
    # Given
    config_path = tmp_path / "wrong-type.yaml"
    _write_registry(config_path, policies=[policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_loaded_policy_is_compatible_with_existing_lineage_extractor() -> None:
    # Given
    anchor, middle, terminal, _ = _r1_events()
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)

    # When
    evidences = extract_remote_session_process_lineage_deviation(
        (anchor, middle, terminal),
        anchor,
        terminal,
        policy,
    )

    # Then
    assert len(evidences) == 1
    assert evidences[0].features["policy_id"] == policy.policy_id
    assert evidences[0].features["version"] == policy.version
    assert evidences[0].features["config_hash"] == policy.config_hash


def test_loaded_policy_is_compatible_with_selector_pipeline() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)

    # When
    result = run_r1_evidence_pipeline_with_selector(
        _r1_events(),
        selector_policy=_selector_policy(),
        approved_policy=policy,
    )

    # Then
    assert result.selector_result.diagnostics == ()
    assert result.lineage_input is not None
    assert result.lineage_input.approved_policy == policy
    assert {evidence.evidence_type for evidence in result.evidences} == {
        "remote_process_network_follow_on",
        "remote_session_process_lineage_deviation",
    }


def test_selector_pipeline_preserves_depth_mismatch_failure() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)

    # When
    with pytest.raises(
        ValueError,
        match="selector lineage_event_count must match approved_lineage length",
    ):
        run_r1_evidence_pipeline_with_selector(
            _r1_events(),
            selector_policy=_selector_policy(lineage_event_count=2),
            approved_policy=policy,
        )

    # Then
    assert len(policy.approved_lineage) == 3


def test_loaded_policy_provenance_is_preserved_in_artifacts(tmp_path: Path) -> None:
    # Given
    anchor, middle, terminal, network = _r1_events()
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)
    lineage_input = R1LineageInput(
        anchor_event_id=anchor.event_id,
        terminal_event_id=terminal.event_id,
        approved_policy=policy,
    )

    # When
    artifact_run = run_and_write_r1_evidence_artifacts(
        (anchor, middle, terminal, network),
        run_id=_RUN_ID,
        output_directory=tmp_path,
        lineage_inputs=(lineage_input,),
    )

    # Then
    assert artifact_run.summary.lineage_inputs is not None
    provenance = artifact_run.summary.lineage_inputs[0]
    assert provenance.policy_id == policy.policy_id
    assert provenance.policy_version == policy.version
    assert provenance.policy_config_hash == policy.config_hash
    lineage_evidence = next(
        evidence
        for evidence in artifact_run.evidences
        if evidence.evidence_type == "remote_session_process_lineage_deviation"
    )
    assert lineage_evidence.features["policy_id"] == policy.policy_id
    assert lineage_evidence.features["version"] == policy.version
    assert lineage_evidence.features["config_hash"] == policy.config_hash


def test_semantically_identical_family_bound_configs_have_the_same_hash(tmp_path: Path) -> None:
    # Given
    first_path = tmp_path / "first-v0.2.yaml"
    second_path = tmp_path / "second-v0.2.yaml"
    _write_registry(
        first_path,
        config_version="v0.2",
        policies=[_family_policy_payload()],
    )
    second_path.write_text(
        """policies:
  - lifecycle: development
    approved_lineage: [wsmprovhost.exe, cmd.exe, powershell.exe]
    family_id: remote_management
    version: v0.2
    policy_id: r1-remote-management-approved-lineage
config_version: v0.2
""",
        encoding="utf-8",
    )

    # When
    first = load_r1_approved_lineage_policies(first_path)[0]
    second = load_r1_approved_lineage_policies(second_path)[0]

    # Then
    assert first == second
    assert first.config_hash == _FAMILY_POLICY_HASH


def test_semantically_identical_frozen_configs_have_the_managed_hash(tmp_path: Path) -> None:
    # Given
    first_path = tmp_path / "first-frozen-v0.2.yaml"
    second_path = tmp_path / "second-frozen-v0.2.yaml"
    frozen_policy = _family_policy_payload(
        version=_FROZEN_POLICY_VERSION,
        lifecycle="frozen",
    )
    _write_registry(
        first_path,
        config_version="v0.2",
        policies=[frozen_policy],
    )
    second_path.write_text(
        """policies:
  - approved_lineage: [wsmprovhost.exe, cmd.exe, powershell.exe]
    lifecycle: frozen
    family_id: remote_management
    policy_id: r1-remote-management-approved-lineage
    version: v0.3
config_version: v0.2
""",
        encoding="utf-8",
    )

    # When
    first = load_r1_approved_lineage_policies(first_path)[0]
    second = load_r1_approved_lineage_policies(second_path)[0]

    # Then
    assert first == second
    assert first.config_hash == _FROZEN_POLICY_HASH


@pytest.mark.parametrize("missing_field", ["family_id", "lifecycle"])
def test_family_bound_policy_rejects_missing_contract_fields(
    tmp_path: Path,
    missing_field: str,
) -> None:
    # Given
    config_path = tmp_path / f"missing-{missing_field}-v0.2.yaml"
    policy = _family_policy_payload()
    policy.pop(missing_field)
    _write_registry(config_path, config_version="v0.2", policies=[policy])

    # When
    with pytest.raises(ValueError, match="does not match v0.2"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize("family_id", ["", "   ", " remote_management", "remote_management "])
def test_family_bound_policy_rejects_invalid_family_id(
    tmp_path: Path,
    family_id: str,
) -> None:
    # Given
    config_path = tmp_path / "invalid-family-v0.2.yaml"
    _write_registry(
        config_path,
        config_version="v0.2",
        policies=[_family_policy_payload(family_id=family_id)],
    )

    # When
    with pytest.raises(ValueError, match="does not match v0.2"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize("lifecycle", ["development", "frozen", "production_candidate"])
def test_family_bound_policy_accepts_canonical_lifecycle_values(
    tmp_path: Path,
    lifecycle: str,
) -> None:
    # Given
    config_path = tmp_path / f"{lifecycle}-v0.2.yaml"
    _write_registry(
        config_path,
        config_version="v0.2",
        policies=[_family_policy_payload(lifecycle=lifecycle)],
    )

    # When
    policy = load_r1_approved_lineage_policies(config_path)[0]

    # Then
    assert policy.lifecycle == lifecycle


def test_family_bound_policy_rejects_unknown_lifecycle(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "unknown-lifecycle-v0.2.yaml"
    _write_registry(
        config_path,
        config_version="v0.2",
        policies=[_family_policy_payload(lifecycle="final-ish")],
    )

    # When
    with pytest.raises(ValueError, match="does not match v0.2"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_family_bound_policy_rejects_duplicate_identity(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "duplicate-family-policy-v0.2.yaml"
    _write_registry(
        config_path,
        config_version="v0.2",
        policies=[
            _family_policy_payload(),
            _family_policy_payload(lifecycle="frozen"),
        ],
    )

    # When
    with pytest.raises(ValueError, match="identities must be unique"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


def test_frozen_policy_rejects_duplicate_semantic_identity(tmp_path: Path) -> None:
    # Given
    config_path = tmp_path / "duplicate-frozen-policy-v0.2.yaml"
    _write_registry(
        config_path,
        config_version="v0.2",
        policies=[
            _family_policy_payload(
                version=_FROZEN_POLICY_VERSION,
                lifecycle="frozen",
            ),
            _family_policy_payload(
                version=_FROZEN_POLICY_VERSION,
                lifecycle="frozen",
                approved_lineage=("wsmprovhost.exe", "powershell.exe"),
            ),
        ],
    )

    # When
    with pytest.raises(ValueError, match="identities must be unique"):
        load_r1_approved_lineage_policies(config_path)

    # Then
    assert config_path.is_file()


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("family_id", "other_family"),
        ("lifecycle", "frozen"),
        ("approved_lineage", ("wsmprovhost.exe", "powershell.exe")),
    ],
)
def test_family_bound_semantic_changes_change_the_hash(
    tmp_path: Path,
    changed_field: str,
    changed_value: object,
) -> None:
    # Given
    base_path = tmp_path / "base-v0.2.yaml"
    changed_path = tmp_path / "changed-v0.2.yaml"
    base_policy = _family_policy_payload()
    changed_policy = {**base_policy, changed_field: changed_value}
    _write_registry(base_path, config_version="v0.2", policies=[base_policy])
    _write_registry(changed_path, config_version="v0.2", policies=[changed_policy])

    # When
    base = load_r1_approved_lineage_policies(base_path)[0]
    changed = load_r1_approved_lineage_policies(changed_path)[0]

    # Then
    assert changed.config_hash != base.config_hash


def test_family_binding_accepts_matching_scenario_family() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FAMILY_POLICY_VERSION,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )

    # When
    result = validate_r1_policy_family_binding("remote_management", policy)

    # Then
    assert result is None


def test_family_binding_rejects_mismatched_scenario_family() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FAMILY_POLICY_VERSION,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )

    # When
    with pytest.raises(ValueError, match="does not match approved policy family_id"):
        validate_r1_policy_family_binding("other_family", policy)

    # Then
    assert policy.family_id == "remote_management"


def test_frozen_policy_accepts_matching_scenario_family() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FROZEN_POLICY_VERSION,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )

    # When
    result = validate_r1_policy_family_binding("remote_management", policy)

    # Then
    assert result is None
    assert policy.lifecycle == "frozen"


def test_frozen_policy_rejects_mismatched_scenario_family() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(
        _FAMILY_POLICY_ID,
        _FROZEN_POLICY_VERSION,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )

    # When
    with pytest.raises(ValueError, match="does not match approved policy family_id"):
        validate_r1_policy_family_binding("other_family", policy)

    # Then
    assert policy.lifecycle == "frozen"


def test_family_binding_rejects_legacy_unbound_policy() -> None:
    # Given
    policy = load_r1_approved_lineage_policy(_POLICY_ID, _POLICY_VERSION)

    # When
    with pytest.raises(ValueError, match="legacy unbound"):
        validate_r1_policy_family_binding("remote_management", policy)

    # Then
    assert policy.family_id is None
    assert policy.lifecycle is None
