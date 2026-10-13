from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from incident_awareness.collection.r1_candidate_generation_seal import (
    DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH,
    R1CandidateBoundaryAttestation,
    R1CandidateGenerationPolicy,
    R1CandidateGenerationSeal,
    R1OwnedProcessTermination,
    R1ScenarioAction,
    candidate_generation_seal_sha256,
    issue_r1_candidate_generation_seal,
    load_r1_candidate_generation_policies,
    load_r1_candidate_generation_policy,
    load_r1_candidate_generation_seal,
    resolve_r1_candidate_close,
    validate_r1_candidate_generation_seal_binding,
    validate_r1_candidate_generation_seal_replay,
    write_r1_candidate_generation_seal,
)
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.r1_stream import R1RunClosed
from incident_awareness.common.models.run import RunMetadata

RUN_ID = "RUN-20261013-001"

POLICY_IDS = {
    "wmi_management": "r1-wmi-management-candidate-generation-seal",
    "remote_management": "r1-remote-management-candidate-generation-seal",
}


def _policy(family_id: str = "wmi_management") -> R1CandidateGenerationPolicy:
    return load_r1_candidate_generation_policy(POLICY_IDS[family_id], "v0.1")


def _metadata(
    *,
    family_id: str = "wmi_management",
    run_type: str = "attack",
    completed: bool = True,
) -> RunMetadata:
    reference = run_type == "attack"
    return RunMetadata.model_validate(
        {
            "run_id": RUN_ID,
            "scenario_id": "R1",
            "run_type": run_type,
            "target_host": "R1-TGTA",
            "start_time": "2026-10-13T01:00:00.000Z",
            "end_time": "2026-10-13T01:13:00.000Z" if completed else None,
            "family_id": family_id,
            "variation_id": "V01" if family_id == "wmi_management" else "V02",
            "repetition": 1,
            "reference_time": "2026-10-13T01:00:00.100Z" if reference else None,
            "reference_action_id": "A01" if reference else None,
            "reference_source_event_id": "100" if reference else None,
            "vm_snapshot": "r1-baseline-v1",
            "sysmon_config_version": "sysmonconfig-sample-v0.1",
            "detector_set_version": None,
            "scenario_version": "v1",
            "schema_versions": {
                "run_metadata": "v0.2",
                "event": "v0.3",
                "evidence": "v0.2",
                "fast_hit": "v0.2",
                "detection_result": "v0.2",
                "fusion_result": "v0.3",
                "decision_result": "v0.2",
                "execution_record": "v0.1",
                "evaluation_input": "v0.1",
            },
            "reference_policy_version": "wmi-ref-v0.1" if reference else None,
        }
    )


def _run_closed() -> R1RunClosed:
    return R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": "CLOSE-RUN-20261013-001-000001",
            "run_id": RUN_ID,
            "final_watermarks": [
                {
                    "partition": {
                        "run_id": RUN_ID,
                        "host_id": "R1-TGTA",
                        "source": "sysmon",
                        "source_channel": "Microsoft-Windows-Sysmon/Operational",
                    },
                    "watermark_id": "WM-RUN-20261013-001-TGTA-000001",
                    "watermark_sequence": 3,
                    "watermark_at": "2026-10-13T01:13:00.000Z",
                    "allowed_lateness_ms": 30000,
                    "covered_through_chunk_sequence": 5,
                }
            ],
            "emitted_at": "2026-10-13T01:13:01.000Z",
        }
    )


def _actions(
    *, family_id: str = "wmi_management", run_type: str = "attack"
) -> tuple[R1ScenarioAction, ...]:
    prefix = "A" if run_type == "attack" else "N"
    if family_id == "wmi_management":
        values = (
            (f"{prefix}01", "invoke", "wmi_process_create", 0),
            (f"{prefix}02", "launch", "process_create", 300),
            (f"{prefix}03", "connect", "network_connection", 480),
            (f"{prefix}04", "run_end", "run_end", 720),
        )
    else:
        values = (
            (f"{prefix}01", "session_begin", "remote_session", 0),
            (f"{prefix}02", "prepare", "file_operation", 120),
            (f"{prefix}03", "launch", "process_create", 300),
            (f"{prefix}04", "connect", "network_connection", 480),
            (f"{prefix}05", "session_end", "remote_session", 600),
        )
    return tuple(
        R1ScenarioAction(action_id=action_id, step=step, action_type=action_type, offset_sec=offset)
        for action_id, step, action_type, offset in values
    )


def _boundary(
    *, family_id: str = "wmi_management", run_type: str = "attack"
) -> R1CandidateBoundaryAttestation:
    prefix = "A" if run_type == "attack" else "N"
    action = (
        {"action_id": f"{prefix}04", "step": "run_end", "action_type": "run_end"}
        if family_id == "wmi_management"
        else {
            "action_id": f"{prefix}05",
            "step": "session_end",
            "action_type": "remote_session",
        }
    )
    intermediate = {
        ("wmi_management", "attack"): "cmd.exe",
        ("wmi_management", "normal"): "wscript.exe",
        ("remote_management", "attack"): "cscript.exe",
        ("remote_management", "normal"): "cmd.exe",
    }[(family_id, run_type)]
    return R1CandidateBoundaryAttestation(
        **action,
        completed_at=datetime(2026, 10, 13, 1, 12, tzinfo=UTC),
        no_actions_after_boundary=True,
        owned_processes=(
            R1OwnedProcessTermination(
                role="intermediate",
                image=intermediate,
                process_guid="{00000000-0000-0000-0000-000000000001}",
                terminal_state="stopped",
            ),
            R1OwnedProcessTermination(
                role="final_tool",
                image="powershell.exe",
                process_guid="{00000000-0000-0000-0000-000000000002}",
                terminal_state="already_exited",
            ),
        ),
    )


def _boundary_record(
    *, family_id: str = "wmi_management", run_type: str = "attack"
) -> ExecutionRecordRow:
    boundary = _boundary(family_id=family_id, run_type=run_type)
    return ExecutionRecordRow(
        run_id=RUN_ID,
        action_id=boundary.action_id,
        timestamp=boundary.completed_at,
        action_type=boundary.action_type,
        description="candidate-generation boundary completed",
    )


def _seal(
    *, family_id: str = "wmi_management", run_type: str = "attack"
) -> R1CandidateGenerationSeal:
    return issue_r1_candidate_generation_seal(
        seal_id="SEAL-RUN-20261013-001-000001",
        run_metadata=_metadata(family_id=family_id, run_type=run_type),
        run_closed=_run_closed(),
        scenario_actions=_actions(family_id=family_id, run_type=run_type),
        boundary=_boundary(family_id=family_id, run_type=run_type),
        boundary_action_record=_boundary_record(family_id=family_id, run_type=run_type),
        policy=_policy(family_id),
        emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
    )


def test_registry_loads_both_family_bound_policies_with_stable_hashes() -> None:
    policies = load_r1_candidate_generation_policies()

    assert {policy.family_id for policy in policies} == {"wmi_management", "remote_management"}
    assert {policy.family_id: policy.config_hash for policy in policies} == {
        "wmi_management": "0d11a265afe096648636c24657a092cb3d9959177a2e219b2ea947a0069682ca",
        "remote_management": "4bfeab14d85aaeecdb233f4c4c193b10c2ffdaee01b138453fef83228af848bc",
    }
    assert all(
        policy.canonical_path == "configs/r1_candidate_generation_policies_v0.1.yaml"
        for policy in policies
    )


def test_policy_lookup_requires_the_exact_id_and_version() -> None:
    policy = load_r1_candidate_generation_policy(POLICY_IDS["wmi_management"], "v0.1")

    assert policy.family_id == "wmi_management"
    with pytest.raises(ValueError, match="was not found"):
        load_r1_candidate_generation_policy(POLICY_IDS["wmi_management"], "v9")


def test_registry_can_hold_a_later_version_for_the_same_family(tmp_path: Path) -> None:
    source = DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH
    payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    next_version = deepcopy(payload["policies"][0])
    next_version["policy_id"] = "r1-wmi-management-candidate-generation-seal-next"
    next_version["version"] = "v0.2"
    payload["policies"].append(next_version)
    config = tmp_path / "policies.yaml"
    config.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    policies = load_r1_candidate_generation_policies(config)

    assert [policy.family_id for policy in policies].count("wmi_management") == 2
    assert (
        load_r1_candidate_generation_policy(
            next_version["policy_id"],
            next_version["version"],
            config_path=config,
        ).family_id
        == "wmi_management"
    )


@pytest.mark.parametrize(
    ("family_id", "run_type", "boundary_action"),
    [
        ("wmi_management", "attack", "A04"),
        ("wmi_management", "normal", "N04"),
        ("remote_management", "attack", "A05"),
        ("remote_management", "normal", "N05"),
    ],
)
def test_issues_family_seal_only_after_expected_final_boundary(
    family_id: str,
    run_type: str,
    boundary_action: str,
) -> None:
    seal = _seal(family_id=family_id, run_type=run_type)

    assert seal.boundary.action_id == boundary_action
    assert seal.input_close_id == _run_closed().close_id
    assert seal.sealed_partitions == _run_closed().final_watermarks
    assert seal.candidate_policy.config_hash == _policy(family_id).config_hash


def test_rejects_boundary_when_a_later_scenario_action_exists() -> None:
    actions = _actions() + (
        R1ScenarioAction(
            action_id="A05",
            step="unexpected_launch",
            action_type="process_create",
            offset_sec=730,
        ),
    )

    with pytest.raises(ValueError, match="boundary must be the final scenario action"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=actions,
            boundary=_boundary(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


@pytest.mark.parametrize("missing_role", ["intermediate", "final_tool"])
def test_rejects_boundary_without_every_run_owned_process(missing_role: str) -> None:
    boundary = _boundary()
    changed = boundary.model_copy(
        update={
            "owned_processes": tuple(
                process for process in boundary.owned_processes if process.role != missing_role
            )
        }
    )

    with pytest.raises(ValueError, match="expected run-owned processes"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=changed,
            boundary_action_record=_boundary_record(),
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


def test_rejects_non_terminal_run_owned_process() -> None:
    boundary = _boundary()
    changed_process = boundary.owned_processes[0].model_copy(update={"terminal_state": "running"})
    changed = boundary.model_copy(
        update={"owned_processes": (changed_process, boundary.owned_processes[1])}
    )

    with pytest.raises(ValueError, match="not in an accepted terminal state"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=changed,
            boundary_action_record=_boundary_record(),
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


def test_rejects_a_different_process_image_even_when_role_matches() -> None:
    boundary = _boundary()
    changed_process = boundary.owned_processes[0].model_copy(update={"image": "wscript.exe"})
    changed = boundary.model_copy(
        update={"owned_processes": (changed_process, boundary.owned_processes[1])}
    )

    with pytest.raises(ValueError, match="expected run-owned processes"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=changed,
            boundary_action_record=_boundary_record(),
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


def test_wmi_provider_host_is_never_claimed_as_run_owned() -> None:
    boundary = _boundary()
    provider = boundary.owned_processes[0].model_copy(update={"image": "WmiPrvSE.exe"})
    changed = boundary.model_copy(
        update={"owned_processes": (provider, boundary.owned_processes[1])}
    )

    with pytest.raises(ValueError, match="protected non-owned process"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=changed,
            boundary_action_record=_boundary_record(),
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("run_id", "RUN-20261013-002", "run_id does not match"),
        ("input_close_id", "CLOSE-DIFFERENT", "input_close_id does not match"),
    ],
)
def test_rejects_seal_that_does_not_bind_to_accepted_close(
    field: str,
    value: str,
    message: str,
) -> None:
    seal = _seal().model_copy(update={field: value})

    with pytest.raises(ValueError, match=message):
        validate_r1_candidate_generation_seal_binding(
            seal,
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


def test_rejects_even_one_changed_final_watermark_reference() -> None:
    seal = _seal()
    changed_watermark = seal.sealed_partitions[0].model_copy(
        update={"covered_through_chunk_sequence": 6}
    )
    changed = seal.model_copy(update={"sealed_partitions": (changed_watermark,)})

    with pytest.raises(ValueError, match="do not exactly match"):
        validate_r1_candidate_generation_seal_binding(
            changed,
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


def test_rejects_a_final_watermark_that_does_not_cover_the_candidate_boundary() -> None:
    seal = _seal()
    before_boundary = seal.sealed_partitions[0].model_copy(
        update={"watermark_at": seal.boundary.completed_at - timedelta(milliseconds=1)}
    )
    changed_close = _run_closed().model_copy(update={"final_watermarks": (before_boundary,)})
    changed_seal = seal.model_copy(update={"sealed_partitions": (before_boundary,)})

    with pytest.raises(ValueError, match="must cover the candidate-generation boundary"):
        validate_r1_candidate_generation_seal_binding(
            changed_seal,
            run_metadata=_metadata(),
            run_closed=changed_close,
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


def test_rejects_a_loaded_seal_whose_boundary_does_not_match_its_run_type() -> None:
    seal = _seal()
    changed_boundary = seal.boundary.model_copy(update={"action_id": "N04"})
    changed = seal.model_copy(update={"boundary": changed_boundary})

    with pytest.raises(ValueError, match="does not match family policy"):
        validate_r1_candidate_generation_seal_binding(
            changed,
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


@pytest.mark.parametrize(
    ("completed_at", "end_time", "message"),
    [
        (
            datetime(2026, 10, 13, 0, 59, 59, 999000, tzinfo=UTC),
            datetime(2026, 10, 13, 1, 13, 0, tzinfo=UTC),
            "precedes",
        ),
        (
            datetime(2026, 10, 13, 1, 12, 0, 1000, tzinfo=UTC),
            datetime(2026, 10, 13, 1, 12, 0, tzinfo=UTC),
            "exceeds",
        ),
    ],
)
def test_rejects_boundary_before_planned_action_offset() -> None:
    too_early = datetime(2026, 10, 13, 1, 0, 1, tzinfo=UTC)
    boundary = _boundary().model_copy(update={"completed_at": too_early})
    record = _boundary_record().model_copy(update={"timestamp": too_early})

    with pytest.raises(ValueError, match="planned action offset"):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=boundary,
            boundary_action_record=record,
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("run_id", "RUN-20261013-002", "run_id"),
        ("action_id", "A03", "final scenario action"),
        ("action_type", "network_connection", "final scenario action"),
        ("timestamp", datetime(2026, 10, 13, 1, 12, 0, 1000, tzinfo=UTC), "completed_at"),
    ],
)
def test_rejects_boundary_not_bound_to_actual_action_record(
    field: str,
    value: object,
    message: str,
) -> None:
    record = _boundary_record().model_copy(update={field: value})

    with pytest.raises(ValueError, match=message):
        issue_r1_candidate_generation_seal(
            seal_id="SEAL-001",
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary=_boundary(),
            boundary_action_record=record,
            policy=_policy(),
            emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


def test_rejects_candidate_boundary_outside_completed_run(
    completed_at: datetime,
    end_time: datetime,
    message: str,
) -> None:
    seal = _seal()
    run_metadata = _metadata().model_copy(update={"end_time": end_time})
    changed = seal.model_copy(
        update={"boundary": seal.boundary.model_copy(update={"completed_at": completed_at})}
    )

    with pytest.raises(ValueError, match=message):
        validate_r1_candidate_generation_seal_binding(
            changed,
            run_metadata=run_metadata,
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


@pytest.mark.parametrize(
    ("run_metadata", "message"),
    [
        (_metadata().model_copy(update={"run_id": "RUN-20261013-002"}), "run_id"),
        (_metadata(family_id="remote_management"), "family_id"),
        (_metadata(run_type="normal"), "run_type"),
    ],
)
def test_rejects_seal_not_bound_to_run_metadata(
    run_metadata: RunMetadata,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_r1_candidate_generation_seal_binding(
            _seal(),
            run_metadata=run_metadata,
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )


def _verified_boundary():
    seal = _seal()
    return validate_r1_candidate_generation_seal_binding(
        seal,
        run_metadata=_metadata(),
        run_closed=_run_closed(),
        scenario_actions=_actions(),
        boundary_action_record=_boundary_record(),
        policy=_policy(),
    )


def test_missing_seal_uses_authoritative_run_end_fallback() -> None:
    resolution = resolve_r1_candidate_close(
        authoritative_run_end=_metadata().end_time,
        verified_boundary=None,
    )

    assert resolution.mode == "authoritative_run_end_fallback"
    assert resolution.candidate_boundary_at == _metadata().end_time
    assert resolution.verified_seal_at is None
    assert resolution.verified_boundary is None


def test_invalid_seal_diagnostic_is_preserved_in_fallback() -> None:
    changed = _seal().model_copy(update={"input_close_id": "CLOSE-DIFFERENT"})
    with pytest.raises(ValueError, match="input_close_id") as error:
        validate_r1_candidate_generation_seal_binding(
            changed,
            run_metadata=_metadata(),
            run_closed=_run_closed(),
            scenario_actions=_actions(),
            boundary_action_record=_boundary_record(),
            policy=_policy(),
        )

    resolution = resolve_r1_candidate_close(
        authoritative_run_end=_metadata().end_time,
        verified_boundary=None,
        validation_diagnostics=(str(error.value),),
    )

    assert resolution.mode == "authoritative_run_end_fallback"
    assert resolution.candidate_boundary_at == _metadata().end_time
    assert "input_close_id" in resolution.diagnostics[0]


def test_valid_boundary_exposes_only_non_ground_truth_runtime_input() -> None:
    verified = _verified_boundary()
    resolution = resolve_r1_candidate_close(
        authoritative_run_end=_metadata().end_time,
        verified_boundary=verified,
    )

    assert resolution.mode == "verified_seal"
    assert resolution.candidate_boundary_at == verified.candidate_boundary_at
    assert resolution.verified_seal_at == verified.verified_seal_at
    assert resolution.verified_boundary == verified
    serialized = json.dumps(verified.model_dump(mode="json"), sort_keys=True)
    for forbidden in ("run_type", "family_id", "owned_processes", "image", "process_guid"):
        assert forbidden not in serialized
    assert set(signature(resolve_r1_candidate_close).parameters) == {
        "authoritative_run_end",
        "verified_boundary",
        "validation_diagnostics",
    }


def test_valid_seal_can_be_verified_before_run_metadata_end_time() -> None:
    in_progress = _metadata(completed=False)
    policy = _policy()
    actions = _actions()
    record = _boundary_record()
    seal = issue_r1_candidate_generation_seal(
        seal_id="SEAL-RUN-20261013-001-EARLY",
        run_metadata=in_progress,
        run_closed=_run_closed(),
        scenario_actions=actions,
        boundary=_boundary(),
        boundary_action_record=record,
        policy=policy,
        emitted_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
    )
    verified = validate_r1_candidate_generation_seal_binding(
        seal,
        run_metadata=in_progress,
        run_closed=_run_closed(),
        scenario_actions=actions,
        boundary_action_record=record,
        policy=policy,
    )

    resolution = resolve_r1_candidate_close(
        authoritative_run_end=None,
        verified_boundary=verified,
    )

    assert resolution.mode == "verified_seal"
    assert resolution.candidate_boundary_at == seal.boundary.completed_at


@pytest.mark.parametrize("diagnostics", [(), ("invalid seal",)])
def test_in_progress_run_without_a_verified_boundary_has_no_run_end_fallback(
    diagnostics: tuple[str, ...],
) -> None:
    with pytest.raises(
        ValueError, match="end_time is required when verified seal close is unavailable"
    ):
        resolve_r1_candidate_close(
            authoritative_run_end=None,
            verified_boundary=None,
            validation_diagnostics=diagnostics,
        )


def test_candidate_window_and_evaluation_horizon_are_not_seal_fields() -> None:
    payload = _seal().model_dump(mode="json", by_alias=True)
    serialized = json.dumps(payload, sort_keys=True)

    assert "candidate_window_sec" not in serialized
    assert "evaluation_horizon" not in serialized


def test_exact_replay_is_allowed_but_changed_content_is_rejected() -> None:
    seal = _seal()
    validate_r1_candidate_generation_seal_replay(seal, seal.model_copy(deep=True))

    changed = seal.model_copy(update={"emitted_at": seal.emitted_at + timedelta(milliseconds=1)})
    with pytest.raises(ValueError, match="reused with different content"):
        validate_r1_candidate_generation_seal_replay(seal, changed)
    assert candidate_generation_seal_sha256(seal) != candidate_generation_seal_sha256(changed)


def test_writer_is_exclusive_and_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "seal.json"
    seal = _seal()
    write_r1_candidate_generation_seal(path, seal)

    assert load_r1_candidate_generation_seal(path) == seal
    with pytest.raises(FileExistsError):
        write_r1_candidate_generation_seal(path, seal)

    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        load_r1_candidate_generation_seal(path)


@pytest.mark.parametrize(
    "bad_time",
    [
        "2026-10-13T01:13:02",
        "2026-10-13T10:13:02+09:00",
        "2026-10-13T01:13:02.000001Z",
        1791853982,
    ],
)
def test_rejects_noncanonical_seal_timestamp(bad_time: object) -> None:
    payload = _seal().model_dump(mode="json", by_alias=True)
    payload["emitted_at"] = bad_time

    with pytest.raises(ValidationError):
        R1CandidateGenerationSeal.model_validate(payload)


def test_policy_config_rejects_unknown_selector_close_shortcuts(tmp_path: Path) -> None:
    config = DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH.read_text(encoding="utf-8")
    changed = config.replace(
        "    forbid_all_actions_after_boundary: true",
        "    candidate_window_sec: 2\n    forbid_all_actions_after_boundary: true",
        1,
    )
    path = tmp_path / "policies.yaml"
    path.write_text(changed, encoding="utf-8")

    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_candidate_generation_policies(path)
