"""Role4 → Role2 handoff of a Run with a RecordId position close (seal, record, proof)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
import r1_position_finality_fixture as fixture

from incident_awareness.collection.r1_candidate_generation_seal import (
    load_r1_candidate_generation_policy,
)
from incident_awareness.collection.r1_position_candidate_generation_seal import (
    issue_r1_position_candidate_generation_seal,
    load_r1_position_candidate_generation_seal,
    load_r1_position_seal_projection_record,
    position_seal_projection_record_sha256,
    validate_r1_position_candidate_generation_seal_binding,
)
from incident_awareness.collection.r1_position_handoff import (
    BOUNDARY_ATTESTATION_FILENAME,
    PROJECTION_RECORD_FILENAME,
    PROOF_FILENAME,
    SEAL_FILENAME,
    R1PositionHandoffError,
    R1PositionHandoffExpectation,
    R1PositionHandoffSources,
    build_seal_inputs,
    issue_r1_position_handoff,
    load_accepted_position_close,
    main,
    proof_id_for,
)
from incident_awareness.collection.r1_role2_verified_position_close_proof import (
    issue_r1_role2_verified_position_close_proof,
    load_r1_role2_verified_position_close_proof,
    validate_r1_role2_verified_position_close_proof,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
)
from incident_awareness.common.models.r1_required_partition import (
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1RunClosed
from incident_awareness.pipeline.r1_record_position_finality import (
    consume_r1_record_position_close,
    export_r1_accepted_record_position_close,
    issue_r1_record_position_close,
    publish_r1_record_position_close,
)

RUN_ID = fixture.RUN_ID
HOST_ID = fixture.HOST_ID
POLICY_ID = "r1-wmi-management-candidate-generation-seal"
ACCEPTED_AT = datetime(2026, 10, 19, 1, 14, 2, tzinfo=UTC)
ISSUED_AT = datetime(2026, 10, 19, 1, 20, tzinfo=UTC)
INTERMEDIATE_GUID = "{00000000-0000-0000-0000-00000000a002}"
FINAL_GUID = "{00000000-0000-0000-0000-00000000a003}"


@dataclass
class Run:
    sources: R1PositionHandoffSources
    expected: R1PositionHandoffExpectation
    output_dir: Path
    snapshot: fixture.Snapshot


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _run_metadata(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "run_id": RUN_ID,
        "scenario_id": "R1",
        "run_type": "attack",
        "target_host": HOST_ID,
        "start_time": "2026-10-19T01:00:00.000Z",
        "end_time": "2026-10-19T01:13:00.000Z",
        "family_id": "wmi_management",
        "variation_id": "V01",
        "repetition": 1,
        "reference_time": "2026-10-19T01:00:00.100Z",
        "reference_action_id": "A01",
        "reference_source_event_id": "1002",
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
        "reference_policy_version": "wmi-ref-v0.1",
    }
    payload.update(overrides)
    return payload


_ACTIONS = (
    ("A01", "invoke", "wmi_process_create", 0, "2026-10-19T01:00:00.000Z"),
    ("A02", "launch", "process_create", 300, "2026-10-19T01:05:00.000Z"),
    ("A03", "connect", "network_connection", 480, "2026-10-19T01:08:00.000Z"),
    ("A04", "run_end", "run_end", 720, "2026-10-19T01:12:00.000Z"),
)


def _attestation(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "action_id": "A04",
        "step": "run_end",
        "action_type": "run_end",
        "completed_at": "2026-10-19T01:12:00.000Z",
        "no_actions_after_boundary": True,
        "owned_processes": [
            {
                "role": "intermediate",
                "image": "cmd.exe",
                "process_guid": INTERMEDIATE_GUID,
                "terminal_state": "stopped",
            },
            {
                "role": "final_tool",
                "image": "powershell.exe",
                "process_guid": FINAL_GUID,
                "terminal_state": "already_exited",
            },
        ],
    }
    payload.update(overrides)
    return payload


def _build_run(tmp_path: Path) -> Run:
    snapshot = fixture.build_snapshot(tmp_path)
    close = issue_r1_record_position_close(
        sources=snapshot.sources,
        reconciliation_path=snapshot.reconciliation_path,
        freeze_generation_path=snapshot.freeze_generation_path,
        export_generation_path=snapshot.export_generation_path,
        clock=lambda: fixture.CLOSE_EMITTED_AT,
    )
    publish_r1_record_position_close(close, snapshot.run_spool_root)
    connection = fixture.FakeLedgerConnection.with_snapshot_chunks(snapshot)
    consume_r1_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        contract=load_r1_required_partition_contract(
            snapshot.contract_path, expected_target_host=HOST_ID
        ),
        connection=connection,
        clock=lambda: ACCEPTED_AT,
    )
    export_path = export_r1_accepted_record_position_close(
        run_spool_root=snapshot.run_spool_root,
        connection=connection,
        contract_path=snapshot.contract_path,
    )

    data = tmp_path / "data"
    truth = data / "ground_truth" / RUN_ID
    _write_json(truth / "run_metadata.json", _run_metadata())
    rows = ["run_id,action_id,timestamp,action_type,description"]
    rows += [f"{RUN_ID},{a},{at},{kind},synthetic {step}" for a, step, kind, _, at in _ACTIONS]
    (truth / "execution_record.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")

    trace = data / "operator_trace" / RUN_ID
    scenario = {
        "scenario_id": "R1",
        "family_id": "wmi_management",
        "runs": {
            "attack": {
                "actions": [
                    {"action_id": a, "step": step, "action_type": kind, "offset_sec": offset}
                    for a, step, kind, offset, _ in _ACTIONS
                ]
            }
        },
    }
    _write_json(trace / "scenario.json", scenario)
    scenario_sha256 = hashlib.sha256((trace / "scenario.json").read_bytes()).hexdigest()
    _write_json(
        trace / "r1_wmi_collection_context.json",
        {
            "schema": "r1-wmi-collection-context",
            "run_id": RUN_ID,
            "target_host": HOST_ID,
            "scenario_sha256": scenario_sha256,
            "lineage": {
                "records": [
                    {"role": "final_tool", "process_guid": FINAL_GUID,
                     "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                    {"role": "intermediate", "process_guid": INTERMEDIATE_GUID,
                     "image": "C:\\Windows\\System32\\cmd.exe"},
                    {"role": "root", "process_guid": "{00000000-0000-0000-0000-00000000a001}",
                     "image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
                ]
            },
        },
    )  # fmt: skip
    _write_json(
        snapshot.control_root / "candidate-boundary-completed.json",
        {
            "schema": "r1-incremental-run-control",
            "contract_version": "v0.1",
            "message_type": "candidate_boundary_completed",
            "run_id": RUN_ID,
            "target_host": HOST_ID,
            "action_id": "A04",
            "candidate_boundary_at": "2026-10-19T01:12:00.000Z",
        },
    )
    _write_json(snapshot.control_root / BOUNDARY_ATTESTATION_FILENAME, _attestation())

    policy = load_r1_candidate_generation_policy(POLICY_ID, "v0.1")
    return Run(
        sources=R1PositionHandoffSources(
            accepted_close_export_path=export_path,
            required_partition_contract_path=snapshot.contract_path,
            control_dir=snapshot.control_root,
            run_spool_root=snapshot.run_spool_root,
            run_metadata_path=truth / "run_metadata.json",
            execution_record_path=truth / "execution_record.csv",
            scenario_json_path=trace / "scenario.json",
            collection_context_path=trace / "r1_wmi_collection_context.json",
        ),
        expected=R1PositionHandoffExpectation(
            run_id=RUN_ID,
            host_id=HOST_ID,
            family_id="wmi_management",
            policy_id=POLICY_ID,
            policy_version="v0.1",
            policy_config_hash=policy.config_hash,
        ),
        output_dir=tmp_path / "role4",
        snapshot=snapshot,
    )


def _issue(run: Run, **overrides: object):
    expected = overrides.pop("expected", run.expected)
    sources = overrides.pop("sources", run.sources)
    return issue_r1_position_handoff(
        sources, expected, output_dir=run.output_dir, clock=lambda: ISSUED_AT, **overrides
    )


def _outputs(run: Run) -> dict[str, bytes | None]:
    return {
        name: (run.output_dir / name).read_bytes() if (run.output_dir / name).exists() else None
        for name in (SEAL_FILENAME, PROJECTION_RECORD_FILENAME, PROOF_FILENAME)
    }


@pytest.fixture
def run(tmp_path) -> Run:
    return _build_run(tmp_path)


def test_full_handoff_issues_a_proof_role2_accepts(run) -> None:
    result = _issue(run)

    proof = load_r1_role2_verified_position_close_proof(result.proof_path)
    record = load_r1_position_seal_projection_record(result.projection_record_path)
    close, receipt, partition = load_accepted_position_close(run.sources, run.expected)
    validation = validate_r1_role2_verified_position_close_proof(
        proof,
        accepted_position_close=close,
        accepted_position_close_receipt=receipt,
        candidate_policy=load_r1_candidate_generation_policy(POLICY_ID, "v0.1"),
        expected_run_id=RUN_ID,
        expected_family_id="wmi_management",
        expected_selector_partition=partition,
        expected_required_partition_contract_sha256=close.required_partition_contract.content_sha256,
        accepted_source_seal_id=result.seal_id,
        accepted_source_seal_projection_sha256=record.projection_sha256,
        accepted_source_seal_projection_record_sha256=position_seal_projection_record_sha256(
            record
        ),
        proof_validated_at=datetime(2026, 10, 19, 1, 30, tzinfo=UTC),
    )

    assert result.reused == ()
    assert validation.proof.proof_id == proof_id_for(RUN_ID)
    assert (
        proof.source_seal_projection_sha256 == record.projection_sha256 == result.projection_sha256
    )
    assert proof.source_seal_projection_record_sha256 == result.projection_record_sha256
    assert proof.non_guarantees == R1_RECORD_POSITION_FINALITY_NON_GUARANTEES
    assert proof.candidate_boundary_at == close.candidate_boundary_at
    proof_text = result.proof_path.read_text(encoding="utf-8")
    for forbidden in ("reference_time", "available_at", "run_type", "watermark_at", "run_closed"):
        assert forbidden not in proof_text


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("run_id", "RUN-20261019-002", "another Run or partition"),
        ("host_id", "R1-TGTB", "accepted position close export"),
        ("family_id", "remote_management", "not the expected Run, host and family"),
        ("policy_id", "r1-remote-management-candidate-generation-seal", "not the expected one"),
        ("policy_config_hash", "0" * 64, "not the expected one"),
    ],
)
def test_expectation_mismatch_fails_before_any_output(run, field, value, message) -> None:
    with pytest.raises(R1PositionHandoffError, match=message):
        _issue(run, expected=replace(run.expected, **{field: value}))
    assert not run.output_dir.exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"target_host": "R1-TGTB"}, "not the expected Run, host and family"),
        ({"family_id": "remote_management", "variation_id": "V02"}, "not the expected Run, host"),
    ],
)
def test_run_metadata_of_another_host_or_family_fails(run, change, message) -> None:
    _write_json(run.sources.run_metadata_path, _run_metadata(**change))

    with pytest.raises(R1PositionHandoffError, match=message):
        _issue(run)
    assert not run.output_dir.exists()


def test_candidate_boundary_that_is_not_the_freeze_request_boundary_fails(run) -> None:
    path = run.snapshot.control_root / "candidate-boundary-completed.json"
    control = json.loads(path.read_text(encoding="utf-8"))
    control["candidate_boundary_at"] = "2026-10-19T01:12:01.000Z"
    _write_json(path, control)

    with pytest.raises(R1PositionHandoffError, match="candidate boundary of the freeze request"):
        _issue(run)
    assert not run.output_dir.exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"completed_at": "2026-10-19T01:12:00.500Z"}, "not this Run's boundary"),
        ({"action_id": "A03"}, "not this Run's boundary"),
    ],
)
def test_boundary_attestation_of_another_boundary_fails(run, change, message) -> None:
    _write_json(run.snapshot.control_root / BOUNDARY_ATTESTATION_FILENAME, _attestation(**change))

    with pytest.raises(R1PositionHandoffError, match=message):
        _issue(run)


def test_attested_process_that_is_not_the_lineage_process_fails(run) -> None:
    owned = _attestation()["owned_processes"]
    owned[1]["process_guid"] = "{00000000-0000-0000-0000-0000000000ff}"
    _write_json(
        run.snapshot.control_root / BOUNDARY_ATTESTATION_FILENAME,
        _attestation(owned_processes=owned),
    )

    with pytest.raises(R1PositionHandoffError, match="not the process of the lineage"):
        _issue(run)


def test_scenario_that_is_not_the_run_scenario_fails(run) -> None:
    scenario = json.loads(run.sources.scenario_json_path.read_text(encoding="utf-8"))
    scenario["runs"]["attack"]["actions"][-1]["offset_sec"] = 700
    _write_json(run.sources.scenario_json_path, scenario)

    with pytest.raises(R1PositionHandoffError, match="not the one this Run was built from"):
        _issue(run)


def test_accepted_close_content_change_fails(run) -> None:
    export = json.loads(run.sources.accepted_close_export_path.read_text(encoding="utf-8"))
    export["accepted_record_position_close"]["event_count"] += 1
    _write_json(run.sources.accepted_close_export_path, export)

    with pytest.raises(R1PositionHandoffError, match="accepted position close export"):
        _issue(run)
    assert not run.output_dir.exists()


def test_snapshot_artifact_changed_after_the_close_fails(run) -> None:
    ack_path = run.snapshot.control_root / "collection-freeze-ack.json"
    ack_path.write_text(json.dumps(json.loads(ack_path.read_text("utf-8")), indent=4), "utf-8")

    with pytest.raises(R1PositionHandoffError, match="freeze ack of this Run is not the one"):
        _issue(run)
    assert not run.output_dir.exists()


def test_rerun_keeps_every_byte_and_reuses_the_outputs(run) -> None:
    _issue(run)
    first = _outputs(run)

    result = issue_r1_position_handoff(
        run.sources,
        run.expected,
        output_dir=run.output_dir,
        clock=lambda: datetime(2026, 10, 19, 2, 0, tzinfo=UTC),
    )

    assert _outputs(run) == first
    assert result.reused == (SEAL_FILENAME, PROJECTION_RECORD_FILENAME, PROOF_FILENAME)


def test_existing_seal_with_other_content_is_kept_and_nothing_follows(run) -> None:
    _issue(run)
    seal_path = run.output_dir / SEAL_FILENAME
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    for name in (PROJECTION_RECORD_FILENAME, PROOF_FILENAME):
        (run.output_dir / name).unlink()
    seal["boundary"]["owned_processes"][0]["terminal_state"] = "exited_by_itself"
    seal_path.write_text(json.dumps(seal, indent=2), encoding="utf-8")
    conflicting = seal_path.read_bytes()

    with pytest.raises(R1PositionHandoffError, match="position seal does not bind this Run"):
        _issue(run)
    assert seal_path.read_bytes() == conflicting
    assert _outputs(run)[PROJECTION_RECORD_FILENAME] is None
    assert _outputs(run)[PROOF_FILENAME] is None


def test_projection_digest_mismatch_writes_no_proof(run) -> None:
    _issue(run)
    (run.output_dir / PROOF_FILENAME).unlink()
    record_path = run.output_dir / PROJECTION_RECORD_FILENAME
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["projection_sha256"] = "0" * 64
    content = {key: value for key, value in record.items() if key != "record_content_sha256"}
    record["record_content_sha256"] = hashlib.sha256(
        json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    with pytest.raises(R1PositionHandoffError, match="digest does not match the seal"):
        _issue(run)
    assert _outputs(run)[PROOF_FILENAME] is None


def test_a_record_path_that_holds_another_artifact_writes_no_proof(run) -> None:
    _issue(run)
    for name in (PROJECTION_RECORD_FILENAME, PROOF_FILENAME):
        (run.output_dir / name).unlink()
    (run.output_dir / PROJECTION_RECORD_FILENAME).write_bytes(
        (run.output_dir / SEAL_FILENAME).read_bytes()
    )

    with pytest.raises(R1PositionHandoffError, match="not a valid artifact of this kind"):
        _issue(run)
    assert _outputs(run)[PROOF_FILENAME] is None


def test_proof_issuer_accepts_only_a_projection_record(run) -> None:
    result = _issue(run)
    close, receipt, _ = load_accepted_position_close(run.sources, run.expected)
    inputs = build_seal_inputs(run.sources, run.expected, close)
    seal = load_r1_position_candidate_generation_seal(result.seal_path)
    verified = validate_r1_position_candidate_generation_seal_binding(
        seal,
        run_metadata=inputs.run_metadata,
        position_close=close,
        position_close_receipt=receipt,
        scenario_actions=inputs.scenario_actions,
        boundary_action_record=inputs.boundary_action_record,
        boundary_completion=inputs.boundary_completion,
        policy=inputs.policy,
    )
    record = load_r1_position_seal_projection_record(result.projection_record_path)
    for not_a_record in (
        seal,
        record.model_dump(mode="json", by_alias=True),
        record.projection_sha256,
    ):
        with pytest.raises(TypeError, match="R1PositionSealProjectionRecord"):
            issue_r1_role2_verified_position_close_proof(
                proof_id=proof_id_for(RUN_ID),
                host_id=HOST_ID,
                verified_boundary=verified,
                source_seal=seal,
                accepted_position_close=close,
                accepted_position_close_receipt=receipt,
                trusted_seal_projection_record=not_a_record,
                candidate_policy=inputs.policy,
                proof_created_at=ISSUED_AT,
            )


def test_event_time_close_export_is_rejected(run) -> None:
    event_time = run.output_dir.parent / "accepted-run-closed.json"
    _write_json(
        event_time,
        {
            "schema": "r1-accepted-close-export",
            "contract_version": "v0.1",
            "accepted_run_closed": {"message_type": "run_closed"},
            "acceptance_receipt": {"run_id": RUN_ID, "close_id": "x", "content_sha256": "0" * 64},
            "required_partition_contract": {},
        },
    )

    with pytest.raises(R1PositionHandoffError, match="accepted position close export"):
        _issue(run, sources=replace(run.sources, accepted_close_export_path=event_time))
    assert not run.output_dir.exists()


def test_event_time_seal_at_the_seal_path_is_rejected(run) -> None:
    run.output_dir.mkdir(parents=True)
    _write_json(
        run.output_dir / SEAL_FILENAME,
        {"schema": "r1-candidate-generation-seal", "contract_version": "v0.1"},
    )

    with pytest.raises(R1PositionHandoffError, match="not a valid artifact of this kind"):
        _issue(run)
    assert _outputs(run)[PROJECTION_RECORD_FILENAME] is None
    assert _outputs(run)[PROOF_FILENAME] is None


def test_event_time_run_closed_is_not_a_position_close(run) -> None:
    close, receipt, _ = load_accepted_position_close(run.sources, run.expected)
    inputs = build_seal_inputs(run.sources, run.expected, close)
    run_closed = R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": f"CLOSE-{RUN_ID}-000001",
            "run_id": RUN_ID,
            "final_watermarks": [
                {
                    "partition": close.partition.model_dump(),
                    "watermark_id": f"WM-{RUN_ID}-TGTA-000001",
                    "watermark_sequence": 1,
                    "watermark_at": "2026-10-19T01:13:00.000Z",
                    "allowed_lateness_ms": 2000,
                    "covered_through_chunk_sequence": 2,
                }
            ],
            "emitted_at": "2026-10-19T01:13:01.000Z",
        }
    )

    with pytest.raises(TypeError, match="R1RecordPositionClose"):
        issue_r1_position_candidate_generation_seal(
            seal_id="SEAL-x",
            run_metadata=inputs.run_metadata,
            position_close=run_closed,
            position_close_receipt=receipt,
            scenario_actions=inputs.scenario_actions,
            boundary=inputs.boundary,
            boundary_action_record=inputs.boundary_action_record,
            boundary_completion=inputs.boundary_completion,
            policy=inputs.policy,
            emitted_at=ISSUED_AT,
        )


def _cli_arguments(run: Run) -> list[str]:
    sources, expected = run.sources, run.expected
    return [
        "issue",
        "--run-id", expected.run_id,
        "--target-host", expected.host_id,
        "--family-id", expected.family_id,
        "--policy-id", expected.policy_id,
        "--policy-version", expected.policy_version,
        "--policy-config-hash", expected.policy_config_hash,
        "--accepted-close-export", str(sources.accepted_close_export_path),
        "--required-partition-contract", str(sources.required_partition_contract_path),
        "--control-dir", str(sources.control_dir),
        "--run-spool-root", str(sources.run_spool_root),
        "--run-metadata", str(sources.run_metadata_path),
        "--execution-record", str(sources.execution_record_path),
        "--scenario-json", str(sources.scenario_json_path),
        "--collection-context", str(sources.collection_context_path),
        "--output-dir", str(run.output_dir),
    ]  # fmt: skip


def test_cli_prints_the_trusted_channel_values_and_no_secret(run, capsys, monkeypatch) -> None:
    secret = "postgresql://role3:not-a-real-password@db.invalid/ledger"
    monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", secret)

    assert main(_cli_arguments(run)) == 0
    summary = json.loads(capsys.readouterr().out)

    record = load_r1_position_seal_projection_record(run.output_dir / PROJECTION_RECORD_FILENAME)
    assert summary["seal_id"] == record.seal_id
    assert summary["projection_sha256"] == record.projection_sha256
    assert summary["projection_record_sha256"] == position_seal_projection_record_sha256(record)
    assert summary["non_guarantees"] == list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES)
    for content in [json.dumps(summary)] + [
        (run.output_dir / name).read_text(encoding="utf-8")
        for name in (SEAL_FILENAME, PROJECTION_RECORD_FILENAME, PROOF_FILENAME)
    ]:
        assert secret not in content and "not-a-real-password" not in content


def test_cli_failure_exits_non_zero_without_output(run, capsys) -> None:
    arguments = _cli_arguments(run)
    arguments[arguments.index("--target-host") + 1] = "R1-TGTB"

    assert main(arguments) == 1
    assert "position handoff failed" in capsys.readouterr().err
    assert not run.output_dir.exists()
