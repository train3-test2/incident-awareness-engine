"""Role4 position seal, trusted projection record and Role2-safe position close proof."""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields
from datetime import UTC, datetime
from inspect import signature

import pytest
import test_r1_candidate_generation_seal as seal_fixture
import test_r1_role2_verified_close_proof as v01_proof_fixture
from pydantic import ValidationError

from incident_awareness.collection.r1_position_candidate_generation_seal import (
    R1PositionCandidateGenerationSeal,
    R1PositionSealProjectionRecord,
    issue_r1_position_candidate_generation_seal,
    issue_r1_position_seal_projection_record,
    load_r1_position_candidate_generation_seal,
    load_r1_position_seal_projection_record,
    role2_safe_position_seal_projection_sha256,
    validate_r1_position_candidate_generation_seal_binding,
    write_r1_position_message,
)
from incident_awareness.collection.r1_role2_verified_close_proof import (
    validate_r1_role2_verified_close_proof,
)
from incident_awareness.collection.r1_role2_verified_position_close_proof import (
    R1Role2VerifiedPositionCloseProof,
    R1Role2VerifiedPositionCloseProofValidation,
    issue_r1_role2_verified_position_close_proof,
    load_r1_role2_verified_position_close_proof,
    validate_r1_role2_verified_position_close_proof,
    validate_r1_role2_verified_position_close_proof_replay,
    write_r1_role2_verified_position_close_proof,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_GUARANTEE,
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
    record_position_close_sha256,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition

RUN_ID = seal_fixture.RUN_ID
HOST_ID = "R1-TGTA"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
CONTRACT_SHA256 = "c" * 64
ACCEPTED_AT = datetime(2026, 10, 13, 1, 14, 2, tzinfo=UTC)
SEAL_AT = datetime(2026, 10, 13, 1, 14, 3, tzinfo=UTC)
RECORDED_AT = datetime(2026, 10, 13, 1, 14, 4, tzinfo=UTC)
PROOF_AT = datetime(2026, 10, 13, 1, 14, 5, tzinfo=UTC)
VALIDATED_AT = datetime(2026, 10, 13, 1, 14, 6, tzinfo=UTC)


def _partition(host_id: str = HOST_ID) -> R1StreamPartition:
    return R1StreamPartition(
        run_id=RUN_ID, host_id=host_id, source="sysmon", source_channel=CHANNEL
    )


def _close(**overrides: object) -> R1RecordPositionClose:
    payload: dict[str, object] = {
        "schema": "r1-record-position-close",
        "contract_version": "v0.1",
        "message_type": "record_position_close",
        "close_id": f"{RUN_ID}-record-position-close-v0.1",
        "run_id": RUN_ID,
        "partition": _partition().model_dump(),
        "required_partition_contract": {"target_host": HOST_ID, "content_sha256": CONTRACT_SHA256},
        "position_frontier": {
            "finality_kind": "sysmon_record_id_position",
            "lower_record_id": 998,
            "upper_record_id": 1677,
            "target_event_ids": [1, 3],
            "channel_generation_id": "d" * 64,
        },
        "covered_through_chunk_sequence": 5,
        "covered_chunks_sha256": "e" * 64,
        "post_commit_ack_count": 5,
        "event_count": 677,
        "source_native_identity_sha256": "f" * 64,
        "live_identity_sha256": "1" * 64,
        "canonical_identity_sha256": "1" * 64,
        "source_snapshot": {
            "request_id": f"{RUN_ID}-freeze-0001",
            "freeze_request_sha256": "2" * 64,
            "freeze_ack_sha256": "3" * 64,
            "run_finalized_sha256": "4" * 64,
            "reconciliation_sha256": "5" * 64,
            "freeze_generation_observation_sha256": "6" * 64,
            "export_generation_observation_sha256": "7" * 64,
        },
        "candidate_boundary_at": "2026-10-13T01:12:00.000Z",
        "observation_boundary_at": "2026-10-13T01:13:00.000Z",
        "emitted_at": "2026-10-13T01:14:01.000Z",
        "guarantee": R1_RECORD_POSITION_FINALITY_GUARANTEE,
        "non_guarantees": list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES),
    }
    payload.update(overrides)
    return R1RecordPositionClose.model_validate(payload)


def _receipt(close: R1RecordPositionClose | None = None, **overrides: object):
    close = close or _close()
    payload: dict[str, object] = {
        "schema": "r1-record-position-close-receipt",
        "contract_version": "v0.1",
        "run_id": RUN_ID,
        "close_id": close.close_id,
        "partition": close.partition.model_dump(),
        "close_content_sha256": record_position_close_sha256(close),
        "ledger_entry_id": 41,
        "accepted_at": ACCEPTED_AT,
    }
    payload.update(overrides)
    return R1AcceptedRecordPositionCloseReceipt.model_validate(payload)


def _seal(run_type: str = "attack", **kwargs: object) -> R1PositionCandidateGenerationSeal:
    close = kwargs.pop("position_close", None) or _close()
    arguments: dict[str, object] = {
        "seal_id": f"SEAL-{RUN_ID}-position-000001",
        "run_metadata": seal_fixture._metadata(run_type=run_type),
        "position_close": close,
        "position_close_receipt": kwargs.pop("position_close_receipt", None) or _receipt(close),
        "scenario_actions": seal_fixture._actions(run_type=run_type),
        "boundary": seal_fixture._boundary(run_type=run_type),
        "boundary_action_record": seal_fixture._boundary_record(run_type=run_type),
        "boundary_completion": seal_fixture._boundary_completion(run_type=run_type),
        "policy": seal_fixture._policy(),
        "emitted_at": SEAL_AT,
    }
    arguments.update(kwargs)
    return issue_r1_position_candidate_generation_seal(**arguments)


def _verified(seal: R1PositionCandidateGenerationSeal, run_type: str = "attack"):
    return validate_r1_position_candidate_generation_seal_binding(
        seal,
        run_metadata=seal_fixture._metadata(run_type=run_type),
        position_close=_close(),
        position_close_receipt=_receipt(),
        scenario_actions=seal_fixture._actions(run_type=run_type),
        boundary_action_record=seal_fixture._boundary_record(run_type=run_type),
        boundary_completion=seal_fixture._boundary_completion(run_type=run_type),
        policy=seal_fixture._policy(),
    )


def _record(seal: R1PositionCandidateGenerationSeal, run_type: str = "attack"):
    return issue_r1_position_seal_projection_record(
        seal=seal,
        verified_boundary=_verified(seal, run_type),
        host_id=HOST_ID,
        recorded_at=RECORDED_AT,
    )


def _proof(**overrides: object) -> R1Role2VerifiedPositionCloseProof:
    seal = _seal()
    arguments: dict[str, object] = {
        "proof_id": f"PROOF-{RUN_ID}-position-000001",
        "host_id": HOST_ID,
        "verified_boundary": _verified(seal),
        "source_seal": seal,
        "accepted_position_close": _close(),
        "accepted_position_close_receipt": _receipt(),
        "trusted_seal_projection_record": _record(seal),
        "candidate_policy": seal_fixture._policy(),
        "proof_created_at": PROOF_AT,
    }
    arguments.update(overrides)
    return issue_r1_role2_verified_position_close_proof(**arguments)


def _validate(proof: R1Role2VerifiedPositionCloseProof, **overrides: object):
    arguments: dict[str, object] = {
        "accepted_position_close": _close(),
        "accepted_position_close_receipt": _receipt(),
        "candidate_policy": seal_fixture._policy(),
        "expected_run_id": RUN_ID,
        "expected_family_id": "wmi_management",
        "expected_selector_partition": _partition(),
        "expected_required_partition_contract_sha256": CONTRACT_SHA256,
        "accepted_source_seal_id": f"SEAL-{RUN_ID}-position-000001",
        "accepted_source_seal_projection_sha256": _record(_seal()).projection_sha256,
        "proof_validated_at": VALIDATED_AT,
    }
    arguments.update(overrides)
    return validate_r1_role2_verified_position_close_proof(proof, **arguments)


def _rehash_proof(payload: dict[str, object]) -> R1Role2VerifiedPositionCloseProof:
    content = {key: value for key, value in payload.items() if key != "proof_content_sha256"}
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    content["proof_content_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    return R1Role2VerifiedPositionCloseProof.model_validate(content)


def test_role3_receipt_role4_seal_proof_and_role2_validation(tmp_path) -> None:
    seal = _seal()
    verified = _verified(seal)
    proof = _proof()

    validation = _validate(proof)

    assert isinstance(validation, R1Role2VerifiedPositionCloseProofValidation)
    assert verified.candidate_boundary_at == datetime(2026, 10, 13, 1, 12, tzinfo=UTC)
    assert verified.verified_seal_at == SEAL_AT
    assert seal.position_close_receipt == _receipt()
    assert proof.position_close_receipt == _receipt()
    assert proof.position_frontier == _close().position_frontier
    assert proof.covered_through_chunk_sequence == proof.post_commit_ack_count == 5
    assert proof.source_reconciliation_sha256 == "5" * 64
    assert proof.required_partition_contract_sha256 == CONTRACT_SHA256
    assert proof.non_guarantees == R1_RECORD_POSITION_FINALITY_NON_GUARANTEES
    assert validation.proof_validated_at == VALIDATED_AT
    for path, message in (
        (tmp_path / "seal.json", seal),
        (tmp_path / "projection.json", _record(seal)),
    ):
        write_r1_position_message(path, message)
    write_r1_role2_verified_position_close_proof(tmp_path / "proof.json", proof)
    assert load_r1_position_candidate_generation_seal(tmp_path / "seal.json") == seal
    assert load_r1_position_seal_projection_record(tmp_path / "projection.json") == _record(seal)
    assert load_r1_role2_verified_position_close_proof(tmp_path / "proof.json") == proof
    with pytest.raises(FileExistsError):
        write_r1_role2_verified_position_close_proof(tmp_path / "proof.json", proof)


def test_proof_has_no_ground_truth_and_no_availability() -> None:
    serialized = json.dumps(_proof().model_dump(mode="json", by_alias=True), sort_keys=True)

    for forbidden in (
        "run_type",
        "owned_processes",
        "process_guid",
        "attack",
        "normal",
        "available_at",
        "evidence",
        "watermark_at",
    ):
        assert forbidden not in serialized.casefold()
    assert {field.name for field in fields(R1Role2VerifiedPositionCloseProofValidation)} == {
        "proof",
        "proof_validated_at",
    }


def test_projection_cannot_distinguish_attack_from_normal() -> None:
    attack = _seal("attack")
    normal = _seal("normal")

    assert attack.run_type != normal.run_type
    assert role2_safe_position_seal_projection_sha256(attack, host_id=HOST_ID) == (
        role2_safe_position_seal_projection_sha256(normal, host_id=HOST_ID)
    )


def test_seal_requires_a_receipt_that_binds_the_close() -> None:
    with pytest.raises(ValueError, match="does not match the close content"):
        _seal(position_close_receipt=_receipt(close_content_sha256="0" * 64))
    with pytest.raises(ValueError, match="another run, close or partition"):
        _seal(position_close_receipt=_receipt(close_id=f"{RUN_ID}-record-position-close-other"))


def test_seal_boundary_must_equal_the_freeze_request_boundary() -> None:
    shifted = _close(candidate_boundary_at="2026-10-13T01:11:59.000Z")

    with pytest.raises(ValueError, match="freeze request candidate boundary"):
        _seal(position_close=shifted, position_close_receipt=_receipt(shifted))


def test_seal_cannot_precede_the_role3_ledger_acceptance() -> None:
    with pytest.raises(ValueError):
        _seal(emitted_at=datetime(2026, 10, 13, 1, 14, 1, tzinfo=UTC))


def test_seal_rejects_an_event_time_run_closed() -> None:
    with pytest.raises(TypeError, match="must be an R1RecordPositionClose"):
        _seal(position_close=seal_fixture._run_closed(), position_close_receipt=_receipt())


def test_trusted_projection_record_from_another_seal_is_rejected() -> None:
    normal_record = _record(_seal("normal"), "normal")

    with pytest.raises(ValueError, match="not made from this source seal"):
        _proof(trusted_seal_projection_record=normal_record)


def test_trusted_projection_digest_that_does_not_match_the_seal_is_rejected() -> None:
    seal = _seal()
    payload = _record(seal).model_dump(mode="json", by_alias=True)
    payload["projection_sha256"] = "9" * 64
    content = {key: value for key, value in payload.items() if key != "record_content_sha256"}
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["record_content_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    forged = R1PositionSealProjectionRecord.model_validate(payload)

    with pytest.raises(ValueError, match="does not match the source seal projection"):
        _proof(trusted_seal_projection_record=forged)


def test_projection_record_content_hash_is_enforced() -> None:
    payload = _record(_seal()).model_dump(mode="json", by_alias=True)
    payload["projection_sha256"] = "9" * 64

    with pytest.raises(ValidationError, match="record_content_sha256"):
        R1PositionSealProjectionRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"accepted_source_seal_projection_sha256": "8" * 64}, "trusted projection digest"),
        ({"accepted_source_seal_id": "SEAL-OTHER"}, "accepted source seal"),
        ({"expected_selector_partition": _partition("R1-TGTB")}, "not the closed partition"),
        ({"expected_required_partition_contract_sha256": "b" * 64}, "expected contract"),
        ({"expected_family_id": "remote_management"}, "expected_family_id"),
        ({"accepted_position_close_receipt": _receipt(ledger_entry_id=42)}, "ledger receipt"),
        ({"proof_validated_at": datetime(2026, 10, 13, 1, 14, 4, tzinfo=UTC)}, "precede"),
    ],
)
def test_role2_rejects_any_binding_mismatch(overrides, message) -> None:
    with pytest.raises(ValueError, match=message):
        _validate(_proof(), **overrides)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_reconciliation_sha256", "0" * 64),
        ("covered_chunks_sha256", "0" * 64),
        ("candidate_boundary_at", "2026-10-13T01:11:00Z"),
    ],
)
def test_role2_rejects_a_rehashed_proof_with_changed_bindings(field, value) -> None:
    payload = _proof().model_dump(mode="json", by_alias=True)
    payload[field] = value

    with pytest.raises(ValueError, match="trusted source seal projection digest"):
        _validate(_rehash_proof(payload))


def test_role2_rejects_a_proof_whose_hash_no_longer_matches() -> None:
    payload = _proof().model_dump(mode="json", by_alias=True)
    payload["covered_chunks_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="proof_content_sha256"):
        R1Role2VerifiedPositionCloseProof.model_validate(payload)


def test_event_time_role2_path_cannot_consume_a_position_proof() -> None:
    with pytest.raises(TypeError, match="R1Role2VerifiedCloseProof"):
        validate_r1_role2_verified_close_proof(
            _proof(),
            accepted_run_closed=seal_fixture._run_closed(),
            accepted_close_receipt=None,
            candidate_policy=seal_fixture._policy(),
            expected_run_id=RUN_ID,
            expected_family_id="wmi_management",
            expected_selector_partition=_partition(),
            accepted_source_seal_id="SEAL",
            accepted_source_seal_projection_sha256="0" * 64,
            proof_validated_at=VALIDATED_AT,
        )


def test_position_artifacts_are_not_event_time_seal_or_proof_inputs() -> None:
    v01_receipt = v01_proof_fixture._receipt()

    with pytest.raises(AttributeError, match="final_watermarks"):
        seal_fixture.issue_r1_candidate_generation_seal(
            seal_id="SEAL-EVENT-TIME",
            run_metadata=seal_fixture._metadata(),
            run_closed=_close(),
            scenario_actions=seal_fixture._actions(),
            boundary=seal_fixture._boundary(),
            boundary_action_record=seal_fixture._boundary_record(),
            boundary_completion=seal_fixture._boundary_completion(),
            policy=seal_fixture._policy(),
            emitted_at=SEAL_AT,
        )
    with pytest.raises(TypeError, match="R1AcceptedRunCloseReceipt"):
        v01_proof_fixture.issue_r1_role2_verified_close_proof(
            proof_id="PROOF-EVENT-TIME",
            host_id=HOST_ID,
            verified_boundary=seal_fixture._verified_boundary(),
            source_seal=seal_fixture._seal(),
            accepted_run_closed=seal_fixture._run_closed(),
            accepted_close_receipt=_receipt(),
            candidate_policy=seal_fixture._policy(),
            proof_created_at=PROOF_AT,
        )
    with pytest.raises(TypeError, match="accepted_run_closed must be an R1RunClosed"):
        validate_r1_role2_verified_close_proof(
            v01_proof_fixture._proof(),
            accepted_run_closed=_close(),
            accepted_close_receipt=v01_receipt,
            candidate_policy=seal_fixture._policy(),
            expected_run_id=RUN_ID,
            expected_family_id="wmi_management",
            expected_selector_partition=_partition(),
            accepted_source_seal_id="SEAL",
            accepted_source_seal_projection_sha256="0" * 64,
            proof_validated_at=VALIDATED_AT,
        )


def test_event_time_artifacts_are_not_position_seal_or_proof_inputs() -> None:
    event_time_seal = seal_fixture._seal()
    v01_receipt = v01_proof_fixture._receipt()

    with pytest.raises(TypeError, match="must be an R1RecordPositionClose"):
        _seal(position_close=seal_fixture._run_closed(), position_close_receipt=_receipt())
    with pytest.raises(TypeError, match="R1AcceptedRecordPositionCloseReceipt"):
        _seal(position_close_receipt=v01_receipt)
    with pytest.raises(TypeError, match="R1PositionCandidateGenerationSeal"):
        issue_r1_position_seal_projection_record(
            seal=event_time_seal,
            verified_boundary=_verified(_seal()),
            host_id=HOST_ID,
            recorded_at=RECORDED_AT,
        )
    with pytest.raises(TypeError, match="R1PositionCandidateGenerationSeal"):
        _proof(source_seal=event_time_seal)
    with pytest.raises(TypeError, match="R1AcceptedRecordPositionCloseReceipt"):
        _proof(accepted_position_close_receipt=v01_receipt)
    with pytest.raises(TypeError, match="must be an R1RecordPositionClose"):
        _validate(_proof(), accepted_position_close=seal_fixture._run_closed())
    with pytest.raises(TypeError, match="R1AcceptedRecordPositionCloseReceipt"):
        _validate(_proof(), accepted_position_close_receipt=v01_receipt)
    with pytest.raises(TypeError, match="R1Role2VerifiedPositionCloseProof"):
        _validate(v01_proof_fixture._proof())


def test_proof_identity_reuse_with_other_content_is_rejected() -> None:
    proof = _proof()
    other = _proof(proof_created_at=datetime(2026, 10, 13, 1, 14, 5, 500000, tzinfo=UTC))

    validate_r1_role2_verified_position_close_proof_replay(proof, _proof())
    with pytest.raises(ValueError, match="reused with different content"):
        validate_r1_role2_verified_position_close_proof_replay(proof, other)


def test_role2_api_requires_every_external_binding() -> None:
    assert set(signature(validate_r1_role2_verified_position_close_proof).parameters) == {
        "proof",
        "accepted_position_close",
        "accepted_position_close_receipt",
        "candidate_policy",
        "expected_run_id",
        "expected_family_id",
        "expected_selector_partition",
        "expected_required_partition_contract_sha256",
        "accepted_source_seal_id",
        "accepted_source_seal_projection_sha256",
        "proof_validated_at",
    }
