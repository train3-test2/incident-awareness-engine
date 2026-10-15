from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path

import pytest
import test_r1_candidate_generation_seal as seal_fixture
from pydantic import ValidationError

from incident_awareness.collection.r1_role2_verified_close_proof import (
    R1Role2VerifiedCloseProof,
    R1Role2VerifiedCloseProofValidation,
    issue_r1_role2_verified_close_proof,
    load_r1_role2_verified_close_proof,
    r1_run_closed_sha256,
    role2_verified_close_proof_sha256,
    validate_r1_role2_verified_close_proof,
    validate_r1_role2_verified_close_proof_replay,
    write_r1_role2_verified_close_proof,
)
from incident_awareness.common.models.r1_stream import R1RunClosed, R1StreamPartition


def _proof() -> R1Role2VerifiedCloseProof:
    return issue_r1_role2_verified_close_proof(
        proof_id="PROOF-RUN-20261013-001-000001",
        host_id="R1-TGTA",
        verified_boundary=seal_fixture._verified_boundary(),
        source_seal=seal_fixture._seal(),
        accepted_run_closed=seal_fixture._run_closed(),
        candidate_policy=seal_fixture._policy(),
        proof_created_at=datetime(2026, 10, 13, 1, 13, 3, tzinfo=UTC),
    )


def _selector_partition(
    host_id: str = "R1-TGTA",
    source: str = "sysmon",
    source_channel: str = "Microsoft-Windows-Sysmon/Operational",
) -> R1StreamPartition:
    return R1StreamPartition(
        run_id=seal_fixture.RUN_ID,
        host_id=host_id,
        source=source,
        source_channel=source_channel,
    )


def _validate(
    proof: R1Role2VerifiedCloseProof,
    *,
    run_closed: R1RunClosed | None = None,
    source_seal_sha256: str | None = None,
    expected_run_id: str = seal_fixture.RUN_ID,
    expected_family_id: str = "wmi_management",
    expected_partition: R1StreamPartition | None = None,
    source_seal_id: str | None = None,
):
    seal = seal_fixture._seal()
    return validate_r1_role2_verified_close_proof(
        proof,
        accepted_run_closed=run_closed or seal_fixture._run_closed(),
        candidate_policy=seal_fixture._policy(),
        expected_run_id=expected_run_id,
        expected_family_id=expected_family_id,
        expected_selector_partition=expected_partition or _selector_partition(),
        accepted_source_seal_id=source_seal_id or seal.seal_id,
        accepted_source_seal_content_sha256=(
            source_seal_sha256 or seal_fixture.candidate_generation_seal_sha256(seal)
        ),
        proof_validated_at=datetime(2026, 10, 13, 1, 13, 4, tzinfo=UTC),
    )


def _rehash(payload: dict[str, object]) -> R1Role2VerifiedCloseProof:
    content = dict(payload)
    content.pop("proof_content_sha256", None)
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    content["proof_content_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return R1Role2VerifiedCloseProof.model_validate(content)


def test_issues_complete_role2_safe_proof_and_validates_it_strictly() -> None:
    proof = _proof()

    validation = _validate(proof)

    assert isinstance(validation, R1Role2VerifiedCloseProofValidation)
    assert validation.proof is proof
    assert validation.proof_validated_at == datetime(2026, 10, 13, 1, 13, 4, tzinfo=UTC)
    assert proof.run_id == seal_fixture.RUN_ID
    assert proof.host_id == "R1-TGTA"
    assert proof.family_id == "wmi_management"
    assert proof.source_seal_id == seal_fixture._seal().seal_id
    assert proof.input_close_id == seal_fixture._run_closed().close_id
    assert proof.sealed_partitions == seal_fixture._run_closed().final_watermarks
    assert proof.source_seal_content_sha256 == (
        seal_fixture.candidate_generation_seal_sha256(seal_fixture._seal())
    )
    assert proof.accepted_run_closed_content_sha256 == r1_run_closed_sha256(
        seal_fixture._run_closed()
    )
    assert proof.proof_content_sha256 != proof.source_seal_content_sha256


def test_proof_contains_no_ground_truth_and_no_availability_claim() -> None:
    proof = _proof()
    serialized = json.dumps(proof.model_dump(mode="json", by_alias=True), sort_keys=True)

    for forbidden in (
        "run_type",
        "owned_processes",
        "process_guid",
        "attack",
        "normal",
        "available_at",
        "evidence",
    ):
        assert forbidden not in serialized.casefold()
    assert "verified_seal_at" in serialized
    assert "proof_created_at" in serialized
    assert "proof_validated_at" not in serialized


def test_strict_api_requires_every_external_binding() -> None:
    assert set(signature(validate_r1_role2_verified_close_proof).parameters) == {
        "proof",
        "accepted_run_closed",
        "candidate_policy",
        "expected_run_id",
        "expected_family_id",
        "expected_selector_partition",
        "accepted_source_seal_id",
        "accepted_source_seal_content_sha256",
        "proof_validated_at",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host_id", "OTHER-HOST"),
        ("family_id", "remote_management"),
        ("source_seal_content_sha256", "a" * 64),
        ("accepted_run_closed_content_sha256", "b" * 64),
        ("input_close_id", "CLOSE-OTHER"),
        ("candidate_boundary_at", "2026-10-13T01:11:59.000Z"),
    ],
)
def test_stale_hash_rejects_tampered_proof(field: str, value: object) -> None:
    payload = _proof().model_dump(mode="json", by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError, match="proof_content_sha256|present in sealed_partitions"):
        R1Role2VerifiedCloseProof.model_validate(payload)


@pytest.mark.parametrize(
    "partition",
    [
        _selector_partition("OTHER-HOST"),
        _selector_partition(source="other-source"),
        _selector_partition(source_channel="Other-Channel"),
    ],
)
def test_rehashed_cross_scope_proof_is_rejected_by_expected_bindings(
    partition: R1StreamPartition,
) -> None:
    proof = _proof()

    with pytest.raises(ValueError, match="expected_run_id"):
        _validate(proof, expected_run_id="RUN-20261013-002")
    with pytest.raises(ValueError, match="expected_family_id"):
        _validate(proof, expected_family_id="remote_management")
    with pytest.raises(ValueError, match="host_id|absent"):
        _validate(proof, expected_partition=partition)


def test_rejects_cross_policy_and_untrusted_source_seal_hash() -> None:
    proof = _proof()
    changed_policy = replace(seal_fixture._policy(), config_hash="c" * 64)

    with pytest.raises(ValueError, match="candidate policy identity"):
        validate_r1_role2_verified_close_proof(
            proof,
            accepted_run_closed=seal_fixture._run_closed(),
            candidate_policy=changed_policy,
            expected_run_id=seal_fixture.RUN_ID,
            expected_family_id="wmi_management",
            expected_selector_partition=_selector_partition(),
            accepted_source_seal_id=seal_fixture._seal().seal_id,
            accepted_source_seal_content_sha256=(
                seal_fixture.candidate_generation_seal_sha256(seal_fixture._seal())
            ),
            proof_validated_at=datetime(2026, 10, 13, 1, 13, 4, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match="source seal content hash"):
        _validate(proof, source_seal_sha256="d" * 64)
    with pytest.raises(ValueError, match="source_seal_id"):
        _validate(proof, source_seal_id="SEAL-OTHER")


def test_rejects_changed_run_closed_content() -> None:
    proof = _proof()
    run_closed = seal_fixture._run_closed()
    changed_close = run_closed.model_copy(
        update={"emitted_at": run_closed.emitted_at + timedelta(milliseconds=1)}
    )

    with pytest.raises(ValueError, match="run_closed content hash"):
        _validate(proof, run_closed=changed_close)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("watermark_id", "WM-OTHER"),
        ("watermark_sequence", 4),
        ("allowed_lateness_ms", 1000),
        ("covered_through_chunk_sequence", 4),
    ],
)
def test_rejects_changed_final_watermark_binding(field: str, value: object) -> None:
    proof = _proof()
    payload = proof.model_dump(mode="json", by_alias=True)
    payload["sealed_partitions"][0][field] = value
    changed_partitions = _rehash(payload)

    with pytest.raises(ValueError, match="sealed_partitions"):
        _validate(changed_partitions)


def test_rejects_incomplete_sequence_and_watermark_before_boundary() -> None:
    payload = _proof().model_dump(mode="json", by_alias=True)
    payload["sealed_partitions"][0]["covered_through_chunk_sequence"] = 0
    with pytest.raises(ValidationError):
        _rehash(payload)

    payload = _proof().model_dump(mode="json", by_alias=True)
    payload["sealed_partitions"][0]["watermark_at"] = "2026-10-13T01:11:59.000Z"
    with pytest.raises(ValidationError, match="cover the candidate boundary"):
        _rehash(payload)


def test_rejects_temporal_inversion() -> None:
    payload = _proof().model_dump(mode="json", by_alias=True)
    payload["proof_created_at"] = "2026-10-13T01:13:01.000Z"

    with pytest.raises(ValidationError, match="must not precede verified_seal_at"):
        _rehash(payload)

    with pytest.raises(ValueError, match="proof_validated_at must not precede"):
        validate_r1_role2_verified_close_proof(
            _proof(),
            accepted_run_closed=seal_fixture._run_closed(),
            candidate_policy=seal_fixture._policy(),
            expected_run_id=seal_fixture.RUN_ID,
            expected_family_id="wmi_management",
            expected_selector_partition=_selector_partition(),
            accepted_source_seal_id=seal_fixture._seal().seal_id,
            accepted_source_seal_content_sha256=(
                seal_fixture.candidate_generation_seal_sha256(seal_fixture._seal())
            ),
            proof_validated_at=datetime(2026, 10, 13, 1, 13, 2, tzinfo=UTC),
        )


def test_issue_rejects_boundary_or_source_that_was_not_the_verified_input() -> None:
    seal = seal_fixture._seal()
    changed_seal = seal.model_copy(
        update={"emitted_at": seal.emitted_at + timedelta(milliseconds=1)}
    )

    with pytest.raises(ValueError, match="does not exactly match source seal"):
        issue_r1_role2_verified_close_proof(
            proof_id="PROOF-OTHER",
            host_id="R1-TGTA",
            verified_boundary=seal_fixture._verified_boundary(),
            source_seal=changed_seal,
            accepted_run_closed=seal_fixture._run_closed(),
            candidate_policy=seal_fixture._policy(),
            proof_created_at=datetime(2026, 10, 13, 1, 13, 3, tzinfo=UTC),
        )


def test_round_trip_retains_every_binding_and_writer_is_exclusive(tmp_path: Path) -> None:
    proof = _proof()
    path = tmp_path / "proof.json"

    write_r1_role2_verified_close_proof(path, proof)
    loaded = load_r1_role2_verified_close_proof(path)

    assert loaded == proof
    assert loaded.model_dump(mode="json", by_alias=True) == proof.model_dump(
        mode="json", by_alias=True
    )
    assert _validate(loaded).proof == proof
    with pytest.raises(FileExistsError):
        write_r1_role2_verified_close_proof(path, proof)


def test_loader_rejects_duplicate_keys_and_changed_content_hash(tmp_path: Path) -> None:
    path = tmp_path / "proof.json"
    path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        load_r1_role2_verified_close_proof(path)

    payload = _proof().model_dump(mode="json", by_alias=True)
    payload["host_id"] = "OTHER-HOST"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match v0.1"):
        load_r1_role2_verified_close_proof(path)


def test_exact_replay_is_idempotent_but_changed_content_is_rejected() -> None:
    proof = _proof()
    validate_r1_role2_verified_close_proof_replay(proof, proof.model_copy(deep=True))

    payload = proof.model_dump(mode="json", by_alias=True)
    payload["proof_created_at"] = "2026-10-13T01:13:04Z"
    changed = _rehash(payload)
    with pytest.raises(ValueError, match="reused with different content"):
        validate_r1_role2_verified_close_proof_replay(proof, changed)
    assert role2_verified_close_proof_sha256(proof) != role2_verified_close_proof_sha256(changed)
