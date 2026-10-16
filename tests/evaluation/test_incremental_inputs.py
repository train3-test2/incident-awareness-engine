"""Synthetic v0.2 receipt boundaries; no detection performance claims."""

import importlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from incident_awareness.collection.r1_role2_verified_close_proof import (
    role2_safe_source_seal_projection_sha256,
)
from incident_awareness.evaluation.incremental_inputs import (
    ARTIFACT_NAMES,
    IncrementalInputPins,
    IncrementalInputTrust,
    incremental_execution_sha256,
    validate_incremental_execution_input,
)
from incident_awareness.pipeline.r1_automated import run_and_write_r1_evidence_artifacts_from_policy
from incident_awareness.pipeline.r1_causal_replay import prepare_r1_incremental_causal_replay_input
from incident_awareness.pipeline.r1_causal_replay_artifacts import canonical_model_sha256
from incident_awareness.pipeline.r1_incremental_availability import (
    build_r1_incremental_causal_availability_envelope,
    load_r1_incremental_availability_publication_receipt,
    write_r1_incremental_causal_availability_envelope,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import write_r1_incremental_checkpoint


@pytest.fixture
def execution(tmp_path, monkeypatch):
    # Reuse Role2's synthetic contract fixture, never local Run artifacts.
    """Build a fully published synthetic execution with isolated recovery trust."""
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "collection"))
    f = importlib.import_module("test_r1_incremental_availability_v02")
    state, snapshot, selector, approved, candidate, close, seal = f._state()
    run = f._run_metadata()
    checkpoint = state.export_checkpoint()
    run_and_write_r1_evidence_artifacts_from_policy(
        f._events(),
        run_id=run.run_id,
        output_directory=tmp_path,
        selector_policy=selector,
        approved_policy_id=approved.policy_id,
        approved_policy_version=approved.version,
        approved_policy_config_path=f._APPROVED_CONFIG_PATH,
        scenario_family_id=run.family_id,
        run_start=run.start_time,
    )
    write_r1_incremental_checkpoint(tmp_path / ARTIFACT_NAMES[2], checkpoint)
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=run,
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    write_r1_incremental_causal_availability_envelope(
        tmp_path / ARTIFACT_NAMES[3],
        envelope,
        clock=lambda: f._PUBLICATION_COMPLETED_AT,
    )
    publication = load_r1_incremental_availability_publication_receipt(tmp_path / ARTIFACT_NAMES[4])
    prepare_r1_incremental_causal_replay_input(
        snapshot,
        envelope,
        checkpoint,
        publication,
        input_validation_path=tmp_path / ARTIFACT_NAMES[5],
        run_metadata=run,
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
        clock=lambda: f._INPUTS_VALIDATED_AT,
    )
    trust = IncrementalInputTrust(
        selector,
        approved,
        candidate,
        f._ingress(),
        close,
        seal.seal_id,
        role2_safe_source_seal_projection_sha256(seal, host_id=run.target_host),
    )
    pins = IncrementalInputPins(
        contract_version="evaluation-incremental-input-v1",
        usage="synthetic_contract_check",
        run_metadata_sha256=canonical_model_sha256(run),
        execution_sha256=incremental_execution_sha256(_contents(tmp_path)),
    )
    return tmp_path, pins, run, trust, f


def _contents(path):
    """Read the complete artifact set for receipt registration and byte comparisons."""
    return {name: (path / name).read_bytes() for name in ARTIFACT_NAMES}


def test_pinned_execution_reuses_validation_time_and_preserves_files(execution):
    """Keep the first validation time and leave every received artifact unchanged."""
    directory, pins, run, trust, f = execution
    original = _contents(directory)
    result = validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    assert len(result.scheduled_evidences) == 2
    assert {x.available_at for x in result.scheduled_evidences} == {f._INPUTS_VALIDATED_AT}
    assert all(x.available_at != f._EVIDENCE_READY_AT for x in result.scheduled_evidences)
    assert _contents(directory) == original


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_missing_artifact_rejected_without_creation(execution, name):
    """Reject missing source artifacts without manufacturing replacement records."""
    directory, pins, run, trust, _ = execution
    (directory / name).unlink()
    with pytest.raises(FileNotFoundError):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    assert not (directory / name).exists()


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_changed_bytes_rejected_even_when_json_semantically_same(execution, name):
    """Bind exact received bytes, including semantically insignificant whitespace."""
    directory, pins, run, trust, _ = execution
    path = directory / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="pinned artifact bytes"):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)


def test_metadata_mismatch_rejected(execution):
    """Reject a Run identity that differs from the registered metadata digest."""
    directory, pins, run, trust, _ = execution
    run = run.model_copy(update={"run_id": "RUN-OTHER"})
    with pytest.raises(ValueError, match="RunMetadata"):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)


def test_wrong_trusted_seal_rejected(execution):
    """Require checkpoint proof to match the independently accepted source seal."""
    directory, pins, run, trust, _ = execution
    trust = replace(trust, accepted_source_seal_projection_sha256="0" * 64)
    with pytest.raises(ValueError):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)


@pytest.mark.parametrize("usage", ["performance", "development", "holdout"])
def test_usage_cannot_be_promoted(execution, usage):
    """Prevent synthetic receipt pins from claiming broader evaluation permission."""
    _, pins, _, _, _ = execution
    with pytest.raises(ValidationError):
        IncrementalInputPins.model_validate({**pins.model_dump(), "usage": usage})


@pytest.mark.parametrize("mutation", ["version", "backdated", "run", "duplicate_key"])
def test_strict_loader_rejects_bad_content_even_with_new_receipt(execution, mutation):
    """Reject malformed contracts even when an outer digest matches the changed file."""
    directory, pins, run, trust, _ = execution
    name = ARTIFACT_NAMES[3] if mutation == "version" else ARTIFACT_NAMES[5]
    path = directory / name
    data = json.loads(path.read_text())
    if mutation == "version":
        data["contract_version"] = "v99"
    elif mutation == "backdated":
        data["inputs_validated_at"] = "2026-10-13T01:00:00Z"
    elif mutation == "run":
        data["run_id"] = "RUN-OTHER"
    if mutation == "duplicate_key":
        path.write_text('{"run_id":"ambiguous",' + path.read_text().lstrip()[1:])
    else:
        path.write_text(json.dumps(data))
    pins = pins.model_copy(
        update={"execution_sha256": incremental_execution_sha256(_contents(directory))}
    )
    with pytest.raises(ValueError):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)


def _rewrite_validation(directory, pins, **updates):
    """Rehash synthetic mutations to exercise pairing beyond self-hash integrity."""
    import hashlib

    path = directory / ARTIFACT_NAMES[5]
    data = json.loads(path.read_text())
    data.update(updates)
    data.pop("validation_content_sha256")
    data["validation_content_sha256"] = hashlib.sha256(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.write_text(json.dumps(data))
    return pins.model_copy(
        update={"execution_sha256": incremental_execution_sha256(_contents(directory))}
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"source_envelope_sha256": "0" * 64},
        {"source_checkpoint_sha256": "0" * 64},
        {"source_publication_receipt_sha256": "0" * 64},
        {"inputs_validated_at": "2026-10-13T01:13:06Z"},
    ],
)
def test_valid_self_hash_cannot_replace_pairing_or_publication_order(execution, updates):
    """Reject validly hashed records bound to wrong sources or premature validation."""
    directory, pins, run, trust, _ = execution
    pins = _rewrite_validation(directory, pins, **updates)
    with pytest.raises(ValueError):
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)


def test_late_validation_is_preserved_not_clamped(execution):
    """Preserve post-Run validation time without creating an in-Run availability."""
    directory, pins, run, trust, _ = execution
    pins = _rewrite_validation(directory, pins, inputs_validated_at="2026-10-13T01:15:00Z")
    result = validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    assert all(x.available_at > run.end_time for x in result.scheduled_evidences)
    assert {x.available_at.isoformat() for x in result.scheduled_evidences} == {
        "2026-10-13T01:15:00+00:00"
    }
