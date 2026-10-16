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
    # Given
    directory, pins, run, trust, f = execution
    original = _contents(directory)
    # When
    result = validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    # Then
    assert len(result.scheduled_evidences) == 2
    assert {x.available_at for x in result.scheduled_evidences} == {f._INPUTS_VALIDATED_AT}
    assert all(x.available_at != f._EVIDENCE_READY_AT for x in result.scheduled_evidences)
    assert _contents(directory) == original


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_missing_artifact_rejected_without_creation(execution, name):
    """Reject missing source artifacts without manufacturing replacement records."""
    # Given
    directory, pins, run, trust, _ = execution
    (directory / name).unlink()
    # When
    with pytest.raises(FileNotFoundError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    # Then
    assert str(exc.value)
    assert not (directory / name).exists()


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_changed_bytes_rejected_even_when_json_semantically_same(execution, name):
    """Bind exact received bytes, including semantically insignificant whitespace."""
    # Given
    directory, pins, run, trust, _ = execution
    path = directory / name
    path.write_bytes(path.read_bytes() + b"\n")
    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert "pinned artifact bytes" in str(exc.value)


def test_metadata_mismatch_rejected(execution):
    """Reject a Run identity that differs from the registered metadata digest."""
    # Given
    directory, pins, run, trust, _ = execution
    run = run.model_copy(update={"run_id": "RUN-OTHER"})
    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert "RunMetadata" in str(exc.value)


def test_wrong_trusted_seal_rejected(execution):
    """Require checkpoint proof to match the independently accepted source seal."""
    # Given
    directory, pins, run, trust, _ = execution
    trust = replace(trust, accepted_source_seal_projection_sha256="0" * 64)
    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert str(exc.value)


@pytest.mark.parametrize("usage", ["performance", "development", "holdout"])
def test_usage_cannot_be_promoted(execution, usage):
    """Prevent synthetic receipt pins from claiming broader evaluation permission."""
    # Given
    _, pins, _, _, _ = execution
    # When
    with pytest.raises(ValidationError) as exc:
        IncrementalInputPins.model_validate({**pins.model_dump(), "usage": usage})

    # Then
    assert str(exc.value)


@pytest.mark.parametrize("mutation", ["version", "backdated", "run", "duplicate_key"])
def test_strict_loader_rejects_bad_content_even_with_new_receipt(execution, mutation):
    """Reject malformed contracts even when an outer digest matches the changed file."""
    # Given
    directory, pins, run, trust, _ = execution
    name = ARTIFACT_NAMES[3] if mutation == "version" else ARTIFACT_NAMES[5]
    path = directory / name
    data = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "version":
        data["contract_version"] = "v99"
    elif mutation == "backdated":
        data["inputs_validated_at"] = "2026-10-13T01:00:00Z"
    elif mutation == "run":
        data["run_id"] = "RUN-OTHER"
    if mutation == "duplicate_key":
        path.write_text(
            '{"run_id":"ambiguous",' + path.read_text(encoding="utf-8").lstrip()[1:],
            encoding="utf-8",
        )
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    pins = pins.model_copy(
        update={"execution_sha256": incremental_execution_sha256(_contents(directory))}
    )
    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert str(exc.value)


def _rewrite_validation(directory, pins, **updates):
    """Rehash synthetic mutations to exercise pairing beyond self-hash integrity."""
    import hashlib

    path = directory / ARTIFACT_NAMES[5]
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(updates)
    data.pop("validation_content_sha256")
    data["validation_content_sha256"] = hashlib.sha256(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.write_text(json.dumps(data), encoding="utf-8")
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
    # Given
    directory, pins, run, trust, _ = execution
    pins = _rewrite_validation(directory, pins, **updates)
    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert str(exc.value)


def test_late_validation_is_preserved_not_clamped(execution):
    """Preserve post-Run validation time without creating an in-Run availability."""
    # Given
    directory, pins, run, trust, _ = execution
    pins = _rewrite_validation(directory, pins, inputs_validated_at="2026-10-13T01:15:00Z")
    # When
    result = validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    # Then
    assert all(x.available_at > run.end_time for x in result.scheduled_evidences)
    assert {x.available_at.isoformat() for x in result.scheduled_evidences} == {
        "2026-10-13T01:15:00+00:00"
    }


@pytest.mark.parametrize(
    "section,field",
    [
        ("selector", "policy_id"),
        ("selector", "version"),
        ("selector", "config_hash"),
        ("lineage_inputs", "anchor_event_id"),
        ("lineage_inputs", "terminal_event_id"),
        ("lineage_inputs", "policy_id"),
        ("lineage_inputs", "policy_version"),
        ("lineage_inputs", "policy_config_hash"),
    ],
)
def test_rehashed_summary_policy_cannot_drift(execution, section, field):
    # Given
    directory, pins, run, trust, _ = execution
    path = directory / ARTIFACT_NAMES[1]
    data = json.loads(path.read_bytes())
    target = data[section] if section == "selector" else data[section][0]
    target[field] = "different"
    path.write_text(json.dumps(data), encoding="utf-8")
    pins = pins.model_copy(
        update={"execution_sha256": incremental_execution_sha256(_contents(directory))}
    )

    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert "summary" in str(exc.value)
    if section == "selector":
        assert "trusted policy" in str(exc.value)


def _isolate_role5(execution, monkeypatch):
    """Keep upstream restoration valid while injecting downstream boundary defects."""
    from types import SimpleNamespace

    from incident_awareness.evaluation import incremental_inputs as module

    directory, _pins, _run, trust, _ = execution
    checkpoint = module.load_r1_incremental_checkpoint(directory / ARTIFACT_NAMES[2])
    restored = module.R1IncrementalEvidenceState.restore_from_checkpoint(
        checkpoint,
        selector_policy=trust.selector,
        approved_policy=trust.approved,
        candidate_policy=trust.candidate,
        ingress=trust.ingress,
        accepted_close_receipt=trust.accepted_close_receipt,
        accepted_source_seal_id=trust.accepted_source_seal_id,
        accepted_source_seal_projection_sha256=trust.accepted_source_seal_projection_sha256,
    ).snapshot
    artifact = module.load_r1_evidence_artifacts(directory)
    validation = module.load_r1_incremental_replay_input_validation(directory / ARTIFACT_NAMES[5])
    monkeypatch.setattr(
        module.R1IncrementalEvidenceState,
        "restore_from_checkpoint",
        lambda *a, **kw: SimpleNamespace(snapshot=restored),
    )
    monkeypatch.setattr(
        module,
        "prepare_r1_incremental_causal_replay_input",
        lambda *a, **kw: SimpleNamespace(incremental_input_validation=validation),
    )
    return module, artifact, restored, checkpoint, validation


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("evidence", "stored Evidence differs"),
        ("count", "input Event count differs"),
        ("provenance", "latest referenced NormalizedEvent.timestamp"),
        ("duplicate", "conflicting Event identity"),
        ("context", "summary lineage provenance"),
    ],
)
def test_role5_semantic_guards_independent_of_producer(execution, monkeypatch, mutation, error):
    # Given
    from datetime import timedelta
    from types import SimpleNamespace

    directory, pins, run, trust, _ = execution
    module, artifact, restored, checkpoint, _ = _isolate_role5(execution, monkeypatch)
    if mutation == "evidence":
        artifact = replace(artifact, evidences=artifact.evidences[:-1])
    elif mutation == "count":
        artifact = replace(
            artifact,
            summary=replace(
                artifact.summary, input_event_count=artifact.summary.input_event_count + 1
            ),
        )
    elif mutation == "provenance":
        changed = artifact.evidences[0].model_copy(
            update={"timestamp": artifact.evidences[0].timestamp + timedelta(milliseconds=1)}
        )
        evidences = (changed, *artifact.evidences[1:])
        artifact = replace(artifact, evidences=evidences)
        restored = replace(restored, evidences=evidences)
        monkeypatch.setattr(
            module.R1IncrementalEvidenceState,
            "restore_from_checkpoint",
            lambda *a, **kw: SimpleNamespace(snapshot=restored),
        )
    elif mutation == "context":
        lineage = artifact.summary.lineage_inputs[0]
        artifact = replace(
            artifact, summary=replace(artifact.summary, lineage_inputs=(lineage, lineage))
        )
    else:
        chunk = checkpoint.accepted_chunks[0]
        event = chunk.events[0].model_copy(
            update={"timestamp": chunk.events[0].timestamp + timedelta(milliseconds=1)}
        )
        changed = chunk.model_copy(update={"events": (event,)})
        checkpoint = checkpoint.model_copy(
            update={"accepted_chunks": (*checkpoint.accepted_chunks, changed)}
        )
        monkeypatch.setattr(module, "load_r1_incremental_checkpoint", lambda *a: checkpoint)
    monkeypatch.setattr(module, "load_r1_evidence_artifacts", lambda *a: artifact)

    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert error in str(exc.value)


@pytest.mark.parametrize("mutation", ["model", "bytes"])
def test_adapter_cannot_replace_first_validation_record(execution, monkeypatch, mutation):
    # Given
    from types import SimpleNamespace

    directory, pins, run, trust, _ = execution
    module, _, _, _, validation = _isolate_role5(execution, monkeypatch)
    original = _contents(directory)

    def adapter(*args, input_validation_path, **kwargs):
        if mutation == "bytes":
            input_validation_path.write_bytes(input_validation_path.read_bytes() + b"\n")
        return SimpleNamespace(
            incremental_input_validation=None if mutation == "model" else validation
        )

    monkeypatch.setattr(module, "prepare_r1_incremental_causal_replay_input", adapter)

    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)
    remaining = _contents(directory)

    # Then
    assert "first validation record" in str(exc.value)
    assert remaining == original


@pytest.mark.parametrize(
    "field",
    ["anchor_event_id", "terminal_event_id", "policy_id", "policy_version", "policy_config_hash"],
)
def test_role5_lineage_binding_independent_of_loader(execution, monkeypatch, field):
    # Given
    directory, pins, run, trust, _ = execution
    module, artifact, _, _, _ = _isolate_role5(execution, monkeypatch)
    lineage = replace(artifact.summary.lineage_inputs[0], **{field: "different"})
    artifact = replace(artifact, summary=replace(artifact.summary, lineage_inputs=(lineage,)))
    monkeypatch.setattr(module, "load_r1_evidence_artifacts", lambda *a: artifact)

    # When
    with pytest.raises(ValueError) as exc:
        validate_incremental_execution_input(directory, pins, run=run, trust=trust)

    # Then
    assert "summary lineage provenance differs from recovered checkpoint" in str(exc.value)
