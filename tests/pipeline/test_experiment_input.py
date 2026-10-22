import hashlib

import pytest

from incident_awareness.pipeline.experiment_input import (
    ExperimentDeclaration,
    current_experiment_declaration,
    experiment_declaration_context,
    verified_declaration,
)


@pytest.mark.parametrize("run_type", ["normal", "attack"])
def test_explicit_labels_are_content_bound_and_context_scoped(run_type):
    data = b"TEST FIXTURE\n"
    declared = ExperimentDeclaration(
        run_type=run_type, content_sha256=hashlib.sha256(data).hexdigest()
    )
    resolved, proof = verified_declaration(declared.metadata(), data)
    assert resolved.run_type.value == run_type
    assert proof["experiment-source"] == "explicit_local_demo_declaration"
    assert current_experiment_declaration() is None
    with experiment_declaration_context(proof):
        assert current_experiment_declaration() == proof
    assert current_experiment_declaration() is None


@pytest.mark.parametrize("mutation", ["missing", "hash", "type", "source", "actor", "time"])
def test_untrusted_or_missing_declarations_do_not_become_run_types(mutation):
    data = b"TEST FIXTURE\n"
    metadata = ExperimentDeclaration(
        run_type="normal", content_sha256=hashlib.sha256(data).hexdigest()
    ).metadata()
    if mutation == "missing":
        metadata = {}
    else:
        key, value = {
            "hash": ("experiment-content-sha256", "0" * 64),
            "type": ("experiment-run-type", "unknown"),
            "source": ("experiment-source", "fusion_miss_inference"),
            "actor": ("experiment-actor-kind", "authenticated_organization"),
            "time": ("experiment-declared-at", "2026-01-01T00:00:00"),
        }[mutation]
        metadata[key] = value
    with pytest.raises(ValueError, match="valid_content_bound_experiment_declaration_required"):
        verified_declaration(metadata, data)
