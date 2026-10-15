"""Real CSV -> handoff -> selection -> Adapter -> evaluation binding tests."""

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_awareness.common.models.run import RunType
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.detection.fast_selection import FastSelectionPolicy, select_fast_hit
from incident_awareness.evaluation.fast_binding import (
    FastBindingInput,
    FastSetBinding,
    fast_binding_sha256,
)
from incident_awareness.evaluation.result_inputs import (
    build_evaluation_inputs,
    evaluate_snapshot,
    load_evaluation_snapshot,
)
from incident_awareness.integration.fast_hit_handoff import (
    adapt_fast_hit_handoff,
    read_fast_hit_handoff,
)


def setup_snapshot(tmp_path, *, miss=False):
    snapshot = load_evaluation_snapshot(Path("tests/fixtures/evaluation/result_snapshot.json"))
    snapshot.runs = snapshot.runs[:1]
    bundle = snapshot.runs[0]
    run = bundle.run_metadata
    snapshot.plan.decision_ids = {run.run_id: bundle.decision.decision_id}
    snapshot.plan.require_fast_binding = True
    bundle.detection.detector_time = datetime(2026, 9, 20, 0, 1, 40, tzinfo=UTC)
    return attach_fast_binding(snapshot, tmp_path, miss=miss)


def attach_fast_binding(snapshot, tmp_path, *, miss=False):
    if (tmp_path / "hits.jsonl").exists():
        tmp_path = Path(tempfile.mkdtemp(prefix="execution-", dir=tmp_path))
    bundle = snapshot.runs[0]
    run = bundle.run_metadata
    timestamp = bundle.detection.detector_time
    config = {
        "detector_engine_version": "synthetic-v1",
        "detector_config_version": "synthetic-config-v1",
        "qualifying_rule_ids": ["synthetic-rule"],
        "rule_metadata": {"synthetic-rule": {"rule_version": "v1", "alert_key": "test"}},
    }
    csv_path, config_path = tmp_path / "source.csv", tmp_path / "config.json"
    csv_path.write_text(
        "Timestamp,RuleID,Computer,RecordID\n"
        + (
            ""
            if miss
            else f"{timestamp.isoformat(timespec='milliseconds')},synthetic-rule,HOST,1\n"
        )
    )
    config_path.write_text(json.dumps(config))
    hits, trace = tmp_path / "hits.jsonl", tmp_path / "trace.json"
    run_fast_handoff(
        csv_path=csv_path,
        config_path=config_path,
        run_id=run.run_id,
        output_path=hits,
        trace_path=trace,
    )
    policy = FastSelectionPolicy(
        policy_version="fast-selection-v1",
        detector_set_version="set-v1",
        detector_config_version=config["detector_config_version"],
        config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
        timestamp_source="hayabusa_csv_timestamp",
        tie_break="timestamp_rule_id_hit_id",
        host_entity_map={"HOST": run.target_host},
    )
    selection, audit = select_fast_hit(
        hits_path=hits,
        trace_path=trace,
        policy=policy,
        run_id=run.run_id,
        entity_id=run.target_host,
    )
    selection_path, audit_path = tmp_path / "selection.json", tmp_path / "selection-audit.json"
    selection_path.write_text(selection.model_dump_json())
    audit_path.write_text(json.dumps(audit))
    binding = FastSetBinding(
        contract_version="fast-set-binding-v1",
        detector_set_version="set-v1",
        detector_config_version=policy.detector_config_version,
        config_sha256=policy.config_sha256,
        selection_policy_sha256=audit["policy_sha256"],
        approval_reference="synthetic-approval",
    )
    bundle.fast_binding = FastBindingInput(
        binding=binding,
        policy=policy,
        hits_path=str(hits),
        trace_path=str(trace),
        selection_path=str(selection_path),
        audit_path=str(audit_path),
    )
    snapshot.plan.fast_binding_hashes = {run.run_id: fast_binding_sha256(binding)}
    adapted = adapt_fast_hit_handoff(
        read_fast_hit_handoff(hits, trace, run_id=run.run_id),
        entity_id=run.target_host,
        selection=selection,
        entity_mapper=policy.host_entity_map.get,
    )
    bundle.detection = adapted.detection_result
    bundle.decision = combine_results(
        bundle.detection,
        bundle.fusion,
        decision_id=bundle.decision.decision_id,
        config_version=snapshot.plan.decision_config_version,
        parallel_required=True,
        source_hit_ids=adapted.source_hit_ids,
        selected_source_hit_id=adapted.selected_source_hit_id,
    )
    bundle.decision.detector_set_version = "set-v1"
    bundle.fast_episodes.start_times = [] if miss else [bundle.detection.detector_time]
    return snapshot


@pytest.mark.parametrize("miss", [False, True])
def test_bound_fast_result_reaches_evaluation(tmp_path, miss):
    snapshot = setup_snapshot(tmp_path, miss=miss)
    report = evaluate_snapshot(snapshot)
    assert report["comparison_ready"]
    assert report["metrics"]["Fast"]["median_ttsd_sec"] == (None if miss else 40)


@pytest.mark.parametrize("missing", ["binding", "pin", "file"])
def test_missing_binding_is_error_not_miss(tmp_path, missing):
    snapshot = setup_snapshot(tmp_path, miss=True)
    if missing == "binding":
        snapshot.runs[0].fast_binding = None
    elif missing == "pin":
        snapshot.plan.fast_binding_hashes = {}
    else:
        Path(snapshot.runs[0].fast_binding.audit_path).unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        evaluate_snapshot(snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("detector_set_version", "other-set"),
        ("detector_config_version", "other-config"),
        ("config_sha256", "0" * 64),
        ("selection_policy_sha256", "0" * 64),
    ],
)
def test_binding_semantics_even_if_record_is_repinned(tmp_path, field, value):
    snapshot = setup_snapshot(tmp_path)
    bundle = snapshot.runs[0]
    setattr(bundle.fast_binding.binding, field, value)
    snapshot.plan.fast_binding_hashes[bundle.run_metadata.run_id] = fast_binding_sha256(
        bundle.fast_binding.binding
    )
    with pytest.raises(ValueError, match="(binding|hash)"):
        evaluate_snapshot(snapshot)


def test_changed_approval_record_rejected_by_pin(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    snapshot.runs[0].fast_binding.binding.approval_reference = "other-approval"
    with pytest.raises(ValueError, match="pinned approval"):
        evaluate_snapshot(snapshot)


@pytest.mark.parametrize("field", ["selection_path", "audit_path"])
def test_stored_selection_and_audit_must_match_recomputed_source(tmp_path, field):
    snapshot = setup_snapshot(tmp_path)
    path = Path(getattr(snapshot.runs[0].fast_binding, field))
    path.write_text("{}")
    with pytest.raises(ValueError, match="stored Fast"):
        evaluate_snapshot(snapshot)


@pytest.mark.parametrize("change", ["set", "sources", "missing_sources", "selected", "detection"])
def test_adapter_and_decision_provenance_cannot_drift(tmp_path, change):
    snapshot = setup_snapshot(tmp_path)
    bundle = snapshot.runs[0]
    if change == "set":
        bundle.decision.detector_set_version = None
    elif change == "sources":
        bundle.decision.source_hit_ids.append("unexpected")
    elif change == "missing_sources":
        bundle.decision.source_hit_ids = None
        bundle.decision.selected_source_hit_id = None
    elif change == "selected":
        bundle.decision.selected_source_hit_id = None
    else:
        bundle.detection.rule_version = "other"
    with pytest.raises(ValueError):
        evaluate_snapshot(snapshot)


def test_r1_performance_cannot_disable_binding(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    snapshot.plan.scenario_id = snapshot.runs[0].run_metadata.scenario_id = "R1"
    snapshot.plan.purpose = "performance"
    snapshot.plan.require_fast_binding = False
    snapshot.plan.fast_binding_hashes = {}
    snapshot.runs[0].fast_binding = None
    with pytest.raises(ValueError, match="requires set binding"):
        build_evaluation_inputs(snapshot)


def test_source_csv_edit_cannot_pass_unchanged_audit(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    (tmp_path / "source.csv").write_text("Timestamp,RuleID,Computer,RecordID\n")
    with pytest.raises(ValueError):
        evaluate_snapshot(snapshot)


def test_normal_run_uses_same_binding_boundary(tmp_path):
    snapshot = setup_snapshot(tmp_path, miss=True)
    snapshot.runs[0].run_metadata.run_type = RunType.NORMAL
    snapshot.runs[0].run_metadata.reference_time = None
    assert evaluate_snapshot(snapshot)["comparison_ready"]


def test_changed_host_mapping_cannot_reuse_approved_policy_hash(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    snapshot.runs[0].fast_binding.policy.host_entity_map["UNUSED"] = "other"
    with pytest.raises(ValueError, match="policy hash"):
        evaluate_snapshot(snapshot)


def test_unplanned_binding_hash_rejected(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    snapshot.plan.fast_binding_hashes["unexpected-run"] = "0" * 64
    with pytest.raises(ValueError, match="unplanned Runs"):
        evaluate_snapshot(snapshot)


def test_json_snapshot_roundtrip_preserves_binding(tmp_path):
    snapshot = setup_snapshot(tmp_path)
    path = tmp_path / "snapshot.json"
    path.write_text(snapshot.model_dump_json())
    assert evaluate_snapshot(load_evaluation_snapshot(path)) == evaluate_snapshot(snapshot)


def test_stored_snapshot_consumes_external_fast_binding(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from psycopg.pq import TransactionStatus

    from incident_awareness.evaluation import stored_snapshot as stored

    snapshot = setup_snapshot(tmp_path)
    bundle = snapshot.runs[0]
    for repository, field in (
        (stored.RunRepository, "run_metadata"),
        (stored.DetectionResultRepository, "detection"),
        (stored.FusionResultRepository, "fusion"),
        (stored.DecisionRepository, "decision"),
    ):
        monkeypatch.setattr(
            repository, "get", lambda self, *args, field=field: getattr(bundle, field)
        )
    connection = SimpleNamespace(
        info=SimpleNamespace(transaction_status=TransactionStatus.IDLE),
        transaction=lambda: nullcontext(),
        execute=lambda *args: None,
    )
    arguments = {
        "snapshot_id": snapshot.snapshot_id,
        "plan": snapshot.plan,
        "fast_episodes": {bundle.run_metadata.run_id: bundle.fast_episodes},
        "fusion_observations": {bundle.run_metadata.run_id: bundle.fusion_observation},
    }
    with pytest.raises(ValueError, match="requires set binding"):
        stored.read_stored_snapshot(connection, **arguments)
    actual = stored.read_stored_snapshot(
        connection, fast_bindings={bundle.run_metadata.run_id: bundle.fast_binding}, **arguments
    )
    assert evaluate_snapshot(actual) == evaluate_snapshot(snapshot)
