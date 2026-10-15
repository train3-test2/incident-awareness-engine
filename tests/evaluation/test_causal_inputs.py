from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_fast_binding import attach_fast_binding

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.decision.fusion.config import (
    FusionConfig,
    ReplayConfig,
    ScoringConfig,
    StoppingConfig,
    WindowConfig,
)
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.evaluation.causal_inputs import (
    CausalReplayEvaluationInput,
    CausalReplayPins,
)
from incident_awareness.evaluation.paired_timing import compare_paired_timing
from incident_awareness.evaluation.result_inputs import (
    EvaluationPlan,
    EvaluationSnapshot,
    FastEpisodeStarts,
    FusionObservation,
    StoredRunResults,
    build_evaluation_inputs,
    evaluate_snapshot,
    load_evaluation_snapshot,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1EvidenceArtifactRun,
    R1ExtractionSummary,
    R1LineageInputProvenance,
    R1SelectorProvenance,
)
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalAvailabilityEnvelope,
    R1CausalEvidenceAvailability,
    R1CausalPolicyIdentity,
)
from incident_awareness.pipeline.r1_causal_replay import (
    run_r1_causal_replay,
)
from incident_awareness.pipeline.r1_causal_replay_artifacts import canonical_model_sha256

_FAST_FIXTURE_DIR = None

_RUN_ID = "RUN-20261012-001"
_HOST_ID = "TARGET-A"
_START = datetime(2026, 10, 12, 1, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=35)
_EVIDENCE_HASH = "a" * 64
_SUMMARY_HASH = "b" * 64


def _evidence(
    evidence_id: str,
    *,
    timestamp: datetime,
    evidence_type: str,
    event_ids: list[str],
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        timestamp=timestamp,
        entity_id=_HOST_ID,
        evidence_type=evidence_type,
        event_ids=event_ids,
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="r1-multi-event-v0.1",
    )


def _evidences() -> tuple[Evidence, ...]:
    return (
        _evidence(
            "E-lineage",
            timestamp=_START + timedelta(seconds=20),
            evidence_type="remote_session_process_lineage_deviation",
            event_ids=["evt-anchor", "evt-middle", "evt-terminal"],
        ),
        _evidence(
            "E-network",
            timestamp=_START + timedelta(seconds=30),
            evidence_type="remote_process_network_follow_on",
            event_ids=["evt-terminal", "evt-network"],
        ),
    )


def _artifact_run(*, evidences: tuple[Evidence, ...] | None = None) -> R1EvidenceArtifactRun:
    loaded_evidences = evidences if evidences is not None else _evidences()
    summary = R1ExtractionSummary(
        run_id=_RUN_ID,
        extractor_version="r1-multi-event-v0.1",
        input_event_count=4,
        evidence_count=len(loaded_evidences),
        status="completed",
        telemetry_completeness="not_provided",
        lineage_inputs=(
            R1LineageInputProvenance(
                anchor_event_id="evt-anchor",
                terminal_event_id="evt-terminal",
                policy_id="approved-policy",
                policy_version="v0.3",
                policy_config_hash="approved-hash",
            ),
        ),
        warnings=(),
        diagnostics=(),
        error_type=None,
        error_message=None,
        evidence_artifact_sha256=_EVIDENCE_HASH,
        selector=R1SelectorProvenance(
            policy_id="selector-policy",
            version="v0.1",
            config_hash="selector-hash",
            status="selected",
            diagnostics=(),
        ),
    )
    return R1EvidenceArtifactRun(
        evidences=loaded_evidences,
        summary=summary,
        evidence_path=Path("r1_evidence.jsonl"),
        summary_path=Path("r1_extraction_summary.json"),
        summary_artifact_sha256=_SUMMARY_HASH,
    )


def _envelope(
    *,
    evidences: tuple[R1CausalEvidenceAvailability, ...] | None = None,
) -> R1CausalAvailabilityEnvelope:
    availability = evidences or tuple(
        R1CausalEvidenceAvailability(
            evidence_id=evidence.evidence_id,
            timestamp=evidence.timestamp,
            available_at=_END,
            event_ids=tuple(evidence.event_ids),
            context_event_ids=(),
        )
        for evidence in _evidences()
    )
    return R1CausalAvailabilityEnvelope(
        contract_version="v0.1",
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_START,
        run_end=_END,
        watermark_at=_END,
        watermark_basis="authoritative_run_end",
        selector_policy_identity=R1CausalPolicyIdentity(
            policy_id="selector-policy",
            version="v0.1",
            config_hash="selector-hash",
        ),
        approved_policy_identity=R1CausalPolicyIdentity(
            policy_id="approved-policy",
            version="v0.3",
            config_hash="approved-hash",
        ),
        source_extractor_version="r1-multi-event-v0.1",
        source_evidence_count=len(availability),
        source_evidence_artifact_sha256=_EVIDENCE_HASH,
        source_extraction_summary_sha256=_SUMMARY_HASH,
        evidences=tuple(
            sorted(
                availability,
                key=lambda item: (item.available_at, item.timestamp, item.evidence_id),
            )
        ),
    )


def _metadata(
    *,
    run_type: RunType = RunType.ATTACK,
    family_id: str | None = "remote_management",
) -> RunMetadata:
    return RunMetadata(
        run_id=_RUN_ID,
        scenario_id="R1",
        run_type=run_type,
        target_host=_HOST_ID,
        start_time=_START,
        end_time=_END,
        family_id=family_id,
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.3",
            evidence="v0.2",
            fast_hit="v0.1",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.1",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def _approved_policy(*, family_id: str = "remote_management") -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="approved-policy",
        version="v0.3",
        config_hash="approved-hash",
        approved_lineage=("anchor.exe", "middle.exe", "terminal.exe"),
        family_id=family_id,
        lifecycle="frozen",
    )


def _config() -> FusionConfig:
    return FusionConfig(
        config_version="fusion-r1-causal-test-v0.1",
        model_version=None,
        window=WindowConfig(window_size_sec=60),
        replay=ReplayConfig(step_size_sec=10),
        scoring=ScoringConfig(
            method="simple_score",
            scorer_version="simple-score-v0.1",
            profile_id="r1-causal-test-v0.1",
            evidence_types=(
                "remote_session_process_lineage_deviation",
                "remote_process_network_follow_on",
            ),
        ),
        stopping=StoppingConfig(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
    )


@pytest.fixture(autouse=True)
def fast_fixture_directory(tmp_path, monkeypatch):
    monkeypatch.setitem(globals(), "_FAST_FIXTURE_DIR", tmp_path)


def _snapshot(*, normal=False, persistence=1):
    run = _metadata(run_type=RunType.NORMAL if normal else RunType.ATTACK).model_copy(
        update={
            "reference_time": None if normal else _START,
            "detector_set_version": "set-v1",
        }
    )
    config = _config()
    config = config.model_copy(
        update={"stopping": config.stopping.model_copy(update={"persistence_k": persistence})}
    )
    envelope = _envelope()
    result = run_r1_causal_replay(
        _artifact_run(),
        envelope,
        run_metadata=run,
        approved_policy=_approved_policy(),
        config=config,
        execution_commit="a" * 40,
    )
    detection = DetectionResult(
        run_id=run.run_id,
        entity_id=run.target_host,
        detector_status="detected",
        detector_time=_START + timedelta(seconds=20),
        detector_id="synthetic",
        rule_id="synthetic-rule",
        rule_version="v1",
        severity=None,
    )
    decision = combine_results(
        detection,
        result.fusion_result,
        decision_id="decision-1",
        config_version="decision-v1",
        parallel_required=True,
    )
    proof = CausalReplayEvaluationInput(
        provenance=result.provenance, envelope=envelope, stopping_trace=result.stopping_trace
    )
    bundle = StoredRunResults(
        run_metadata=run,
        detection=detection,
        fusion=result.fusion_result,
        decision=decision,
        fast_episodes=FastEpisodeStarts(
            run_id=run.run_id,
            entity_id=run.target_host,
            policy_version="episodes-v1",
            detector_set_version="set-v1",
            observation_start=_START,
            observation_end=_END,
            start_times=[detection.detector_time],
        ),
        fusion_observation=FusionObservation(
            run_id=run.run_id,
            entity_id=run.target_host,
            observation_start=_START,
            observation_end=_END,
        ),
        causal_replay=proof,
    )
    plan = EvaluationPlan(
        scenario_id="R1",
        purpose="smoke",
        require_causal_replay=True,
        decision_ids={run.run_id: decision.decision_id},
        decision_config_version="decision-v1",
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=None,
        detector_set_version="set-v1",
        fast_episode_policy_version="episodes-v1",
        evaluation_horizon_sec=35,
        causal_replay_pins={
            run.run_id: CausalReplayPins(
                provenance_sha256=canonical_model_sha256(proof.provenance),
                envelope_sha256=canonical_model_sha256(envelope),
            )
        },
    )
    snapshot = EvaluationSnapshot(snapshot_id="causal-test", plan=plan, runs=[bundle])
    return attach_fast_binding(snapshot, _FAST_FIXTURE_DIR)


def _repin(snapshot):
    proof = snapshot.runs[0].causal_replay
    snapshot.plan.causal_replay_pins[_RUN_ID] = CausalReplayPins(
        provenance_sha256=canonical_model_sha256(proof.provenance),
        envelope_sha256=canonical_model_sha256(proof.envelope),
    )


@pytest.mark.parametrize("normal", [False, True])
def test_actual_causal_producer_output_passes_evaluation(normal):
    snapshot = _snapshot(normal=normal)
    frames, excluded = build_evaluation_inputs(snapshot)
    assert not excluded
    assert frames["Fusion"].iloc[0].timestamp == _END
    assert snapshot.runs[0].causal_replay.provenance.terminal_partial_tick
    if not normal:
        assert evaluate_snapshot(snapshot)["metrics"]["Fusion"]["median_ttsd_sec"] == 35
        assert compare_paired_timing(snapshot)["per_run"][0]["fusion_minus_fast_sec"] == 15


def test_json_roundtrip(tmp_path):
    snapshot = _snapshot()
    path = tmp_path / "snapshot.json"
    path.write_text(snapshot.model_dump_json())
    assert evaluate_snapshot(load_evaluation_snapshot(path)) == evaluate_snapshot(snapshot)


@pytest.mark.parametrize("missing", ["proof", "pins"])
def test_official_r1_requires_causal_inputs_even_without_opt_in(missing):
    snapshot = _snapshot()
    if missing == "proof":
        snapshot.runs[0].causal_replay = None
    else:
        snapshot.plan.causal_replay_pins = {}
    with pytest.raises(ValueError, match="requires provenance"):
        build_evaluation_inputs(snapshot)


def test_offline_smoke_is_explicitly_separate():
    snapshot = _snapshot()
    snapshot.plan.purpose = "smoke"
    snapshot.plan.require_causal_replay = False
    snapshot.plan.causal_replay_pins = {}
    snapshot.runs[0].causal_replay = None
    build_evaluation_inputs(snapshot)
    snapshot.plan.require_causal_replay = True
    with pytest.raises(ValueError, match="requires provenance"):
        build_evaluation_inputs(snapshot)


@pytest.mark.parametrize("field", ["provenance_sha256", "envelope_sha256"])
def test_execution_pins_reject_replaced_artifacts(field):
    snapshot = _snapshot()
    setattr(snapshot.plan.causal_replay_pins[_RUN_ID], field, "0" * 64)
    with pytest.raises(ValueError, match="pinned execution hash"):
        build_evaluation_inputs(snapshot)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("source_evidence_artifact_sha256", "c" * 64, "provenance/envelope"),
        ("source_extraction_summary_sha256", "c" * 64, "provenance/envelope"),
        ("source_causal_envelope_contract_version", "v9", "version mismatch"),
        ("fusion_result_sha256", "c" * 64, "FusionResult"),
        ("fusion_stopping_trace_sha256", "c" * 64, "stopping trace"),
        ("fusion_episode_ids", ("other-episode",), "episode identity"),
    ],
)
def test_semantic_links_checked_even_with_matching_provenance_pin(field, value, message):
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    proof.provenance = proof.provenance.model_copy(update={field: value})
    _repin(snapshot)
    with pytest.raises(ValueError, match=message):
        build_evaluation_inputs(snapshot)


def test_missing_trace_tick_rejected_even_with_updated_hash():
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    proof.stopping_trace.points.pop(1)
    proof.provenance = proof.provenance.model_copy(
        update={"fusion_stopping_trace_sha256": canonical_model_sha256(proof.stopping_trace)}
    )
    _repin(snapshot)
    with pytest.raises(ValueError, match="every evaluated replay point"):
        build_evaluation_inputs(snapshot)


def test_score_cannot_precede_whole_episode_availability():
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    proof.stopping_trace.points[1].score = 0.5
    proof.provenance = proof.provenance.model_copy(
        update={"fusion_stopping_trace_sha256": canonical_model_sha256(proof.stopping_trace)}
    )
    _repin(snapshot)
    with pytest.raises(ValueError, match="score precedes"):
        build_evaluation_inputs(snapshot)


def test_persistence_miss_is_valid_and_not_missing_provenance():
    snapshot = _snapshot(persistence=2)
    assert snapshot.runs[0].fusion.fusion_status == "miss"
    assert compare_paired_timing(snapshot)["per_run"][0]["outcome"] == "fast_only"
    snapshot.runs[0].causal_replay = None
    with pytest.raises(ValueError, match="requires provenance"):
        evaluate_snapshot(snapshot)


def test_horizon_excludes_late_causal_detection_without_backdating():
    snapshot = _snapshot()
    snapshot.plan.evaluation_horizon_sec = 34
    assert snapshot.runs[0].fusion.fusion_time == _END
    assert compare_paired_timing(snapshot)["per_run"][0]["outcome"] == "fast_only"


@pytest.mark.parametrize("kind", ["config", "entity", "coverage", "policy"])
def test_cross_artifact_identity_and_scope_must_agree(kind):
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    proof = bundle.causal_replay
    if kind == "config":
        config = proof.provenance.fusion_runtime_config.model_copy(
            update={"config_version": "other"}
        )
        proof.provenance = proof.provenance.model_copy(update={"fusion_runtime_config": config})
        message = "config version"
    elif kind == "entity":
        proof.envelope = proof.envelope.model_copy(update={"entity_id": "OTHER-HOST"})
        message = "Run/entity"
    elif kind == "policy":
        identity = proof.envelope.approved_policy_identity.model_copy(update={"version": "v9"})
        proof.envelope = proof.envelope.model_copy(update={"approved_policy_identity": identity})
        message = "approved_policy_identity"
    else:
        snapshot.plan.evaluation_horizon_sec = 20
        bundle.fusion_observation.observation_end = _START + timedelta(seconds=30)
        message = "observation must match"
    _repin(snapshot)
    with pytest.raises(ValueError, match=message):
        build_evaluation_inputs(snapshot)


def test_backdated_episode_rejected_even_if_output_hashes_are_rebound():
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    proof = bundle.causal_replay
    early = _START + timedelta(seconds=30)
    bundle.fusion.fusion_time = early
    bundle.fusion.fusion_episodes[0].start_time = early
    point = proof.stopping_trace.points[-2]
    point.score = 1
    point.policy_state = "on"
    point.persistence_count = 1
    attach_fast_binding(snapshot, _FAST_FIXTURE_DIR)
    proof.provenance = proof.provenance.model_copy(
        update={
            "fusion_time": early,
            "fusion_result_sha256": canonical_model_sha256(bundle.fusion),
            "fusion_stopping_trace_sha256": canonical_model_sha256(proof.stopping_trace),
        }
    )
    _repin(snapshot)
    with pytest.raises(ValueError, match="score precedes"):
        build_evaluation_inputs(snapshot)


def test_not_evaluated_remains_excluded_and_cannot_carry_proof():
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    bundle.fusion = bundle.fusion.model_copy(
        update={
            "fusion_status": "not_evaluated",
            "fusion_time": None,
            "score_at_decision": None,
            "fusion_episodes": [],
            "contributing_evidence_ids": [],
        }
    )
    attach_fast_binding(snapshot, _FAST_FIXTURE_DIR)
    bundle.fusion_observation = None
    with pytest.raises(ValueError, match="must not carry causal"):
        build_evaluation_inputs(snapshot)
    bundle.causal_replay = None
    snapshot.plan.causal_replay_pins = {}
    frames, exclusions = build_evaluation_inputs(snapshot)
    assert frames["Fusion"].empty
    assert {e["method"] for e in exclusions} == {"Fusion", "Hybrid"}


def test_unplanned_pin_is_rejected():
    snapshot = _snapshot()
    snapshot.plan.causal_replay_pins["UNPLANNED"] = snapshot.plan.causal_replay_pins[_RUN_ID]
    with pytest.raises(ValueError, match="unplanned Runs"):
        build_evaluation_inputs(snapshot)


def test_stored_snapshot_requires_same_external_causal_bundle(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from psycopg.pq import TransactionStatus

    from incident_awareness.evaluation import stored_snapshot as stored

    snapshot = _snapshot()
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
    kwargs = {
        "snapshot_id": snapshot.snapshot_id,
        "plan": snapshot.plan,
        "fast_episodes": {_RUN_ID: bundle.fast_episodes},
        "fast_bindings": {_RUN_ID: bundle.fast_binding},
        "fusion_observations": {_RUN_ID: bundle.fusion_observation},
    }
    with pytest.raises(ValueError, match="requires provenance"):
        stored.read_stored_snapshot(connection, **kwargs)
    actual = stored.read_stored_snapshot(
        connection, causal_replays={_RUN_ID: bundle.causal_replay}, **kwargs
    )
    assert evaluate_snapshot(actual) == evaluate_snapshot(snapshot)


@pytest.mark.parametrize(
    "reference_offset,horizon,fast_ttsd,fusion_ttsd,outcome",
    [
        (0, 35, 20, 35, "both_detected"),
        (20, 15, 0, 15, "both_detected"),
        (21, 14, None, 14, "fusion_only"),
        (0, 19, None, None, "both_miss"),
        (20, 0, 0, None, "fast_only"),
        (35, 0, None, 0, "fusion_only"),
        (0, 600, 20, 35, "both_detected"),
    ],
)
def test_causal_eligible_boundaries_flow_through_metrics_and_paired_report(
    reference_offset, horizon, fast_ttsd, fusion_ttsd, outcome
):
    # The same real causal replay result is evaluated against explicit ground truth.
    # No runtime timestamps or causal artifacts are moved to gain eligibility.
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    bundle.run_metadata.reference_time = _START + timedelta(seconds=reference_offset)
    snapshot.plan.evaluation_horizon_sec = horizon
    report = evaluate_snapshot(snapshot)
    pair = compare_paired_timing(snapshot)["per_run"][0]
    assert pair["outcome"] == outcome
    for method, expected in (("Fast", fast_ttsd), ("Fusion", fusion_ttsd)):
        assert pair["paths"][method]["ttsd_sec"] == expected
        assert report["metrics"][method]["median_ttsd_sec"] == expected
    expected_delta = (
        fusion_ttsd - fast_ttsd if fast_ttsd is not None and fusion_ttsd is not None else None
    )
    assert pair["fusion_minus_fast_sec"] == expected_delta
    assert bundle.fusion.fusion_time == _END
    assert bundle.detection.detector_time == _START + timedelta(seconds=20)


def test_causal_eligible_tie_uses_same_time_without_fabricated_improvement():
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    bundle.detection.detector_time = _END
    bundle.fast_episodes.start_times = [_END]
    attach_fast_binding(snapshot, _FAST_FIXTURE_DIR)
    pair = compare_paired_timing(snapshot)["per_run"][0]
    assert pair["outcome"] == "both_detected"
    assert pair["earlier_eligible_path"] == "tie"
    assert pair["fusion_minus_fast_sec"] == 0
    assert evaluate_snapshot(snapshot)["metrics"]["Hybrid"]["median_ttsd_sec"] == 35


@pytest.mark.parametrize("field", ["provenance", "envelope", "stopping_trace"])
def test_json_missing_required_causal_artifact_is_not_a_miss(tmp_path, field):
    import json

    payload = _snapshot().model_dump(mode="json")
    del payload["runs"][0]["causal_replay"][field]
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match=field):
        load_evaluation_snapshot(path)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("terminal_partial_tick", False, "terminal_partial_tick"),
        ("availability_gate_contract", "timestamp <= replay_time", "availability_gate_contract"),
        ("replay_ordering_contract", "timestamp", "replay_ordering_contract"),
        ("watermark_at", _END - timedelta(milliseconds=1), "watermark"),
        ("evaluated_replay_points", (_START, _END), "partial tick"),
    ],
)
def test_mutated_provenance_revalidated_before_evaluation(field, value, message):
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    proof.provenance = proof.provenance.model_copy(update={field: value})
    _repin(snapshot)
    with pytest.raises(ValueError, match=message):
        evaluate_snapshot(snapshot)


@pytest.mark.parametrize("window_sec,passes", [(15, True), (14.999, False)])
def test_contributing_evidence_window_cutoff_is_inclusive(window_sec, passes):
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    config = proof.provenance.fusion_runtime_config
    config = config.model_copy(
        update={"window": config.window.model_copy(update={"window_size_sec": window_sec})}
    )
    proof.provenance = proof.provenance.model_copy(update={"fusion_runtime_config": config})
    _repin(snapshot)
    # At t=35, Evidence at t=20 is exactly on the 15-second cutoff.
    if passes:
        build_evaluation_inputs(snapshot)
    else:
        with pytest.raises(ValueError, match="outside the event-time window"):
            build_evaluation_inputs(snapshot)


def test_unknown_contributor_rejected_even_when_result_and_decision_agree():
    snapshot = _snapshot()
    bundle = snapshot.runs[0]
    proof = bundle.causal_replay
    bundle.fusion.contributing_evidence_ids = ["unknown"]
    bundle.fusion.fusion_episodes[0].contributing_evidence_ids = ["unknown"]
    attach_fast_binding(snapshot, _FAST_FIXTURE_DIR)
    proof.provenance = proof.provenance.model_copy(
        update={
            "contributing_evidence_ids": ("unknown",),
            "fusion_result_sha256": canonical_model_sha256(bundle.fusion),
        }
    )
    _repin(snapshot)
    with pytest.raises(ValueError, match="unknown Evidence"):
        build_evaluation_inputs(snapshot)


@pytest.mark.parametrize("mutation", ["duplicate", "after_end"])
def test_invalid_trace_timestamps_rejected_before_metrics(mutation):
    snapshot = _snapshot()
    proof = snapshot.runs[0].causal_replay
    if mutation == "duplicate":
        proof.stopping_trace.points.insert(1, proof.stopping_trace.points[0])
        message = "strictly increasing"
    else:
        proof.stopping_trace.points[-1].timestamp = _END + timedelta(milliseconds=1)
        message = "every evaluated replay point"
    proof.provenance = proof.provenance.model_copy(
        update={"fusion_stopping_trace_sha256": canonical_model_sha256(proof.stopping_trace)}
    )
    _repin(snapshot)
    with pytest.raises(ValueError, match=message):
        evaluate_snapshot(snapshot)


@pytest.mark.parametrize("field", ["fast_binding", "causal_replay"])
def test_r1_performance_requires_both_execution_proofs(field):
    snapshot = _snapshot()
    snapshot.plan.require_fast_binding = False
    snapshot.plan.require_causal_replay = False
    snapshot.plan.purpose = "performance"
    # Whole-episode proof is also forbidden, even when both proofs exist.
    setattr(snapshot.runs[0], field, None)
    with pytest.raises(ValueError, match="requires"):
        build_evaluation_inputs(snapshot)


@pytest.mark.parametrize("scenario", ["R1", "R1-wmi", "custom-scenario"])
@pytest.mark.parametrize("persistence", [1, 2])
def test_whole_episode_is_smoke_only(scenario, persistence):
    snapshot = _snapshot(persistence=persistence)
    build_evaluation_inputs(snapshot)
    snapshot.plan.scenario_id = scenario
    snapshot.runs[0].run_metadata.scenario_id = scenario
    snapshot.plan.purpose = "performance"
    snapshot.plan.require_causal_replay = False
    with pytest.raises(ValueError, match="whole-episode availability"):
        build_evaluation_inputs(snapshot)


@pytest.mark.parametrize("scenario", ["R1-wmi", "custom-scenario"])
def test_other_performance_scenarios_require_causal_proof(scenario):
    snapshot = _snapshot()
    snapshot.plan.scenario_id = scenario
    snapshot.runs[0].run_metadata.scenario_id = scenario
    snapshot.plan.purpose = "performance"
    snapshot.plan.require_causal_replay = False
    snapshot.runs[0].causal_replay = None
    snapshot.plan.causal_replay_pins = {}
    with pytest.raises(ValueError, match="requires provenance"):
        build_evaluation_inputs(snapshot)
