"""Role1 receive boundary for published Role2 Evidence and its wall-clock trace.

Only a finalized verified-proof artifact set passes this boundary. Provisional state,
position proofs, and run_end fallback output never reach Fusion. Trace times are the
actual processing observations; ``fusion_time`` stays the Fusion result field. A Fast
path that was not run stays ``not_evaluated`` and leaves the Decision incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import psycopg

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1CandidateGenerationPolicy,
    load_r1_candidate_generation_policy,
)
from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.result import DecisionResult, DetectorStatus
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import FusionConfig, load_fusion_config
from incident_awareness.decision.fusion.result_builder import build_fusion_result
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_provenance import resolve_r1_evidence_provenance
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionAdapterResult,
    build_not_evaluated_detection_result,
    combine_fast_adapter_result,
)
from incident_awareness.pipeline.fusion import build_fusion_runtime_config_snapshot
from incident_awareness.pipeline.persistence import (
    persist_r1_results,
    resolve_expected_supersedes_decision_id,
)
from incident_awareness.pipeline.r1_artifact_io import utc_now
from incident_awareness.pipeline.r1_artifacts import (
    R1_EVIDENCE_FILENAME,
    R1_EXTRACTION_SUMMARY_FILENAME,
    load_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_causal_replay import prepare_r1_incremental_causal_replay_input
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    serialize_r1_causal_fusion_result,
    serialize_r1_causal_fusion_stopping_trace,
)
from incident_awareness.pipeline.r1_incremental_availability import (
    _publish_immutable_bytes,
    load_r1_incremental_availability_publication_receipt,
    load_r1_incremental_causal_availability_envelope,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    incremental_evidence_sha256,
    load_r1_incremental_checkpoint,
)
from incident_awareness.pipeline.r1_incremental_consumer import (
    DEFAULT_R1_APPROVED_POLICY_ID,
    DEFAULT_R1_APPROVED_POLICY_VERSION,
    R1_INCREMENTAL_AVAILABILITY_FILENAME,
    R1_INCREMENTAL_CHECKPOINT_FILENAME,
    R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME,
    R1CommittedChunkIngress,
    _DeadLetterSink,
    r1_selector_policy,
    unique_checkpoint_events,
)
from incident_awareness.pipeline.r1_incremental_evidence import R1IncrementalEvidenceState
from incident_awareness.pipeline.r1_operational_trace import (
    R1OperationalTrace,
    R1OperationalTraceRecord,
)
from incident_awareness.pipeline.r1_stream_wiring import load_close_export
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1StreamDeliveryRepository,
)

R1_FUSION_TRACE_FILENAME = "r1_fusion_execution_trace.jsonl"
R1_FUSION_RESULT_FILENAME = "r1_fusion_result.json"
R1_FUSION_STOPPING_TRACE_FILENAME = "r1_fusion_stopping_trace.json"
R1_DECISION_RESULT_FILENAME = "r1_decision_result.json"
DEFAULT_R1_DECISION_CONFIG_VERSION = "parallel-v0.2"


class R1FusionHandoffRejected(ValueError):
    """Published input failed the Role1 receive boundary; Fusion did not run."""


@dataclass(frozen=True, slots=True)
class R1FusionHandoffTrust:
    selector_policy: R1SelectorPolicy
    approved_policy: ApprovedLineagePolicy
    candidate_policy: R1CandidateGenerationPolicy
    close_export_path: Path
    source_seal_id: str
    source_seal_projection_sha256: str
    ingress: R1CommittedChunkIngress


@dataclass(frozen=True, slots=True)
class R1FusionHandoffResult:
    fusion_result: FusionResult
    decision_result: DecisionResult
    decision_complete: bool
    persisted_to_database: bool
    trace: tuple[R1OperationalTraceRecord, ...]
    already_consumed: bool = False


def consume_published_r1_evidence(
    published_directory: Path,
    *,
    output_directory: Path,
    run_metadata: RunMetadata,
    trust: R1FusionHandoffTrust,
    config: FusionConfig,
    fast_result: FastDetectionAdapterResult | None = None,
    decision_config_version: str = DEFAULT_R1_DECISION_CONFIG_VERSION,
    connection: Any | None = None,
    availability_clock: Callable[[], datetime] | None = None,
    trace_clock: Callable[[], datetime] | None = None,
) -> R1FusionHandoffResult:
    """Validate one published set, run causal Fusion, and record the outcome."""
    trace = R1OperationalTrace(
        output_directory / R1_FUSION_TRACE_FILENAME,
        clock=trace_clock or utc_now,
    )
    run_id = run_metadata.run_id
    try:
        validated = _validate_published_input(
            published_directory,
            run_metadata=run_metadata,
            trust=trust,
            availability_clock=availability_clock,
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        trace.append(
            "handoff_rejected",
            run_id=run_id,
            details={"reason": str(error), "fusion_invoked": False},
        )
        raise R1FusionHandoffRejected(str(error)) from error

    existing = _load_completed_handoff(trace, output_directory, validated.input_identity)
    if existing is not None:
        return existing

    handoff = trace.append(
        "handoff_accepted",
        run_id=run_id,
        details=validated.input_identity,
    )
    started = trace.append(
        "fusion_processing_started",
        run_id=run_id,
        details={"handoff_accepted_at": handoff.observed_at},
    )
    try:
        replay = config.build_runner().run_causal(
            validated.scheduled_evidences,
            run_id=run_id,
            entity_id=run_metadata.target_host,
            run_start=run_metadata.start_time,
            run_end=run_metadata.end_time,
        )
    except (TypeError, ValueError) as error:
        trace.append(
            "fusion_processing_failed",
            run_id=run_id,
            details={"reason": str(error), "fusion_result_written": False},
        )
        raise
    fusion_result = build_fusion_result(
        replay,
        run_id=run_id,
        entity_id=run_metadata.target_host,
        scoring_config_version=config.config_version,
        scoring_profile_id=config.scoring.profile_id,
        scoring_method=config.scoring.method,
        scorer_version=config.scoring.scorer_version,
        model_version=config.model_version,
    )
    stopping_trace = FusionStoppingTrace(
        run_id=run_id,
        entity_id=run_metadata.target_host,
        scoring_config_version=config.config_version,
        points=[
            FusionStoppingTracePoint(
                timestamp=point.timestamp,
                score=point.score,
                persistence_count=point.persistence_count,
                policy_state=point.policy_state,
            )
            for point in replay.stopping_trace
        ],
    )
    result_bytes = serialize_r1_causal_fusion_result(fusion_result)
    trace_bytes = serialize_r1_causal_fusion_stopping_trace(stopping_trace)
    _publish_immutable_bytes(output_directory / R1_FUSION_RESULT_FILENAME, result_bytes)
    _publish_immutable_bytes(output_directory / R1_FUSION_STOPPING_TRACE_FILENAME, trace_bytes)
    completed = trace.append(
        "fusion_processing_completed",
        run_id=run_id,
        details={
            "fusion_processing_started_at": started.observed_at,
            "fusion_status": fusion_result.fusion_status,
            "fusion_time": _result_fusion_time(fusion_result),
            "contributing_evidence_ids": list(fusion_result.contributing_evidence_ids),
            "fusion_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "stopping_trace_sha256": hashlib.sha256(trace_bytes).hexdigest(),
        },
    )

    fast = fast_result or build_not_evaluated_detection_result(
        run_id=run_id,
        entity_id=run_metadata.target_host,
    )
    decision_id = (
        f"DEC-R1-{uuid5(NAMESPACE_URL, f'{run_id}|{hashlib.sha256(result_bytes).hexdigest()}')}"
    )
    supersedes = None
    if connection is not None:
        supersedes = resolve_expected_supersedes_decision_id(
            decision_id=decision_id,
            run_id=run_id,
            entity_id=run_metadata.target_host,
            connection=connection,
        )
    decision = combine_fast_adapter_result(
        fast,
        fusion_result,
        decision_id=decision_id,
        config_version=decision_config_version,
        parallel_required=True,
        supersedes_decision_id=supersedes,
    )
    decision_bytes = (decision.model_dump_json(by_alias=True) + "\n").encode("utf-8")
    _publish_immutable_bytes(output_directory / R1_DECISION_RESULT_FILENAME, decision_bytes)
    if connection is not None:
        persist_r1_results(
            run_metadata,
            validated.events,
            fusion_result,
            stopping_trace,
            build_fusion_runtime_config_snapshot(
                config=config,
                run_id=run_id,
                entity_id=run_metadata.target_host,
            ),
            fast,
            decision,
            connection=connection,
        )
    decision_complete = fast.detection_result.detector_status is not DetectorStatus.NOT_EVALUATED
    trace.append(
        "decision_recorded",
        run_id=run_id,
        details={
            "fusion_processing_completed_at": completed.observed_at,
            "decision_id": decision.decision_id,
            "decision_sha256": hashlib.sha256(decision_bytes).hexdigest(),
            "decision_complete": decision_complete,
            "fast_status": fast.detection_result.detector_status.value,
            "persisted_to_database": connection is not None,
            "fusion_result_sha256": completed.details["fusion_result_sha256"],
            "input_envelope_sha256": validated.input_identity["envelope_sha256"],
        },
    )
    return R1FusionHandoffResult(
        fusion_result=fusion_result,
        decision_result=decision,
        decision_complete=decision_complete,
        persisted_to_database=connection is not None,
        trace=trace.records(),
    )


@dataclass(frozen=True, slots=True)
class _ValidatedPublishedInput:
    scheduled_evidences: tuple
    events: tuple
    input_identity: dict[str, object]


def _validate_published_input(
    directory: Path,
    *,
    run_metadata: RunMetadata,
    trust: R1FusionHandoffTrust,
    availability_clock: Callable[[], datetime] | None,
) -> _ValidatedPublishedInput:
    checkpoint_path = directory / R1_INCREMENTAL_CHECKPOINT_FILENAME
    envelope_path = directory / R1_INCREMENTAL_AVAILABILITY_FILENAME
    receipt_path = directory / f"{R1_INCREMENTAL_AVAILABILITY_FILENAME}.publication.json"
    checkpoint = load_r1_incremental_checkpoint(checkpoint_path)
    if checkpoint.status != "finalized" or checkpoint.close_mode != "verified_close_proof":
        raise ValueError(
            "Role1 accepts only finalized verified-proof Evidence, "
            f"got status={checkpoint.status!r} close_mode={checkpoint.close_mode!r}"
        )
    if run_metadata.end_time is None:
        raise ValueError("Role1 causal Fusion requires an authoritative Run end")
    envelope = load_r1_incremental_causal_availability_envelope(envelope_path)
    publication = load_r1_incremental_availability_publication_receipt(receipt_path)
    _, close_receipt = load_close_export(trust.close_export_path)
    restored = R1IncrementalEvidenceState.restore_from_checkpoint(
        checkpoint,
        selector_policy=trust.selector_policy,
        approved_policy=trust.approved_policy,
        ingress=trust.ingress,
        candidate_policy=trust.candidate_policy,
        accepted_close_receipt=close_receipt,
        accepted_source_seal_id=trust.source_seal_id,
        accepted_source_seal_projection_sha256=trust.source_seal_projection_sha256,
    ).snapshot
    artifacts = load_r1_evidence_artifacts(directory)
    if tuple(artifacts.evidences) != tuple(restored.evidences):
        raise ValueError("published Evidence differs from the recovered checkpoint")
    events = unique_checkpoint_events(checkpoint)
    resolve_r1_evidence_provenance(artifacts.evidences, events)
    replay_input = prepare_r1_incremental_causal_replay_input(
        restored,
        envelope,
        checkpoint,
        publication,
        input_validation_path=directory / R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME,
        run_metadata=run_metadata,
        selector_policy=trust.selector_policy,
        approved_policy=trust.approved_policy,
        candidate_policy=trust.candidate_policy,
        clock=availability_clock,
    )
    validation = replay_input.incremental_input_validation
    assert validation is not None
    identity: dict[str, object] = {
        "input_validation": "passed",
        "evidence_payload_sha256": {
            item.evidence_id: incremental_evidence_sha256(item) for item in artifacts.evidences
        },
        "evidence_artifact_sha256": _sha256(directory / R1_EVIDENCE_FILENAME),
        "summary_artifact_sha256": _sha256(directory / R1_EXTRACTION_SUMMARY_FILENAME),
        "checkpoint_sha256": _sha256(checkpoint_path),
        "envelope_sha256": _sha256(envelope_path),
        "publication_receipt_sha256": _sha256(receipt_path),
        "validation_record_sha256": _sha256(directory / R1_INCREMENTAL_REPLAY_VALIDATION_FILENAME),
        "inputs_validated_at": validation.inputs_validated_at.isoformat().replace("+00:00", "Z"),
    }
    return _ValidatedPublishedInput(replay_input.scheduled_evidences, events, identity)


def _load_completed_handoff(
    trace: R1OperationalTrace,
    output_directory: Path,
    identity: dict[str, object],
) -> R1FusionHandoffResult | None:
    records = trace.records()
    completed = [
        record
        for record in records
        if record.stage == "decision_recorded"
        and record.details.get("input_envelope_sha256") == identity["envelope_sha256"]
    ]
    if not completed:
        return None
    last = completed[-1]
    result_bytes = (output_directory / R1_FUSION_RESULT_FILENAME).read_bytes()
    if hashlib.sha256(result_bytes).hexdigest() != last.details["fusion_result_sha256"]:
        raise ValueError("recorded Fusion output differs from the operational trace")
    decision_bytes = (output_directory / R1_DECISION_RESULT_FILENAME).read_bytes()
    if hashlib.sha256(decision_bytes).hexdigest() != last.details["decision_sha256"]:
        raise ValueError("recorded Decision differs from the operational trace")
    return R1FusionHandoffResult(
        fusion_result=FusionResult.model_validate_json(result_bytes),
        decision_result=DecisionResult.model_validate_json(decision_bytes),
        decision_complete=bool(last.details["decision_complete"]),
        persisted_to_database=bool(last.details["persisted_to_database"]),
        trace=records,
        already_consumed=True,
    )


def _result_fusion_time(fusion_result: FusionResult) -> str | None:
    return fusion_result.model_dump(mode="json")["fusion_time"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--published-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-metadata", required=True)
    parser.add_argument("--fusion-config", required=True)
    parser.add_argument("--close-export", required=True)
    parser.add_argument("--candidate-policy-id", required=True)
    parser.add_argument("--candidate-policy-version", required=True)
    parser.add_argument("--source-seal-id", required=True)
    parser.add_argument("--source-seal-projection-sha256", required=True)
    parser.add_argument("--approved-policy-id", default=DEFAULT_R1_APPROVED_POLICY_ID)
    parser.add_argument("--approved-policy-version", default=DEFAULT_R1_APPROVED_POLICY_VERSION)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = DatabaseConfig.from_environment()
    with psycopg.connect(config.url, autocommit=False) as connection:
        result = consume_published_r1_evidence(
            Path(args.published_dir),
            output_directory=Path(args.output_dir),
            run_metadata=RunMetadata.model_validate_json(
                Path(args.run_metadata).read_text(encoding="utf-8-sig")
            ),
            trust=R1FusionHandoffTrust(
                selector_policy=r1_selector_policy(),
                approved_policy=load_r1_approved_lineage_policy(
                    args.approved_policy_id,
                    args.approved_policy_version,
                    config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
                ),
                candidate_policy=load_r1_candidate_generation_policy(
                    args.candidate_policy_id, args.candidate_policy_version
                ),
                close_export_path=Path(args.close_export),
                source_seal_id=args.source_seal_id,
                source_seal_projection_sha256=args.source_seal_projection_sha256,
                ingress=R1CommittedChunkIngress(
                    R1StreamDeliveryRepository(connection),
                    dead_letter_sink=_DeadLetterSink(),
                    clock=utc_now,
                ),
            ),
            config=load_fusion_config(Path(args.fusion_config)),
            connection=connection,
        )
        print(result.fusion_result.fusion_status, result.decision_complete)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "R1FusionHandoffRejected",
    "R1FusionHandoffResult",
    "R1FusionHandoffTrust",
    "consume_published_r1_evidence",
]
