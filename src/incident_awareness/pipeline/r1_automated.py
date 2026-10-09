"""R1 development/offline Evidence 실행 구성요소를 고수준으로 연결한다."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1EvidenceArtifactRun,
    R1SelectorProvenance,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_evidence import (
    R1SelectedEvidencePipelineResult,
    run_r1_evidence_pipeline_with_selector,
)


@dataclass(frozen=True, slots=True)
class R1AutomatedEvidenceArtifactRun:
    """자동 선택 runtime 결과와 기존 immutable artifact 결과를 묶는다."""

    pipeline_result: R1SelectedEvidencePipelineResult
    artifact_run: R1EvidenceArtifactRun


def run_r1_evidence_pipeline_from_policy(
    events: Iterable[NormalizedEvent],
    *,
    selector_policy: R1SelectorPolicy,
    approved_policy_id: str,
    approved_policy_version: str,
    approved_policy_config_path: Path = DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    scenario_family_id: str | None = None,
    run_start: datetime | None = None,
) -> R1SelectedEvidencePipelineResult:
    """관리 config의 approved policy를 selector 기반 Evidence 경로에 주입한다."""
    event_batch = tuple(events)
    approved_policy = load_r1_approved_lineage_policy(
        approved_policy_id,
        approved_policy_version,
        config_path=approved_policy_config_path,
    )
    _validate_automated_policy_family(scenario_family_id, approved_policy)
    return run_r1_evidence_pipeline_with_selector(
        event_batch,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
        run_start=run_start,
    )


def run_and_write_r1_evidence_artifacts_from_policy(
    events: Iterable[NormalizedEvent],
    *,
    run_id: str,
    output_directory: Path,
    selector_policy: R1SelectorPolicy,
    approved_policy_id: str,
    approved_policy_version: str,
    approved_policy_config_path: Path = DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    scenario_family_id: str | None = None,
    run_start: datetime | None = None,
) -> R1AutomatedEvidenceArtifactRun:
    """자동 선택 Evidence를 기존 R1 artifact contract로 게시한다."""
    event_batch = tuple(events)
    pipeline_result = run_r1_evidence_pipeline_from_policy(
        event_batch,
        selector_policy=selector_policy,
        approved_policy_id=approved_policy_id,
        approved_policy_version=approved_policy_version,
        approved_policy_config_path=approved_policy_config_path,
        scenario_family_id=scenario_family_id,
        run_start=run_start,
    )
    lineage_inputs = (
        () if pipeline_result.lineage_input is None else (pipeline_result.lineage_input,)
    )
    selector_provenance = R1SelectorProvenance(
        policy_id=selector_policy.policy_id,
        version=selector_policy.version,
        config_hash=selector_policy.config_hash,
        status="selected" if pipeline_result.selector_result.selection is not None else "failed",
        diagnostics=pipeline_result.selector_result.diagnostics,
    )
    artifact_run = run_and_write_r1_evidence_artifacts(
        event_batch,
        run_id=run_id,
        output_directory=output_directory,
        lineage_inputs=lineage_inputs,
        selector_provenance=selector_provenance,
    )
    return R1AutomatedEvidenceArtifactRun(
        pipeline_result=pipeline_result,
        artifact_run=artifact_run,
    )


def _validate_automated_policy_family(
    scenario_family_id: str | None,
    approved_policy: ApprovedLineagePolicy,
) -> None:
    if approved_policy.family_id is None:
        if scenario_family_id is not None:
            validate_r1_policy_family_binding(scenario_family_id, approved_policy)
        return
    if scenario_family_id is None:
        raise ValueError("scenario_family_id is required for a family-bound approved policy")
    validate_r1_policy_family_binding(scenario_family_id, approved_policy)


__all__ = [
    "R1AutomatedEvidenceArtifactRun",
    "run_and_write_r1_evidence_artifacts_from_policy",
    "run_r1_evidence_pipeline_from_policy",
]
