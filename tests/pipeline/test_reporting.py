import logging
from datetime import UTC, datetime

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.reporting import (
    build_execution_summary,
    log_execution_summary,
    log_pipeline_error,
)
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


def test_builds_and_logs_concise_execution_summary(caplog) -> None:
    summary = build_execution_summary(
        _artifacts(),
        NormalizedEvidenceArtifacts(events=(), evidences=()),
        _fusion_result(),
        _fast_result(),
        _decision_result(),
    )

    with caplog.at_level(logging.INFO, logger="incident_awareness.pipeline.reporting"):
        log_execution_summary(summary)

    assert summary.run_id == "RUN-20260920-001"
    assert summary.entity_id == "WIN-01"
    assert summary.normalized_event_count == 0
    assert summary.evidence_count == 0
    assert "run_id=RUN-20260920-001" in caplog.text
    assert "fusion_status=miss" in caplog.text
    assert "decision_path=none" in caplog.text


def test_logs_pipeline_stage_and_exception(caplog) -> None:
    error = ValueError("manifest run_id mismatch")

    with caplog.at_level(logging.ERROR, logger="incident_awareness.pipeline.reporting"):
        log_pipeline_error("artifact_validation", error)

    assert "stage=artifact_validation" in caplog.text
    assert "manifest run_id mismatch" in caplog.text


def _artifacts() -> S0PipelineArtifacts:
    return S0PipelineArtifacts(
        run_metadata=RunMetadata.model_validate(
            {
                "run_id": "RUN-20260920-001",
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": "WIN-01",
                "start_time": datetime(2026, 9, 20, tzinfo=UTC),
                "schema_versions": {
                    "run_metadata": "v0.2",
                    "event": "v0.2",
                    "evidence": "v0.2",
                    "fast_hit": "v0.2",
                    "detection_result": "v0.2",
                    "fusion_result": "v0.2",
                    "decision_result": "v0.2",
                    "execution_record": "v0.1",
                    "evaluation_input": "v0.1",
                },
            }
        ),
        sysmon_records=(),
        normalization_context=SysmonNormalizationContext(
            run_id="RUN-20260920-001",
            raw_log_id="RAW-002",
            segment_no=1,
        ),
    )


def _fusion_result() -> FusionResult:
    return FusionResult(
        run_id="RUN-20260920-001",
        entity_id="WIN-01",
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-s0-pair-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[],
    )


def _fast_result() -> FastDetectionAdapterResult:
    return FastDetectionAdapterResult(
        detection_result=DetectionResult(
            run_id="RUN-20260920-001",
            entity_id="WIN-01",
            detector_time=None,
            detector_status="miss",
            detector_id=None,
            rule_id=None,
            rule_version=None,
            severity=None,
        ),
        source_hit_ids=(),
        selected_source_hit_id=None,
    )


def _decision_result() -> DecisionResult:
    return DecisionResult(
        run_id="RUN-20260920-001",
        decision_id="D-001",
        entity_id="WIN-01",
        fast_status="miss",
        fusion_status="miss",
        detector_time=None,
        fusion_time=None,
        t_e=None,
        decision_path="none",
        winning_path="none",
        decision_reason="Both evaluated paths missed",
        config_version="parallel-v0.2",
    )
