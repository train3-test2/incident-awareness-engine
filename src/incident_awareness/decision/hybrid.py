"""Combine canonical Fast and Fusion results for required parallel execution."""

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult


def combine_results(
    detection: DetectionResult,
    fusion: FusionResult,
    *,
    decision_id: str,
    config_version: str,
    parallel_required: bool,
    source_hit_ids: list[str] | tuple[str, ...] | None = None,
    selected_source_hit_id: str | None = None,
) -> DecisionResult:
    """Use the v0.2 truth table; optional-path policies need a separate config."""
    if parallel_required is not True:
        raise ValueError("Only parallel_required=true is supported by this combiner")
    for name, value in (("decision_id", decision_id), ("config_version", config_version)):
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise ValueError(
                f"{name} must be a non-blank identifier without surrounding whitespace"
            )
    # Validate copies at the exchange boundary, including mutations of existing models.
    detection = DetectionResult.model_validate_json(detection.model_dump_json())
    fusion = FusionResult.model_validate_json(fusion.model_dump_json())
    if detection.run_id != fusion.run_id or detection.entity_id != fusion.entity_id:
        raise ValueError("Fast and Fusion must have the same run_id and entity_id")
    if not detection.entity_id.strip() or detection.entity_id != detection.entity_id.strip():
        raise ValueError("entity_id must not be blank or contain surrounding whitespace")
    fast_status = detection.detector_status.value
    fusion_status = fusion.fusion_status
    t_e = None
    decision_path = None
    winning_path = None
    if "not_evaluated" in (fast_status, fusion_status):
        reason = "Required parallel evaluation was not completed"
    elif fast_status == "detected" and fusion_status == "detected":
        assert detection.detector_time is not None and fusion.fusion_time is not None
        t_e = min(detection.detector_time, fusion.fusion_time)
        decision_path = "fast_and_fusion"
        winning_path = (
            "fast"
            if detection.detector_time < fusion.fusion_time
            else "fusion"
            if fusion.fusion_time < detection.detector_time
            else "tie"
        )
        reason = "Both paths detected; compared canonical UTC millisecond timestamps"
    elif fast_status == "detected":
        t_e = detection.detector_time
        decision_path = winning_path = "fast"
        reason = "Only Fast detected"
    elif fusion_status == "detected":
        t_e = fusion.fusion_time
        decision_path = winning_path = "fusion"
        reason = "Only Fusion detected"
    else:
        decision_path = winning_path = "none"
        reason = "Both evaluated paths missed"
    return DecisionResult(
        run_id=detection.run_id,
        entity_id=detection.entity_id,
        decision_id=decision_id,
        config_version=config_version,
        fast_status=fast_status,
        fusion_status=fusion_status,
        detector_time=detection.detector_time,
        fusion_time=fusion.fusion_time,
        t_e=t_e,
        decision_path=decision_path,
        winning_path=winning_path,
        decision_reason=reason,
        # Preserve the input Fusion decision provenance, not direct attribution to t_e.
        contributing_evidence_ids=list(fusion.contributing_evidence_ids),
        model_version=fusion.model_version,
        rule_version=detection.rule_version,
        source_hit_ids=list(source_hit_ids) if source_hit_ids is not None else None,
        selected_source_hit_id=selected_source_hit_id,
    )
