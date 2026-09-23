"""Invoke the supported parallel Hybrid combiner at the Pipeline boundary."""

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.integration.fast_hit_handoff import (
    FastDetectionAdapterResult,
    combine_fast_adapter_result,
)
from incident_awareness.pipeline.cli import PipelineInputs


def combine_parallel_decision(
    inputs: PipelineInputs,
    fast_result: FastDetectionAdapterResult,
    fusion_result: FusionResult,
) -> DecisionResult:
    """Combine Fast and Fusion results with the currently supported policy.

    The existing combiner supports only ``parallel_required=true``. Optional
    path behaviour must be added with a versioned execution-config policy,
    rather than inferred by the First Cycle pipeline.
    """
    decision = combine_fast_adapter_result(
        fast_result,
        fusion_result,
        decision_id=inputs.decision_id,
        config_version=inputs.decision_config_version,
        parallel_required=True,
    )
    return DecisionResult.model_validate_json(decision.model_dump_json())


__all__ = ["combine_parallel_decision"]
