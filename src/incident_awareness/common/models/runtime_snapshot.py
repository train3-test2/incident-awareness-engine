"""Decision-time Runtime snapshot contract."""

from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.result import DecisionResult, DetectionResult


class DecisionRuntimeSnapshot(BaseModel):
    """Detection and Fusion Runtime results captured for one Decision."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    detection_result: DetectionResult
    fusion_result: FusionResult
    fusion_stopping_trace: FusionStoppingTrace

    @model_validator(mode="after")
    def validate_runtime_contracts(self) -> "DecisionRuntimeSnapshot":
        if self.detection_result.run_id != self.run_id:
            raise ValueError("DetectionResult run_id must match DecisionRuntimeSnapshot run_id")
        if self.fusion_result.run_id != self.run_id:
            raise ValueError("FusionResult run_id must match DecisionRuntimeSnapshot run_id")
        if self.fusion_stopping_trace.run_id != self.run_id:
            raise ValueError("FusionStoppingTrace run_id must match DecisionRuntimeSnapshot run_id")

        if self.detection_result.entity_id != self.entity_id:
            raise ValueError(
                "DetectionResult entity_id must match DecisionRuntimeSnapshot entity_id"
            )
        if self.fusion_result.entity_id != self.entity_id:
            raise ValueError("FusionResult entity_id must match DecisionRuntimeSnapshot entity_id")
        if self.fusion_stopping_trace.entity_id != self.entity_id:
            raise ValueError(
                "FusionStoppingTrace entity_id must match DecisionRuntimeSnapshot entity_id"
            )

        if (
            self.fusion_stopping_trace.scoring_config_version
            != self.fusion_result.scoring_config_version
        ):
            raise ValueError(
                "FusionStoppingTrace scoring_config_version must match "
                "FusionResult scoring_config_version"
            )

        if self.fusion_result.fusion_status == "not_evaluated":
            if self.fusion_stopping_trace.points:
                raise ValueError("not_evaluated FusionResult requires an empty FusionStoppingTrace")
        elif not self.fusion_stopping_trace.points:
            raise ValueError(
                f"{self.fusion_result.fusion_status} FusionResult requires a non-empty "
                "FusionStoppingTrace"
            )

        return self


def build_decision_runtime_snapshot(
    *,
    decision_result: DecisionResult,
    detection_result: DetectionResult,
    fusion_result: FusionResult,
    fusion_stopping_trace: FusionStoppingTrace,
) -> DecisionRuntimeSnapshot:
    """Build a snapshot after validating Decision-to-Runtime relationships."""
    if decision_result.fast_status != detection_result.detector_status:
        raise ValueError("DecisionResult fast_status must match DetectionResult detector_status")
    if decision_result.detector_time != detection_result.detector_time:
        raise ValueError("DecisionResult detector_time must match DetectionResult detector_time")
    if decision_result.fusion_status.value != fusion_result.fusion_status:
        raise ValueError("DecisionResult fusion_status must match FusionResult fusion_status")
    if decision_result.fusion_time != fusion_result.fusion_time:
        raise ValueError("DecisionResult fusion_time must match FusionResult fusion_time")

    return DecisionRuntimeSnapshot(
        decision_id=decision_result.decision_id,
        run_id=decision_result.run_id,
        entity_id=decision_result.entity_id,
        detection_result=detection_result,
        fusion_result=fusion_result,
        fusion_stopping_trace=fusion_stopping_trace,
    )


__all__ = ["DecisionRuntimeSnapshot", "build_decision_runtime_snapshot"]
