"""Adapt a validated Fast Runner handoff for the First Cycle pipeline."""

from pathlib import Path

from pydantic import ValidationError

from incident_awareness.integration.fast_hit_handoff import (
    EntityIdMapper,
    FastDetectionAdapterResult,
    FastDetectionSelection,
    adapt_fast_hit_handoff,
    direct_host_entity_mapper,
    read_fast_hit_handoff,
)
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts


def load_s0_fast_detection(
    inputs: PipelineInputs,
    artifacts: S0PipelineArtifacts,
    *,
    entity_mapper: EntityIdMapper = direct_host_entity_mapper,
) -> FastDetectionAdapterResult:
    """Read the Fast Handoff and adapt Role 5's selected outcome.

    The First Cycle default maps a native host directly to the canonical
    endpoint-host entity. Callers with an explicit mapping can supply it
    without discarding the Adapter's complete FastHit provenance.
    """
    selection = _read_fast_detection_selection(inputs.fast_selection_path)
    handoff = read_fast_hit_handoff(
        inputs.fast_hits_path,
        inputs.fast_trace_path,
        run_id=artifacts.run_metadata.run_id,
    )
    return adapt_fast_hit_handoff(
        handoff,
        entity_id=inputs.entity_id,
        selection=selection,
        entity_mapper=entity_mapper,
    )


def _read_fast_detection_selection(path: Path) -> FastDetectionSelection:
    try:
        return FastDetectionSelection.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValidationError) as error:
        raise ValueError(f"FastDetectionSelection is not valid: {path}") from error


__all__ = ["load_s0_fast_detection"]
