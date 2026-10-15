"""Bind completed Fast artifacts to an externally approved set/config record.

Approval is an operator responsibility. A pinned record detects substitution;
it is not a signature or an automatic detector approval/freeze decision.
"""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.detection.fast_runner import Identifier
from incident_awareness.detection.fast_selection import FastSelectionPolicy, select_fast_hit
from incident_awareness.integration.fast_hit_handoff import (
    Sha256,
    adapt_fast_hit_handoff,
    read_fast_hit_handoff,
)


class FastSetBinding(BaseModel):
    """One externally reviewed immutable set/config/policy association."""

    model_config = ConfigDict(extra="forbid")
    contract_version: Literal["fast-set-binding-v1"]
    detector_set_version: Identifier
    detector_config_version: Identifier
    config_sha256: Sha256
    selection_policy_sha256: Sha256
    approval_reference: Identifier


def fast_binding_sha256(binding: FastSetBinding) -> str:
    """Hash sorted compact UTF-8 JSON with no trailing newline."""
    binding = FastSetBinding.model_validate(binding.model_dump())
    return hashlib.sha256(
        json.dumps(
            binding.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


class FastBindingInput(BaseModel):
    """Local artifact paths; keep private paths and environment outside Git."""

    model_config = ConfigDict(extra="forbid")
    binding: FastSetBinding
    policy: FastSelectionPolicy
    hits_path: str
    trace_path: str
    selection_path: str
    audit_path: str


def validate_fast_binding(
    value: FastBindingInput,
    *,
    expected_binding_sha256: str,
    run: RunMetadata,
    detection: DetectionResult,
    decision: DecisionResult,
) -> None:
    """Recompute selection and compare its actual consumer result and provenance."""
    value = FastBindingInput.model_validate(value.model_dump())
    binding, policy = value.binding, value.policy
    if fast_binding_sha256(binding) != expected_binding_sha256:
        raise ValueError("Fast binding differs from the pinned approval record")
    if run.detector_set_version != binding.detector_set_version:
        raise ValueError("Run detector set differs from Fast binding")
    for name in ("detector_set_version", "detector_config_version", "config_sha256"):
        if getattr(binding, name) != getattr(policy, name):
            raise ValueError(f"Fast binding/selection policy mismatch: {name}")
    selection, expected_audit = select_fast_hit(
        hits_path=Path(value.hits_path),
        trace_path=Path(value.trace_path),
        policy=policy,
        run_id=run.run_id,
        entity_id=run.target_host,
    )
    if expected_audit["policy_sha256"] != binding.selection_policy_sha256:
        raise ValueError("selection policy hash differs from Fast binding")
    actual_selection = json.loads(Path(value.selection_path).read_text(encoding="utf-8"))
    actual_audit = json.loads(Path(value.audit_path).read_text(encoding="utf-8"))
    if actual_selection != selection.model_dump(mode="json"):
        raise ValueError("stored Fast selection differs from source replay")
    if actual_audit != expected_audit:
        raise ValueError("stored Fast selection audit differs from source replay")
    handoff = read_fast_hit_handoff(
        Path(value.hits_path), Path(value.trace_path), run_id=run.run_id
    )
    adapted = adapt_fast_hit_handoff(
        handoff,
        entity_id=run.target_host,
        selection=selection,
        entity_mapper=policy.host_entity_map.get,
    )
    if adapted.detection_result != detection:
        raise ValueError("DetectionResult differs from bound Fast selection")
    if (decision.run_id, decision.entity_id) != (run.run_id, run.target_host):
        raise ValueError("Fast Decision Run/entity mismatch")
    if decision.detector_set_version != binding.detector_set_version:
        raise ValueError("Decision detector set differs from Fast binding")
    if decision.source_hit_ids is None or tuple(decision.source_hit_ids) != adapted.source_hit_ids:
        raise ValueError("Decision source hit IDs differ from bound Fast selection")
    if decision.selected_source_hit_id != adapted.selected_source_hit_id:
        raise ValueError("Decision selected source hit differs from bound Fast selection")
