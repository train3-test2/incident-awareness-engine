"""Binary evidence presence for a caller-selected single Run/entity window."""

from collections.abc import Iterable
from dataclasses import dataclass

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import validate_managed_evidence_types


@dataclass(frozen=True)
class StaticFeatureVector:
    feature_names: tuple[str, ...]
    values: tuple[int, ...]
    evidence_ids: tuple[str, ...]
    run_id: str
    entity_id: str


def extract_static_features(
    active_evidence: Iterable[Evidence],
    *,
    feature_names: Iterable[str],
    run_id: str,
    entity_id: str,
) -> StaticFeatureVector:
    """Preserve declared column order; never select windows or infer labels."""
    RunMetadata.validate_run_id(run_id)
    if not isinstance(entity_id, str) or not entity_id.strip() or entity_id != entity_id.strip():
        raise ValueError("entity_id must be nonblank and trimmed")
    if isinstance(feature_names, (str, bytes)):
        raise TypeError("feature_names must be a sequence of names")
    names = tuple(feature_names)
    if not names or any(
        not isinstance(name, str) or not name.strip() or name != name.strip() for name in names
    ):
        raise ValueError("feature_names must contain nonblank, trimmed names")
    if len(set(names)) != len(names):
        raise ValueError("feature_names must be unique")
    validate_managed_evidence_types(names)
    active_types = set()
    identifiers = set()
    seen: dict[str, Evidence] = {}
    for original in active_evidence:
        row = Evidence.model_validate(original.model_dump(mode="json"))
        validate_managed_evidence_types((row.evidence_type,))
        if row.run_id != run_id or row.entity_id != entity_id:
            raise ValueError("Evidence must belong to the requested Run/entity")
        if row.evidence_id in seen and seen[row.evidence_id] != row:
            raise ValueError("conflicting records for the same evidence_id")
        seen[row.evidence_id] = row
        if row.feature_channel_group == "fusion_feature" and row.evidence_type in names:
            active_types.add(row.evidence_type)
            identifiers.add(row.evidence_id)
    return StaticFeatureVector(
        feature_names=names,
        values=tuple(int(name in active_types) for name in names),
        evidence_ids=tuple(sorted(identifiers)),
        run_id=run_id,
        entity_id=entity_id,
    )
