"""Weighted presence of evidence types within the existing Fusion window."""

import math
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.config import validate_managed_evidence_types
from incident_awareness.decision.fusion.simple_score import SimpleScorer


class WeightedRuleScorer(SimpleScorer):
    """Normalize active type weights by all configured weights.

    Repeated evidence of one type contributes once. Windowing, cadence and
    episode transitions remain the responsibility of TemporalReplayRunner.
    The inherited denominator is the type count; total_weight is the weighted
    normalization denominator.
    """

    def __init__(self, weights: Mapping[str, float]) -> None:
        copied = dict(weights)
        if not copied:
            raise ValueError("weights must not be empty")
        for name, weight in copied.items():
            if not isinstance(name, str) or not name.strip() or name != name.strip():
                raise ValueError("weight keys must be nonblank, trimmed evidence types")
            if isinstance(weight, bool) or not isinstance(weight, (int, float)):
                raise TypeError("weights must be finite positive numbers")
            try:
                valid = math.isfinite(weight) and weight > 0
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError("weights must be finite positive numbers")
        validate_managed_evidence_types(copied)
        try:
            total = math.fsum(copied[name] for name in sorted(copied))
        except OverflowError as exc:
            raise ValueError("total weight must be finite") from exc
        if not math.isfinite(total):
            raise ValueError("total weight must be finite")
        super().__init__(copied)
        self._weights = MappingProxyType(copied)
        self._total_weight = total

    @property
    def total_weight(self) -> float:
        return self._total_weight

    def score(self, active_evidence: Iterable[Evidence]) -> float:
        active_types = {
            evidence.evidence_type
            for evidence in active_evidence
            if self._is_scoring_evidence(evidence)
        }
        return math.fsum(self._weights[name] for name in sorted(active_types)) / self.total_weight
