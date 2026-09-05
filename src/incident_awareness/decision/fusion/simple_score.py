from collections.abc import Iterable

from incident_awareness.common.models.evidence import Evidence


class SimpleScorer:
    def __init__(self, evidence_types: Iterable[str]) -> None:
        profile_types = tuple(evidence_types)

        if not profile_types:
            raise ValueError("evidence_types must not be empty")

        if any(not evidence_type.strip() for evidence_type in profile_types):
            raise ValueError("evidence_types must not contain blank values")

        if len(set(profile_types)) != len(profile_types):
            raise ValueError("evidence_types must not contain duplicates")

        

        self._profile_types = frozenset(profile_types)

    @property
    def denominator(self) -> int:
        return len(self._profile_types)

    def score(self, active_evidence: Iterable[Evidence]) -> float:
        active_types = {
            evidence.evidence_type
            for evidence in active_evidence
            if evidence.feature_channel_group == "fusion_feature"
            and evidence.evidence_type in self._profile_types
        }

        return len(active_types) / self.denominator
