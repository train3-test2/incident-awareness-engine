from collections.abc import Iterable


class SimpleScorer:
    def __init__(self, evidence_types: Iterable[str]) -> None:
        profile_types = tuple(evidence_types)

        if not profile_types:
            raise ValueError("evidence_types must not be empty")

        if len(set(profile_types)) != len(profile_types):
            raise ValueError("evidence_types must not contain duplicates")

        self._profile_types = frozenset(profile_types)

    @property
    def denominator(self) -> int:
        return len(self._profile_types)
