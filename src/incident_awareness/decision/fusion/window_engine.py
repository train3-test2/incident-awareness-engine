from collections import deque
from datetime import datetime, timedelta

from incident_awareness.common.models.evidence import Evidence

StateKey = tuple[str, str]


class WindowEngine:
    def __init__(self, window_size: timedelta) -> None:
        if window_size <= timedelta(0):
            raise ValueError("window_size must be greater than zero")

        self.window_size = window_size
        self._states: dict[StateKey, deque[Evidence]] = {}
        self._last_timestamp: dict[StateKey, datetime] = {}
        self._last_advance_timestamp: dict[StateKey, datetime] = {}

    def ingest(self, evidence: Evidence) -> None:
        key = (evidence.run_id, evidence.entity_id)

        last_advance_timestamp = self._last_advance_timestamp.get(key)
        if last_advance_timestamp is not None and evidence.timestamp < last_advance_timestamp:
            raise ValueError("cannot ingest evidence before latest window advance timestamp")

        last_timestamp = self._last_timestamp.get(key)

        if last_timestamp is not None and evidence.timestamp < last_timestamp:
            raise ValueError(
                "Evidence timestamps must be non-decreasing within the same run_id/entity_id"
            )

        state = self._states.setdefault(key, deque())
        state.append(evidence)

        self._last_timestamp[key] = evidence.timestamp

    def advance_to(
        self,
        *,
        run_id: str,
        entity_id: str,
        timestamp: datetime,
    ) -> None:
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")
        if timestamp.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be UTC")

        key = (run_id, entity_id)

        last_advance_timestamp = self._last_advance_timestamp.get(key)
        if last_advance_timestamp is not None and timestamp < last_advance_timestamp:
            raise ValueError("advance timestamp must be non-decreasing")

        last_timestamp = self._last_timestamp.get(key)
        if last_timestamp is not None and last_timestamp > timestamp:
            raise ValueError("cannot advance window before latest ingested evidence timestamp")

        self._last_advance_timestamp[key] = timestamp

        state = self._states.get(key)
        if state is None:
            return

        cutoff = timestamp - self.window_size

        while state and state[0].timestamp < cutoff:
            state.popleft()

    def get_active_evidence(
        self,
        *,
        run_id: str,
        entity_id: str,
    ) -> list[Evidence]:
        key = (run_id, entity_id)

        state = self._states.get(key)

        if state is None:
            return []

        last_advance_timestamp = self._last_advance_timestamp.get(key)
        if last_advance_timestamp is None:
            return list(state)

        return [evidence for evidence in state if evidence.timestamp <= last_advance_timestamp]

    def reset(
        self,
        *,
        run_id: str,
        entity_id: str,
    ) -> None:
        key = (run_id, entity_id)

        self._states.pop(key, None)
        self._last_timestamp.pop(key, None)
        self._last_advance_timestamp.pop(key, None)
