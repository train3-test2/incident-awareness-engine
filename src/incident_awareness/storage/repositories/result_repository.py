from collections.abc import Mapping
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.runtime_snapshot import DecisionRuntimeSnapshot


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...

    def fetchall(self) -> list[tuple[object, ...] | Mapping[str, object]]: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_UPSERT_FUSION_RESULT = """
INSERT INTO fusion_results (
    run_id,
    entity_id,
    fusion_status,
    fusion_time,
    payload
)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (run_id, entity_id) DO UPDATE SET
    fusion_status = EXCLUDED.fusion_status,
    fusion_time = EXCLUDED.fusion_time,
    payload = EXCLUDED.payload
"""

_SELECT_FUSION_RESULT_PAYLOAD = """
SELECT payload
FROM fusion_results
WHERE run_id = %s AND entity_id = %s
"""

_UPSERT_FUSION_STOPPING_TRACE = """
INSERT INTO fusion_stopping_traces (
    run_id,
    entity_id,
    scoring_config_version,
    payload
)
VALUES (%s, %s, %s, %s)
ON CONFLICT (run_id, entity_id) DO UPDATE SET
    scoring_config_version = EXCLUDED.scoring_config_version,
    payload = EXCLUDED.payload
"""

_SELECT_FUSION_STOPPING_TRACE_PAYLOAD = """
SELECT payload
FROM fusion_stopping_traces
WHERE run_id = %s AND entity_id = %s
"""

_UPSERT_DETECTION_RESULT = """
INSERT INTO detection_results (
    run_id,
    entity_id,
    detector_status,
    detector_time,
    detector_id,
    payload
)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (run_id, entity_id) DO UPDATE SET
    detector_status = EXCLUDED.detector_status,
    detector_time = EXCLUDED.detector_time,
    detector_id = EXCLUDED.detector_id,
    payload = EXCLUDED.payload
"""

_SELECT_DETECTION_RESULT_PAYLOAD = """
SELECT payload
FROM detection_results
WHERE run_id = %s AND entity_id = %s
"""

_INSERT_DECISION = """
INSERT INTO decisions (
    decision_id,
    run_id,
    entity_id,
    fast_status,
    fusion_status,
    detector_time,
    fusion_time,
    t_e,
    decision_path,
    winning_path,
    payload
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

_SELECT_DECISION_PAYLOAD = "SELECT payload FROM decisions WHERE decision_id = %s"

_SELECT_DECISIONS_BY_SCOPE = """
SELECT payload
FROM decisions
WHERE run_id = %s
  AND entity_id = %s
"""

_INSERT_DECISION_RUNTIME_SNAPSHOT = """
INSERT INTO decision_runtime_snapshots (
    decision_id,
    run_id,
    entity_id,
    payload
)
VALUES (%s, %s, %s, %s)
"""

_SELECT_DECISION_RUNTIME_SNAPSHOT_PAYLOAD = """
SELECT payload
FROM decision_runtime_snapshots
WHERE decision_id = %s
"""

_SELECT_DECISION_WITH_RUNTIME_SNAPSHOT_PAYLOADS = """
SELECT
    decision.payload AS decision_payload,
    snapshot.payload AS snapshot_payload
FROM decisions AS decision
LEFT JOIN decision_runtime_snapshots AS snapshot
  ON snapshot.decision_id = decision.decision_id
 AND snapshot.run_id = decision.run_id
 AND snapshot.entity_id = decision.entity_id
WHERE decision.decision_id = %s
"""


_SELECT_CURRENT_DECISION_HEADS = """
WITH scope_decisions AS (
    SELECT decision_id, payload
    FROM decisions
    WHERE run_id = %s AND entity_id = %s
),
current_heads AS (
    SELECT candidate.payload
    FROM scope_decisions AS candidate
    WHERE NOT EXISTS (
        SELECT 1
        FROM scope_decisions AS successor
        WHERE successor.payload ->> 'supersedes_decision_id' = candidate.decision_id
    )
    LIMIT 2
)
SELECT
    EXISTS (SELECT 1 FROM scope_decisions) AS scope_has_decisions,
    current_heads.payload
FROM (SELECT 1) AS singleton
LEFT JOIN current_heads ON TRUE
"""


class DecisionIntegrityError(RuntimeError):
    """저장된 Decision lifecycle이 무결성 조건을 위반했다."""


class FusionResultRepository:
    """FusionResult Contract를 fusion_results 테이블에 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, result: FusionResult) -> None:
        self._connection.execute(
            _UPSERT_FUSION_RESULT,
            (
                result.run_id,
                result.entity_id,
                result.fusion_status,
                result.fusion_time,
                Jsonb(result.model_dump(mode="json")),
            ),
        )

    def get(self, run_id: str, entity_id: str) -> FusionResult | None:
        row = self._connection.execute(
            _SELECT_FUSION_RESULT_PAYLOAD,
            (run_id, entity_id),
        ).fetchone()
        if row is None:
            return None

        return FusionResult.model_validate(_payload_from_row(row, table_name="fusion_results"))


class FusionStoppingTraceRepository:
    """FusionStoppingTrace Contract를 최신 Runtime trace로 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, trace: FusionStoppingTrace) -> None:
        self._connection.execute(
            _UPSERT_FUSION_STOPPING_TRACE,
            (
                trace.run_id,
                trace.entity_id,
                trace.scoring_config_version,
                Jsonb(trace.model_dump(mode="json")),
            ),
        )

    def get(self, run_id: str, entity_id: str) -> FusionStoppingTrace | None:
        row = self._connection.execute(
            _SELECT_FUSION_STOPPING_TRACE_PAYLOAD,
            (run_id, entity_id),
        ).fetchone()
        if row is None:
            return None

        return FusionStoppingTrace.model_validate(
            _payload_from_row(row, table_name="fusion_stopping_traces")
        )


class DetectionResultRepository:
    """DetectionResult Contract를 detection_results 테이블에 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, result: DetectionResult) -> None:
        self._connection.execute(
            _UPSERT_DETECTION_RESULT,
            (
                result.run_id,
                result.entity_id,
                result.detector_status.value,
                result.detector_time,
                result.detector_id,
                Jsonb(result.model_dump(mode="json")),
            ),
        )

    def get(self, run_id: str, entity_id: str) -> DetectionResult | None:
        row = self._connection.execute(
            _SELECT_DETECTION_RESULT_PAYLOAD,
            (run_id, entity_id),
        ).fetchone()
        if row is None:
            return None

        return DetectionResult.model_validate(
            _payload_from_row(row, table_name="detection_results")
        )


class DecisionRepository:
    """불변 DecisionResult Contract를 decisions 테이블에 저장하고 복원한다."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, result: DecisionResult) -> None:
        self._connection.execute(
            _INSERT_DECISION,
            (
                result.decision_id,
                result.run_id,
                result.entity_id,
                result.fast_status.value,
                result.fusion_status.value,
                result.detector_time,
                result.fusion_time,
                result.t_e,
                result.decision_path.value if result.decision_path is not None else None,
                result.winning_path.value if result.winning_path is not None else None,
                Jsonb(result.model_dump(mode="json")),
            ),
        )

    def get(self, decision_id: str) -> DecisionResult | None:
        row = self._connection.execute(_SELECT_DECISION_PAYLOAD, (decision_id,)).fetchone()
        if row is None:
            return None

        return DecisionResult.model_validate(_payload_from_row(row, table_name="decisions"))

    def list_by_scope(self, run_id: str, entity_id: str) -> list[DecisionResult]:
        rows = self._connection.execute(
            _SELECT_DECISIONS_BY_SCOPE,
            (run_id, entity_id),
        ).fetchall()
        return [
            DecisionResult.model_validate(_payload_from_row(row, table_name="decisions"))
            for row in rows
        ]

    def get_current_head(self, run_id: str, entity_id: str) -> DecisionResult | None:
        rows = self._connection.execute(
            _SELECT_CURRENT_DECISION_HEADS,
            (run_id, entity_id),
        ).fetchall()
        if not rows:
            raise RuntimeError("current Decision head query returned no rows")

        scope_has_decisions = _scope_has_decisions_from_head_row(rows[0])
        head_payloads = [
            payload for row in rows if (payload := _payload_from_head_row(row)) is not None
        ]
        if not head_payloads:
            if not scope_has_decisions:
                return None
            raise DecisionIntegrityError(
                f"no current Decision head for run_id={run_id!r}, entity_id={entity_id!r}"
            )
        if len(head_payloads) > 1:
            raise DecisionIntegrityError(
                f"multiple current Decision heads for run_id={run_id!r}, entity_id={entity_id!r}"
            )

        return DecisionResult.model_validate(head_payloads[0])


class DecisionRuntimeSnapshotRepository:
    """Store and restore the immutable Runtime snapshot for one Decision."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def save(self, snapshot: DecisionRuntimeSnapshot) -> None:
        self._connection.execute(
            _INSERT_DECISION_RUNTIME_SNAPSHOT,
            (
                snapshot.decision_id,
                snapshot.run_id,
                snapshot.entity_id,
                Jsonb(snapshot.model_dump(mode="json")),
            ),
        )

    def get(self, decision_id: str) -> DecisionRuntimeSnapshot | None:
        row = self._connection.execute(
            _SELECT_DECISION_RUNTIME_SNAPSHOT_PAYLOAD,
            (decision_id,),
        ).fetchone()
        if row is None:
            return None

        return DecisionRuntimeSnapshot.model_validate(
            _payload_from_row(row, table_name="decision_runtime_snapshots")
        )

    def get_with_decision(
        self,
        decision_id: str,
    ) -> tuple[DecisionResult, DecisionRuntimeSnapshot | None] | None:
        row = self._connection.execute(
            _SELECT_DECISION_WITH_RUNTIME_SNAPSHOT_PAYLOADS,
            (decision_id,),
        ).fetchone()
        if row is None:
            return None

        if isinstance(row, tuple):
            decision_payload, snapshot_payload = row
        else:
            decision_payload = row["decision_payload"]
            snapshot_payload = row["snapshot_payload"]

        if not isinstance(decision_payload, Mapping):
            raise TypeError("decisions.payload must be a JSON object")
        if snapshot_payload is not None and not isinstance(snapshot_payload, Mapping):
            raise TypeError("decision_runtime_snapshots.payload must be a JSON object")

        decision = DecisionResult.model_validate(decision_payload)
        snapshot = (
            None
            if snapshot_payload is None
            else DecisionRuntimeSnapshot.model_validate(snapshot_payload)
        )
        return decision, snapshot


def _scope_has_decisions_from_head_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> bool:
    value = row[0] if isinstance(row, tuple) else row["scope_has_decisions"]
    if not isinstance(value, bool):
        raise TypeError("current Decision head query must return a boolean scope flag")
    return value


def _payload_from_head_row(
    row: tuple[object, ...] | Mapping[str, object],
) -> Mapping[str, object] | None:
    payload = row[1] if isinstance(row, tuple) else row["payload"]
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise TypeError("decisions.payload must be a JSON object")
    return payload


def _payload_from_row(
    row: tuple[object, ...] | Mapping[str, object],
    *,
    table_name: str,
) -> Mapping[str, object]:
    payload = row[0] if isinstance(row, tuple) else row["payload"]
    if not isinstance(payload, Mapping):
        raise TypeError(f"{table_name}.payload는 JSON 객체여야 합니다.")

    return payload
