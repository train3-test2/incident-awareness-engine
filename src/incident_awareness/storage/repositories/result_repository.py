from collections.abc import Mapping
from typing import Protocol

from psycopg.types.json import Jsonb

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...

    def commit(self) -> None: ...


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
        self._connection.commit()

    def get(self, run_id: str, entity_id: str) -> FusionResult | None:
        row = self._connection.execute(
            _SELECT_FUSION_RESULT_PAYLOAD,
            (run_id, entity_id),
        ).fetchone()
        if row is None:
            return None

        return FusionResult.model_validate(_payload_from_row(row, table_name="fusion_results"))


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
        self._connection.commit()

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
        self._connection.commit()

    def get(self, decision_id: str) -> DecisionResult | None:
        row = self._connection.execute(_SELECT_DECISION_PAYLOAD, (decision_id,)).fetchone()
        if row is None:
            return None

        return DecisionResult.model_validate(_payload_from_row(row, table_name="decisions"))


def _payload_from_row(
    row: tuple[object, ...] | Mapping[str, object],
    *,
    table_name: str,
) -> Mapping[str, object]:
    payload = row[0] if isinstance(row, tuple) else row["payload"]
    if not isinstance(payload, Mapping):
        raise TypeError(f"{table_name}.payload는 JSON 객체여야 합니다.")

    return payload
