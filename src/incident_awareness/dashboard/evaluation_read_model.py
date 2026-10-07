"""Read a configured EvaluationSnapshot through the existing evaluators."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from incident_awareness.evaluation.alert_burden import evaluate_normal_alert_burden
from incident_awareness.evaluation.paired_timing import compare_paired_timing
from incident_awareness.evaluation.result_inputs import (
    evaluate_snapshot,
    load_evaluation_snapshot,
)

EVALUATION_SNAPSHOT_PATH_ENV = "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_PATH"


class EvaluationSnapshotUnavailableError(RuntimeError):
    """Configured EvaluationSnapshot cannot be accessed."""


class StoredEvaluationSnapshotInvalidError(RuntimeError):
    """Stored EvaluationSnapshot or its derived reports are invalid."""


@dataclass(frozen=True, slots=True)
class EvaluationReadModel:
    evaluation: dict
    normal_alert_burden: dict
    paired_timing: dict


class DashboardEvaluationReader:
    def __init__(self, snapshot_path: Path) -> None:
        self._snapshot_path = snapshot_path

    def get_evaluation(self) -> EvaluationReadModel:
        try:
            snapshot = load_evaluation_snapshot(self._snapshot_path)
        except OSError as exc:
            raise EvaluationSnapshotUnavailableError from exc
        except ValueError as exc:
            raise StoredEvaluationSnapshotInvalidError from exc

        try:
            evaluation = evaluate_snapshot(snapshot)
            normal_alert_burden = evaluate_normal_alert_burden(snapshot)
            paired_timing = compare_paired_timing(snapshot)
        except ValueError as exc:
            raise StoredEvaluationSnapshotInvalidError from exc

        return EvaluationReadModel(
            evaluation=evaluation,
            normal_alert_burden=normal_alert_burden,
            paired_timing=paired_timing,
        )


def evaluation_snapshot_path_from_environment(
    environment: Mapping[str, str] | None = None,
) -> Path:
    values = os.environ if environment is None else environment
    configured = values.get(EVALUATION_SNAPSHOT_PATH_ENV)
    if configured is None or not configured.strip():
        raise EvaluationSnapshotUnavailableError

    path = Path(configured)
    if not path.is_absolute():
        raise EvaluationSnapshotUnavailableError
    return path
