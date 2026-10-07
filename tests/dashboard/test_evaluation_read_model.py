import inspect
from pathlib import Path

import pytest

from incident_awareness.dashboard import evaluation_read_model
from incident_awareness.dashboard.evaluation_read_model import (
    EVALUATION_SNAPSHOT_PATH_ENV,
    DashboardEvaluationReader,
    EvaluationReadModel,
    EvaluationSnapshotUnavailableError,
    StoredEvaluationSnapshotInvalidError,
    evaluation_snapshot_path_from_environment,
)
from incident_awareness.evaluation.result_inputs import load_evaluation_snapshot

FIXTURE = Path("tests/fixtures/evaluation/result_snapshot.json").resolve()


def test_reader_loads_once_and_passes_the_same_snapshot_to_all_evaluators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot = load_evaluation_snapshot(FIXTURE)
    original = snapshot.model_dump(mode="python")
    load_calls: list[Path] = []
    evaluator_snapshots: list[object] = []
    evaluation = {"report": "evaluation"}
    alert_burden = {"report": "alert-burden"}
    paired_timing = {"report": "paired-timing"}

    def load(path: Path):
        load_calls.append(path)
        return snapshot

    def evaluate(value):
        evaluator_snapshots.append(value)
        return evaluation

    def evaluate_alert_burden(value):
        evaluator_snapshots.append(value)
        return alert_burden

    def evaluate_paired_timing(value):
        evaluator_snapshots.append(value)
        return paired_timing

    monkeypatch.setattr(evaluation_read_model, "load_evaluation_snapshot", load)
    monkeypatch.setattr(evaluation_read_model, "evaluate_snapshot", evaluate)
    monkeypatch.setattr(
        evaluation_read_model,
        "evaluate_normal_alert_burden",
        evaluate_alert_burden,
    )
    monkeypatch.setattr(
        evaluation_read_model,
        "compare_paired_timing",
        evaluate_paired_timing,
    )
    reader = DashboardEvaluationReader(FIXTURE)

    # When
    result = reader.get_evaluation()

    # Then
    assert result == EvaluationReadModel(
        evaluation=evaluation,
        normal_alert_burden=alert_burden,
        paired_timing=paired_timing,
    )
    assert load_calls == [FIXTURE]
    assert len(evaluator_snapshots) == 3
    assert all(value is snapshot for value in evaluator_snapshots)
    assert snapshot.model_dump(mode="python") == original


def test_reader_does_not_mutate_the_snapshot_used_by_real_evaluators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot = load_evaluation_snapshot(FIXTURE)
    original = snapshot.model_dump(mode="python")
    monkeypatch.setattr(
        evaluation_read_model,
        "load_evaluation_snapshot",
        lambda _path: snapshot,
    )
    reader = DashboardEvaluationReader(FIXTURE)

    # When
    result = reader.get_evaluation()

    # Then
    assert result.evaluation["snapshot_id"] == snapshot.snapshot_id
    assert snapshot.model_dump(mode="python") == original


def test_reader_classifies_snapshot_access_failure_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    def fail_load(_path: Path):
        raise OSError("sensitive path detail")

    monkeypatch.setattr(evaluation_read_model, "load_evaluation_snapshot", fail_load)
    reader = DashboardEvaluationReader(FIXTURE)

    # When
    with pytest.raises(EvaluationSnapshotUnavailableError):
        reader.get_evaluation()

    # Then
    # The public exception type, rather than the source OSError, defines the boundary.


def test_reader_classifies_snapshot_validation_failure_as_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    def fail_load(_path: Path):
        raise ValueError("sensitive validation detail")

    monkeypatch.setattr(evaluation_read_model, "load_evaluation_snapshot", fail_load)
    reader = DashboardEvaluationReader(FIXTURE)

    # When
    with pytest.raises(StoredEvaluationSnapshotInvalidError):
        reader.get_evaluation()

    # Then
    # The public exception type, rather than validation detail, defines the boundary.


@pytest.mark.parametrize(
    "evaluator_name",
    [
        "evaluate_snapshot",
        "evaluate_normal_alert_burden",
        "compare_paired_timing",
    ],
)
def test_reader_classifies_evaluator_validation_failure_as_invalid(
    monkeypatch: pytest.MonkeyPatch,
    evaluator_name: str,
) -> None:
    # Given
    snapshot = load_evaluation_snapshot(FIXTURE)
    monkeypatch.setattr(
        evaluation_read_model,
        "load_evaluation_snapshot",
        lambda _path: snapshot,
    )
    monkeypatch.setattr(evaluation_read_model, "evaluate_snapshot", lambda _value: {})
    monkeypatch.setattr(
        evaluation_read_model,
        "evaluate_normal_alert_burden",
        lambda _value: {},
    )
    monkeypatch.setattr(evaluation_read_model, "compare_paired_timing", lambda _value: {})

    def fail_evaluation(_snapshot):
        raise ValueError("sensitive evaluator detail")

    monkeypatch.setattr(evaluation_read_model, evaluator_name, fail_evaluation)
    reader = DashboardEvaluationReader(FIXTURE)

    # When
    with pytest.raises(StoredEvaluationSnapshotInvalidError):
        reader.get_evaluation()

    # Then
    # Invalid evaluator output is not replaced with an empty metric report.


@pytest.mark.parametrize("configured", [None, "", "   ", "relative/snapshot.json"])
def test_snapshot_path_configuration_rejects_missing_blank_and_relative_values(
    configured: str | None,
) -> None:
    # Given
    environment = {} if configured is None else {EVALUATION_SNAPSHOT_PATH_ENV: configured}

    # When
    with pytest.raises(EvaluationSnapshotUnavailableError):
        evaluation_snapshot_path_from_environment(environment)

    # Then
    # No CWD-relative production fallback is accepted.


def test_snapshot_path_configuration_accepts_an_absolute_path() -> None:
    # Given
    environment = {EVALUATION_SNAPSHOT_PATH_ENV: str(FIXTURE)}

    # When
    result = evaluation_snapshot_path_from_environment(environment)

    # Then
    assert result == FIXTURE


def test_reader_contains_no_runtime_timing_or_metric_formula() -> None:
    # Given
    source = inspect.getsource(evaluation_read_model)

    # When
    forbidden_fragments = (
        "detector_time",
        "fusion_time",
        ".t_e",
        "reference_time +",
        "median(",
        "quantile(",
    )

    # Then
    assert all(fragment not in source for fragment in forbidden_fragments)
