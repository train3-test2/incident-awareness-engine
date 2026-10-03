import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from incident_awareness.pipeline import runner
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.fusion import S0FusionPipelineResult
from incident_awareness.pipeline.reporting import PipelineExecutionSummary
from incident_awareness.pipeline.runner import run_first_cycle_pipeline
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


class _Connection:
    def __init__(self, *, fail_rollback: bool = False) -> None:
        self.rollbacks = 0
        self._fail_rollback = fail_rollback

    def rollback(self) -> None:
        self.rollbacks += 1
        if self._fail_rollback:
            raise RuntimeError("database rollback failed")


def test_runs_each_first_cycle_stage_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    calls: list[str] = []
    connection = object()
    artifacts = SimpleNamespace(run_metadata=SimpleNamespace(run_id="RUN-20260920-001"))
    normalized_artifacts = object()
    fusion_result = object()
    stopping_trace = object()
    runtime_config_snapshot = object()
    fusion_output = S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
    )
    fast_result = object()
    decision_result = object()
    summary = PipelineExecutionSummary(
        run_id="RUN-20260920-001",
        entity_id="WIN-01",
        normalized_event_count=2,
        evidence_count=2,
        fusion_status="detected",
        detector_status="detected",
        decision_path="fast_and_fusion",
    )

    monkeypatch.setattr(
        runner,
        "load_s0_pipeline_artifacts",
        lambda inputs: _record(calls, "artifact_validation", artifacts),
    )
    monkeypatch.setattr(
        runner,
        "normalize_sysmon_and_extract_evidence",
        lambda value: _record(calls, "normalization", normalized_artifacts),
    )
    monkeypatch.setattr(
        runner,
        "run_s0_fusion_with_trace",
        lambda inputs, value, normalized: _record(calls, "fusion", fusion_output),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        lambda inputs, value: _record(calls, "fast_handoff", fast_result),
    )

    def resolve_expected_supersedes(**kwargs) -> str:
        assert kwargs == {
            "decision_id": "D-001",
            "run_id": "RUN-20260920-001",
            "entity_id": "WIN-01",
            "connection": connection,
        }
        return _record(calls, "lifecycle_resolution", "D-000")

    def combine_decision(inputs, fast, fusion, *, supersedes_decision_id):
        assert supersedes_decision_id == "D-000"
        return _record(calls, "hybrid", decision_result)

    monkeypatch.setattr(
        runner,
        "resolve_expected_supersedes_decision_id",
        resolve_expected_supersedes,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        combine_decision,
    )

    def persist_results(*args, **kwargs) -> None:
        assert args == (
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            fast_result,
            decision_result,
        )
        assert kwargs == {"connection": connection}
        _record(calls, "persistence", None)

    monkeypatch.setattr(runner, "persist_s0_results", persist_results)
    monkeypatch.setattr(runner, "build_execution_summary", lambda *args: summary)
    monkeypatch.setattr(runner, "log_execution_summary", lambda value: calls.append("summary"))

    # When
    actual_summary = run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert actual_summary == summary
    assert calls == [
        "artifact_validation",
        "normalization",
        "fusion",
        "fast_handoff",
        "lifecycle_resolution",
        "hybrid",
        "persistence",
        "summary",
    ]


def test_rolls_back_caller_connection_when_combine_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = _Connection()
    error = RuntimeError("Decision combination failed")
    persistence_calls: list[object] = []
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="none",
        error=error,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        _raise_or_return("combine", "combine", error, None),
    )
    monkeypatch.setattr(
        runner,
        "persist_s0_results",
        lambda *args, **kwargs: persistence_calls.append(None),
    )

    # When
    with pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert exc_info.value is error
    assert connection.rollbacks == 1
    assert persistence_calls == []


def test_preserves_combine_error_when_rollback_fails(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    connection = _Connection(fail_rollback=True)
    error = RuntimeError("Decision combination failed")
    _configure_successful_stages(
        monkeypatch,
        runner,
        failing_stage="none",
        error=error,
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        _raise_or_return("combine", "combine", error, None),
    )

    # When
    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError) as exc_info:
        run_first_cycle_pipeline(_inputs(), connection=connection)

    # Then
    assert exc_info.value is error
    assert connection.rollbacks == 1
    assert "Hybrid Decision rollback failed" in caplog.text


@pytest.mark.parametrize(
    ("failing_stage", "error"),
    [
        ("artifact_validation", ValueError("manifest run_id mismatch")),
        ("fast_handoff", ValueError("FastHit trace run_id mismatch")),
        ("hybrid", DecisionIntegrityError("Decision lifecycle is invalid")),
        ("persistence", RuntimeError("database connection lost")),
    ],
)
def test_logs_and_reraises_failure_at_each_external_boundary(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failing_stage: str,
    error: Exception,
) -> None:
    _configure_successful_stages(monkeypatch, runner, failing_stage=failing_stage, error=error)

    with (
        caplog.at_level(logging.ERROR, logger="incident_awareness.pipeline.reporting"),
        pytest.raises(type(error), match=str(error)),
    ):
        run_first_cycle_pipeline(_inputs(), connection=object())

    assert f"stage={failing_stage}" in caplog.text
    assert str(error) in caplog.text


def _configure_successful_stages(
    monkeypatch: pytest.MonkeyPatch,
    runner: object,
    *,
    failing_stage: str,
    error: Exception,
) -> None:
    artifacts = SimpleNamespace(run_metadata=SimpleNamespace(run_id="RUN-20260920-001"))
    normalized_artifacts = object()
    fusion_result = object()
    stopping_trace = object()
    runtime_config_snapshot = object()
    fusion_output = S0FusionPipelineResult(
        fusion_result=fusion_result,
        stopping_trace=stopping_trace,
        runtime_config_snapshot=runtime_config_snapshot,
    )
    fast_result = object()
    decision_result = object()

    monkeypatch.setattr(
        runner,
        "load_s0_pipeline_artifacts",
        _raise_or_return(failing_stage, "artifact_validation", error, artifacts),
    )
    monkeypatch.setattr(
        runner,
        "normalize_sysmon_and_extract_evidence",
        _raise_or_return(failing_stage, "normalization", error, normalized_artifacts),
    )
    monkeypatch.setattr(
        runner,
        "run_s0_fusion_with_trace",
        _raise_or_return(failing_stage, "fusion", error, fusion_output),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        _raise_or_return(failing_stage, "fast_handoff", error, fast_result),
    )
    monkeypatch.setattr(
        runner,
        "resolve_expected_supersedes_decision_id",
        _raise_or_return(failing_stage, "hybrid", error, None),
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        lambda *args, **kwargs: decision_result,
    )
    monkeypatch.setattr(
        runner,
        "persist_s0_results",
        _raise_or_return(failing_stage, "persistence", error, None),
    )


def _raise_or_return(
    failing_stage: str,
    current_stage: str,
    error: Exception,
    value: object,
):
    def operation(*args, **kwargs):
        if current_stage == failing_stage:
            raise error
        return value

    return operation


def _record(calls: list[str], stage: str, value: object) -> object:
    calls.append(stage)
    return value


def _inputs() -> PipelineInputs:
    unused_path = Path("unused")
    return PipelineInputs(
        run_metadata_path=unused_path,
        manifest_path=unused_path,
        sysmon_jsonl_path=unused_path,
        fast_hits_path=unused_path,
        fast_trace_path=unused_path,
        fast_selection_path=unused_path,
        fusion_config_path=unused_path,
        entity_id="WIN-01",
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )
