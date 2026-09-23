import logging
from pathlib import Path

import pytest

from incident_awareness.pipeline import runner
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.reporting import PipelineExecutionSummary
from incident_awareness.pipeline.runner import run_first_cycle_pipeline


def test_runs_each_first_cycle_stage_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    artifacts = object()
    normalized_artifacts = object()
    fusion_result = object()
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
        "run_s0_fusion",
        lambda inputs, value, normalized: _record(calls, "fusion", fusion_result),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        lambda inputs, value: _record(calls, "fast_handoff", fast_result),
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        lambda inputs, fast, fusion: _record(calls, "hybrid", decision_result),
    )
    monkeypatch.setattr(
        runner,
        "persist_s0_results",
        lambda *args, **kwargs: _record(calls, "persistence", None),
    )
    monkeypatch.setattr(runner, "build_execution_summary", lambda *args: summary)
    monkeypatch.setattr(runner, "log_execution_summary", lambda value: calls.append("summary"))

    actual_summary = run_first_cycle_pipeline(_inputs(), connection=object())

    assert actual_summary == summary
    assert calls == [
        "artifact_validation",
        "normalization",
        "fusion",
        "fast_handoff",
        "hybrid",
        "persistence",
        "summary",
    ]


@pytest.mark.parametrize(
    ("failing_stage", "error"),
    [
        ("artifact_validation", ValueError("manifest run_id mismatch")),
        ("fast_handoff", ValueError("FastHit trace run_id mismatch")),
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
    artifacts = object()
    normalized_artifacts = object()
    fusion_result = object()
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
        "run_s0_fusion",
        _raise_or_return(failing_stage, "fusion", error, fusion_result),
    )
    monkeypatch.setattr(
        runner,
        "load_s0_fast_detection",
        _raise_or_return(failing_stage, "fast_handoff", error, fast_result),
    )
    monkeypatch.setattr(
        runner,
        "combine_parallel_decision",
        _raise_or_return(failing_stage, "hybrid", error, decision_result),
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
