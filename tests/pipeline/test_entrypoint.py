from contextlib import nullcontext

from incident_awareness.pipeline import __main__ as entrypoint


def test_main_parses_inputs_and_runs_first_cycle_pipeline(monkeypatch) -> None:
    # Given
    inputs = object()
    runtime_observer = object()
    telemetry_observer = object()
    timing_collector = object()
    received: list[tuple[object, object, object, object]] = []
    lifecycle: list[str] = []

    class ObserverContext:
        def __enter__(self):
            lifecycle.append("enter")
            return runtime_observer

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            lifecycle.append("exit")

    monkeypatch.setattr(entrypoint, "parse_cli_args", lambda argv: inputs)
    monkeypatch.setattr(entrypoint, "PostgresPipelineRuntimeObserver", ObserverContext)
    monkeypatch.setattr(
        entrypoint, "telemetry_observer_context", lambda: nullcontext(telemetry_observer)
    )
    monkeypatch.setattr(
        entrypoint, "stage_timing_storage_context", lambda: nullcontext(timing_collector)
    )
    monkeypatch.setattr(
        entrypoint,
        "run_first_cycle_pipeline",
        lambda value, *, runtime_observer, telemetry_observer, stage_timing_collector: (
            received.append((value, runtime_observer, telemetry_observer, stage_timing_collector))
        ),
    )

    # When
    exit_code = entrypoint.main(["--run-metadata", "run_metadata.json"])

    # Then
    assert exit_code == 0
    assert received == [(inputs, runtime_observer, telemetry_observer, timing_collector)]
    assert lifecycle == ["enter", "exit"]
