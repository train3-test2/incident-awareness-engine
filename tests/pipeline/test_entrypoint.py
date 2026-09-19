from incident_awareness.pipeline import __main__ as entrypoint


def test_main_parses_inputs_and_runs_first_cycle_pipeline(monkeypatch) -> None:
    inputs = object()
    received: list[object] = []
    monkeypatch.setattr(entrypoint, "parse_cli_args", lambda argv: inputs)
    monkeypatch.setattr(entrypoint, "run_first_cycle_pipeline", received.append)

    exit_code = entrypoint.main(["--run-metadata", "run_metadata.json"])

    assert exit_code == 0
    assert received == [inputs]
