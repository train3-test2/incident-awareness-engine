from pathlib import Path

import pytest

from incident_awareness.pipeline.cli import PipelineInputs, parse_cli_args


@pytest.fixture
def input_paths(tmp_path: Path) -> dict[str, Path]:
    paths = {
        "run_metadata": tmp_path / "run_metadata.json",
        "manifest": tmp_path / "manifest.json",
        "sysmon_jsonl": tmp_path / "sysmon-0001.jsonl",
        "fast_hits": tmp_path / "fast-hits.jsonl",
        "fast_trace": tmp_path / "fast-trace.json",
        "fast_selection": tmp_path / "fast-selection.json",
        "fusion_config": tmp_path / "fusion-config.yaml",
    }
    for path in paths.values():
        path.write_text("{}", encoding="utf-8")
    return paths


def _arguments(paths: dict[str, Path]) -> list[str]:
    return [
        "--run-metadata",
        str(paths["run_metadata"]),
        "--manifest",
        str(paths["manifest"]),
        "--sysmon-jsonl",
        str(paths["sysmon_jsonl"]),
        "--fast-hits",
        str(paths["fast_hits"]),
        "--fast-trace",
        str(paths["fast_trace"]),
        "--fast-selection",
        str(paths["fast_selection"]),
        "--fusion-config",
        str(paths["fusion_config"]),
        "--entity-id",
        "WIN-01",
        "--decision-id",
        "D-001",
        "--decision-config-version",
        "parallel-v0.2",
    ]


def test_parses_all_first_cycle_input_paths_and_execution_settings(
    input_paths: dict[str, Path],
) -> None:
    inputs = parse_cli_args(_arguments(input_paths))

    assert inputs == PipelineInputs(
        run_metadata_path=input_paths["run_metadata"],
        manifest_path=input_paths["manifest"],
        sysmon_jsonl_path=input_paths["sysmon_jsonl"],
        fast_hits_path=input_paths["fast_hits"],
        fast_trace_path=input_paths["fast_trace"],
        fast_selection_path=input_paths["fast_selection"],
        fusion_config_path=input_paths["fusion_config"],
        entity_id="WIN-01",
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )


@pytest.mark.parametrize(
    "option",
    [
        "--run-metadata",
        "--manifest",
        "--sysmon-jsonl",
        "--fast-hits",
        "--fast-trace",
        "--fast-selection",
        "--fusion-config",
    ],
)
def test_rejects_missing_input_file(
    input_paths: dict[str, Path],
    option: str,
) -> None:
    arguments = _arguments(input_paths)
    arguments[arguments.index(option) + 1] = str(input_paths["run_metadata"].parent / "missing")

    with pytest.raises(ValueError, match="existing file"):
        parse_cli_args(arguments)


def test_rejects_duplicate_input_paths(input_paths: dict[str, Path]) -> None:
    arguments = _arguments(input_paths)
    arguments[arguments.index("--manifest") + 1] = str(input_paths["run_metadata"])

    with pytest.raises(ValueError, match="distinct"):
        parse_cli_args(arguments)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--entity-id", " "),
        ("--decision-id", " D-001"),
        ("--decision-config-version", "parallel-v0.2 "),
    ],
)
def test_rejects_invalid_execution_identifiers(
    input_paths: dict[str, Path],
    option: str,
    value: str,
) -> None:
    arguments = _arguments(input_paths)
    arguments[arguments.index(option) + 1] = value

    with pytest.raises(ValueError, match="identifier"):
        parse_cli_args(arguments)
