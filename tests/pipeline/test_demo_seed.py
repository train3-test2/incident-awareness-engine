import hashlib
import json
from pathlib import Path

import pytest

from incident_awareness.integration.fast_hit_handoff import read_fast_hit_handoff
from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.demo_seed import materialize_first_cycle_demo_seed
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts

SEED_ROOT = Path(__file__).parents[1] / "fixtures" / "pipeline" / "first_cycle"
FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")


def test_materializes_a_self_consistent_first_cycle_input_set(tmp_path: Path) -> None:
    destination = tmp_path / "demo-inputs"

    result = materialize_first_cycle_demo_seed(
        seed_root=SEED_ROOT,
        destination=destination,
        run_id="RUN-20261002-001",
    )

    assert result.destination == destination.resolve()
    metadata = json.loads((destination / "run_metadata.json").read_text(encoding="utf-8"))
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    hit = json.loads((destination / "fast" / "hits.jsonl").read_text(encoding="utf-8"))
    trace = json.loads((destination / "fast" / "trace.json").read_text(encoding="utf-8"))
    selection = json.loads((destination / "fast" / "selection.json").read_text(encoding="utf-8"))
    sysmon = (destination / "sysmon-0001.jsonl").read_text(encoding="utf-8")

    assert metadata["run_id"] == "RUN-20261002-001"
    assert metadata["start_time"] == "2026-10-02T00:00:00.000Z"
    assert manifest["run_id"] == "RUN-20261002-001"
    assert "RUN-20261002-001" in manifest["items"][1]["path"]
    assert manifest["items"][1]["sha256"] == _sha256(destination / "sysmon-0001.jsonl")
    assert "2026-10-02T00:00:00.000Z" in sysmon
    assert "2026-10-02 00:00:10.000" in sysmon
    assert hit["run_id"] == "RUN-20261002-001"
    assert hit["hit_id"] == "RUN-20261002-001-hit-1"
    assert hit["timestamp"] == "2026-10-02T00:00:05.000Z"
    assert selection["selected_hit_id"] == hit["hit_id"]
    assert trace["run_id"] == "RUN-20261002-001"
    assert trace["output_sha256"] == _sha256(destination / "fast" / "hits.jsonl")
    assert trace["input_sha256"] == _sha256(destination / "fast" / "handoff.csv")
    assert trace["hits"][0]["hit_id"] == hit["hit_id"]

    inputs = _pipeline_inputs(destination)
    artifacts = load_s0_pipeline_artifacts(inputs)
    _rewrite_trace_paths_for_local_validation(destination)
    handoff = read_fast_hit_handoff(
        destination / "fast" / "hits.jsonl",
        destination / "fast" / "trace.json",
        run_id=artifacts.run_metadata.run_id,
    )

    assert len(artifacts.sysmon_records) == 2
    assert handoff.trace.run_id == "RUN-20261002-001"


def test_rejects_an_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "demo-inputs"
    destination.mkdir()

    with pytest.raises(FileExistsError, match="already exists"):
        materialize_first_cycle_demo_seed(
            seed_root=SEED_ROOT,
            destination=destination,
            run_id="RUN-20261002-001",
        )


def _pipeline_inputs(destination: Path):
    return parse_cli_args(
        [
            "--run-metadata",
            str(destination / "run_metadata.json"),
            "--manifest",
            str(destination / "manifest.json"),
            "--sysmon-jsonl",
            str(destination / "sysmon-0001.jsonl"),
            "--fast-hits",
            str(destination / "fast" / "hits.jsonl"),
            "--fast-trace",
            str(destination / "fast" / "trace.json"),
            "--fast-selection",
            str(destination / "fast" / "selection.json"),
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--entity-id",
            "WIN-01",
            "--decision-id",
            "DEC-RUN-20261002-001",
            "--decision-config-version",
            "parallel-v0.2",
        ]
    )


def _rewrite_trace_paths_for_local_validation(destination: Path) -> None:
    trace_path = destination / "fast" / "trace.json"
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["input_csv"] = str((destination / "fast" / "handoff.csv").resolve())
    trace["config_path"] = str((destination / "fast" / "config.json").resolve())
    trace_path.write_text(json.dumps(trace), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
