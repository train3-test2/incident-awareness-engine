import json
import shutil
from pathlib import Path

from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.runner import run_first_cycle_pipeline

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "pipeline" / "first_cycle"
FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")


class _Connection:
    def __init__(self) -> None:
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        return None

    def commit(self) -> None:
        self.commits += 1


def test_first_cycle_fixture_runs_through_the_assembled_pipeline(tmp_path: Path) -> None:
    fixture_root = tmp_path / "inputs"
    shutil.copytree(FIXTURE_ROOT, fixture_root)
    _rewrite_trace_paths_for_local_fixture(fixture_root)
    inputs = parse_cli_args(
        [
            "--run-metadata",
            str(fixture_root / "run_metadata.json"),
            "--manifest",
            str(fixture_root / "manifest.json"),
            "--sysmon-jsonl",
            str(fixture_root / "sysmon-0001.jsonl"),
            "--fast-hits",
            str(fixture_root / "fast" / "hits.jsonl"),
            "--fast-trace",
            str(fixture_root / "fast" / "trace.json"),
            "--fast-selection",
            str(fixture_root / "fast" / "selection.json"),
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--entity-id",
            "WIN-01",
            "--decision-id",
            "D-FIXTURE-001",
            "--decision-config-version",
            "parallel-v0.2",
        ]
    )
    connection = _Connection()

    summary = run_first_cycle_pipeline(inputs, connection=connection)

    assert summary.run_id == "RUN-20260920-001"
    assert summary.entity_id == "WIN-01"
    assert summary.normalized_event_count == 2
    assert summary.evidence_count == 2
    assert summary.fusion_status == "detected"
    assert summary.detector_status == "detected"
    assert summary.decision_path == "fast_and_fusion"
    assert connection.commits == 1


def _rewrite_trace_paths_for_local_fixture(fixture_root: Path) -> None:
    trace_path = fixture_root / "fast" / "trace.json"
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    trace["input_csv"] = str((fixture_root / "fast" / "handoff.csv").resolve())
    trace["config_path"] = str((fixture_root / "fast" / "config.json").resolve())
    trace_path.write_text(json.dumps(trace), encoding="utf-8")
