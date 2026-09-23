import hashlib
import json
from pathlib import Path

import pytest

from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts

RUN_ID = "RUN-20260920-001"
SCHEMA_VERSIONS = {
    "run_metadata": "v0.2",
    "event": "v0.2",
    "evidence": "v0.2",
    "fast_hit": "v0.2",
    "detection_result": "v0.2",
    "fusion_result": "v0.3",
    "decision_result": "v0.2",
    "execution_record": "v0.1",
    "evaluation_input": "v0.1",
}


@pytest.fixture
def inputs(tmp_path: Path) -> PipelineInputs:
    telemetry_dir = tmp_path / "raw" / RUN_ID / "telemetry"
    telemetry_dir.mkdir(parents=True)
    ground_truth_dir = tmp_path / "ground_truth" / RUN_ID
    ground_truth_dir.mkdir(parents=True)

    sysmon_jsonl_path = telemetry_dir / "sysmon-0001.jsonl"
    sysmon_jsonl_path.write_text(
        json.dumps({"RecordId": 1, "EventId": 1, "EventData": {}}) + "\n",
        encoding="utf-8",
    )
    evtx_path = telemetry_dir / "sysmon-0001.evtx"
    evtx_path.write_bytes(b"evtx")

    run_metadata_path = ground_truth_dir / "run_metadata.json"
    run_metadata_path.write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": "WIN-01",
                "start_time": "2026-09-20T00:00:00.000Z",
                "end_time": "2026-09-20T00:01:00.000Z",
                "schema_versions": SCHEMA_VERSIONS,
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "raw" / RUN_ID / "manifest.json"
    _write_manifest(manifest_path, sysmon_jsonl_path, evtx_path)

    fast_hits_path = tmp_path / "fast-hits.jsonl"
    fast_trace_path = tmp_path / "fast-trace.json"
    fast_selection_path = tmp_path / "fast-selection.json"
    fusion_config_path = tmp_path / "fusion.yaml"
    for path in (fast_hits_path, fast_trace_path, fast_selection_path, fusion_config_path):
        path.write_text("{}", encoding="utf-8")

    return PipelineInputs(
        run_metadata_path=run_metadata_path,
        manifest_path=manifest_path,
        sysmon_jsonl_path=sysmon_jsonl_path,
        fast_hits_path=fast_hits_path,
        fast_trace_path=fast_trace_path,
        fast_selection_path=fast_selection_path,
        fusion_config_path=fusion_config_path,
        entity_id="WIN-01",
        decision_id="D-001",
        decision_config_version="parallel-v0.2",
    )


def _write_manifest(manifest_path: Path, jsonl_path: Path, evtx_path: Path) -> None:
    telemetry_path = f"C:\\S0\\data\\raw\\{RUN_ID}\\telemetry"
    manifest_path.write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "items": [
                    {
                        "raw_log_id": "RAW-001",
                        "path": f"{telemetry_path}\\sysmon-0001.evtx",
                        "sha256": hashlib.sha256(evtx_path.read_bytes()).hexdigest(),
                        "layer": "raw_telemetry",
                        "source": "sysmon",
                    },
                    {
                        "raw_log_id": "RAW-002",
                        "path": f"{telemetry_path}\\sysmon-0001.jsonl",
                        "sha256": hashlib.sha256(jsonl_path.read_bytes()).hexdigest(),
                        "layer": "raw_telemetry",
                        "source": "sysmon",
                        "derived_from": f"{telemetry_path}\\sysmon-0001.evtx",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _read_manifest(inputs: PipelineInputs) -> dict[str, object]:
    return json.loads(inputs.manifest_path.read_text(encoding="utf-8"))


def _write_manifest_data(inputs: PipelineInputs, manifest: dict[str, object]) -> None:
    inputs.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_loads_s0_artifacts_with_manifest_bound_provenance(inputs: PipelineInputs) -> None:
    artifacts = load_s0_pipeline_artifacts(inputs)

    assert artifacts.run_metadata.run_id == RUN_ID
    assert artifacts.run_metadata.schema_versions.fusion_result == "v0.3"
    assert artifacts.normalization_context.run_id == RUN_ID
    assert artifacts.normalization_context.raw_log_id == "RAW-002"
    assert artifacts.normalization_context.segment_no == 1
    assert [record.record_no for record in artifacts.sysmon_records] == [1]


def test_rejects_manifest_with_a_different_run_id(inputs: PipelineInputs) -> None:
    manifest = _read_manifest(inputs)
    manifest["run_id"] = "RUN-20260920-002"
    _write_manifest_data(inputs, manifest)

    with pytest.raises(ValueError, match="run_id"):
        load_s0_pipeline_artifacts(inputs)


def test_rejects_sysmon_jsonl_that_does_not_match_manifest_hash(inputs: PipelineInputs) -> None:
    inputs.sysmon_jsonl_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        load_s0_pipeline_artifacts(inputs)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_log_id", " "),
        ("layer", "detector_output"),
        ("source", "other"),
    ],
)
def test_rejects_invalid_sysmon_raw_log_provenance(
    inputs: PipelineInputs,
    field: str,
    value: str,
) -> None:
    manifest = _read_manifest(inputs)
    items = manifest["items"]
    assert isinstance(items, list)
    items[1][field] = value
    _write_manifest_data(inputs, manifest)

    with pytest.raises(ValueError, match="Sysmon JSONL manifest item"):
        load_s0_pipeline_artifacts(inputs)


def test_rejects_unreadable_sysmon_jsonl(inputs: PipelineInputs) -> None:
    inputs.sysmon_jsonl_path.write_text("not-json\n", encoding="utf-8")
    manifest = _read_manifest(inputs)
    items = manifest["items"]
    assert isinstance(items, list)
    items[1]["sha256"] = hashlib.sha256(inputs.sysmon_jsonl_path.read_bytes()).hexdigest()
    _write_manifest_data(inputs, manifest)

    with pytest.raises(ValueError, match="not readable"):
        load_s0_pipeline_artifacts(inputs)


@pytest.mark.parametrize("invalid_item", ["not-an-object", 1, None])
def test_rejects_non_object_manifest_items(
    inputs: PipelineInputs,
    invalid_item: object,
) -> None:
    manifest = _read_manifest(inputs)
    items = manifest["items"]
    assert isinstance(items, list)
    items.append(invalid_item)
    _write_manifest_data(inputs, manifest)

    with pytest.raises(TypeError, match="must be a JSON object"):
        load_s0_pipeline_artifacts(inputs)


def test_rejects_derived_from_that_matches_only_an_evtx_filename(inputs: PipelineInputs) -> None:
    manifest = _read_manifest(inputs)
    items = manifest["items"]
    assert isinstance(items, list)
    items[0]["path"] = f"D:\\copied\\raw\\{RUN_ID}\\telemetry\\sysmon-0001.evtx"
    _write_manifest_data(inputs, manifest)

    with pytest.raises(ValueError, match="exactly one EVTX"):
        load_s0_pipeline_artifacts(inputs)


def test_rejects_derived_from_with_multiple_matching_evtx_items(inputs: PipelineInputs) -> None:
    manifest = _read_manifest(inputs)
    items = manifest["items"]
    assert isinstance(items, list)
    items.append(items[0].copy())
    _write_manifest_data(inputs, manifest)

    with pytest.raises(ValueError, match="exactly one EVTX"):
        load_s0_pipeline_artifacts(inputs)
