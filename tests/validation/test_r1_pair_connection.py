"""실행 기록 기반 audit selector와 실제 normalizer/extractor 연결 검증."""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "tools/validation/check_r1_pair_connection.py"
spec = importlib.util.spec_from_file_location("pair_check", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@pytest.fixture
def sample(tmp_path):
    run_id = "RUN-20261005-912"
    base = tmp_path / run_id / "data"
    operator = base / "operator_trace" / run_id
    operator.mkdir(parents=True)
    (operator / "scenario.json").write_text(
        json.dumps(
            {
                "family_id": "remote_management",
                "variation_id": "V02",
                "repetition": 1,
                "dataset_tier": "development",
                "run_metadata": {"target_host": "HOST"},
                "internal_connection": {
                    "target": "10.20.30.40",
                    "port": 23456,
                    "protocol": "TCP",
                    "lab_cidr": "10.20.30.0/24",
                },
            }
        )
    )
    raw = base / "raw" / run_id
    (raw / "telemetry").mkdir(parents=True)
    ground = base / "ground_truth" / run_id
    ground.mkdir(parents=True)
    (ground / "execution_record.csv").write_text(
        "run_id,action_id,timestamp\n"
        + "".join(
            f"{run_id},A{n},{t}Z\n"
            for n, t in [
                ("01", "2026-10-05T00:00:00"),
                ("03", "2026-10-05T00:05:00"),
                ("04", "2026-10-05T00:08:00"),
            ]
        )
    )
    rows = []
    for number, name, guid, parent, time, eid in [
        (1, "wsmprovhost.exe", "root", "outside", "00:00:00", 1),
        (2, "cscript.exe", "middle", "root", "00:04:59", 1),
        (3, "powershell.exe", "terminal", "middle", "00:05:02", 1),
        (4, "powershell.exe", "terminal", None, "00:08:02", 3),
    ]:
        data = {
            "UtcTime": f"2026-10-05 {time}.000",
            "Image": f"C:\\{name}",
            "ProcessGuid": guid,
            "ParentProcessGuid": parent,
        }
        if eid == 3:
            data.update(Protocol="tcp", DestinationIp="10.20.30.40", DestinationPort="23456")
        rows.append(
            {
                "RecordId": number,
                "EventId": eid,
                "TimeCreated": f"2026-10-05T{time}.007Z",
                "Computer": "HOST",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventData": data,
            }
        )
    source = raw / "telemetry/sysmon-0001.jsonl"

    def write():
        source.write_text("".join(json.dumps(row) + "\n" for row in rows))
        (raw / "manifest.json").write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "raw_log_id": "RAW-002",
                            "path": "sysmon-0001.jsonl",
                            "sha256": audit.sha(source),
                        }
                    ]
                }
            )
        )

    write()
    output = tmp_path / "output"
    output.mkdir()
    policy = audit.ApprovedLineagePolicy(
        "audit", "v0.1", "a" * 64, ("wsmprovhost.exe", "cmd.exe", "powershell.exe")
    )
    return tmp_path, run_id, output, policy, rows, write, source


def test_actual_pipeline_preserves_clocks_and_boundary_candidates(sample):
    pair, rid, output, policy, _rows, _write, _source = sample
    result = audit.check_run(pair, rid, "A", output, policy)
    assert result["normalized_count"] == 4
    assert result["network_record_id"] == "4"
    assert len(result["evidence_types"]) == 2
    assert result["diagnostics"] == []
    normalized = [
        json.loads(x) for x in (output / rid / "normalized_events.jsonl").read_text().splitlines()
    ]
    assert normalized[0]["timestamp"] != normalized[0]["record_time"]
    assert result["provenance"][0]["source_record_ids"] == ["1", "2", "3"]


def test_records_scenario_and_approved_policy_validation_provenance(sample):
    # Given
    pair, rid, output, _policy, _rows, _write, _source = sample
    policy = audit.load_r1_approved_lineage_policy(
        "r1-v02-development-connection",
        "v0.1",
    )

    # When
    result = audit.check_run(pair, rid, "A", output, policy)

    # Then
    assert policy.config_hash == (
        "59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78"
    )
    assert result["validation_provenance"] == {
        "scenario": {
            "family_id": "remote_management",
            "variation_id": "V02",
            "dataset_tier": "development",
        },
        "approved_policy": {
            "policy_id": "r1-v02-development-connection",
            "version": "v0.1",
            "config_hash": policy.config_hash,
        },
    }


def test_duplicate_terminal_rejected_instead_of_chosen(sample):
    pair, rid, output, policy, rows, write, _source = sample
    rows.append({**rows[2], "RecordId": 5})
    write()
    with pytest.raises(ValueError, match="t\\+5 terminal: expected one candidate, got 2"):
        audit.check_run(pair, rid, "A", output, policy)


def test_hash_mismatch_rejected_before_normalization(sample):
    pair, rid, output, policy, _rows, _write, source = sample
    source.write_text(source.read_text() + "\n")
    with pytest.raises(ValueError, match="JSONL hash mismatch"):
        audit.check_run(pair, rid, "A", output, policy)


def test_broken_lineage_rejected(sample):
    pair, rid, output, policy, rows, write, _source = sample
    rows[2]["EventData"]["ParentProcessGuid"] = "missing"
    write()
    with pytest.raises(ValueError, match="lineage parent: expected one candidate, got 0"):
        audit.check_run(pair, rid, "A", output, policy)


def test_extractor_reports_truncated_lineage_instead_of_empty_success(sample):
    from incident_awareness.common.models.event import NormalizedEvent
    from incident_awareness.pipeline.r1_evidence import (
        R1LineageInput,
        run_r1_evidence_pipeline_with_diagnostics,
    )

    pair, rid, output, policy, _rows, _write, _source = sample
    audit.check_run(pair, rid, "A", output, policy)
    events = [
        NormalizedEvent.model_validate_json(line)
        for line in (output / rid / "normalized_events.jsonl").read_text().splitlines()
    ]
    by_record = {e.source_event_id: e for e in events}
    result = run_r1_evidence_pipeline_with_diagnostics(
        [e for e in events if e.source_event_id != "2"],
        lineage_inputs=[R1LineageInput(by_record["1"].event_id, by_record["3"].event_id, policy)],
    )
    assert result.diagnostics == ("truncated_lineage",)
    assert all(
        e.evidence_type != "remote_session_process_lineage_deviation" for e in result.evidences
    )


@pytest.mark.parametrize("field,value", [("target", "10.20.30.41"), ("port", 23457)])
def test_external_destination_mismatch_rejected(sample, field, value):
    pair, rid, output, policy, _rows, _write, _source = sample
    path = pair / rid / "data/operator_trace" / rid / "scenario.json"
    scenario = json.loads(path.read_text())
    scenario["internal_connection"][field] = value
    path.write_text(json.dumps(scenario))
    with pytest.raises(ValueError, match="t\\+8 approved connection"):
        audit.check_run(pair, rid, "A", output, policy)


def test_external_host_mismatch_rejected(sample):
    pair, rid, output, policy, _rows, _write, _source = sample
    path = pair / rid / "data/operator_trace" / rid / "scenario.json"
    scenario = json.loads(path.read_text())
    scenario["run_metadata"]["target_host"] = "OTHER-HOST"
    path.write_text(json.dumps(scenario))
    with pytest.raises(ValueError, match="host"):
        audit.check_run(pair, rid, "A", output, policy)


def test_missing_external_scenario_rejected(sample):
    pair, rid, output, policy, _rows, _write, _source = sample
    (pair / rid / "data/operator_trace" / rid / "scenario.json").unlink()
    with pytest.raises(FileNotFoundError):
        audit.check_run(pair, rid, "A", output, policy)
