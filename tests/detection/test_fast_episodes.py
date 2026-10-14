import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_fast_selection import prepare

from incident_awareness.detection.fast_episodes import (
    DevelopmentEpisodePolicy,
    build_development_episodes,
)


def setup(tmp_path, seconds=(1, 5, 15)):
    args = prepare(
        tmp_path,
        "".join(f"2026-10-08T00:00:{s:02d}.000Z,rule-a,HOST,{i}\n" for i, s in enumerate(seconds)),
    )
    args["selection_policy"] = args.pop("policy")
    args["episode_policy"] = DevelopmentEpisodePolicy(
        policy_version="fast-development-episodes-v1",
        purpose="development-only",
        inactivity_gap_sec=10,
        grouping="run_entity_all_qualifying_rules",
        boundary="gap_greater_than_or_equal",
    )
    args["observation_start"] = datetime(2026, 10, 8, tzinfo=UTC)
    args["observation_end"] = datetime(2026, 10, 8, 0, 1, tzinfo=UTC)
    source = tmp_path / "source"
    source.write_bytes(b"synthetic raw")
    args["source_path"] = source
    trace = json.loads(args["trace_path"].read_text())

    def artifact(name, data):
        path = tmp_path / name
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}

    stdout = artifact("stdout", b"Events with hits / Total events: 1 / 1")
    stderr = artifact("stderr", b"")
    raw_jsonl = artifact("raw.jsonl", b'{"EventId":1}\n')
    engine = artifact("engine", b"synthetic engine")
    rule = artifact("rule", b"synthetic rule")
    metadata = artifact(
        "metadata",
        json.dumps(
            {
                "run_id": args["run_id"],
                "target_host": args["entity_id"],
                "start_time": args["observation_start"].isoformat(),
                "end_time": args["observation_end"].isoformat(),
            }
        ).encode(),
    )
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest = artifact(
        "manifest",
        json.dumps(
            {
                "run_id": args["run_id"],
                "items": [
                    {"sha256": source_hash},
                    {"sha256": raw_jsonl["sha256"]},
                ],
            }
        ).encode(),
    )
    execution = artifact(
        "execution",
        json.dumps(
            {
                "run_id": args["run_id"],
                "exit_code": 0,
                "source_sha256": source_hash,
                "engine_sha256": engine["sha256"],
                "rule_sha256": rule["sha256"],
                "stdout_sha256": stdout["sha256"],
                "stderr_sha256": stderr["sha256"],
                "source_unchanged": True,
                "csv_byte_identical": True,
                "error_named_files": [],
                "jsonl_count": 1,
                "command": [
                    engine["path"],
                    "dfir-timeline",
                    "-f",
                    str(source),
                    "-r",
                    rule["path"],
                    "-o",
                    trace["input_csv"],
                    "--verbose",
                    "--validate-checksums",
                ],
            }
        ).encode(),
    )
    coverage = {
        "contract_version": "fast-development-coverage-v2",
        "purpose": "development-interface-only",
        "run_id": args["run_id"],
        "entity_id": args["entity_id"],
        "observation_start": args["observation_start"].isoformat(),
        "observation_end": args["observation_end"].isoformat(),
        "source_sha256": source_hash,
        "csv_sha256": trace["input_sha256"],
        "config_sha256": trace["config_sha256"],
        "collection_basis": "declared-export-window-and-validator",
        "collection_evidence": [artifact("validator", b"synthetic validation")],
        "parse_error_count": None,
        "diagnostic_execution": execution,
        "stdout": stdout,
        "stderr": stderr,
        "raw_jsonl": raw_jsonl,
        "engine": engine,
        "rule": rule,
        "metadata": metadata,
        "manifest": manifest,
    }
    args["coverage_path"] = tmp_path / "coverage.json"
    save(args, coverage)
    return args, coverage


def save(args, coverage):
    args["coverage_path"].write_text(json.dumps(coverage))
    args["coverage_sha256"] = hashlib.sha256(args["coverage_path"].read_bytes()).hexdigest()


def test_gap_boundary_and_membership(tmp_path):
    args, _ = setup(tmp_path)
    result, audit = build_development_episodes(**args)
    assert [t.second for t in result.start_times] == [1, 15]
    assert [len(g["hit_ids"]) for g in audit["episodes"]] == [2, 1]
    assert audit["performance_eligible"] is False


def test_empty_full_scan(tmp_path):
    args, _ = setup(tmp_path, ())
    assert build_development_episodes(**args)[0].start_times == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "performance"),
        ("collection_evidence", []),
        ("parse_error_count", 1),
        ("contract_version", "legacy"),
        ("run_id", "other"),
        ("entity_id", "other"),
        ("source_sha256", "0" * 64),
        ("csv_sha256", "0" * 64),
        ("config_sha256", "0" * 64),
        ("observation_end", "2026-10-08T00:00:30Z"),
    ],
)
def test_reject_incomplete_or_mismatched_coverage(tmp_path, field, value):
    args, coverage = setup(tmp_path)
    coverage[field] = value
    save(args, coverage)
    with pytest.raises(ValueError):
        build_development_episodes(**args)


def test_reject_tampered_pin(tmp_path):
    args, _ = setup(tmp_path)
    args["coverage_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="coverage hash"):
        build_development_episodes(**args)


def test_reject_outside_observation(tmp_path):
    args, coverage = setup(tmp_path)
    args["observation_end"] = args["observation_end"].replace(minute=0, second=10)
    coverage["observation_end"] = args["observation_end"].isoformat()
    meta_path = Path(coverage["metadata"]["path"])
    meta = json.loads(meta_path.read_text())
    meta["end_time"] = coverage["observation_end"]
    meta_path.write_text(json.dumps(meta))
    coverage["metadata"]["sha256"] = hashlib.sha256(meta_path.read_bytes()).hexdigest()
    save(args, coverage)
    with pytest.raises(ValueError, match="outside"):
        build_development_episodes(**args)


@pytest.mark.parametrize(
    "field", ["stdout", "stderr", "raw_jsonl", "metadata", "manifest", "diagnostic_execution"]
)
def test_evidence_tampering(tmp_path, field):
    args, coverage = setup(tmp_path)
    Path(coverage[field]["path"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="hash mismatch"):
        build_development_episodes(**args)


@pytest.mark.parametrize(
    "field,value", [("exit_code", 1), ("jsonl_count", 2), ("error_named_files", ["errors.log"])]
)
def test_rehashed_failed_scan(tmp_path, field, value):
    args, coverage = setup(tmp_path)
    path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(path.read_text())
    execution[field] = value
    path.write_text(json.dumps(execution))
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(args, coverage)
    with pytest.raises(ValueError):
        build_development_episodes(**args)


def test_missing_coverage(tmp_path):
    args, _ = setup(tmp_path)
    args["coverage_path"].unlink()
    with pytest.raises(FileNotFoundError):
        build_development_episodes(**args)


@pytest.mark.parametrize("change", ["filter", "quiet", "missing_verbose", "wrong_source"])
def test_reject_unverified_command(tmp_path, change):
    args, coverage = setup(tmp_path)
    path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(path.read_text())
    command = execution["command"]
    if change == "filter":
        command.extend(["--include-eid", "1"])
    elif change == "quiet":
        command.append("--quiet-errors")
    elif change == "missing_verbose":
        command.remove("--verbose")
    else:
        command[command.index("-f") + 1] = coverage["engine"]["path"]
    path.write_text(json.dumps(execution))
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(args, coverage)
    with pytest.raises(ValueError):
        build_development_episodes(**args)


@pytest.mark.parametrize(
    "output",
    [
        b"Events with hits / Total events: 1 / 2",
        b"Warning: corrupted chunk\nEvents with hits / Total events: 1 / 1",
    ],
)
def test_reject_bad_diagnostic_output_even_rehashed(tmp_path, output):
    args, coverage = setup(tmp_path)
    path = Path(coverage["stdout"]["path"])
    path.write_bytes(output)
    coverage["stdout"]["sha256"] = hashlib.sha256(output).hexdigest()
    execution_path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(execution_path.read_text())
    execution["stdout_sha256"] = coverage["stdout"]["sha256"]
    execution_path.write_text(json.dumps(execution))
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(
        execution_path.read_bytes()
    ).hexdigest()
    save(args, coverage)
    with pytest.raises(ValueError):
        build_development_episodes(**args)


def test_numeric_zero_is_not_a_reported_counter(tmp_path):
    args, coverage = setup(tmp_path)
    coverage["parse_error_count"] = 0
    save(args, coverage)
    with pytest.raises(ValueError):
        build_development_episodes(**args)
