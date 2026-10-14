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
        policy_version="fast-development-episodes-v2",
        purpose="development-only",
        inactivity_gap_sec=10,
        grouping="run_entity_alert_key",
        boundary="gap_greater_than_or_equal",
    )
    args["observation_start"] = datetime(2026, 10, 8, tzinfo=UTC)
    args["observation_end"] = datetime(2026, 10, 8, 0, 1, tzinfo=UTC)
    source = tmp_path / "source"
    source.write_bytes(b"synthetic raw")
    args["source_path"] = source
    trace = json.loads(args["trace_path"].read_text(encoding="utf-8"))

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
                    "-w",
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
    args["coverage_path"].write_text(json.dumps(coverage), encoding="utf-8")
    args["coverage_sha256"] = hashlib.sha256(args["coverage_path"].read_bytes()).hexdigest()


def test_gap_boundary_and_membership(tmp_path):
    # Given
    args, _ = setup(tmp_path)
    # When
    result, audit = build_development_episodes(**args)

    # Then
    assert [t.second for t in result.start_times] == [1, 15]
    assert [len(g["hit_ids"]) for g in audit["episodes"]] == [2, 1]
    assert audit["performance_eligible"] is False


def test_empty_full_scan(tmp_path):
    # Given
    args, _ = setup(tmp_path, ())
    # When
    result, _ = build_development_episodes(**args)

    # Then
    assert result.start_times == []


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
    # Given
    args, coverage = setup(tmp_path)
    coverage[field] = value
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


def test_reject_tampered_pin(tmp_path):
    # Given
    args, _ = setup(tmp_path)
    args["coverage_sha256"] = "0" * 64
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "coverage hash" in str(exc.value)


def test_reject_outside_observation(tmp_path):
    # Given
    args, coverage = setup(tmp_path)
    args["observation_end"] = args["observation_end"].replace(minute=0, second=10)
    coverage["observation_end"] = args["observation_end"].isoformat()
    meta_path = Path(coverage["metadata"]["path"])
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["end_time"] = coverage["observation_end"]
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    coverage["metadata"]["sha256"] = hashlib.sha256(meta_path.read_bytes()).hexdigest()
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "outside" in str(exc.value)


@pytest.mark.parametrize(
    "field", ["stdout", "stderr", "raw_jsonl", "metadata", "manifest", "diagnostic_execution"]
)
def test_evidence_tampering(tmp_path, field):
    # Given
    args, coverage = setup(tmp_path)
    Path(coverage[field]["path"]).write_bytes(b"tampered")
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "hash mismatch" in str(exc.value)


@pytest.mark.parametrize(
    "field,value", [("exit_code", 1), ("jsonl_count", 2), ("error_named_files", ["errors.log"])]
)
def test_rehashed_failed_scan(tmp_path, field, value):
    # Given
    args, coverage = setup(tmp_path)
    path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(path.read_text(encoding="utf-8"))
    execution[field] = value
    path.write_text(json.dumps(execution), encoding="utf-8")
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


def test_missing_coverage(tmp_path):
    # Given
    args, _ = setup(tmp_path)
    args["coverage_path"].unlink()
    # When
    with pytest.raises(FileNotFoundError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


@pytest.mark.parametrize("change", ["filter", "quiet", "missing_verbose", "wrong_source"])
def test_reject_unverified_command(tmp_path, change):
    # Given
    args, coverage = setup(tmp_path)
    path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(path.read_text(encoding="utf-8"))
    command = execution["command"]
    if change == "filter":
        command.extend(["--include-eid", "1"])
    elif change == "quiet":
        command.append("--quiet-errors")
    elif change == "missing_verbose":
        command.remove("--verbose")
    else:
        command[command.index("-f") + 1] = coverage["engine"]["path"]
    path.write_text(json.dumps(execution), encoding="utf-8")
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


@pytest.mark.parametrize(
    "output",
    [
        b"Events with hits / Total events: 1 / 2",
        b"Warning: corrupted chunk\nEvents with hits / Total events: 1 / 1",
    ],
)
def test_reject_bad_diagnostic_output_even_rehashed(tmp_path, output):
    # Given
    args, coverage = setup(tmp_path)
    path = Path(coverage["stdout"]["path"])
    path.write_bytes(output)
    coverage["stdout"]["sha256"] = hashlib.sha256(output).hexdigest()
    execution_path = Path(coverage["diagnostic_execution"]["path"])
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["stdout_sha256"] = coverage["stdout"]["sha256"]
    execution_path.write_text(json.dumps(execution), encoding="utf-8")
    coverage["diagnostic_execution"]["sha256"] = hashlib.sha256(
        execution_path.read_bytes()
    ).hexdigest()
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


def test_numeric_zero_is_not_a_reported_counter(tmp_path):
    # Given
    args, coverage = setup(tmp_path)
    coverage["parse_error_count"] = 0
    save(args, coverage)
    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


def rehash_artifact(coverage, field, payload):
    raw = json.dumps(payload).encode("utf-8")
    Path(coverage[field]["path"]).write_bytes(raw)
    coverage[field]["sha256"] = hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("field", ["hits_sha256", "input_csv_sha256", "trace_sha256"])
def test_grouping_rejects_different_selection_snapshot(tmp_path, monkeypatch, field):
    # Given
    import incident_awareness.detection.fast_episodes as module

    args, _ = setup(tmp_path)
    original = module.select_fast_hit

    def select_then_replace(**kwargs):
        result, audit = original(**kwargs)
        if field == "input_csv_sha256":
            original_read = module.read_fast_hit_handoff

            def replaced(*a, **kw):
                handoff = original_read(*a, **kw)
                handoff.trace.input_sha256 = "0" * 64
                return handoff

            monkeypatch.setattr(module, "read_fast_hit_handoff", replaced)
        else:
            audit[field] = "0" * 64
        return result, audit

    monkeypatch.setattr(module, "select_fast_hit", select_then_replace)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "handoff changed after selection" in str(exc.value)


@pytest.mark.parametrize("mixed", [False, True])
def test_inactivity_uses_previous_hit_per_alert_key(tmp_path, mixed):
    # Given
    from incident_awareness.detection.fast_runner import run_fast_handoff

    args, coverage = setup(tmp_path, (0, 9, 18))
    if mixed:
        trace = json.loads(args["trace_path"].read_text(encoding="utf-8"))
        csv = Path(trace["input_csv"])
        csv.write_text(
            csv.read_text(encoding="utf-8").replace("00:00:09.000Z,rule-a", "00:00:09.000Z,rule-b"),
            encoding="utf-8",
        )
        args["hits_path"].unlink()
        args["trace_path"].unlink()
        run_fast_handoff(
            csv_path=csv,
            config_path=Path(trace["config_path"]),
            run_id=args["run_id"],
            output_path=args["hits_path"],
            trace_path=args["trace_path"],
        )
        coverage["csv_sha256"] = hashlib.sha256(csv.read_bytes()).hexdigest()
        save(args, coverage)

    # When
    result, audit = build_development_episodes(**args)

    # Then
    assert [t.second for t in result.start_times] == ([0, 9, 18] if mixed else [0])
    assert [g["alert_key"] for g in audit["episodes"]] == (
        ["rule-a", "rule-b", "rule-a"] if mixed else ["rule-a"]
    )


@pytest.mark.parametrize(
    "change", ["mode", "wizard", "missing", "duplicate", "argument", "positional"]
)
def test_command_structure_is_rejected_after_rehash(tmp_path, change):
    # Given
    args, coverage = setup(tmp_path)
    execution = json.loads(Path(coverage["diagnostic_execution"]["path"]).read_bytes())
    command = execution["command"]
    if change == "mode":
        command[1] = "csv-timeline"
    elif change == "wizard":
        command.remove("-w")
    elif change == "missing":
        index = command.index("-f")
        del command[index : index + 2]
    elif change == "duplicate":
        command.extend(["-r", coverage["rule"]["path"]])
    elif change == "argument":
        command.pop(command.index("-o") + 1)
    else:
        command.append("unexpected")
    rehash_artifact(coverage, "diagnostic_execution", execution)
    save(args, coverage)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert str(exc.value)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("run_id", "other", "metadata identity"),
        ("target_host", "other", "metadata identity"),
        ("start_time", "2026-10-08T00:00:01Z", "metadata identity"),
        ("end_time", "2026-10-08T00:00:59Z", "metadata identity"),
    ],
)
def test_rehashed_metadata_binding(tmp_path, field, value, error):
    # Given
    args, coverage = setup(tmp_path)
    metadata = json.loads(Path(coverage["metadata"]["path"]).read_bytes())
    metadata[field] = value
    rehash_artifact(coverage, "metadata", metadata)
    save(args, coverage)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert error in str(exc.value)


@pytest.mark.parametrize("index", [0, 1])
def test_rehashed_manifest_binding(tmp_path, index):
    # Given
    args, coverage = setup(tmp_path)
    manifest = json.loads(Path(coverage["manifest"]["path"]).read_bytes())
    manifest["items"][index]["sha256"] = "0" * 64
    rehash_artifact(coverage, "manifest", manifest)
    save(args, coverage)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "manifest does not bind" in str(exc.value)


@pytest.mark.parametrize("change", ["csv", "stderr", "source_unchanged", "csv_byte_identical"])
def test_rehashed_scan_semantics(tmp_path, change):
    # Given
    args, coverage = setup(tmp_path)
    execution = json.loads(Path(coverage["diagnostic_execution"]["path"]).read_bytes())
    if change == "csv":
        execution["command"][execution["command"].index("-o") + 1] = coverage["rule"]["path"]
        error = "diagnostic CSV differs"
    elif change == "stderr":
        Path(coverage["stderr"]["path"]).write_bytes(b"problem")
        coverage["stderr"]["sha256"] = hashlib.sha256(b"problem").hexdigest()
        execution["stderr_sha256"] = coverage["stderr"]["sha256"]
        error = "stderr must be empty"
    else:
        execution[change] = False
        error = "successful scan"
    rehash_artifact(coverage, "diagnostic_execution", execution)
    save(args, coverage)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert error in str(exc.value)


def test_valid_replacement_handoff_after_selection_is_rejected(tmp_path, monkeypatch):
    # Given
    import incident_awareness.detection.fast_episodes as module

    args, _ = setup(tmp_path)
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir()
    replacement = prepare(replacement_dir, "2026-10-08T00:00:02.000Z,rule-a,HOST,1\n")
    original = module.select_fast_hit

    def select_then_replace(**kwargs):
        selection, audit = original(**kwargs)
        args["hits_path"].write_bytes(replacement["hits_path"].read_bytes())
        args["trace_path"].write_bytes(replacement["trace_path"].read_bytes())
        return selection, audit

    monkeypatch.setattr(module, "select_fast_hit", select_then_replace)

    # When
    with pytest.raises(ValueError) as exc:
        build_development_episodes(**args)

    # Then
    assert "handoff changed after selection" in str(exc.value)


def test_long_no_wizard_option_is_accepted(tmp_path):
    # Given
    args, coverage = setup(tmp_path)
    execution = json.loads(Path(coverage["diagnostic_execution"]["path"]).read_bytes())
    execution["command"][execution["command"].index("-w")] = "--no-wizard"
    rehash_artifact(coverage, "diagnostic_execution", execution)
    save(args, coverage)

    # When
    result, _ = build_development_episodes(**args)

    # Then
    assert len(result.start_times) == 2
