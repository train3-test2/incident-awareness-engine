import hashlib
import json

import pytest

from incident_awareness.detection.fast_runner import run_fast_handoff
from incident_awareness.detection.fast_selection import FastSelectionPolicy, main, select_fast_hit

RUN = "RUN-20261008-001"


def prepare(tmp_path, rows):
    config = {
        "detector_engine_version": "test-v1",
        "detector_config_version": "test-config",
        "qualifying_rule_ids": ["rule-a", "rule-b"],
        "rule_metadata": {r: {"rule_version": "v1", "alert_key": r} for r in ("rule-a", "rule-b")},
    }
    csv = tmp_path / "hits.csv"
    csv.write_text("Timestamp,RuleID,Computer,RecordID\n" + rows, encoding="utf-8")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")
    hits, trace = tmp_path / "hits.jsonl", tmp_path / "trace.json"
    run_fast_handoff(csv_path=csv, config_path=cfg, run_id=RUN, output_path=hits, trace_path=trace)
    policy = FastSelectionPolicy(
        policy_version="fast-selection-v1",
        detector_set_version="synthetic-set",
        detector_config_version="test-config",
        config_sha256=hashlib.sha256(cfg.read_bytes()).hexdigest(),
        timestamp_source="hayabusa_csv_timestamp",
        tie_break="timestamp_rule_id_hit_id",
        host_entity_map={"HOST": "entity", "OTHER": "other"},
    )
    return {
        "hits_path": hits,
        "trace_path": trace,
        "policy": policy,
        "run_id": RUN,
        "entity_id": "entity",
    }


def test_earliest_entity_hit_not_csv_first(tmp_path):
    args = prepare(
        tmp_path,
        "2026-10-08T00:00:02.000Z,rule-a,HOST,2\n"
        "2026-10-08T00:00:00.000Z,rule-a,OTHER,3\n"
        "2026-10-08T00:00:01.000Z,rule-b,HOST,1\n",
    )
    selection, audit = select_fast_hit(**args)
    assert selection.selected_hit_id == f"{RUN}-hit-3"
    assert audit["candidate_hit_ids"] == [f"{RUN}-hit-3", f"{RUN}-hit-1"]
    assert select_fast_hit(**args)[1] == audit


def test_tie_rule_then_hit_id(tmp_path):
    args = prepare(
        tmp_path,
        "2026-10-08T00:00:01.000Z,rule-b,HOST,1\n"
        "2026-10-08T00:00:01.000Z,rule-a,HOST,2\n"
        "2026-10-08T00:00:01.000Z,rule-a,HOST,3\n",
    )
    assert select_fast_hit(**args)[0].selected_hit_id == f"{RUN}-hit-2"


@pytest.mark.parametrize("rows", ["", "2026-10-08T00:00:01.000Z,rule-a,OTHER,1\n"])
def test_completed_miss(tmp_path, rows):
    selection, _ = select_fast_hit(**prepare(tmp_path, rows))
    assert selection.detector_status == "miss"
    assert selection.selected_hit_id is None


def test_unknown_host_is_error(tmp_path):
    args = prepare(tmp_path, "2026-10-08T00:00:01.000Z,rule-a,UNKNOWN,1\n")
    with pytest.raises(ValueError, match="mapping"):
        select_fast_hit(**args)


@pytest.mark.parametrize(
    "field,value", [("config_sha256", "0" * 64), ("detector_config_version", "other")]
)
def test_config_binding(tmp_path, field, value):
    args = prepare(tmp_path, "")
    args["policy"] = args["policy"].model_copy(update={field: value})
    with pytest.raises(ValueError, match="(hash|version)"):
        select_fast_hit(**args)


def test_rehashed_timestamp_tampering_rejected(tmp_path):
    args = prepare(tmp_path, "2026-10-08T00:00:01.000Z,rule-a,HOST,1\n")
    hit = json.loads(args["hits_path"].read_text())
    hit["timestamp"] = "2026-10-08T00:00:03.000Z"
    args["hits_path"].write_text(json.dumps(hit) + "\n")
    trace = json.loads(args["trace_path"].read_text())
    trace["output_sha256"] = hashlib.sha256(args["hits_path"].read_bytes()).hexdigest()
    args["trace_path"].write_text(json.dumps(trace))
    with pytest.raises(ValueError, match="source CSV"):
        select_fast_hit(**args)


def test_cli_and_overwrite(tmp_path, monkeypatch):
    args = prepare(tmp_path, "2026-10-08T00:00:01.000Z,rule-a,HOST,1\n")
    policy = tmp_path / "policy.json"
    policy.write_text(args["policy"].model_dump_json())
    output = tmp_path / "selected"
    monkeypatch.setattr(
        "sys.argv",
        [
            "fast_selection",
            "--hits",
            str(args["hits_path"]),
            "--trace",
            str(args["trace_path"]),
            "--policy",
            str(policy),
            "--run-id",
            RUN,
            "--entity-id",
            "entity",
            "--output-dir",
            str(output),
        ],
    )
    main()
    before = (output / "selection.json").read_bytes()
    assert json.loads(before)["selected_hit_id"] == f"{RUN}-hit-1"
    assert (output / "selection-audit.json").is_file()
    with pytest.raises(SystemExit):
        main()
    assert (output / "selection.json").read_bytes() == before


@pytest.mark.parametrize("change", ["config", "csv", "run", "entity"])
def test_invalid_context_rejected(tmp_path, change):
    args = prepare(tmp_path, "")
    if change in ("config", "csv"):
        path = tmp_path / ("config.json" if change == "config" else "hits.csv")
        path.write_text(path.read_text() + "\n")
    elif change == "run":
        args["run_id"] = "RUN-20261008-002"
    else:
        args["entity_id"] = "unknown"
    with pytest.raises(ValueError):
        select_fast_hit(**args)


@pytest.mark.parametrize("failure", ["write", "publish"])
def test_cli_failure_cleans_staging_and_allows_retry(tmp_path, monkeypatch, failure):
    # Given
    from pathlib import Path

    args = prepare(tmp_path, "2026-10-08T00:00:01.000Z,rule-a,HOST,1\n")
    policy = tmp_path / "policy.json"
    policy.write_text(args["policy"].model_dump_json(), encoding="utf-8")
    output = tmp_path / "selected"
    monkeypatch.setattr(
        "sys.argv",
        [
            "fast_selection",
            "--hits",
            str(args["hits_path"]),
            "--trace",
            str(args["trace_path"]),
            "--policy",
            str(policy),
            "--run-id",
            RUN,
            "--entity-id",
            "entity",
            "--output-dir",
            str(output),
        ],
    )
    original_write = Path.write_text

    def fail_write(path, *values, **kwargs):
        if path.name == "selection-audit.json":
            raise OSError("injected write failure")
        return original_write(path, *values, **kwargs)

    def fail_publish(path, target):
        raise OSError("injected publish failure")

    # When
    with monkeypatch.context() as patch:
        if failure == "write":
            patch.setattr(Path, "write_text", fail_write)
        else:
            patch.setattr(Path, "rename", fail_publish)
        with pytest.raises(SystemExit) as error:
            main()
    output_exists_after_failure = output.exists()
    staging_after_failure = list(tmp_path.glob(".selected-*"))
    main()
    selection = json.loads((output / "selection.json").read_text(encoding="utf-8"))
    audit = json.loads((output / "selection-audit.json").read_text(encoding="utf-8"))

    # Then
    assert error.value.code == 2
    assert not output_exists_after_failure
    assert staging_after_failure == []
    assert selection == audit["selection"]
    assert list(tmp_path.glob(".selected-*")) == []


def test_cli_preserves_existing_empty_directory(tmp_path, monkeypatch):
    # Given
    args = prepare(tmp_path, "")
    policy = tmp_path / "policy.json"
    policy.write_text(args["policy"].model_dump_json(), encoding="utf-8")
    output = tmp_path / "selected"
    output.mkdir()
    monkeypatch.setattr(
        "sys.argv",
        [
            "fast_selection",
            "--hits",
            str(args["hits_path"]),
            "--trace",
            str(args["trace_path"]),
            "--policy",
            str(policy),
            "--run-id",
            RUN,
            "--entity-id",
            "entity",
            "--output-dir",
            str(output),
        ],
    )

    # When
    with pytest.raises(SystemExit) as error:
        main()
    contents = list(output.iterdir())

    # Then
    assert error.value.code == 2
    assert output.is_dir()
    assert contents == []
    assert list(tmp_path.glob(".selected-*")) == []
