import hashlib
import json
from datetime import UTC, datetime

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
    coverage = {
        "run_id": args["run_id"],
        "entity_id": args["entity_id"],
        "observation_start": args["observation_start"].isoformat(),
        "observation_end": args["observation_end"].isoformat(),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "csv_sha256": trace["input_sha256"],
        "config_sha256": trace["config_sha256"],
        "collection_complete": True,
        "scan_complete": True,
        "parse_error_count": 0,
        "exit_code": 0,
        "producer_record": "synthetic verification",
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
        ("collection_complete", False),
        ("scan_complete", False),
        ("parse_error_count", 1),
        ("exit_code", 1),
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
    save(args, coverage)
    with pytest.raises(ValueError, match="outside"):
        build_development_episodes(**args)
