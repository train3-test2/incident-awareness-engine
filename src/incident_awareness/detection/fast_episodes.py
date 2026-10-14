"""Development-only episode grouping over a verified, fully scanned handoff."""

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.detection.fast_selection import FastSelectionPolicy, select_fast_hit
from incident_awareness.evaluation.result_inputs import FastEpisodeStarts
from incident_awareness.integration.fast_hit_handoff import read_fast_hit_handoff


class DevelopmentEpisodePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_version: Literal["fast-development-episodes-v1"]
    purpose: Literal["development-only"]
    # Sessionization: a gap >= this value opens another episode.
    inactivity_gap_sec: int = Field(strict=True, gt=0)
    grouping: Literal["run_entity_all_qualifying_rules"]
    boundary: Literal["gap_greater_than_or_equal"]


class FastScanCoverage(BaseModel):
    """Producer attestation, pinned by the caller; not inferred from empty CSV."""

    model_config = ConfigDict(extra="forbid")
    run_id: str
    entity_id: str
    observation_start: datetime
    observation_end: datetime
    source_sha256: str
    csv_sha256: str
    config_sha256: str
    collection_complete: Literal[True]
    scan_complete: Literal[True]
    parse_error_count: Literal[0]
    exit_code: Literal[0]
    producer_record: str = Field(min_length=1)


def build_development_episodes(
    *,
    hits_path: Path,
    trace_path: Path,
    selection_policy: FastSelectionPolicy,
    episode_policy: DevelopmentEpisodePolicy,
    coverage_path: Path,
    coverage_sha256: str,
    source_path: Path,
    run_id: str,
    entity_id: str,
    observation_start: datetime,
    observation_end: datetime,
) -> tuple[FastEpisodeStarts, dict]:
    """Return upstream evaluation input plus membership provenance, never metrics.

    Caller must obtain the coverage pin from a trusted producer record. A hash
    detects mutation, but does not authenticate the producer's completeness claim.
    """
    episode_policy = DevelopmentEpisodePolicy.model_validate(episode_policy.model_dump())
    selection_policy = FastSelectionPolicy.model_validate(selection_policy.model_dump())
    raw = coverage_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != coverage_sha256:
        raise ValueError("coverage hash mismatch")
    coverage = FastScanCoverage.model_validate_json(raw)
    for value in (
        observation_start,
        observation_end,
        coverage.observation_start,
        coverage.observation_end,
    ):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("observation timestamps must be UTC aware")
        if value.microsecond % 1000:
            raise ValueError("observation timestamps must have millisecond precision")
    if observation_start >= observation_end:
        raise ValueError("observation interval must be positive")
    if (
        coverage.run_id,
        coverage.entity_id,
        coverage.observation_start,
        coverage.observation_end,
    ) != (run_id, entity_id, observation_start, observation_end):
        raise ValueError("coverage identity or observation interval mismatch")
    if hashlib.sha256(source_path.read_bytes()).hexdigest() != coverage.source_sha256:
        raise ValueError("source hash mismatch")
    selection, audit = select_fast_hit(
        hits_path=hits_path,
        trace_path=trace_path,
        policy=selection_policy,
        run_id=run_id,
        entity_id=entity_id,
    )
    if (
        coverage.csv_sha256 != audit["input_csv_sha256"]
        or coverage.config_sha256 != selection_policy.config_sha256
    ):
        raise ValueError("coverage CSV/config binding mismatch")
    handoff = read_fast_hit_handoff(hits_path, trace_path, run_id=run_id)
    records = sorted(
        (
            h
            for h in handoff.records
            if selection_policy.host_entity_map[h.native_host_id] == entity_id
        ),
        key=lambda h: (h.timestamp, h.rule_id, h.hit_id),
    )
    if len({h.hit_id for h in records}) != len(records):
        raise ValueError("duplicate hit identity")
    groups = []
    previous = None
    for hit in records:
        if not observation_start <= hit.timestamp <= observation_end:
            raise ValueError("hit outside observation interval")
        if previous is None or hit.timestamp - previous >= timedelta(
            seconds=episode_policy.inactivity_gap_sec
        ):
            groups.append({"start_time": hit.timestamp, "hit_ids": []})
        groups[-1]["hit_ids"].append(hit.hit_id)
        previous = hit.timestamp
    result = FastEpisodeStarts(
        run_id=run_id,
        entity_id=entity_id,
        policy_version=f"{episode_policy.policy_version}-gap{episode_policy.inactivity_gap_sec}s",
        detector_set_version=selection_policy.detector_set_version,
        observation_start=observation_start,
        observation_end=observation_end,
        start_times=[g["start_time"] for g in groups],
    )
    return result, {
        "purpose": "development-only",
        "performance_eligible": False,
        "episode_policy": episode_policy.model_dump(mode="json"),
        "coverage_sha256": coverage_sha256,
        "selection_audit": audit,
        "selection": selection.model_dump(mode="json"),
        "episodes": groups,
    }
