"""Development-only episode grouping over a verified, fully scanned handoff."""

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.detection.fast_selection import FastSelectionPolicy, select_fast_hit
from incident_awareness.evaluation.result_inputs import FastEpisodeStarts
from incident_awareness.integration.fast_hit_handoff import read_fast_hit_handoff


class DevelopmentEpisodePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_version: Literal["fast-development-episodes-v2"]
    purpose: Literal["development-only"]
    # Sessionization: a gap >= this value opens another episode.
    inactivity_gap_sec: int = Field(strict=True, gt=0)
    grouping: Literal["run_entity_alert_key"]
    boundary: Literal["gap_greater_than_or_equal"]


class CoverageArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def read_verified(self) -> bytes:
        raw = Path(self.path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != self.sha256:
            raise ValueError("coverage evidence hash mismatch")
        return raw


class FastScanCoverage(BaseModel):
    """Bounded offline-export evidence, never a claim of lossless collection."""

    model_config = ConfigDict(extra="forbid")
    contract_version: Literal["fast-development-coverage-v2"]
    purpose: Literal["development-interface-only"]
    run_id: str
    entity_id: str
    observation_start: datetime
    observation_end: datetime
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    csv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_basis: Literal["declared-export-window-and-validator"]
    collection_evidence: list[CoverageArtifact] = Field(min_length=1)
    # Numeric parser errors are not reported by Hayabusa; no fabricated zero.
    parse_error_count: None
    diagnostic_execution: CoverageArtifact
    stdout: CoverageArtifact
    stderr: CoverageArtifact
    raw_jsonl: CoverageArtifact
    manifest: CoverageArtifact
    metadata: CoverageArtifact
    engine: CoverageArtifact
    rule: CoverageArtifact

    def verify_scan(self) -> dict:
        for artifact in self.collection_evidence:
            artifact.read_verified()
        manifest = json.loads(self.manifest.read_verified().decode("utf-8-sig"))
        metadata = json.loads(self.metadata.read_verified().decode("utf-8-sig"))
        if (
            manifest["run_id"] != self.run_id
            or metadata["run_id"] != self.run_id
            or metadata["target_host"] != self.entity_id
            or datetime.fromisoformat(metadata["start_time"]) != self.observation_start
            or datetime.fromisoformat(metadata["end_time"]) != self.observation_end
        ):
            raise ValueError("collection metadata identity or interval mismatch")
        hashes = {item["sha256"].lower() for item in manifest["items"]}
        if self.source_sha256 not in hashes or self.raw_jsonl.sha256 not in hashes:
            raise ValueError("manifest does not bind scan source and JSONL")
        execution = json.loads(self.diagnostic_execution.read_verified())
        stdout_bytes = self.stdout.read_verified()
        stderr_bytes = self.stderr.read_verified()
        self.engine.read_verified()
        self.rule.read_verified()
        raw_records = [
            json.loads(line)
            for line in self.raw_jsonl.read_verified().decode("utf-8-sig").splitlines()
            if line.strip()
        ]
        if not raw_records:
            raise ValueError("empty raw export cannot establish scan coverage")
        if (
            execution["run_id"] != self.run_id
            or execution["exit_code"] != 0
            or execution["source_sha256"] != self.source_sha256
            or execution["engine_sha256"] != self.engine.sha256
            or execution["rule_sha256"] != self.rule.sha256
            or execution["stdout_sha256"] != self.stdout.sha256
            or execution["stderr_sha256"] != self.stderr.sha256
            or execution["source_unchanged"] is not True
            or execution["csv_byte_identical"] is not True
            or execution["error_named_files"] != []
        ):
            raise ValueError("diagnostic execution does not bind a successful scan")
        if stderr_bytes:
            raise ValueError("diagnostic stderr must be empty")
        command = execution["command"]
        if (
            not isinstance(command, list)
            or len(command) < 2
            or not all(isinstance(arg, str) and arg for arg in command)
            or command[1] != "dfir-timeline"
        ):
            raise ValueError("unsupported diagnostic subcommand")
        switches = {"-w", "--no-wizard", "-O", "-t", "-K", "--verbose", "--validate-checksums"}
        paths = {}
        seen = set()
        index = 2
        while index < len(command):
            flag = command[index]
            canonical = "-w" if flag == "--no-wizard" else flag
            if canonical in seen:
                raise ValueError("duplicate diagnostic option")
            seen.add(canonical)
            if flag in {"-f", "-r", "-o"}:
                if index + 1 >= len(command) or command[index + 1].startswith("-"):
                    raise ValueError("missing diagnostic option argument")
                paths[flag] = command[index + 1]
                index += 2
            elif flag in switches:
                index += 1
            else:
                raise ValueError("filtered or unsupported diagnostic scan")
        if not {"-f", "-r", "-o", "-w", "--verbose", "--validate-checksums"} <= seen:
            raise ValueError("required scan diagnostics or paths not enabled")
        if (
            hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() != self.engine.sha256
            or hashlib.sha256(Path(paths["-r"]).read_bytes()).hexdigest() != self.rule.sha256
        ):
            raise ValueError("diagnostic engine/rule mismatch")
        if hashlib.sha256(Path(paths["-f"]).read_bytes()).hexdigest() != self.source_sha256:
            raise ValueError("diagnostic command source mismatch")
        if hashlib.sha256(Path(paths["-o"]).read_bytes()).hexdigest() != self.csv_sha256:
            raise ValueError("diagnostic CSV differs from bound handoff")
        stdout = re.sub(r"\x1b\[[0-9;]*m", "", stdout_bytes.decode("utf-8"))
        if re.search(r"(?i)\b(error|failed|warning)\b", stdout):
            raise ValueError("diagnostic stdout reports a problem")
        counts = re.findall(
            r"Events with hits\s*/\s*Total events:\s*([\d,]+)\s*/\s*([\d,]+)", stdout
        )
        if len(counts) != 1 or int(counts[0][1].replace(",", "")) != len(raw_records):
            raise ValueError("scan count differs from raw JSONL")
        if execution["jsonl_count"] != len(raw_records):
            raise ValueError("diagnostic raw count mismatch")
        return {
            "raw_record_count": len(raw_records),
            "reported_errors": [],
            "parse_error_count": None,
            "scope": "supplied-export-only",
        }


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
    scan_verification = coverage.verify_scan()
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
    if (
        handoff.trace.output_sha256 != audit["hits_sha256"]
        or handoff.trace.input_sha256 != audit["input_csv_sha256"]
        or hashlib.sha256(trace_path.read_bytes()).hexdigest() != audit["trace_sha256"]
    ):
        raise ValueError("handoff changed after selection")
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
    active = {}
    for hit in records:
        if not observation_start <= hit.timestamp <= observation_end:
            raise ValueError("hit outside observation interval")
        previous = active.get(hit.alert_key)
        if previous is None or hit.timestamp - previous[0] >= timedelta(
            seconds=episode_policy.inactivity_gap_sec
        ):
            group = {"start_time": hit.timestamp, "alert_key": hit.alert_key, "hit_ids": []}
            groups.append(group)
        else:
            group = previous[1]
        group["hit_ids"].append(hit.hit_id)
        active[hit.alert_key] = (hit.timestamp, group)
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
        "coverage": coverage.model_dump(mode="json"),
        "scan_verification": scan_verification,
        "selection_audit": audit,
        "selection": selection.model_dump(mode="json"),
        "episodes": groups,
    }
