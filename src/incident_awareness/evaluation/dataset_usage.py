"""Explicit usage sidecars for dataset construction; never infer permission from absence."""

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_awareness.common.models.run import RunMetadata

Identifier = Annotated[str, Field(strict=True, min_length=1, pattern=r"^\S(?:.*\S)?$")]
Split = Literal["train", "validation", "test"]
Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]


class RunUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    run_id: Identifier
    pair_id: Identifier | None
    eligible_splits: tuple[Split, ...]
    used_for_tuning: Annotated[bool, Field(strict=True)]
    reason: Identifier

    @field_validator("run_id")
    @classmethod
    def valid_run(cls, value: str) -> str:
        return RunMetadata.validate_run_id(value)

    @model_validator(mode="after")
    def consistent(self) -> "RunUsage":
        if len(self.eligible_splits) != len(set(self.eligible_splits)):
            raise ValueError("duplicate eligible split")
        if self.used_for_tuning and self.eligible_splits:
            raise ValueError("tuning-only records cannot permit formal splits")
        return self


class UsagePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    schema_version: Literal["dataset-usage-v0.1"]
    policy_version: Identifier
    source_sha256: tuple[Digest, ...] = Field(min_length=1)
    runs: tuple[RunUsage, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_runs(self) -> "UsagePolicy":
        ids = [row.run_id for row in self.runs]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate or conflicting usage records for Run")
        return self


def canonical_usage(policy: UsagePolicy) -> dict:
    value = policy.model_dump(mode="json")
    value["source_sha256"] = sorted(set(value["source_sha256"]))
    value["runs"] = sorted(value["runs"], key=lambda row: row["run_id"])
    for row in value["runs"]:
        row["eligible_splits"] = sorted(row["eligible_splits"])
    return value


def usage_digest(policy: UsagePolicy) -> str:
    encoded = json.dumps(
        canonical_usage(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_usage_policy(paths: list[Path], *, policy_version: str) -> UsagePolicy:
    """Merge canonical policies or historical Pair sidecars, retaining byte hashes.

    Historical Pair sidecars intentionally include observational metadata; only
    explicit eligibility fields grant permission. No source_index flag is used.
    """
    runs = []
    hashes = []
    for path in paths:
        content = path.read_bytes()
        hashes.append(hashlib.sha256(content).hexdigest())
        data = json.loads(content)
        if not isinstance(data, dict):
            raise TypeError("usage sidecar must be an object")
        if "schema_version" in data:
            policy = UsagePolicy.model_validate(data)
            runs.extend(policy.runs)
            hashes.extend(policy.source_sha256)
            continue
        # Compatibility with the reviewed Pair-002 data-usage.json sidecar.
        if not isinstance(data.get("pair_id"), str) or not data["pair_id"].strip():
            raise ValueError("historical Pair sidecar requires pair_id")
        eligible = []
        for split in ("train", "validation", "test"):
            value = data[f"eligible_for_{split}"]
            if not isinstance(value, bool):
                raise TypeError("eligibility flags must be booleans")
            if value:
                eligible.append(split)
        if "eligible_splits" in data and data["eligible_splits"] != eligible:
            raise ValueError("conflicting eligibility fields")
        for field in ("normal_run_id", "attack_run_id"):
            runs.append(
                RunUsage(
                    run_id=data[field],
                    pair_id=data["pair_id"],
                    eligible_splits=eligible,
                    used_for_tuning=data["used_for_tuning"],
                    reason=data["reason"],
                )
            )
    return UsagePolicy(
        schema_version="dataset-usage-v0.1",
        policy_version=policy_version,
        source_sha256=hashes,
        runs=runs,
    )
