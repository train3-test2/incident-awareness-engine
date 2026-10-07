"""Validate explicit Run/group partitions without reading evaluation outcomes."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.evaluation.dataset_usage import UsagePolicy, canonical_usage, usage_digest

Identifier = Annotated[str, Field(strict=True, min_length=1, pattern=r"^\S(?:.*\S)?$")]
Split = Literal["train", "validation", "test"]
SPLITS = ("train", "validation", "test")


class SplitAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: Identifier
    group_id: Identifier
    split: Split

    @field_validator("run_id")
    @classmethod
    def valid_run(cls, value: str) -> str:
        return RunMetadata.validate_run_id(value)


class SplitManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    usage_policy: UsagePolicy
    manifest_version: Identifier
    grouping_policy_version: Identifier
    inventory_run_ids: tuple[Identifier, ...] = Field(min_length=1)
    inventory_family_ids: dict[Identifier, Identifier]
    assignments: tuple[SplitAssignment, ...] = Field(min_length=1)

    @field_validator("inventory_run_ids")
    @classmethod
    def valid_inventory(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            RunMetadata.validate_run_id(value)
        if len(values) != len(set(values)):
            raise ValueError("duplicate inventory Run")
        return values

    @model_validator(mode="after")
    def valid_partition(self) -> "SplitManifest":
        assigned = [row.run_id for row in self.assignments]
        if len(assigned) != len(set(assigned)):
            raise ValueError("each Run must have exactly one assignment")
        if set(assigned) != set(self.inventory_run_ids):
            raise ValueError("assignments must exactly cover inventory")
        if {row.split for row in self.assignments} != set(SPLITS):
            raise ValueError("train, validation and test must each contain a Run")
        if set(self.inventory_family_ids) != set(self.inventory_run_ids):
            raise ValueError("family inventory must exactly cover Run inventory")
        usage = {row.run_id: row for row in self.usage_policy.runs}
        missing = set(self.inventory_run_ids) - set(usage)
        if missing:
            raise ValueError(f"usage records missing for inventory: {sorted(missing)}")
        pairs = {}
        for row in self.assignments:
            record = usage[row.run_id]
            if row.split not in record.eligible_splits:
                raise ValueError(f"Run {row.run_id} excluded from {row.split}: {record.reason}")
            if record.pair_id is not None:
                previous = pairs.setdefault(record.pair_id, row.split)
                if previous != row.split:
                    raise ValueError("a usage Pair must not cross split boundaries")
        families = {}
        groups = {}
        for row in self.assignments:
            family = self.inventory_family_ids[row.run_id]
            previous_family = families.setdefault(family, row.split)
            if previous_family != row.split:
                raise ValueError("a family must not cross split boundaries")
            previous = groups.setdefault(row.group_id, row.split)
            if previous != row.split:
                raise ValueError("a group must not cross split boundaries")
        return self


def audit_split_manifest(manifest: SplitManifest) -> dict:
    """Revalidate and hash canonical metadata; this is not full leakage certification."""
    manifest = SplitManifest.model_validate(manifest.model_dump(mode="json"))
    canonical = manifest.model_dump(mode="json")
    canonical["usage_policy"] = canonical_usage(manifest.usage_policy)
    canonical["inventory_run_ids"] = sorted(canonical["inventory_run_ids"])
    canonical["assignments"] = sorted(canonical["assignments"], key=lambda row: row["run_id"])
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "schema_version": "split-audit-v0.2",
        "usage_policy_version": manifest.usage_policy.policy_version,
        "usage_sha256": usage_digest(manifest.usage_policy),
        "manifest_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "manifest": canonical,
        "splits": {
            split: {
                "run_ids": sorted(row.run_id for row in manifest.assignments if row.split == split),
                "family_ids": sorted(
                    {
                        manifest.inventory_family_ids[row.run_id]
                        for row in manifest.assignments
                        if row.split == split
                    }
                ),
                "group_ids": sorted(
                    {row.group_id for row in manifest.assignments if row.split == split}
                ),
            }
            for split in SPLITS
        },
    }


def build_split_manifest(payload: dict, usage_policy: UsagePolicy) -> SplitManifest:
    """Attach explicitly loaded usage without silently replacing embedded policy."""
    policy = UsagePolicy.model_validate(usage_policy.model_dump(mode="json"))
    if "usage_policy" in payload:
        embedded = UsagePolicy.model_validate(payload["usage_policy"])
        if canonical_usage(embedded) != canonical_usage(policy):
            raise ValueError("embedded and supplied usage policy conflict")
    return SplitManifest.model_validate({**payload, "usage_policy": policy})


def main() -> None:
    """Build a validated manifest from inventory and required external sidecars."""
    import argparse
    from pathlib import Path

    from incident_awareness.evaluation.dataset_usage import load_usage_policy

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--usage", required=True, action="append", type=Path)
    parser.add_argument("--policy-version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = build_split_manifest(
            json.loads(args.inventory.read_text(encoding="utf-8")),
            load_usage_policy(args.usage, policy_version=args.policy_version),
        )
        result = audit_split_manifest(manifest)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result["manifest"], stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
