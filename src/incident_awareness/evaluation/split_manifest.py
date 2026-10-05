"""Validate explicit Run/group partitions without reading evaluation outcomes."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_awareness.common.models.run import RunMetadata

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
    canonical["inventory_run_ids"] = sorted(canonical["inventory_run_ids"])
    canonical["assignments"] = sorted(canonical["assignments"], key=lambda row: row["run_id"])
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "schema_version": "split-audit-v0.1",
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
