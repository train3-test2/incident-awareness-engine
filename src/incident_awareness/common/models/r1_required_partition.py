"""R1 required-partition contract envelope and Role2 consumer API."""

import json
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.run import RunMetadata

R1_REQUIRED_PARTITION_SCHEMA = "r1-required-partitions"
R1_REQUIRED_PARTITION_CONTRACT_VERSION = "v0.1"


class R1RequiredPartitionContractError(ValueError):
    """Raised when a required-partition contract cannot be consumed safely."""


class R1RequiredPartition(BaseModel):
    """One canonical source partition required for a bound target host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: Literal["sysmon"]
    source_channel: Literal["Microsoft-Windows-Sysmon/Operational"]


class R1RequiredPartitionContract(BaseModel):
    """Versioned envelope for the R1 canonical required-partition contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-required-partitions"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    target_host: StrictStr = Field(min_length=1)
    required_partitions: tuple[R1RequiredPartition, ...] = Field(
        min_length=1,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("target_host")
    @classmethod
    def validate_target_host_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("target_host must not contain leading or trailing whitespace")
        return value

    def validate_for_run(self, run_metadata: RunMetadata) -> None:
        """Reject use of this contract for a Run bound to another target host."""
        if self.target_host != run_metadata.target_host:
            raise ValueError(
                "required-partition contract target_host must match RunMetadata.target_host"
            )

    @model_validator(mode="after")
    def validate_unique_required_partitions(self) -> "R1RequiredPartitionContract":
        partition_identities = [
            (partition.source, partition.source_channel) for partition in self.required_partitions
        ]
        if len(partition_identities) != len(set(partition_identities)):
            raise ValueError("required_partitions must not contain duplicate partitions")
        return self


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise R1RequiredPartitionContractError(
                f"required-partition contract contains duplicate JSON key {key!r}"
            )
        document[key] = value
    return document


def load_r1_required_partition_contract(
    path: str | Path, *, run_metadata: RunMetadata
) -> R1RequiredPartitionContract:
    """Load and fail-closed validate a required-partition contract for one Run.

    This is the public Role2 consumer boundary. It rejects unreadable or
    malformed documents, duplicate JSON keys, schema validation failures, and
    contracts bound to a target host other than ``run_metadata.target_host``.
    """
    contract_path = Path(path)
    try:
        content = contract_path.read_text(encoding="utf-8")
    except OSError as error:
        raise R1RequiredPartitionContractError(
            f"required-partition contract cannot be read: {contract_path}"
        ) from error

    try:
        document = json.loads(content, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as error:
        raise R1RequiredPartitionContractError(
            f"required-partition contract is not valid JSON: {contract_path}"
        ) from error

    if not isinstance(document, dict):
        raise R1RequiredPartitionContractError("required-partition contract must be a JSON object")

    try:
        contract = R1RequiredPartitionContract.model_validate(document)
        contract.validate_for_run(run_metadata)
    except (ValidationError, ValueError) as error:
        raise R1RequiredPartitionContractError(
            f"required-partition contract is invalid for run {run_metadata.run_id}: {error}"
        ) from error

    return contract


__all__ = [
    "R1_REQUIRED_PARTITION_CONTRACT_VERSION",
    "R1_REQUIRED_PARTITION_SCHEMA",
    "R1RequiredPartition",
    "R1RequiredPartitionContract",
    "R1RequiredPartitionContractError",
    "load_r1_required_partition_contract",
]
