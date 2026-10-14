"""R1 required-partition contract envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from incident_awareness.common.models.run import RunMetadata

R1_REQUIRED_PARTITION_SCHEMA = "r1-required-partitions"
R1_REQUIRED_PARTITION_CONTRACT_VERSION = "v0.1"


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
        validate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-required-partitions"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    target_host: StrictStr = Field(min_length=1)
    required_partitions: tuple[R1RequiredPartition, ...] = Field(min_length=1)

    @field_validator("target_host")
    @classmethod
    def validate_target_host_identifier(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("target_host must not contain leading or trailing whitespace")
        return value

    def validate_for_run(self, run_metadata: RunMetadata) -> None:
        """Reject use of this contract for a Run bound to another target host."""
        if self.target_host != run_metadata.target_host:
            raise ValueError("required-partition contract target_host must match RunMetadata.target_host")

    @model_validator(mode="after")
    def validate_unique_required_partitions(self) -> "R1RequiredPartitionContract":
        partition_identities = [
            (partition.source, partition.source_channel) for partition in self.required_partitions
        ]
        if len(partition_identities) != len(set(partition_identities)):
            raise ValueError("required_partitions must not contain duplicate partitions")
        return self


__all__ = [
    "R1_REQUIRED_PARTITION_CONTRACT_VERSION",
    "R1_REQUIRED_PARTITION_SCHEMA",
    "R1RequiredPartition",
    "R1RequiredPartitionContract",
]
