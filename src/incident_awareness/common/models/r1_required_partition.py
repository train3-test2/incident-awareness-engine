"""R1 required-partition contract envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

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
    def validate_target_host(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("target_host must not contain leading or trailing whitespace")
        return value


__all__ = [
    "R1_REQUIRED_PARTITION_CONTRACT_VERSION",
    "R1_REQUIRED_PARTITION_SCHEMA",
    "R1RequiredPartition",
    "R1RequiredPartitionContract",
]
