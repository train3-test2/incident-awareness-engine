"""R1 required-partition contract envelope."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

R1_REQUIRED_PARTITION_SCHEMA = "r1-required-partitions"
R1_REQUIRED_PARTITION_CONTRACT_VERSION = "v0.1"


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


__all__ = [
    "R1_REQUIRED_PARTITION_CONTRACT_VERSION",
    "R1_REQUIRED_PARTITION_SCHEMA",
    "R1RequiredPartitionContract",
]
