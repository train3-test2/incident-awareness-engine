import pytest
from pydantic import ValidationError

from incident_awareness.common.models.r1_required_partition import (
    R1_REQUIRED_PARTITION_CONTRACT_VERSION,
    R1_REQUIRED_PARTITION_SCHEMA,
    R1RequiredPartitionContract,
)


def _contract(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": R1_REQUIRED_PARTITION_SCHEMA,
        "contract_version": R1_REQUIRED_PARTITION_CONTRACT_VERSION,
    }
    value.update(updates)
    return value


def test_accepts_the_r1_required_partition_contract_envelope() -> None:
    contract = R1RequiredPartitionContract.model_validate(_contract())

    assert contract.model_dump(by_alias=True) == _contract()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "r1-required-partitions-v2"),
        ("contract_version", "v0.2"),
    ],
)
def test_rejects_an_unsupported_contract_identity(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(_contract(**{field: value}))


def test_rejects_undefined_contract_fields() -> None:
    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(_contract(unexpected="value"))


def test_json_schema_exposes_the_canonical_schema_and_version() -> None:
    schema = R1RequiredPartitionContract.model_json_schema(by_alias=True)

    assert schema["properties"]["schema"]["const"] == R1_REQUIRED_PARTITION_SCHEMA
    assert schema["properties"]["contract_version"]["const"] == (
        R1_REQUIRED_PARTITION_CONTRACT_VERSION
    )
