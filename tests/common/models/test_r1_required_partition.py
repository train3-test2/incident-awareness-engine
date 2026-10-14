import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from incident_awareness.common.models.r1_required_partition import (
    R1_REQUIRED_PARTITION_CONTRACT_VERSION,
    R1_REQUIRED_PARTITION_SCHEMA,
    R1RequiredPartitionContract,
    R1RequiredPartitionContractError,
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.run import RunMetadata

FIXTURE_PATH = (
    Path(__file__).parents[2]
    / "fixtures"
    / "evidence"
    / "r1_target_a_required_partitions_v0.1.json"
)


def _contract(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": R1_REQUIRED_PARTITION_SCHEMA,
        "contract_version": R1_REQUIRED_PARTITION_CONTRACT_VERSION,
        "target_host": "Target-A",
        "required_partitions": [
            {
                "source": "sysmon",
                "source_channel": "Microsoft-Windows-Sysmon/Operational",
            }
        ],
    }
    value.update(updates)
    return value


def _run_metadata(*, target_host: str) -> RunMetadata:
    return RunMetadata.model_validate(
        {
            "run_id": "RUN-20261014-001",
            "scenario_id": "R1",
            "run_type": "attack",
            "target_host": target_host,
            "start_time": "2026-10-14T00:00:00.000Z",
            "schema_versions": {
                "run_metadata": "v0.2",
                "event": "v0.3",
                "evidence": "v0.2",
                "fast_hit": "v0.2",
                "detection_result": "v0.2",
                "fusion_result": "v0.3",
                "decision_result": "v0.2",
                "execution_record": "v0.2",
                "evaluation_input": "v0.2",
            },
        }
    )


def test_accepts_the_r1_required_partition_contract_envelope() -> None:
    contract = R1RequiredPartitionContract.model_validate(_contract())

    assert contract.model_dump(mode="json", by_alias=True) == _contract()


def test_contract_json_round_trip_and_schema() -> None:
    contract = R1RequiredPartitionContract.model_validate(_contract())
    serialized = contract.model_dump_json(by_alias=True)
    wire = json.loads(serialized)
    restored = R1RequiredPartitionContract.model_validate_json(serialized)
    schema = R1RequiredPartitionContract.model_json_schema(by_alias=True)
    validator = Draft202012Validator(schema)

    validator.validate(wire)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate({**wire, "unexpected": "value"})

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(
            {
                **wire,
                "required_partitions": [
                    *wire["required_partitions"],
                    *wire["required_partitions"],
                ],
            }
        )

    assert restored == contract
    assert wire == _contract()


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


def test_rejects_schema_id_without_the_required_schema_alias() -> None:
    payload = _contract()
    payload["schema_id"] = payload.pop("schema")

    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(payload)


def test_rejects_undefined_contract_fields() -> None:
    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(_contract(unexpected="value"))


@pytest.mark.parametrize("target_host", ["", " Target-A", "Target-A "])
def test_rejects_a_blank_or_noncanonical_target_host(target_host: str) -> None:
    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(_contract(target_host=target_host))


def test_accepts_a_contract_bound_to_the_run_target_host() -> None:
    contract = R1RequiredPartitionContract.model_validate(_contract(target_host="Target-A"))

    contract.validate_for_run(_run_metadata(target_host="Target-A"))


def test_rejects_a_contract_bound_to_another_target_host() -> None:
    contract = R1RequiredPartitionContract.model_validate(_contract(target_host="Target-A"))

    with pytest.raises(ValueError, match="must match RunMetadata.target_host"):
        contract.validate_for_run(_run_metadata(target_host="Target-B"))


def test_role2_loader_returns_the_target_a_fixture_bound_to_the_run_target_host() -> None:
    contract = load_r1_required_partition_contract(
        FIXTURE_PATH,
        run_metadata=_run_metadata(target_host="Target-A"),
    )

    assert contract.model_dump(mode="json", by_alias=True) == _contract()


def test_role2_loader_rejects_a_contract_bound_to_another_target_host(tmp_path: Path) -> None:
    contract_path = tmp_path / "required-partitions.json"
    contract_path.write_text(json.dumps(_contract(target_host="Target-A")), encoding="utf-8")

    with pytest.raises(R1RequiredPartitionContractError, match="invalid for run"):
        load_r1_required_partition_contract(
            contract_path,
            run_metadata=_run_metadata(target_host="Target-B"),
        )


def test_role2_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    contract_path = tmp_path / "required-partitions.json"
    contract_path.write_text(
        '{"schema":"r1-required-partitions","schema":"r1-required-partitions"}',
        encoding="utf-8",
    )

    with pytest.raises(R1RequiredPartitionContractError, match="duplicate JSON key"):
        load_r1_required_partition_contract(
            contract_path,
            run_metadata=_run_metadata(target_host="Target-A"),
        )


def test_rejects_an_empty_required_partition_set() -> None:
    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(_contract(required_partitions=[]))


def test_rejects_duplicate_required_partitions() -> None:
    partition = {
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
    }

    with pytest.raises(ValidationError, match="duplicate partitions"):
        R1RequiredPartitionContract.model_validate(
            _contract(required_partitions=[partition, partition])
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "security"),
        ("source", "Sysmon"),
        ("source_channel", "microsoft-windows-sysmon/operational"),
        ("source_channel", "Microsoft-Windows-Sysmon/Debug"),
    ],
)
def test_rejects_an_unsupported_source_or_source_channel(field: str, value: str) -> None:
    partition = _contract()["required_partitions"][0]
    assert isinstance(partition, dict)

    with pytest.raises(ValidationError):
        R1RequiredPartitionContract.model_validate(
            _contract(required_partitions=[{**partition, field: value}])
        )


def test_json_schema_exposes_the_canonical_schema_and_version() -> None:
    schema = R1RequiredPartitionContract.model_json_schema(by_alias=True)

    assert schema["properties"]["schema"]["const"] == R1_REQUIRED_PARTITION_SCHEMA
    assert schema["properties"]["contract_version"]["const"] == (
        R1_REQUIRED_PARTITION_CONTRACT_VERSION
    )
    assert schema["properties"]["target_host"]["minLength"] == 1
    assert schema["properties"]["required_partitions"]["minItems"] == 1
    assert schema["properties"]["required_partitions"]["uniqueItems"] is True
    assert schema["additionalProperties"] is False
    partition_schema = schema["$defs"]["R1RequiredPartition"]["properties"]
    assert partition_schema["source"]["const"] == "sysmon"
    assert partition_schema["source_channel"]["const"] == ("Microsoft-Windows-Sysmon/Operational")
