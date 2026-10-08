"""Repository-managed R1 approved lineage policy를 검증해 로드한다."""

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError, field_validator
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.evidence.r1_multi_event import (
    ApprovedLineagePolicy,
    R1PolicyLifecycle,
)

DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH = (
    Path(__file__).parents[3] / "configs" / "r1_approved_lineage_policies_v0.1.yaml"
)
DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH = (
    Path(__file__).parents[3] / "configs" / "r1_approved_lineage_policies_v0.2.yaml"
)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _PolicyIdentityAndLineage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: StrictStr
    version: StrictStr
    approved_lineage: list[StrictStr] = Field(min_length=1)

    @field_validator("policy_id", "version")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy identity values must not be blank")
        if value != value.strip():
            raise ValueError("policy identity values must not contain surrounding whitespace")
        return value

    @field_validator("approved_lineage")
    @classmethod
    def validate_approved_lineage(cls, value: list[str]) -> list[str]:
        if any(not process_name.strip() for process_name in value):
            raise ValueError("approved_lineage must not contain blank values")
        if any(process_name != process_name.strip() for process_name in value):
            raise ValueError("approved_lineage must not contain surrounding whitespace")
        return value


class _LegacyApprovedLineagePolicyConfig(_PolicyIdentityAndLineage):
    pass


class _FamilyBoundApprovedLineagePolicyConfig(_PolicyIdentityAndLineage):
    family_id: StrictStr
    lifecycle: R1PolicyLifecycle

    @field_validator("family_id")
    @classmethod
    def validate_policy_family_id(cls, value: str) -> str:
        return validate_family_id(value)


class _LegacyApprovedLineagePolicyRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal["v0.1"]
    policies: list[_LegacyApprovedLineagePolicyConfig] = Field(min_length=1)


class _FamilyBoundApprovedLineagePolicyRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal["v0.2"]
    policies: list[_FamilyBoundApprovedLineagePolicyConfig] = Field(min_length=1)


_PolicyConfig = _LegacyApprovedLineagePolicyConfig | _FamilyBoundApprovedLineagePolicyConfig
_PolicyRegistry = _LegacyApprovedLineagePolicyRegistry | _FamilyBoundApprovedLineagePolicyRegistry


def load_r1_approved_lineage_policies(
    config_path: Path = DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
) -> tuple[ApprovedLineagePolicy, ...]:
    """검증한 config의 모든 approved lineage policy를 순서대로 반환한다."""
    registry = _load_registry(config_path)
    policies: list[ApprovedLineagePolicy] = []
    identities: set[tuple[str, str]] = set()

    for policy_config in registry.policies:
        identity = (policy_config.policy_id, policy_config.version)
        if identity in identities:
            raise ValueError(
                "R1 approved lineage policy identities must be unique: "
                f"{policy_config.policy_id}/{policy_config.version}"
            )
        identities.add(identity)
        policies.append(_build_policy(policy_config))

    return tuple(policies)


def load_r1_approved_lineage_policy(
    policy_id: str,
    version: str,
    *,
    config_path: Path = DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
) -> ApprovedLineagePolicy:
    """정확한 policy ID와 version에 해당하는 approved lineage policy를 반환한다."""
    _validate_lookup_identity("policy_id", policy_id)
    _validate_lookup_identity("version", version)

    for policy in load_r1_approved_lineage_policies(config_path):
        if policy.policy_id == policy_id and policy.version == version:
            return policy

    raise ValueError(f"R1 approved lineage policy was not found: {policy_id}/{version}")


def validate_r1_policy_family_binding(
    scenario_family_id: str,
    policy: ApprovedLineagePolicy,
) -> None:
    """Scenario와 family-bound policy가 같은 canonical family인지 검증한다."""
    if not isinstance(policy, ApprovedLineagePolicy):
        raise TypeError("policy must be an ApprovedLineagePolicy")
    validated_scenario_family_id = validate_family_id(scenario_family_id)
    if policy.family_id is None or policy.lifecycle is None:
        raise ValueError(
            "legacy unbound approved policy is not eligible for family-bound execution"
        )
    if validated_scenario_family_id != policy.family_id:
        raise ValueError(
            "scenario family_id does not match approved policy family_id: "
            f"{validated_scenario_family_id} != {policy.family_id}"
        )


def _load_registry(config_path: Path) -> _PolicyRegistry:
    if not isinstance(config_path, Path):
        raise TypeError("config_path must be a Path")
    if not config_path.is_file():
        raise FileNotFoundError(f"R1 approved lineage policy config was not found: {config_path}")

    try:
        config_data = yaml.load(
            config_path.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("R1 approved lineage policy config is not valid YAML") from error

    config_version = config_data.get("config_version") if isinstance(config_data, dict) else None
    registry_type: type[_PolicyRegistry]
    if config_version == "v0.1":
        registry_type = _LegacyApprovedLineagePolicyRegistry
    elif config_version == "v0.2":
        registry_type = _FamilyBoundApprovedLineagePolicyRegistry
    else:
        raise ValueError("R1 approved lineage policy config does not match v0.1 or v0.2")

    try:
        return registry_type.model_validate(config_data)
    except ValidationError as error:
        raise ValueError(
            f"R1 approved lineage policy config does not match {config_version}"
        ) from error


def _build_policy(policy_config: _PolicyConfig) -> ApprovedLineagePolicy:
    canonical_payload = _canonical_policy_payload(policy_config)
    family_id = None
    lifecycle = None
    if isinstance(policy_config, _FamilyBoundApprovedLineagePolicyConfig):
        family_id = policy_config.family_id
        lifecycle = policy_config.lifecycle
    return ApprovedLineagePolicy(
        policy_id=policy_config.policy_id,
        version=policy_config.version,
        config_hash=hashlib.sha256(canonical_payload).hexdigest(),
        approved_lineage=tuple(policy_config.approved_lineage),
        family_id=family_id,
        lifecycle=lifecycle,
    )


def _canonical_policy_payload(policy_config: _PolicyConfig) -> bytes:
    payload = {
        "policy_id": policy_config.policy_id,
        "version": policy_config.version,
        "approved_lineage": policy_config.approved_lineage,
    }
    if isinstance(policy_config, _FamilyBoundApprovedLineagePolicyConfig):
        payload["family_id"] = policy_config.family_id
        payload["lifecycle"] = policy_config.lifecycle
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_lookup_identity(field_name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")


__all__ = [
    "DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH",
    "DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH",
    "load_r1_approved_lineage_policies",
    "load_r1_approved_lineage_policy",
    "validate_r1_policy_family_binding",
]
