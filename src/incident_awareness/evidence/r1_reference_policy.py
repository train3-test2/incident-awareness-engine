"""Repository-managed R1 reference policy를 검증하고 적용한다."""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
)
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.common.models.event import NormalizedEvent

DEFAULT_R1_REFERENCE_POLICIES_PATH = (
    Path(__file__).parents[3] / "configs" / "r1_reference_policies_v0.1.yaml"
)
R1_REFERENCE_POLICY_LOADER_VERSION = "r1-reference-policy-loader-v0.1"


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


class _ReferencePolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: StrictStr
    version: StrictStr
    family_id: StrictStr
    reference_action_id: StrictStr
    action_type: Literal["wmi_process_create"]
    invocation_method: Literal["Win32_Process.Create"]
    success_return_value: Literal[0]
    require_process_id: StrictBool
    reference_source: Literal["sysmon"]
    reference_source_layer: Literal["raw_telemetry"]
    reference_event_type: Literal["process_create"]
    reference_process_name: StrictStr
    candidate_start_offset_sec: Literal[0]
    candidate_window_sec: StrictInt = Field(gt=0)
    expected_evaluation_horizon_sec: StrictInt = Field(gt=0)

    @field_validator(
        "policy_id",
        "version",
        "reference_action_id",
        "reference_process_name",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reference policy string values must not be blank")
        if value != value.strip():
            raise ValueError(
                "reference policy string values must not contain surrounding whitespace"
            )
        return value

    @field_validator("family_id")
    @classmethod
    def validate_policy_family_id(cls, value: str) -> str:
        return validate_family_id(value)


class _ReferencePolicyRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal["v0.1"]
    policies: list[_ReferencePolicyConfig] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class R1ReferencePolicy:
    """검증된 reference policy와 canonical provenance."""

    config_path: Path
    canonical_path: str
    policy_id: str
    version: str
    family_id: str
    config_hash: str
    reference_action_id: str
    action_type: str
    invocation_method: str
    success_return_value: int
    require_process_id: bool
    reference_source: str
    reference_source_layer: str
    reference_event_type: str
    reference_process_name: str
    candidate_start_offset_sec: int
    candidate_window_sec: int
    expected_evaluation_horizon_sec: int


@dataclass(frozen=True, slots=True)
class R1WmiActionResult:
    """WMI A01 호출 결과 중 reference 판정에 필요한 값."""

    action_id: str
    action_type: str
    invocation_method: str
    invoked_at_utc: datetime
    return_value: int
    process_id: int | None


@dataclass(frozen=True, slots=True)
class R1ReferenceSelection:
    """유일하게 선택된 reference와 적용한 policy provenance."""

    run_id: str
    entity_id: str
    reference_action_id: str
    reference_time: datetime
    reference_source_event_id: str
    reference_event_id: str
    action_process_id: int
    policy_id: str
    reference_policy_version: str
    policy_config_hash: str
    policy_config_path: str
    scenario_evaluation_horizon_sec: int
    expected_evaluation_horizon_sec: int
    horizon_matches: bool


def load_r1_reference_policies(
    config_path: Path = DEFAULT_R1_REFERENCE_POLICIES_PATH,
) -> tuple[R1ReferencePolicy, ...]:
    """Strict config의 모든 reference policy를 반환한다."""
    registry = _load_registry(config_path)
    identities: set[tuple[str, str]] = set()
    policies: list[R1ReferencePolicy] = []

    for policy_config in registry.policies:
        identity = (policy_config.policy_id, policy_config.version)
        if identity in identities:
            raise ValueError(
                "R1 reference policy identities must be unique: "
                f"{policy_config.policy_id}/{policy_config.version}"
            )
        identities.add(identity)
        policies.append(_build_policy(config_path, policy_config))

    return tuple(policies)


def load_r1_reference_policy(
    policy_id: str,
    version: str,
    *,
    config_path: Path = DEFAULT_R1_REFERENCE_POLICIES_PATH,
) -> R1ReferencePolicy:
    """정확한 ID와 version의 reference policy를 반환한다."""
    _validate_identity("policy_id", policy_id)
    _validate_identity("version", version)

    for policy in load_r1_reference_policies(config_path):
        if policy.policy_id == policy_id and policy.version == version:
            return policy

    raise ValueError(f"R1 reference policy was not found: {policy_id}/{version}")


def resolve_r1_wmi_reference(
    events: Iterable[NormalizedEvent],
    *,
    policy: R1ReferencePolicy,
    scenario_family_id: str,
    reference_policy_version: str,
    evaluation_horizon_sec: int,
    action_result: R1WmiActionResult,
    action_attributed_event_ids: Iterable[str],
    lineage_process_guids: Iterable[str],
) -> R1ReferenceSelection:
    """A01 attribution과 GUID lineage가 함께 확인한 유일한 EID 1을 선택한다."""
    if not isinstance(policy, R1ReferencePolicy):
        raise TypeError("policy must be an R1ReferencePolicy")
    _validate_policy_binding(
        policy,
        scenario_family_id=scenario_family_id,
        reference_policy_version=reference_policy_version,
        evaluation_horizon_sec=evaluation_horizon_sec,
    )
    _validate_action_result(policy, action_result)

    event_batch = tuple(events)
    if any(not isinstance(event, NormalizedEvent) for event in event_batch):
        raise TypeError("events must contain NormalizedEvent items")
    attributed_event_ids = _validated_string_set(
        "action_attributed_event_ids",
        action_attributed_event_ids,
    )
    lineage_guids = _validated_string_set(
        "lineage_process_guids",
        lineage_process_guids,
    )

    structural_candidates = tuple(
        event
        for event in event_batch
        if event.event_id in attributed_event_ids
        and _matches_reference_event(event, policy, lineage_guids, action_result)
        and _has_wmi_context_parent(event, event_batch, policy, lineage_guids)
    )
    candidates: list[tuple[NormalizedEvent, str]] = []
    window_start = action_result.invoked_at_utc + timedelta(
        seconds=policy.candidate_start_offset_sec
    )
    window_end = action_result.invoked_at_utc + timedelta(seconds=policy.candidate_window_sec)
    for event in structural_candidates:
        if event.timestamp_source != "event_time" or event.event_time is None:
            raise ValueError("R1 reference Event must carry parsed Sysmon EventData.UtcTime")
        if not window_start <= event.event_time <= window_end:
            continue
        source_record_id = _validate_sysmon_record_id(event)
        candidates.append((event, source_record_id))
    if len(candidates) != 1:
        raise ValueError(f"R1 reference candidate count must be exactly 1, found {len(candidates)}")

    selected, source_record_id = candidates[0]

    return R1ReferenceSelection(
        reference_action_id=policy.reference_action_id,
        reference_time=selected.event_time,
        reference_source_event_id=source_record_id,
        reference_event_id=selected.event_id,
        action_process_id=action_result.process_id,
        policy_id=policy.policy_id,
        reference_policy_version=policy.version,
        policy_config_hash=policy.config_hash,
        run_id=selected.run_id,
        entity_id=selected.host_id,
        policy_config_path=policy.canonical_path,
        scenario_evaluation_horizon_sec=evaluation_horizon_sec,
        expected_evaluation_horizon_sec=policy.expected_evaluation_horizon_sec,
        horizon_matches=True,
    )


def validate_normal_reference_fields(
    *,
    reference_action_id: str | None,
    reference_time: datetime | None,
    reference_source_event_id: str | None,
) -> None:
    """Normal Run의 reference 3개 필드가 모두 null인지 검증한다."""
    if any(
        value is not None
        for value in (
            reference_action_id,
            reference_time,
            reference_source_event_id,
        )
    ):
        raise ValueError("Normal Run reference fields must all be null")


def _load_registry(config_path: Path) -> _ReferencePolicyRegistry:
    if not isinstance(config_path, Path):
        raise TypeError("config_path must be a Path")
    if not config_path.is_file():
        raise FileNotFoundError(f"R1 reference policy config was not found: {config_path}")

    try:
        config_data = yaml.load(
            config_path.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("R1 reference policy config is not valid YAML") from error

    try:
        return _ReferencePolicyRegistry.model_validate(config_data)
    except ValidationError as error:
        raise ValueError("R1 reference policy config does not match v0.1") from error


def _build_policy(config_path: Path, policy_config: _ReferencePolicyConfig) -> R1ReferencePolicy:
    canonical_payload = json.dumps(
        policy_config.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    config_hash = hashlib.sha256(canonical_payload).hexdigest()
    return R1ReferencePolicy(
        config_path=config_path.resolve(),
        canonical_path=_canonical_config_path(config_path, policy_config, config_hash),
        config_hash=config_hash,
        **policy_config.model_dump(),
    )


def _canonical_config_path(
    config_path: Path,
    policy_config: _ReferencePolicyConfig,
    config_hash: str,
) -> str:
    resolved_path = config_path.resolve()
    repository_root = Path(__file__).parents[3].resolve()
    try:
        return resolved_path.relative_to(repository_root).as_posix()
    except ValueError:
        return f"external-policy:{policy_config.policy_id}/{policy_config.version}@{config_hash}"


def _validate_policy_binding(
    policy: R1ReferencePolicy,
    *,
    scenario_family_id: str,
    reference_policy_version: str,
    evaluation_horizon_sec: int,
) -> None:
    if validate_family_id(scenario_family_id) != policy.family_id:
        raise ValueError("scenario family_id does not match reference policy family_id")
    _validate_identity("reference_policy_version", reference_policy_version)
    if reference_policy_version != policy.version:
        raise ValueError("RunMetadata reference_policy_version does not match reference policy")
    if isinstance(evaluation_horizon_sec, bool) or not isinstance(evaluation_horizon_sec, int):
        raise TypeError("evaluation_horizon_sec must be an integer")
    if evaluation_horizon_sec != policy.expected_evaluation_horizon_sec:
        raise ValueError("scenario evaluation_horizon_sec does not match reference policy")


def _validate_action_result(
    policy: R1ReferencePolicy,
    action_result: R1WmiActionResult,
) -> None:
    if not isinstance(action_result, R1WmiActionResult):
        raise TypeError("action_result must be an R1WmiActionResult")
    if action_result.action_id != policy.reference_action_id:
        raise ValueError("WMI action result does not match reference_action_id")
    if action_result.action_type != policy.action_type:
        raise ValueError("WMI action result does not match policy action_type")
    if action_result.invocation_method != policy.invocation_method:
        raise ValueError("WMI action result does not match policy invocation_method")
    if not isinstance(action_result.invoked_at_utc, datetime):
        raise TypeError("WMI A01 invocation time must be a datetime")
    if (
        action_result.invoked_at_utc.tzinfo is None
        or action_result.invoked_at_utc.utcoffset() is None
    ):
        raise ValueError("WMI A01 invocation time must include timezone information")
    if action_result.invoked_at_utc.utcoffset() != timedelta(0):
        raise ValueError("WMI A01 invocation time must be UTC")
    if isinstance(action_result.return_value, bool) or not isinstance(
        action_result.return_value,
        int,
    ):
        raise TypeError("WMI ReturnValue must be an integer")
    if action_result.return_value != policy.success_return_value:
        raise ValueError("WMI A01 did not succeed")
    if policy.require_process_id and (
        isinstance(action_result.process_id, bool)
        or not isinstance(action_result.process_id, int)
        or action_result.process_id < 1
    ):
        raise ValueError("WMI A01 must return a valid ProcessId")


def _validated_string_set(field_name: str, values: Iterable[str]) -> frozenset[str]:
    materialized = tuple(values)
    if any(not isinstance(value, str) or not value.strip() for value in materialized):
        raise ValueError(f"{field_name} must contain non-blank strings")
    return frozenset(materialized)


def _matches_reference_event(
    event: NormalizedEvent,
    policy: R1ReferencePolicy,
    lineage_process_guids: frozenset[str],
    action_result: R1WmiActionResult,
) -> bool:
    process = event.process
    return (
        event.source == policy.reference_source
        and event.source_layer == policy.reference_source_layer
        and event.event_type == policy.reference_event_type
        and process is not None
        and process.process_guid is not None
        and process.process_guid in lineage_process_guids
        and process.pid == action_result.process_id
        and process.parent_process_guid is not None
        and process.name is not None
        and process.name.casefold() == policy.reference_process_name.casefold()
    )


def _has_wmi_context_parent(
    candidate: NormalizedEvent,
    events: tuple[NormalizedEvent, ...],
    policy: R1ReferencePolicy,
    lineage_process_guids: frozenset[str],
) -> bool:
    process = candidate.process
    if process is None or process.parent_process_guid is None:
        return False
    return any(
        context.run_id == candidate.run_id
        and context.host_id == candidate.host_id
        and context.source == policy.reference_source
        and context.source_layer == policy.reference_source_layer
        and context.event_type == policy.reference_event_type
        and context.process is not None
        and context.process.process_guid == process.parent_process_guid
        and context.process.process_guid in lineage_process_guids
        and context.process.name is not None
        and context.process.name.casefold() == "wmiprvse.exe"
        for context in events
    )


def _validate_identity(field_name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string")
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")


def _validate_sysmon_record_id(event: NormalizedEvent) -> str:
    source_record_id = event.raw_ref.source_record_id
    if (
        not isinstance(source_record_id, str)
        or not source_record_id.isascii()
        or not source_record_id.isdecimal()
        or str(int(source_record_id)) != source_record_id
    ):
        raise ValueError("R1 reference raw_ref.source_record_id must be canonical decimal")
    if event.source_event_id != source_record_id:
        raise ValueError("R1 reference source_event_id must match raw_ref.source_record_id")
    return source_record_id


__all__ = [
    "DEFAULT_R1_REFERENCE_POLICIES_PATH",
    "R1_REFERENCE_POLICY_LOADER_VERSION",
    "R1ReferencePolicy",
    "R1ReferenceSelection",
    "R1WmiActionResult",
    "load_r1_reference_policies",
    "load_r1_reference_policy",
    "resolve_r1_wmi_reference",
    "validate_normal_reference_fields",
]
