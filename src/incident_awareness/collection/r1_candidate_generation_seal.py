"""R1 family별 terminal 후보 생성 종료 seal 계약.

이 모듈은 Role4 시나리오 경계와 Role3 ``run_closed``를 결속한다. Seal은
telemetry completeness를 스스로 선언하지 않으며, 둘 중 하나만으로 Evidence를
확정해서는 안 된다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver

from incident_awareness.collection.r1_pair_identity import validate_family_id
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.r1_stream import R1FinalPartitionWatermark, R1RunClosed
from incident_awareness.common.models.run import RunMetadata, RunType

DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH = (
    Path(__file__).parents[3] / "configs" / "r1_candidate_generation_policies_v0.1.yaml"
)
R1_CANDIDATE_GENERATION_SEAL_SCHEMA = "r1-candidate-generation-seal"
R1_CANDIDATE_GENERATION_SEAL_CONTRACT_VERSION = "v0.1"


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


class _BoundaryActionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: StrictStr = Field(min_length=1)
    step: StrictStr = Field(min_length=1)
    action_type: StrictStr = Field(min_length=1)

    @field_validator("action_id", "step", "action_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("boundary action identifier", value)


class _OwnedProcessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: StrictStr = Field(min_length=1)
    image: StrictStr = Field(min_length=1)

    @field_validator("role", "image")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("owned process policy value", value)


class _CandidateGenerationPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: StrictStr = Field(min_length=1)
    version: StrictStr = Field(min_length=1)
    family_id: StrictStr = Field(min_length=1)
    normal_boundary: _BoundaryActionConfig
    attack_boundary: _BoundaryActionConfig
    normal_owned_processes: tuple[_OwnedProcessConfig, ...] = Field(min_length=1)
    attack_owned_processes: tuple[_OwnedProcessConfig, ...] = Field(min_length=1)
    accepted_terminal_states: tuple[StrictStr, ...] = Field(min_length=1)
    forbid_all_actions_after_boundary: Literal[True]
    protected_non_owned_process_names: tuple[StrictStr, ...]

    @field_validator("policy_id", "version")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _validate_unpadded("candidate-generation policy identity", value)

    @field_validator("family_id")
    @classmethod
    def validate_family(cls, value: str) -> str:
        return validate_family_id(value)

    @field_validator(
        "accepted_terminal_states",
        "protected_non_owned_process_names",
    )
    @classmethod
    def validate_unique_strings(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_unpadded("policy list value", value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("candidate-generation policy lists must not contain duplicates")
        return normalized

    @field_validator("normal_owned_processes", "attack_owned_processes")
    @classmethod
    def validate_owned_processes(
        cls,
        values: tuple[_OwnedProcessConfig, ...],
    ) -> tuple[_OwnedProcessConfig, ...]:
        roles = tuple(value.role for value in values)
        images = tuple(_image_basename(value.image) for value in values)
        if len(roles) != len(set(roles)):
            raise ValueError("owned process policies must not contain duplicate roles")
        if len(images) != len(set(images)):
            raise ValueError("owned process policies must not contain duplicate images")
        return values


class _CandidateGenerationPolicyRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal["v0.1"]
    policies: tuple[_CandidateGenerationPolicyConfig, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class R1CandidateGenerationPolicy:
    """검증된 family-bound candidate-generation seal policy."""

    config_path: Path
    canonical_path: str
    config_hash: str
    policy_id: str
    version: str
    family_id: str
    normal_boundary: _BoundaryActionConfig
    attack_boundary: _BoundaryActionConfig
    normal_owned_processes: tuple[_OwnedProcessConfig, ...]
    attack_owned_processes: tuple[_OwnedProcessConfig, ...]
    accepted_terminal_states: tuple[str, ...]
    forbid_all_actions_after_boundary: bool
    protected_non_owned_process_names: tuple[str, ...]


class R1ScenarioAction(BaseModel):
    """Seal 검증에 필요한 versioned scenario action의 최소 표현."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: StrictStr = Field(min_length=1)
    step: StrictStr = Field(min_length=1)
    action_type: StrictStr = Field(min_length=1)
    offset_sec: int = Field(strict=True, ge=0)

    @field_validator("action_id", "step", "action_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("scenario action identifier", value)


class R1OwnedProcessTermination(BaseModel):
    """Run 소유 프로세스가 candidate boundary에서 종료됐다는 증명."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: StrictStr = Field(min_length=1)
    image: StrictStr = Field(min_length=1)
    process_guid: StrictStr = Field(min_length=1)
    terminal_state: StrictStr = Field(min_length=1)

    @field_validator("role", "image", "process_guid", "terminal_state")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("owned process value", value)


class R1CandidateBoundaryAttestation(BaseModel):
    """Role4가 scenario 실행 결과에서 만든 candidate-generation 경계 증명."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: StrictStr = Field(min_length=1)
    step: StrictStr = Field(min_length=1)
    action_type: StrictStr = Field(min_length=1)
    completed_at: datetime
    no_actions_after_boundary: Literal[True]
    owned_processes: tuple[R1OwnedProcessTermination, ...] = Field(min_length=1)

    @field_validator("action_id", "step", "action_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("boundary attestation identifier", value)

    @field_validator("completed_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime("boundary completed_at", value)

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _validate_utc_milliseconds("boundary completed_at", value)

    @model_validator(mode="after")
    def validate_owned_process_identity(self) -> R1CandidateBoundaryAttestation:
        roles = tuple(process.role for process in self.owned_processes)
        guids = tuple(process.process_guid.casefold() for process in self.owned_processes)
        if len(roles) != len(set(roles)):
            raise ValueError("owned_processes must not contain duplicate roles")
        if len(guids) != len(set(guids)):
            raise ValueError("owned_processes must not contain duplicate ProcessGuid values")
        return self


class R1CandidateBoundaryCompletion(BaseModel):
    """Run 소유 프로세스 정리가 실제로 끝난 시각의 Role4 증명."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: StrictStr = Field(min_length=1)
    action_id: StrictStr = Field(min_length=1)
    step: StrictStr = Field(min_length=1)
    action_type: StrictStr = Field(min_length=1)
    action_started_at: datetime
    completed_at: datetime
    completion_source: Literal[
        "wmi_run_end.completed_utc",
        "remote_session.close_completed_at",
    ]

    @field_validator("run_id", "action_id", "step", "action_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("boundary completion identity", value)

    @field_validator("action_started_at", "completed_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime("boundary completion timestamp", value)

    @field_validator("action_started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_milliseconds("boundary completion timestamp", value)

    @model_validator(mode="after")
    def validate_order(self) -> R1CandidateBoundaryCompletion:
        if self.completed_at < self.action_started_at:
            raise ValueError("boundary completion cannot precede its action start")
        return self


class R1CandidatePolicyIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: StrictStr = Field(min_length=1)
    version: StrictStr = Field(min_length=1)
    config_hash: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    config_path: StrictStr = Field(min_length=1)

    @field_validator("policy_id", "version", "config_path")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_unpadded("candidate policy provenance", value)


class R1CandidateGenerationSeal(BaseModel):
    """Role4 boundary와 accepted Role3 run close를 결속하는 immutable message."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_name=True,
        serialize_by_alias=True,
    )

    schema_id: Literal["r1-candidate-generation-seal"] = Field(
        validation_alias="schema",
        serialization_alias="schema",
    )
    contract_version: Literal["v0.1"]
    message_type: Literal["candidate_generation_seal"]
    seal_id: StrictStr = Field(min_length=1)
    run_id: StrictStr = Field(min_length=1)
    family_id: StrictStr = Field(min_length=1)
    run_type: RunType
    input_close_id: StrictStr = Field(min_length=1)
    sealed_partitions: tuple[R1FinalPartitionWatermark, ...] = Field(min_length=1)
    candidate_policy: R1CandidatePolicyIdentity
    boundary: R1CandidateBoundaryAttestation
    emitted_at: datetime

    @field_validator("seal_id", "input_close_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _validate_unpadded("candidate-generation seal identity", value)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        RunMetadata.validate_required_identifier(value)
        return RunMetadata.validate_run_id(value)

    @field_validator("family_id")
    @classmethod
    def validate_family(cls, value: str) -> str:
        return validate_family_id(value)

    @field_validator("emitted_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime("seal emitted_at", value)

    @field_validator("emitted_at")
    @classmethod
    def validate_emitted_at(cls, value: datetime) -> datetime:
        return _validate_utc_milliseconds("seal emitted_at", value)

    @model_validator(mode="after")
    def validate_scope(self) -> R1CandidateGenerationSeal:
        partitions = tuple(_partition_key(item) for item in self.sealed_partitions)
        if len(partitions) != len(set(partitions)):
            raise ValueError("sealed_partitions must not contain duplicate partitions")
        if any(item.partition.run_id != self.run_id for item in self.sealed_partitions):
            raise ValueError("every sealed partition run_id must match seal run_id")
        if self.emitted_at < self.boundary.completed_at:
            raise ValueError("seal emitted_at must not precede boundary completion")
        return self


class R1VerifiedCandidateBoundary(BaseModel):
    """Role4 검증 뒤 Role2에 전달하는 Ground Truth 비포함 경계."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: StrictStr = Field(min_length=1)
    seal_id: StrictStr = Field(min_length=1)
    input_close_id: StrictStr = Field(min_length=1)
    candidate_boundary_at: datetime
    verified_seal_at: datetime

    @field_validator("run_id", "seal_id", "input_close_id")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _validate_unpadded("verified boundary identity", value)

    @field_validator("candidate_boundary_at", "verified_seal_at", mode="before")
    @classmethod
    def reject_numeric_datetime(cls, value: object) -> object:
        return _reject_numeric_datetime("verified boundary timestamp", value)

    @field_validator("candidate_boundary_at", "verified_seal_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _validate_utc_milliseconds("verified boundary timestamp", value)


@dataclass(frozen=True, slots=True)
class R1CandidateCloseResolution:
    """Ground Truth 없이 검증된 경계 또는 whole-episode fallback을 반환한다."""

    mode: Literal["verified_seal", "authoritative_run_end_fallback"]
    candidate_boundary_at: datetime
    verified_seal_at: datetime | None
    diagnostics: tuple[str, ...]
    verified_boundary: R1VerifiedCandidateBoundary | None


def load_r1_candidate_generation_policies(
    config_path: Path = DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH,
) -> tuple[R1CandidateGenerationPolicy, ...]:
    """Strict registry의 모든 candidate-generation policy를 반환한다."""
    registry = _load_registry(config_path)
    identities: set[tuple[str, str]] = set()
    result: list[R1CandidateGenerationPolicy] = []
    for config in registry.policies:
        identity = (config.policy_id, config.version)
        if identity in identities:
            raise ValueError("candidate-generation policy identities must be unique")
        identities.add(identity)
        result.append(_build_policy(config_path, config))
    return tuple(result)


def load_r1_candidate_generation_policy(
    policy_id: str,
    version: str,
    *,
    config_path: Path = DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH,
) -> R1CandidateGenerationPolicy:
    """정확한 ID와 version의 candidate-generation policy를 반환한다."""
    validated_policy_id = _validate_text_identity("policy_id", policy_id)
    validated_version = _validate_text_identity("version", version)
    for policy in load_r1_candidate_generation_policies(config_path):
        if policy.policy_id == validated_policy_id and policy.version == validated_version:
            return policy
    raise ValueError(
        f"R1 candidate-generation policy was not found: {validated_policy_id}/{validated_version}"
    )


def issue_r1_candidate_generation_seal(
    *,
    seal_id: str,
    run_metadata: RunMetadata,
    run_closed: R1RunClosed,
    scenario_actions: tuple[R1ScenarioAction, ...],
    boundary: R1CandidateBoundaryAttestation,
    boundary_action_record: ExecutionRecordRow,
    boundary_completion: R1CandidateBoundaryCompletion,
    policy: R1CandidateGenerationPolicy,
    emitted_at: datetime,
) -> R1CandidateGenerationSeal:
    """Scenario 경계와 accepted ``run_closed``를 모두 받아야 seal을 발급한다."""
    _validate_run_binding(run_metadata, run_closed, policy)
    expected_boundary = (
        policy.attack_boundary
        if run_metadata.run_type is RunType.ATTACK
        else policy.normal_boundary
    )
    _validate_scenario_boundary(scenario_actions, expected_boundary)
    expected_processes = (
        policy.attack_owned_processes
        if run_metadata.run_type is RunType.ATTACK
        else policy.normal_owned_processes
    )
    _validate_boundary_attestation(boundary, expected_boundary, expected_processes, policy)
    _validate_boundary_action_completion(
        boundary,
        scenario_actions[-1],
        boundary_action_record,
        boundary_completion,
        run_metadata,
    )
    emitted = _validate_utc_milliseconds("seal emitted_at", emitted_at)
    if emitted < run_closed.emitted_at:
        raise ValueError("seal cannot be emitted before the accepted run_closed")

    seal = R1CandidateGenerationSeal(
        schema=R1_CANDIDATE_GENERATION_SEAL_SCHEMA,
        contract_version=R1_CANDIDATE_GENERATION_SEAL_CONTRACT_VERSION,
        message_type="candidate_generation_seal",
        seal_id=seal_id,
        run_id=run_metadata.run_id,
        family_id=policy.family_id,
        run_type=run_metadata.run_type,
        input_close_id=run_closed.close_id,
        sealed_partitions=run_closed.final_watermarks,
        candidate_policy=R1CandidatePolicyIdentity(
            policy_id=policy.policy_id,
            version=policy.version,
            config_hash=policy.config_hash,
            config_path=policy.canonical_path,
        ),
        boundary=boundary,
        emitted_at=emitted,
    )
    validate_r1_candidate_generation_seal_binding(
        seal,
        run_metadata=run_metadata,
        run_closed=run_closed,
        scenario_actions=scenario_actions,
        boundary_action_record=boundary_action_record,
        boundary_completion=boundary_completion,
        policy=policy,
    )
    return seal


def validate_r1_candidate_generation_seal_binding(
    seal: R1CandidateGenerationSeal,
    *,
    run_metadata: RunMetadata,
    run_closed: R1RunClosed,
    scenario_actions: tuple[R1ScenarioAction, ...],
    boundary_action_record: ExecutionRecordRow,
    boundary_completion: R1CandidateBoundaryCompletion,
    policy: R1CandidateGenerationPolicy,
) -> R1VerifiedCandidateBoundary:
    """Role4에서 Ground Truth 결속을 검증하고 비정답 경계만 반환한다."""
    _validate_run_binding(run_metadata, run_closed, policy)
    if seal.run_id != run_closed.run_id:
        raise ValueError("seal run_id does not match run_closed")
    if seal.run_type is not run_metadata.run_type:
        raise ValueError("seal run_type does not match RunMetadata")
    if seal.input_close_id != run_closed.close_id:
        raise ValueError("seal input_close_id does not match run_closed")
    if seal.sealed_partitions != run_closed.final_watermarks:
        raise ValueError("seal final watermark references do not exactly match run_closed")
    if any(
        watermark.watermark_at < seal.boundary.completed_at for watermark in seal.sealed_partitions
    ):
        raise ValueError("every final watermark must cover the candidate-generation boundary")
    expected_identity = (
        policy.policy_id,
        policy.version,
        policy.config_hash,
        policy.canonical_path,
    )
    actual_identity = (
        seal.candidate_policy.policy_id,
        seal.candidate_policy.version,
        seal.candidate_policy.config_hash,
        seal.candidate_policy.config_path,
    )
    if actual_identity != expected_identity:
        raise ValueError("seal candidate policy identity does not match registered policy")
    if seal.family_id != policy.family_id:
        raise ValueError("seal family_id does not match candidate-generation policy")
    expected_boundary = (
        policy.attack_boundary if seal.run_type is RunType.ATTACK else policy.normal_boundary
    )
    _validate_scenario_boundary(scenario_actions, expected_boundary)
    expected_processes = (
        policy.attack_owned_processes
        if seal.run_type is RunType.ATTACK
        else policy.normal_owned_processes
    )
    _validate_boundary_attestation(
        seal.boundary,
        expected_boundary,
        expected_processes,
        policy,
    )
    _validate_boundary_action_completion(
        seal.boundary,
        scenario_actions[-1],
        boundary_action_record,
        boundary_completion,
        run_metadata,
    )
    _validate_boundary_within_run(seal.boundary, run_metadata)
    if seal.emitted_at < run_closed.emitted_at:
        raise ValueError("seal emitted_at must not precede run_closed")
    return R1VerifiedCandidateBoundary(
        run_id=seal.run_id,
        seal_id=seal.seal_id,
        input_close_id=seal.input_close_id,
        candidate_boundary_at=seal.boundary.completed_at,
        verified_seal_at=seal.emitted_at,
    )


def resolve_r1_candidate_close(
    *,
    authoritative_run_end: datetime | None,
    verified_boundary: R1VerifiedCandidateBoundary | None,
    validation_diagnostics: tuple[str, ...] = (),
) -> R1CandidateCloseResolution:
    """Role2 runtime에서 Ground Truth 없이 후보 close 시각만 결정한다."""
    if verified_boundary is not None:
        return R1CandidateCloseResolution(
            mode="verified_seal",
            candidate_boundary_at=verified_boundary.candidate_boundary_at,
            verified_seal_at=verified_boundary.verified_seal_at,
            diagnostics=(),
            verified_boundary=verified_boundary,
        )

    diagnostics = validation_diagnostics or ("verified candidate-generation boundary is absent",)
    if authoritative_run_end is None:
        raise ValueError(
            "authoritative RunMetadata.end_time is required when verified seal close is unavailable"
        )
    validated_run_end = _validate_utc_milliseconds(
        "authoritative RunMetadata.end_time",
        authoritative_run_end,
    )
    return R1CandidateCloseResolution(
        mode="authoritative_run_end_fallback",
        candidate_boundary_at=validated_run_end,
        verified_seal_at=None,
        diagnostics=tuple(diagnostics),
        verified_boundary=None,
    )


def candidate_generation_seal_sha256(seal: R1CandidateGenerationSeal) -> str:
    """재전달 identity 충돌 판정에 사용할 canonical content hash."""
    return _canonical_sha256(seal.model_dump(mode="json", by_alias=True))


def validate_r1_candidate_generation_seal_replay(
    existing: R1CandidateGenerationSeal,
    incoming: R1CandidateGenerationSeal,
) -> None:
    """같은 seal identity가 다른 content로 재사용되면 거부한다."""
    if existing.run_id != incoming.run_id or existing.seal_id != incoming.seal_id:
        raise ValueError("candidate-generation seal replay identity does not match")
    if candidate_generation_seal_sha256(existing) != candidate_generation_seal_sha256(incoming):
        raise ValueError("candidate-generation seal identity was reused with different content")


def write_r1_candidate_generation_seal(path: Path, seal: R1CandidateGenerationSeal) -> None:
    """Seal을 exclusive create로 기록해 기존 identity를 덮어쓰지 않는다."""
    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    payload = seal.model_dump(mode="json", by_alias=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def load_r1_candidate_generation_seal(path: Path) -> R1CandidateGenerationSeal:
    """Duplicate JSON key와 schema drift를 거부하며 seal을 읽는다."""
    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("R1 candidate-generation seal is not valid UTF-8 JSON") from error
    try:
        return R1CandidateGenerationSeal.model_validate(payload)
    except ValidationError as error:
        raise ValueError("R1 candidate-generation seal does not match v0.1") from error


def _load_registry(config_path: Path) -> _CandidateGenerationPolicyRegistry:
    if not isinstance(config_path, Path):
        raise TypeError("config_path must be a Path")
    if not config_path.is_file():
        raise FileNotFoundError(
            f"R1 candidate-generation policy config was not found: {config_path}"
        )
    try:
        payload = yaml.load(config_path.read_text(encoding="utf-8"), Loader=_UniqueKeySafeLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ValueError("R1 candidate-generation policy config is not valid YAML") from error
    try:
        return _CandidateGenerationPolicyRegistry.model_validate(payload)
    except ValidationError as error:
        raise ValueError("R1 candidate-generation policy config does not match v0.1") from error


def _build_policy(
    config_path: Path,
    config: _CandidateGenerationPolicyConfig,
) -> R1CandidateGenerationPolicy:
    payload = config.model_dump(mode="json")
    return R1CandidateGenerationPolicy(
        config_path=config_path.resolve(),
        canonical_path=_canonical_config_path(config_path, config),
        config_hash=_canonical_sha256(payload),
        policy_id=config.policy_id,
        version=config.version,
        family_id=config.family_id,
        normal_boundary=config.normal_boundary,
        attack_boundary=config.attack_boundary,
        normal_owned_processes=config.normal_owned_processes,
        attack_owned_processes=config.attack_owned_processes,
        accepted_terminal_states=config.accepted_terminal_states,
        forbid_all_actions_after_boundary=config.forbid_all_actions_after_boundary,
        protected_non_owned_process_names=config.protected_non_owned_process_names,
    )


def _canonical_config_path(path: Path, config: _CandidateGenerationPolicyConfig) -> str:
    resolved = path.resolve()
    repository_root = Path(__file__).parents[3].resolve()
    try:
        return resolved.relative_to(repository_root).as_posix()
    except ValueError:
        digest = _canonical_sha256(config.model_dump(mode="json"))
        return f"external-policy:{config.policy_id}/{config.version}@{digest}"


def _validate_run_binding(
    run_metadata: RunMetadata,
    run_closed: R1RunClosed,
    policy: R1CandidateGenerationPolicy,
) -> None:
    if run_metadata.run_id != run_closed.run_id:
        raise ValueError("RunMetadata run_id does not match run_closed")
    if run_metadata.family_id != policy.family_id:
        raise ValueError("RunMetadata family_id does not match candidate-generation policy")


def _validate_scenario_boundary(
    actions: tuple[R1ScenarioAction, ...],
    expected: _BoundaryActionConfig,
) -> None:
    if not actions:
        raise ValueError("scenario actions must not be empty")
    identities = tuple(action.action_id for action in actions)
    if len(identities) != len(set(identities)):
        raise ValueError("scenario action IDs must be unique")
    offsets = tuple(action.offset_sec for action in actions)
    if offsets != tuple(sorted(offsets)):
        raise ValueError("scenario actions must be ordered by non-decreasing offset")
    last = actions[-1]
    if (last.action_id, last.step, last.action_type) != (
        expected.action_id,
        expected.step,
        expected.action_type,
    ):
        raise ValueError("candidate-generation boundary must be the final scenario action")


def _validate_boundary_attestation(
    boundary: R1CandidateBoundaryAttestation,
    expected: _BoundaryActionConfig,
    expected_processes: tuple[_OwnedProcessConfig, ...],
    policy: R1CandidateGenerationPolicy,
) -> None:
    if (boundary.action_id, boundary.step, boundary.action_type) != (
        expected.action_id,
        expected.step,
        expected.action_type,
    ):
        raise ValueError("boundary attestation does not match family policy")
    protected = {name.casefold() for name in policy.protected_non_owned_process_names}
    if any(_image_basename(process.image) in protected for process in boundary.owned_processes):
        raise ValueError("protected non-owned process must not be claimed or terminated by the Run")
    expected_by_role = {
        process.role: _image_basename(process.image) for process in expected_processes
    }
    actual_by_role = {
        process.role: _image_basename(process.image) for process in boundary.owned_processes
    }
    if actual_by_role != expected_by_role:
        raise ValueError("boundary attestation does not match the expected run-owned processes")
    accepted_states = set(policy.accepted_terminal_states)
    if any(process.terminal_state not in accepted_states for process in boundary.owned_processes):
        raise ValueError("run-owned process is not in an accepted terminal state")


def _validate_boundary_within_run(
    boundary: R1CandidateBoundaryAttestation,
    run_metadata: RunMetadata,
) -> None:
    if boundary.completed_at < run_metadata.start_time:
        raise ValueError("candidate-generation boundary precedes RunMetadata.start_time")
    if run_metadata.end_time is not None and boundary.completed_at > run_metadata.end_time:
        raise ValueError("candidate-generation boundary exceeds RunMetadata.end_time")


def _validate_boundary_action_completion(
    boundary: R1CandidateBoundaryAttestation,
    scenario_boundary: R1ScenarioAction,
    action_record: ExecutionRecordRow,
    completion: R1CandidateBoundaryCompletion,
    run_metadata: RunMetadata,
) -> None:
    if action_record.run_id != run_metadata.run_id:
        raise ValueError("boundary action record run_id does not match RunMetadata")
    if (action_record.action_id, action_record.action_type) != (
        scenario_boundary.action_id,
        scenario_boundary.action_type,
    ):
        raise ValueError("boundary action record does not match the final scenario action")
    if completion.run_id != run_metadata.run_id:
        raise ValueError("boundary completion run_id does not match RunMetadata")
    if (completion.action_id, completion.step, completion.action_type) != (
        scenario_boundary.action_id,
        scenario_boundary.step,
        scenario_boundary.action_type,
    ):
        raise ValueError("boundary completion does not match the final scenario action")
    expected_source = (
        "wmi_run_end.completed_utc"
        if run_metadata.family_id == "wmi_management"
        else "remote_session.close_completed_at"
    )
    if completion.completion_source != expected_source:
        raise ValueError("boundary completion source does not match the scenario family")
    if action_record.timestamp != completion.action_started_at:
        raise ValueError("boundary action record does not match the actual action start")
    if boundary.completed_at != completion.completed_at:
        raise ValueError("boundary completed_at does not match the actual completion proof")
    planned_not_before = run_metadata.start_time + timedelta(seconds=scenario_boundary.offset_sec)
    if action_record.timestamp < planned_not_before:
        raise ValueError("candidate-generation boundary action precedes its planned action offset")


def _partition_key(watermark: R1FinalPartitionWatermark) -> tuple[str, str, str, str]:
    partition = watermark.partition
    return partition.run_id, partition.host_id, partition.source, partition.source_channel


def _image_basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _validate_unpadded(field: str, value: str) -> str:
    if value != value.strip() or not value:
        raise ValueError(f"{field} must be non-blank without surrounding whitespace")
    return value


def _validate_text_identity(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return _validate_unpadded(field, value)


def _reject_numeric_datetime(field: str, value: object) -> object:
    if isinstance(value, int | float) or (isinstance(value, str) and _is_numeric_string(value)):
        raise ValueError(f"{field} must not be a numeric Unix timestamp")
    return value


def _validate_utc_milliseconds(field: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be UTC")
    if value.microsecond % 1000 != 0:
        raise ValueError(f"{field} must use millisecond precision")
    return value.astimezone(UTC)


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_numeric_string(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


__all__ = [
    "DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH",
    "R1_CANDIDATE_GENERATION_SEAL_CONTRACT_VERSION",
    "R1_CANDIDATE_GENERATION_SEAL_SCHEMA",
    "R1CandidateBoundaryAttestation",
    "R1CandidateBoundaryCompletion",
    "R1CandidateCloseResolution",
    "R1CandidateGenerationPolicy",
    "R1CandidateGenerationSeal",
    "R1CandidatePolicyIdentity",
    "R1OwnedProcessTermination",
    "R1ScenarioAction",
    "R1VerifiedCandidateBoundary",
    "candidate_generation_seal_sha256",
    "issue_r1_candidate_generation_seal",
    "load_r1_candidate_generation_policies",
    "load_r1_candidate_generation_policy",
    "load_r1_candidate_generation_seal",
    "resolve_r1_candidate_close",
    "validate_r1_candidate_generation_seal_binding",
    "validate_r1_candidate_generation_seal_replay",
    "write_r1_candidate_generation_seal",
]
