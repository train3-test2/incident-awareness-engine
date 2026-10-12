"""R1 causal replay 실행 provenance를 별도 immutable artifact로 저장한다."""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_serializer,
    field_validator,
    model_validator,
)

from incident_awareness.common.models.fusion import (
    FusionResult,
    FusionStoppingTrace,
    _serialize_utc_milliseconds,
)
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
)
from incident_awareness.pipeline.r1_causal_availability import R1CausalPolicyIdentity

R1_CAUSAL_REPLAY_PROVENANCE_FILENAME = "r1_causal_replay_provenance.json"
R1_CAUSAL_FUSION_RESULT_FILENAME = "r1_causal_fusion_result.json"
R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME = "r1_causal_fusion_stopping_trace.json"
R1_CAUSAL_REPLAY_PROVENANCE_CONTRACT_VERSION = "v0.1"
R1_CAUSAL_AVAILABILITY_GATE_CONTRACT = "available_at <= replay_time"
R1_CAUSAL_REPLAY_ORDERING_CONTRACT = "(available_at, timestamp, evidence_id)"


class R1CausalReplayProvenance(BaseModel):
    """Role5가 causal replay 실행을 결정적으로 검증할 provenance다."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["v0.1"]
    run_id: StrictStr
    entity_id: StrictStr
    source_causal_envelope_contract_version: StrictStr
    source_evidence_artifact_sha256: StrictStr
    source_extraction_summary_sha256: StrictStr
    selector_policy_identity: R1CausalPolicyIdentity
    approved_policy_identity: R1CausalPolicyIdentity
    watermark_at: datetime
    watermark_basis: StrictStr
    availability_gate_contract: Literal["available_at <= replay_time"]
    replay_ordering_contract: Literal["(available_at, timestamp, evidence_id)"]
    replay_start: datetime
    replay_end: datetime
    step_size_sec: float = Field(gt=0)
    terminal_partial_tick: StrictBool
    evaluated_replay_points: tuple[datetime, ...] = Field(min_length=1)
    fusion_runtime_config: FusionRuntimeConfigSnapshot
    fusion_result_sha256: StrictStr
    fusion_stopping_trace_sha256: StrictStr
    fusion_status: Literal["detected", "miss", "not_evaluated"]
    fusion_time: datetime | None
    contributing_evidence_ids: tuple[StrictStr, ...]
    fusion_episode_ids: tuple[StrictStr, ...]
    execution_commit: StrictStr

    @field_validator(
        "run_id",
        "entity_id",
        "source_causal_envelope_contract_version",
        "watermark_basis",
        "execution_commit",
    )
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("causal replay provenance strings must be non-blank and unpadded")
        return value

    @field_validator("source_evidence_artifact_sha256", "source_extraction_summary_sha256")
    @classmethod
    def validate_source_hash(cls, value: str) -> str:
        return _validate_sha256(value)

    @field_validator("fusion_result_sha256", "fusion_stopping_trace_sha256")
    @classmethod
    def validate_output_hash(cls, value: str) -> str:
        return _validate_sha256(value)

    @field_validator(
        "watermark_at",
        "replay_start",
        "replay_end",
        "fusion_time",
        "evaluated_replay_points",
    )
    @classmethod
    def validate_utc_times(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            if item is None:
                continue
            if item.tzinfo is None or item.utcoffset() is None:
                raise ValueError("causal replay provenance times must include timezone information")
            if item.utcoffset() != timedelta(0):
                raise ValueError("causal replay provenance times must be UTC")
        return value

    @field_serializer(
        "watermark_at",
        "replay_start",
        "replay_end",
        "fusion_time",
        when_used="json",
    )
    def serialize_utc_time(self, value: datetime | None) -> str | None:
        return _serialize_utc_milliseconds(value)

    @field_serializer("evaluated_replay_points", when_used="json")
    def serialize_replay_points(self, values: tuple[datetime, ...]) -> tuple[str, ...]:
        serialized: list[str] = []
        for value in values:
            item = _serialize_utc_milliseconds(value)
            assert item is not None
            serialized.append(item)
        return tuple(serialized)

    @field_validator("evaluated_replay_points")
    @classmethod
    def validate_replay_points(
        cls,
        values: tuple[datetime, ...],
    ) -> tuple[datetime, ...]:
        if any(current <= previous for previous, current in pairwise(values)):
            raise ValueError("evaluated replay points must be strictly increasing")
        return values

    @model_validator(mode="after")
    def validate_contract(self) -> "R1CausalReplayProvenance":
        if self.replay_end < self.replay_start:
            raise ValueError("replay_end must not be earlier than replay_start")
        if self.evaluated_replay_points[0] != self.replay_start:
            raise ValueError("evaluated replay points must start at replay_start")
        if self.evaluated_replay_points[-1] != self.replay_end:
            raise ValueError("evaluated replay points must end at replay_end")
        if self.watermark_at != self.replay_end:
            raise ValueError("whole-episode watermark must match replay_end")
        if self.fusion_runtime_config.run_id != self.run_id:
            raise ValueError("Fusion runtime config run_id must match provenance run_id")
        if self.fusion_runtime_config.entity_id != self.entity_id:
            raise ValueError("Fusion runtime config entity_id must match provenance entity_id")
        if self.fusion_runtime_config.replay.step_size_sec != self.step_size_sec:
            raise ValueError("replay cadence must match the Fusion runtime config")
        step = timedelta(seconds=self.step_size_sec)
        expected_partial = (self.replay_end - self.replay_start) % step != timedelta(0)
        if self.terminal_partial_tick is not expected_partial:
            raise ValueError("terminal_partial_tick must describe the replay boundaries")
        replay_gaps = tuple(
            current - previous for previous, current in pairwise(self.evaluated_replay_points)
        )
        if replay_gaps:
            regular_gaps = replay_gaps[:-1] if self.terminal_partial_tick else replay_gaps
            if any(gap != step for gap in regular_gaps):
                raise ValueError("replay points must follow the configured cadence")
            if self.terminal_partial_tick and not timedelta(0) < replay_gaps[-1] < step:
                raise ValueError("terminal partial tick must be shorter than the cadence")
        if self.fusion_time is not None and self.fusion_time not in self.evaluated_replay_points:
            raise ValueError("fusion_time must be an evaluated causal replay point")
        if self.fusion_status == "detected" and self.fusion_time is None:
            raise ValueError("detected causal replay must include fusion_time")
        if self.fusion_status != "detected" and self.fusion_time is not None:
            raise ValueError("non-detected causal replay must not include fusion_time")
        if len(self.contributing_evidence_ids) != len(set(self.contributing_evidence_ids)):
            raise ValueError("contributing Evidence IDs must be unique")
        if len(self.fusion_episode_ids) != len(set(self.fusion_episode_ids)):
            raise ValueError("Fusion episode IDs must be unique")
        return self


@dataclass(frozen=True, slots=True)
class R1CausalReplayProvenanceArtifact:
    provenance: R1CausalReplayProvenance
    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class R1CausalReplayModelArtifact:
    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class R1CausalReplayArtifactSet:
    fusion_result: R1CausalReplayModelArtifact
    fusion_stopping_trace: R1CausalReplayModelArtifact
    provenance: R1CausalReplayProvenanceArtifact


@dataclass(frozen=True, slots=True)
class R1CausalReplayArtifactRun:
    fusion_result: FusionResult
    fusion_stopping_trace: FusionStoppingTrace
    provenance: R1CausalReplayProvenance


def serialize_r1_causal_replay_provenance(
    provenance: R1CausalReplayProvenance,
) -> bytes:
    """동일 provenance를 항상 같은 UTF-8 JSON bytes로 직렬화한다."""
    if not isinstance(provenance, R1CausalReplayProvenance):
        raise TypeError("provenance must be an R1CausalReplayProvenance")
    return _serialize_canonical_model(provenance)


def canonical_model_sha256(model: BaseModel) -> str:
    """검증된 Pydantic output과 provenance를 연결하는 canonical hash다."""
    return hashlib.sha256(_serialize_canonical_model(model)).hexdigest()


def serialize_r1_causal_fusion_result(fusion_result: FusionResult) -> bytes:
    if not isinstance(fusion_result, FusionResult):
        raise TypeError("fusion_result must be a FusionResult")
    return _serialize_canonical_model(fusion_result)


def serialize_r1_causal_fusion_stopping_trace(
    stopping_trace: FusionStoppingTrace,
) -> bytes:
    if not isinstance(stopping_trace, FusionStoppingTrace):
        raise TypeError("stopping_trace must be a FusionStoppingTrace")
    return _serialize_canonical_model(stopping_trace)


def write_r1_causal_replay_provenance(
    provenance: R1CausalReplayProvenance,
    *,
    output_directory: Path,
) -> R1CausalReplayProvenanceArtifact:
    """기존 파일을 덮어쓰지 않고 causal replay provenance를 게시한다."""
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a Path")
    if not output_directory.is_dir():
        raise ValueError(f"output_directory must be an existing directory: {output_directory}")
    content = serialize_r1_causal_replay_provenance(provenance)
    target = output_directory / R1_CAUSAL_REPLAY_PROVENANCE_FILENAME
    _publish_files(((target, content),))

    return R1CausalReplayProvenanceArtifact(
        provenance=provenance,
        path=target,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def write_r1_causal_replay_artifacts(
    fusion_result: FusionResult,
    stopping_trace: FusionStoppingTrace,
    provenance: R1CausalReplayProvenance,
    *,
    output_directory: Path,
) -> R1CausalReplayArtifactSet:
    """Fusion outputs 다음 provenance를 완료 표식으로 immutable 게시한다."""
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a Path")
    if not output_directory.is_dir():
        raise ValueError(f"output_directory must be an existing directory: {output_directory}")

    fusion_result_content = serialize_r1_causal_fusion_result(fusion_result)
    stopping_trace_content = serialize_r1_causal_fusion_stopping_trace(stopping_trace)
    if hashlib.sha256(fusion_result_content).hexdigest() != provenance.fusion_result_sha256:
        raise ValueError("FusionResult bytes do not match replay provenance")
    if (
        hashlib.sha256(stopping_trace_content).hexdigest()
        != provenance.fusion_stopping_trace_sha256
    ):
        raise ValueError("FusionStoppingTrace bytes do not match replay provenance")

    provenance_content = serialize_r1_causal_replay_provenance(provenance)
    fusion_result_path = output_directory / R1_CAUSAL_FUSION_RESULT_FILENAME
    stopping_trace_path = output_directory / R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME
    provenance_path = output_directory / R1_CAUSAL_REPLAY_PROVENANCE_FILENAME
    _publish_files(
        (
            (fusion_result_path, fusion_result_content),
            (stopping_trace_path, stopping_trace_content),
            (provenance_path, provenance_content),
        )
    )
    return R1CausalReplayArtifactSet(
        fusion_result=R1CausalReplayModelArtifact(
            path=fusion_result_path,
            sha256=hashlib.sha256(fusion_result_content).hexdigest(),
        ),
        fusion_stopping_trace=R1CausalReplayModelArtifact(
            path=stopping_trace_path,
            sha256=hashlib.sha256(stopping_trace_content).hexdigest(),
        ),
        provenance=R1CausalReplayProvenanceArtifact(
            provenance=provenance,
            path=provenance_path,
            sha256=hashlib.sha256(provenance_content).hexdigest(),
        ),
    )


def load_r1_causal_replay_provenance(
    artifact_path: Path,
) -> R1CausalReplayProvenance:
    """별도 causal replay provenance artifact를 strict model로 읽는다."""
    if not isinstance(artifact_path, Path):
        raise TypeError("artifact_path must be a Path")
    return R1CausalReplayProvenance.model_validate_json(
        artifact_path.read_bytes(),
        strict=True,
    )


def load_r1_causal_replay_artifacts(
    output_directory: Path,
) -> R1CausalReplayArtifactRun:
    """저장된 Fusion outputs와 provenance의 canonical hash 연결을 검증한다."""
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a Path")
    fusion_result_content = (output_directory / R1_CAUSAL_FUSION_RESULT_FILENAME).read_bytes()
    stopping_trace_content = (
        output_directory / R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME
    ).read_bytes()
    provenance_content = (output_directory / R1_CAUSAL_REPLAY_PROVENANCE_FILENAME).read_bytes()
    fusion_result = FusionResult.model_validate_json(fusion_result_content)
    stopping_trace = FusionStoppingTrace.model_validate_json(stopping_trace_content)
    provenance = R1CausalReplayProvenance.model_validate_json(provenance_content, strict=True)
    if hashlib.sha256(fusion_result_content).hexdigest() != provenance.fusion_result_sha256:
        raise ValueError("stored FusionResult SHA-256 does not match replay provenance")
    if (
        hashlib.sha256(stopping_trace_content).hexdigest()
        != provenance.fusion_stopping_trace_sha256
    ):
        raise ValueError("stored FusionStoppingTrace SHA-256 does not match replay provenance")
    return R1CausalReplayArtifactRun(
        fusion_result=fusion_result,
        fusion_stopping_trace=stopping_trace,
        provenance=provenance,
    )


def _validate_sha256(value: str) -> str:
    if len(value) != 64 or set(value) - frozenset("0123456789abcdef"):
        raise ValueError("artifact hashes must be lowercase SHA-256")
    return value


def _serialize_canonical_model(model: BaseModel) -> bytes:
    payload = model.model_dump(mode="json")
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _publish_files(files: tuple[tuple[Path, bytes], ...]) -> None:
    """기존 파일을 덮어쓰지 않고 마지막 파일을 완료 표식으로 게시한다."""
    if any(target.exists() for target, _ in files):
        existing = next(target for target, _ in files if target.exists())
        raise FileExistsError(f"R1 causal replay artifact already exists: {existing.name}")

    staged: list[Path] = []
    published: list[tuple[Path, Path]] = []
    try:
        for target, content in files:
            with tempfile.NamedTemporaryFile(
                dir=target.parent,
                prefix=f".{target.name}.",
                delete=False,
            ) as temporary:
                temporary.write(content)
                staged.append(Path(temporary.name))
        for source, (target, _) in zip(staged, files, strict=True):
            os.link(source, target)
            published.append((source, target))
    except BaseException:
        for source, target in reversed(published):
            try:
                if os.path.samestat(source.stat(), target.lstat()):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for source in staged:
            source.unlink(missing_ok=True)


__all__ = [
    "R1_CAUSAL_AVAILABILITY_GATE_CONTRACT",
    "R1_CAUSAL_FUSION_RESULT_FILENAME",
    "R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME",
    "R1_CAUSAL_REPLAY_ORDERING_CONTRACT",
    "R1_CAUSAL_REPLAY_PROVENANCE_CONTRACT_VERSION",
    "R1_CAUSAL_REPLAY_PROVENANCE_FILENAME",
    "R1CausalReplayArtifactRun",
    "R1CausalReplayArtifactSet",
    "R1CausalReplayModelArtifact",
    "R1CausalReplayProvenance",
    "R1CausalReplayProvenanceArtifact",
    "canonical_model_sha256",
    "load_r1_causal_replay_artifacts",
    "load_r1_causal_replay_provenance",
    "serialize_r1_causal_fusion_result",
    "serialize_r1_causal_fusion_stopping_trace",
    "serialize_r1_causal_replay_provenance",
    "write_r1_causal_replay_artifacts",
    "write_r1_causal_replay_provenance",
]
