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
    field_validator,
    model_validator,
)

from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
)
from incident_awareness.pipeline.r1_causal_availability import R1CausalPolicyIdentity

R1_CAUSAL_REPLAY_PROVENANCE_FILENAME = "r1_causal_replay_provenance.json"
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


def serialize_r1_causal_replay_provenance(
    provenance: R1CausalReplayProvenance,
) -> bytes:
    """동일 provenance를 항상 같은 UTF-8 JSON bytes로 직렬화한다."""
    if not isinstance(provenance, R1CausalReplayProvenance):
        raise TypeError("provenance must be an R1CausalReplayProvenance")
    payload = provenance.model_dump(mode="json")
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def canonical_model_sha256(model: BaseModel) -> str:
    """검증된 Pydantic output과 provenance를 연결하는 canonical hash다."""
    payload = model.model_dump(mode="json")
    content = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


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
    if target.exists():
        raise FileExistsError(f"R1 causal replay artifact already exists: {target.name}")

    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            staged = Path(temporary.name)
        os.link(staged, target)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)

    return R1CausalReplayProvenanceArtifact(
        provenance=provenance,
        path=target,
        sha256=hashlib.sha256(content).hexdigest(),
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


def _validate_sha256(value: str) -> str:
    if len(value) != 64 or set(value) - frozenset("0123456789abcdef"):
        raise ValueError("artifact hashes must be lowercase SHA-256")
    return value


__all__ = [
    "R1_CAUSAL_AVAILABILITY_GATE_CONTRACT",
    "R1_CAUSAL_REPLAY_ORDERING_CONTRACT",
    "R1_CAUSAL_REPLAY_PROVENANCE_CONTRACT_VERSION",
    "R1_CAUSAL_REPLAY_PROVENANCE_FILENAME",
    "R1CausalReplayProvenance",
    "R1CausalReplayProvenanceArtifact",
    "canonical_model_sha256",
    "load_r1_causal_replay_provenance",
    "serialize_r1_causal_replay_provenance",
    "write_r1_causal_replay_provenance",
]
