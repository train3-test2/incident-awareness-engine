"""Validate or execute the Pair-004/005 development-only R1 causal replay."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import FusionConfig, load_fusion_config
from incident_awareness.evidence.r1_approved_lineage_policy import (
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1EvidenceArtifactRun,
    load_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalAvailabilityEnvelope,
    build_r1_causal_availability_envelope_from_artifacts,
)
from incident_awareness.pipeline.r1_causal_replay import run_and_write_r1_causal_replay
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    R1_CAUSAL_FUSION_RESULT_FILENAME,
    R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
    R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
    load_r1_causal_replay_artifacts,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUTS_ROOT = REPOSITORY_ROOT.parent / "R1-causal-inputs"
DEFAULT_FUSION_CONFIG_PATH = (
    REPOSITORY_ROOT / "configs" / "fusion" / "fusion_config_r1_causal_dev_connection_v0.1.yaml"
)
DEFAULT_APPROVED_POLICY_CONFIG_PATH = (
    REPOSITORY_ROOT / "configs" / "r1_approved_lineage_policies_v0.2.yaml"
)

TARGET_RUN_IDS = (
    "RUN-20261008-917",
    "RUN-20261008-918",
    "RUN-20261008-919",
    "RUN-20261008-920",
)
EXPECTED_PAIR_IDS = {
    "RUN-20261008-917": "R1-PAIR-20261008-004",
    "RUN-20261008-918": "R1-PAIR-20261008-004",
    "RUN-20261008-919": "R1-PAIR-20261008-005",
    "RUN-20261008-920": "R1-PAIR-20261008-005",
}
EXPECTED_FAMILY_ID = "remote_management"
EXPECTED_TARGET_HOST = "R1-TGTA"
EXPECTED_PACKAGE_ID = "R1-PAIR004-005-OFFLINE-EVIDENCE"
EXPECTED_SOURCE_MANIFEST_SHA256 = "b7ca4478b66436b49a38e6c0c646791e676c0ad94da64cae8715a7d98bf617f8"

SELECTOR_POLICY_PAYLOAD = {
    "lineage_event_count": 3,
    "policy_id": "r1-structural-lineage-selector",
    "version": "v0.1",
}
EXPECTED_SELECTOR_POLICY_SHA256 = "669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d"
APPROVED_POLICY_ID = "r1-remote-management-approved-lineage"
APPROVED_POLICY_VERSION = "v0.3"
EXPECTED_APPROVED_POLICY_SHA256 = "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"

EXPECTED_FUSION_CONFIG_VERSION = "fusion-config-r1-causal-dev-connection-v0.1"
EXPECTED_SCORING_PROFILE_ID = "r1-causal-dev-connection-v0.1"
EXPECTED_SCORING_EVIDENCE_TYPES = (
    "remote_session_process_lineage_deviation",
    "remote_process_network_follow_on",
)
DEVELOPMENT_INDEX_FILENAME = "r1_causal_dev_replay_index.json"
REQUIRED_SOURCE_FILENAMES = frozenset(
    {
        "normalized_events.jsonl",
        "provenance_validation.json",
        "r1_evidence.jsonl",
        "r1_extraction_summary.json",
    }
)
REQUIRED_PERMITTED_USES = frozenset(
    {
        "development causal replay pipeline integration verification",
        "FusionResult generation and contract validation",
        "FusionStoppingTrace generation and contract validation",
        "causal replay provenance generation and contract validation",
    }
)
REQUIRED_PROHIBITED_USES = frozenset(
    {
        "TTSD performance claims",
        "early-recognition improvement claims against baseline",
        "holdout evaluation",
        "final evaluation",
        "modification of original Evidence, Summary or manifest bytes",
    }
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")

type JsonObject = dict[str, object]


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class ExecutionRevision:
    commit: str
    dirty: bool
    status_porcelain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionInvocation:
    executable: str
    argv: tuple[str, ...]
    cwd: str


@dataclass(frozen=True, slots=True)
class ValidatedRun:
    run_id: str
    pair_id: str
    artifact_directory: Path
    run_metadata_source: SourceFile
    run_metadata: RunMetadata
    source_files: Mapping[str, SourceFile]
    artifact_run: R1EvidenceArtifactRun
    envelope: R1CausalAvailabilityEnvelope


@dataclass(frozen=True, slots=True)
class ValidationPlan:
    inputs_root: Path
    outputs_root: Path
    approval_source: SourceFile
    source_manifest: SourceFile
    fusion_config_source: SourceFile
    approved_policy_config_source: SourceFile
    selector_policy: R1SelectorPolicy
    approved_policy: ApprovedLineagePolicy
    fusion_config: FusionConfig
    runs: tuple[ValidatedRun, ...]


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _unique_json_object(pairs: list[tuple[str, object]]) -> JsonObject:
    payload: JsonObject = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON key: {key}")
        payload[key] = value
    return payload


def _read_json_object(path: Path, *, description: str) -> JsonObject:
    try:
        payload = json.loads(
            path.read_bytes(),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{description} is not valid unique-key UTF-8 JSON: {path}") from error
    if not isinstance(payload, dict):
        raise TypeError(f"{description} root must be a JSON object: {path}")
    return payload


def _require_mapping(value: object, *, field_name: str) -> JsonObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{field_name} must be a JSON object")
    return value


def _require_string(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field_name} must be a non-blank unpadded string")
    return value


def _require_sha256(value: object, *, field_name: str) -> str:
    digest = _require_string(value, field_name=field_name)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256")
    return digest


def _require_string_list(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError(f"{field_name} must be a JSON array")
    return tuple(_require_string(item, field_name=field_name) for item in value)


def _resolve_relative_path(root: Path, raw_path: str, *, field_name: str) -> Path:
    windows_path = PureWindowsPath(raw_path)
    posix_path = PurePosixPath(raw_path.replace("\\", "/"))
    if windows_path.drive or windows_path.root or posix_path.is_absolute():
        raise ValueError(f"{field_name} must be relative")
    if not posix_path.parts or any(part in {"", ".", ".."} for part in posix_path.parts):
        raise ValueError(f"{field_name} must not contain traversal or empty segments")

    resolved_root = root.resolve()
    resolved_path = resolved_root.joinpath(*posix_path.parts).resolve()
    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"{field_name} escapes its allowed root")
    return resolved_path


def _validate_outputs_root(
    outputs_root: Path,
    *,
    extracted_root: Path,
    approval_path: Path,
) -> Path:
    resolved_outputs_root = outputs_root.resolve()
    protected_roots = {
        "Git repository": REPOSITORY_ROOT.resolve(),
        "extracted input directory": extracted_root.resolve(),
        "approval record directory": approval_path.resolve().parent,
    }
    for description, protected_root in protected_roots.items():
        if resolved_outputs_root == protected_root or resolved_outputs_root.is_relative_to(
            protected_root
        ):
            raise ValueError(
                f"outputs_root must be outside the {description}: {resolved_outputs_root}"
            )
    return resolved_outputs_root


def _load_usage_scope(approval_path: Path) -> tuple[JsonObject, SourceFile]:
    payload = _read_json_object(approval_path, description="development usage approval")
    if payload.get("record_version") != "v0.1":
        raise ValueError("development usage approval record_version must be v0.1")
    if payload.get("package_id") != EXPECTED_PACKAGE_ID:
        raise ValueError("development usage approval package_id does not match")
    if payload.get("output_classification") != "development-only":
        raise ValueError("development usage approval must remain development-only")
    if payload.get("preserves_original_artifacts") is not True:
        raise ValueError("development usage approval must preserve original artifacts")
    permitted = frozenset(
        _require_string_list(payload.get("permitted_use"), field_name="permitted_use")
    )
    prohibited = frozenset(
        _require_string_list(payload.get("prohibited_use"), field_name="prohibited_use")
    )
    if not REQUIRED_PERMITTED_USES <= permitted:
        raise ValueError("development usage approval does not permit the required replay outputs")
    if not REQUIRED_PROHIBITED_USES <= prohibited:
        raise ValueError("development usage approval does not preserve evaluation restrictions")
    recorded_manifest_hash = _require_sha256(
        payload.get("source_manifest_sha256"),
        field_name="source_manifest_sha256",
    )
    if recorded_manifest_hash != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise ValueError("development usage approval records an unexpected manifest SHA-256")
    return payload, SourceFile(path=approval_path.resolve(), sha256=_sha256_file(approval_path))


def _load_source_manifest(
    extracted_root: Path,
    approval: JsonObject,
) -> tuple[JsonObject, SourceFile]:
    recorded_relative_path = _require_string(
        approval.get("source_manifest_relative_path"),
        field_name="source_manifest_relative_path",
    )
    recorded_path = _resolve_relative_path(
        extracted_root,
        recorded_relative_path,
        field_name="source_manifest_relative_path",
    )
    if not recorded_path.is_file():
        raise FileNotFoundError(f"approved source manifest was not found: {recorded_path}")

    candidates: list[tuple[Path, JsonObject]] = []
    for candidate in sorted(extracted_root.rglob("manifest.json")):
        try:
            payload = _read_json_object(candidate, description="source manifest candidate")
        except ValueError:
            if candidate.resolve() == recorded_path:
                raise
            continue
        if payload.get("package_id") == EXPECTED_PACKAGE_ID:
            candidates.append((candidate.resolve(), payload))
    if len(candidates) != 1:
        raise ValueError(
            "recursive discovery must find exactly one approved source manifest; "
            f"found {len(candidates)}"
        )
    manifest_path, manifest = candidates[0]
    if manifest_path != recorded_path:
        raise ValueError("approval manifest path does not match recursive package discovery")
    actual_hash = _sha256_file(manifest_path)
    if actual_hash != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise ValueError("source manifest SHA-256 does not match the approved frozen value")
    if approval.get("source_manifest_sha256") != actual_hash:
        raise ValueError("source manifest SHA-256 does not match the usage approval")
    return manifest, SourceFile(path=manifest_path, sha256=actual_hash)


def _manifest_runs(manifest: JsonObject) -> dict[str, JsonObject]:
    run_values = manifest.get("runs")
    if not isinstance(run_values, list):
        raise TypeError("source manifest runs must be a JSON array")
    runs: dict[str, JsonObject] = {}
    for index, value in enumerate(run_values):
        run = _require_mapping(value, field_name=f"runs[{index}]")
        run_id = _require_string(run.get("run_id"), field_name=f"runs[{index}].run_id")
        if run_id in runs:
            raise ValueError(f"source manifest contains duplicate run_id: {run_id}")
        runs[run_id] = run
    actual_ids = frozenset(runs)
    expected_ids = frozenset(TARGET_RUN_IDS)
    if actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        unexpected = sorted(actual_ids - expected_ids)
        raise ValueError(
            f"source manifest Run set mismatch; missing={missing}, unexpected={unexpected}"
        )
    return runs


def _build_selector_policy() -> R1SelectorPolicy:
    canonical_payload = json.dumps(
        SELECTOR_POLICY_PAYLOAD,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    actual_hash = _sha256_bytes(canonical_payload)
    if actual_hash != EXPECTED_SELECTOR_POLICY_SHA256:
        raise ValueError("fixed selector policy payload SHA-256 does not match its contract")
    return R1SelectorPolicy(
        policy_id=SELECTOR_POLICY_PAYLOAD["policy_id"],
        version=SELECTOR_POLICY_PAYLOAD["version"],
        config_hash=actual_hash,
        lineage_event_count=SELECTOR_POLICY_PAYLOAD["lineage_event_count"],
    )


def _load_approved_policy(config_path: Path) -> tuple[ApprovedLineagePolicy, SourceFile]:
    policy = load_r1_approved_lineage_policy(
        APPROVED_POLICY_ID,
        APPROVED_POLICY_VERSION,
        config_path=config_path,
    )
    if policy.config_hash != EXPECTED_APPROVED_POLICY_SHA256:
        raise ValueError("loaded approved lineage policy canonical SHA-256 does not match")
    if policy.family_id != EXPECTED_FAMILY_ID or policy.lifecycle != "frozen":
        raise ValueError("approved lineage policy must be frozen and remote_management-bound")
    validate_r1_policy_family_binding(EXPECTED_FAMILY_ID, policy)
    return policy, SourceFile(path=config_path.resolve(), sha256=_sha256_file(config_path))


def _load_development_fusion_config(config_path: Path) -> tuple[FusionConfig, SourceFile]:
    config = load_fusion_config(config_path)
    actual_contract = (
        config.config_version,
        config.model_version,
        config.window.window_size_sec,
        config.replay.step_size_sec,
        config.scoring.method,
        config.scoring.scorer_version,
        config.scoring.profile_id,
        config.scoring.evidence_types,
        config.stopping.threshold_on,
        config.stopping.threshold_off,
        config.stopping.persistence_k,
    )
    expected_contract = (
        EXPECTED_FUSION_CONFIG_VERSION,
        None,
        300.0,
        10.0,
        "simple_score",
        "simple-score-v0.1",
        EXPECTED_SCORING_PROFILE_ID,
        EXPECTED_SCORING_EVIDENCE_TYPES,
        0.8,
        0.4,
        2,
    )
    if actual_contract != expected_contract:
        raise ValueError("development Fusion config does not match the frozen connection settings")
    return config, SourceFile(path=config_path.resolve(), sha256=_sha256_file(config_path))


def _discover_artifact_directory(extracted_root: Path, run_id: str) -> Path:
    candidates: set[Path] = set()
    for summary_path in extracted_root.rglob("r1_extraction_summary.json"):
        parent = summary_path.parent.resolve()
        if run_id in parent.parts:
            candidates.add(parent)
            continue
        try:
            summary = _read_json_object(summary_path, description="R1 extraction summary")
        except ValueError:
            continue
        if summary.get("run_id") == run_id:
            candidates.add(parent)
    if len(candidates) != 1:
        raise ValueError(
            f"recursive discovery must find exactly one Evidence directory for {run_id}; "
            f"found {len(candidates)}"
        )
    return next(iter(candidates))


def _discover_run_metadata(extracted_root: Path, run_id: str) -> tuple[RunMetadata, SourceFile]:
    candidates: set[Path] = set()
    for metadata_path in extracted_root.rglob("run_metadata.json"):
        resolved = metadata_path.resolve()
        if run_id in resolved.parts:
            candidates.add(resolved)
            continue
        try:
            metadata_payload = _read_json_object(metadata_path, description="RunMetadata")
        except ValueError:
            continue
        if metadata_payload.get("run_id") == run_id:
            candidates.add(resolved)
    if len(candidates) != 1:
        raise ValueError(
            f"recursive discovery must find exactly one RunMetadata for {run_id}; "
            f"found {len(candidates)}"
        )
    metadata_path = next(iter(candidates))
    metadata_content = metadata_path.read_bytes()
    run_metadata = RunMetadata.model_validate_json(metadata_content)
    if run_metadata.run_id != run_id:
        raise ValueError("RunMetadata run_id does not match its discovered Run")
    if run_metadata.family_id != EXPECTED_FAMILY_ID:
        raise ValueError(f"RunMetadata family_id mismatch for {run_id}")
    if run_metadata.target_host != EXPECTED_TARGET_HOST:
        raise ValueError(f"RunMetadata target_host mismatch for {run_id}")
    if run_metadata.end_time is None:
        raise ValueError(f"RunMetadata end_time is required for {run_id}")
    return run_metadata, SourceFile(
        path=metadata_path,
        sha256=_sha256_bytes(metadata_content),
    )


def _validate_manifest_identity(
    manifest_run: JsonObject,
    *,
    run_id: str,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
) -> str:
    pair_id = _require_string(manifest_run.get("pair_id"), field_name=f"{run_id}.pair_id")
    if pair_id != EXPECTED_PAIR_IDS[run_id]:
        raise ValueError(f"manifest pair_id mismatch for {run_id}")
    selector = _require_mapping(manifest_run.get("selector"), field_name=f"{run_id}.selector")
    selector_identity = (
        selector.get("policy_id"),
        selector.get("version"),
        selector.get("config_hash"),
        selector.get("status"),
        selector.get("diagnostics"),
    )
    expected_selector_identity = (
        selector_policy.policy_id,
        selector_policy.version,
        selector_policy.config_hash,
        "selected",
        [],
    )
    if selector_identity != expected_selector_identity:
        raise ValueError(f"manifest selector identity mismatch for {run_id}")
    approved = _require_mapping(
        manifest_run.get("approved_policy"),
        field_name=f"{run_id}.approved_policy",
    )
    approved_identity = (
        approved.get("policy_id"),
        approved.get("version"),
        approved.get("config_hash"),
        approved.get("family_id"),
        approved.get("lifecycle"),
    )
    expected_approved_identity = (
        approved_policy.policy_id,
        approved_policy.version,
        approved_policy.config_hash,
        approved_policy.family_id,
        approved_policy.lifecycle,
    )
    if approved_identity != expected_approved_identity:
        raise ValueError(f"manifest approved policy identity mismatch for {run_id}")
    return pair_id


def _validate_manifest_source_files(
    manifest_run: JsonObject,
    *,
    manifest_directory: Path,
    run_id: str,
) -> dict[str, SourceFile]:
    files = _require_mapping(manifest_run.get("files"), field_name=f"{run_id}.files")
    missing = REQUIRED_SOURCE_FILENAMES - files.keys()
    if missing:
        raise ValueError(f"manifest files are missing for {run_id}: {sorted(missing)}")

    sources: dict[str, SourceFile] = {}
    for filename, raw_record in files.items():
        record = _require_mapping(raw_record, field_name=f"{run_id}.files.{filename}")
        raw_path = _require_string(record.get("path"), field_name=f"{filename}.path")
        path = _resolve_relative_path(
            manifest_directory,
            raw_path,
            field_name=f"{run_id}.{filename}.path",
        )
        if path.name != filename:
            raise ValueError(f"manifest filename/path mismatch for {run_id}: {filename}")
        if not path.is_file():
            raise FileNotFoundError(f"manifest source file was not found: {path}")
        expected_hash = _require_sha256(
            record.get("sha256"),
            field_name=f"{run_id}.{filename}.sha256",
        )
        actual_hash = _sha256_file(path)
        if actual_hash != expected_hash:
            raise ValueError(f"source SHA-256 mismatch for {run_id}/{filename}")
        sources[filename] = SourceFile(path=path, sha256=actual_hash)
    return sources


def _validate_run(
    *,
    extracted_root: Path,
    manifest_directory: Path,
    manifest_run: JsonObject,
    run_id: str,
    selector_policy: R1SelectorPolicy,
    approved_policy: ApprovedLineagePolicy,
) -> ValidatedRun:
    pair_id = _validate_manifest_identity(
        manifest_run,
        run_id=run_id,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
    )
    source_files = _validate_manifest_source_files(
        manifest_run,
        manifest_directory=manifest_directory,
        run_id=run_id,
    )
    artifact_directory = _discover_artifact_directory(extracted_root, run_id)
    source_artifact_parents = {
        source_files[filename].path.parent for filename in REQUIRED_SOURCE_FILENAMES
    }
    if source_artifact_parents != {artifact_directory}:
        raise ValueError(
            f"manifest files do not match the discovered Evidence directory for {run_id}"
        )

    run_metadata, metadata_source = _discover_run_metadata(extracted_root, run_id)
    artifact_run = load_r1_evidence_artifacts(artifact_directory)
    if artifact_run.summary.run_id != run_id:
        raise ValueError(f"loaded Evidence artifact run_id mismatch for {run_id}")
    if artifact_run.summary_artifact_sha256 != source_files["r1_extraction_summary.json"].sha256:
        raise ValueError(f"loaded extraction summary SHA-256 mismatch for {run_id}")
    if artifact_run.summary.evidence_artifact_sha256 != source_files["r1_evidence.jsonl"].sha256:
        raise ValueError(f"loaded Evidence SHA-256 mismatch for {run_id}")

    validate_r1_policy_family_binding(run_metadata.family_id, approved_policy)
    envelope = build_r1_causal_availability_envelope_from_artifacts(
        artifact_run,
        run_metadata=run_metadata,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
    )
    return ValidatedRun(
        run_id=run_id,
        pair_id=pair_id,
        artifact_directory=artifact_directory,
        run_metadata_source=metadata_source,
        run_metadata=run_metadata,
        source_files=source_files,
        artifact_run=artifact_run,
        envelope=envelope,
    )


def validate_development_replay_inputs(
    *,
    inputs_root: Path,
    approval_path: Path,
    outputs_root: Path,
    fusion_config_path: Path,
    approved_policy_config_path: Path,
    run_ids: Sequence[str],
) -> ValidationPlan:
    """Validate frozen inputs and build official v0.1 availability envelopes."""
    selected_run_ids = tuple(run_ids)
    if not selected_run_ids or len(selected_run_ids) != len(set(selected_run_ids)):
        raise ValueError("run_ids must contain one or more unique target Run IDs")
    if any(run_id not in TARGET_RUN_IDS for run_id in selected_run_ids):
        raise ValueError("run_ids contains a Run outside the Pair-004/005 target set")
    resolved_inputs_root = inputs_root.resolve()
    resolved_approval_path = approval_path.resolve()
    extracted_root = (resolved_inputs_root / "extracted").resolve()
    if not extracted_root.is_dir():
        raise FileNotFoundError(f"extracted input root was not found: {extracted_root}")
    resolved_outputs_root = _validate_outputs_root(
        outputs_root,
        extracted_root=extracted_root,
        approval_path=resolved_approval_path,
    )

    approval, approval_source = _load_usage_scope(resolved_approval_path)
    manifest, manifest_source = _load_source_manifest(extracted_root, approval)
    runs_by_id = _manifest_runs(manifest)
    selector_policy = _build_selector_policy()
    approved_policy, approved_policy_config_source = _load_approved_policy(
        approved_policy_config_path
    )
    if selector_policy.lineage_event_count != len(approved_policy.approved_lineage):
        raise ValueError("selector lineage_event_count must match approved_lineage length")
    fusion_config, fusion_config_source = _load_development_fusion_config(fusion_config_path)

    collisions = [
        resolved_outputs_root / run_id
        for run_id in selected_run_ids
        if (resolved_outputs_root / run_id).exists()
    ]
    if collisions:
        raise FileExistsError(
            "development replay output directory already exists: "
            + ", ".join(str(path) for path in collisions)
        )

    validated_runs = tuple(
        _validate_run(
            extracted_root=extracted_root,
            manifest_directory=manifest_source.path.parent,
            manifest_run=runs_by_id[run_id],
            run_id=run_id,
            selector_policy=selector_policy,
            approved_policy=approved_policy,
        )
        for run_id in selected_run_ids
    )
    return ValidationPlan(
        inputs_root=resolved_inputs_root,
        outputs_root=resolved_outputs_root,
        approval_source=approval_source,
        source_manifest=manifest_source,
        fusion_config_source=fusion_config_source,
        approved_policy_config_source=approved_policy_config_source,
        selector_policy=selector_policy,
        approved_policy=approved_policy,
        fusion_config=fusion_config,
        runs=validated_runs,
    )


def _git_execution_revision(repository_root: Path) -> ExecutionRevision:
    try:
        commit_process = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
        status_process = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError("failed to read the actual Git execution revision") from error
    commit = commit_process.stdout.strip().lower()
    if _COMMIT_PATTERN.fullmatch(commit) is None:
        raise RuntimeError("git rev-parse HEAD did not return a full commit SHA")
    status_porcelain = tuple(status_process.stdout.splitlines())
    return ExecutionRevision(
        commit=commit,
        dirty=bool(status_porcelain),
        status_porcelain=status_porcelain,
    )


def _source_record(source: SourceFile) -> JsonObject:
    return {"path": str(source.path), "sha256": source.sha256}


def build_check_report(
    plan: ValidationPlan,
    revision: ExecutionRevision,
) -> JsonObject:
    return {
        "mode": "check",
        "output_classification": "development-only",
        "official_evaluation_authorized": False,
        "execution": {
            "commit": revision.commit,
            "dirty": revision.dirty,
            "handoff_eligible": not revision.dirty,
            "status_porcelain": list(revision.status_porcelain),
        },
        "approval": _source_record(plan.approval_source),
        "source_manifest": _source_record(plan.source_manifest),
        "fusion_config": {
            **_source_record(plan.fusion_config_source),
            "config_version": plan.fusion_config.config_version,
            "scoring_profile_id": plan.fusion_config.scoring.profile_id,
        },
        "selector_policy": {
            "policy_id": plan.selector_policy.policy_id,
            "version": plan.selector_policy.version,
            "config_hash": plan.selector_policy.config_hash,
            "lineage_event_count": plan.selector_policy.lineage_event_count,
        },
        "approved_policy": {
            **_source_record(plan.approved_policy_config_source),
            "policy_id": plan.approved_policy.policy_id,
            "version": plan.approved_policy.version,
            "config_hash": plan.approved_policy.config_hash,
            "family_id": plan.approved_policy.family_id,
            "lifecycle": plan.approved_policy.lifecycle,
        },
        "runs": [
            {
                "run_id": run.run_id,
                "pair_id": run.pair_id,
                "family_id": run.run_metadata.family_id,
                "target_host": run.run_metadata.target_host,
                "artifact_directory": str(run.artifact_directory),
                "run_metadata": _source_record(run.run_metadata_source),
                "source_files": {
                    name: _source_record(source)
                    for name, source in sorted(run.source_files.items())
                },
                "causal_availability": {
                    "contract_version": run.envelope.contract_version,
                    "watermark_basis": run.envelope.watermark_basis,
                    "watermark_at": run.envelope.watermark_at.isoformat(),
                    "evidence_count": run.envelope.source_evidence_count,
                },
                "output_directory": str(plan.outputs_root / run.run_id),
            }
            for run in plan.runs
        ],
    }


def _serialize_json(payload: JsonObject) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_json_exclusive(path: Path, payload: JsonObject) -> str:
    content = _serialize_json(payload)
    with path.open("xb") as stream:
        stream.write(content)
    return _sha256_bytes(content)


def _validate_development_index(
    index_path: Path,
    *,
    expected_payload: JsonObject,
    staging_directory: Path,
    final_directory: Path,
) -> str:
    restored = _read_json_object(index_path, description="development replay index")
    if restored != expected_payload:
        raise ValueError("stored development replay index reload mismatch")

    outputs = _require_mapping(restored.get("outputs"), field_name="outputs")
    expected_filenames = {
        R1_CAUSAL_FUSION_RESULT_FILENAME,
        R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
        R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
    }
    if set(outputs) != expected_filenames:
        raise ValueError("development replay index output set mismatch")
    for filename in expected_filenames:
        output = _require_mapping(outputs[filename], field_name=f"outputs.{filename}")
        expected_path = (final_directory / filename).resolve()
        if output.get("path") != str(expected_path):
            raise ValueError("development replay index must record final artifact paths")
        recorded_hash = _require_sha256(
            output.get("sha256"),
            field_name=f"outputs.{filename}.sha256",
        )
        if recorded_hash != _sha256_file(staging_directory / filename):
            raise ValueError(f"development replay index SHA-256 mismatch for {filename}")

    expected_staged_files = expected_filenames | {DEVELOPMENT_INDEX_FILENAME}
    actual_staged_files = {path.name for path in staging_directory.iterdir() if path.is_file()}
    if actual_staged_files != expected_staged_files:
        raise ValueError("staged development replay output set mismatch")
    if any(path.is_dir() for path in staging_directory.iterdir()):
        raise ValueError("staged development replay must not contain subdirectories")
    return _sha256_file(index_path)


def execute_development_replays(
    plan: ValidationPlan,
    *,
    revision: ExecutionRevision,
    invocation: ExecutionInvocation,
) -> tuple[JsonObject, ...]:
    """Execute the same causal runtime for every selected Run and verify persisted outputs."""
    if revision.dirty:
        raise ValueError(
            "--execute requires a clean Git worktree; dirty executions are not handoff-eligible"
        )
    extracted_root = (plan.inputs_root / "extracted").resolve()
    outputs_root = _validate_outputs_root(
        plan.outputs_root,
        extracted_root=extracted_root,
        approval_path=plan.approval_source.path,
    )
    if outputs_root != plan.outputs_root:
        raise ValueError("outputs_root canonical path changed after input validation")
    outputs_root.mkdir(parents=True, exist_ok=True)

    reports: list[JsonObject] = []
    for run in plan.runs:
        final_directory = (outputs_root / run.run_id).resolve()
        if final_directory.parent != outputs_root:
            raise ValueError(f"Run output path escapes outputs_root: {run.run_id}")
        if final_directory.exists():
            raise FileExistsError(
                f"development replay output directory already exists: {final_directory}"
            )

        with tempfile.TemporaryDirectory(
            dir=outputs_root,
            prefix=f".{run.run_id}.staging-",
        ) as temporary_directory:
            staging_directory = Path(temporary_directory).resolve()
            result = run_and_write_r1_causal_replay(
                run.artifact_run,
                run.envelope,
                run_metadata=run.run_metadata,
                approved_policy=plan.approved_policy,
                config=plan.fusion_config,
                execution_commit=revision.commit,
                output_directory=staging_directory,
            )
            restored = load_r1_causal_replay_artifacts(staging_directory)
            if restored.fusion_result != result.pipeline_result.fusion_result:
                raise ValueError(f"stored FusionResult reload mismatch for {run.run_id}")
            if restored.fusion_stopping_trace != result.pipeline_result.stopping_trace:
                raise ValueError(f"stored FusionStoppingTrace reload mismatch for {run.run_id}")
            if restored.provenance != result.pipeline_result.provenance:
                raise ValueError(f"stored causal provenance reload mismatch for {run.run_id}")

            output_sources = {
                R1_CAUSAL_FUSION_RESULT_FILENAME: SourceFile(
                    path=final_directory / R1_CAUSAL_FUSION_RESULT_FILENAME,
                    sha256=result.artifacts.fusion_result.sha256,
                ),
                R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME: SourceFile(
                    path=final_directory / R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
                    sha256=result.artifacts.fusion_stopping_trace.sha256,
                ),
                R1_CAUSAL_REPLAY_PROVENANCE_FILENAME: SourceFile(
                    path=final_directory / R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
                    sha256=result.provenance_artifact.sha256,
                ),
            }
            index_payload: JsonObject = {
                "record_version": "v0.1",
                "output_classification": "development-only",
                "official_evaluation_authorized": False,
                "run_id": run.run_id,
                "pair_id": run.pair_id,
                "family_id": run.run_metadata.family_id,
                "target_host": run.run_metadata.target_host,
                "source_manifest": _source_record(plan.source_manifest),
                "approval": _source_record(plan.approval_source),
                "run_metadata": _source_record(run.run_metadata_source),
                "source_files": {
                    name: _source_record(source)
                    for name, source in sorted(run.source_files.items())
                },
                "fusion_config": {
                    **_source_record(plan.fusion_config_source),
                    "config_version": plan.fusion_config.config_version,
                    "scoring_profile_id": plan.fusion_config.scoring.profile_id,
                },
                "selector_policy": {
                    "policy_id": plan.selector_policy.policy_id,
                    "version": plan.selector_policy.version,
                    "config_hash": plan.selector_policy.config_hash,
                    "lineage_event_count": plan.selector_policy.lineage_event_count,
                },
                "approved_policy": {
                    **_source_record(plan.approved_policy_config_source),
                    "policy_id": plan.approved_policy.policy_id,
                    "version": plan.approved_policy.version,
                    "config_hash": plan.approved_policy.config_hash,
                    "family_id": plan.approved_policy.family_id,
                    "lifecycle": plan.approved_policy.lifecycle,
                },
                "execution": {
                    "commit": revision.commit,
                    "dirty": revision.dirty,
                    "handoff_eligible": True,
                    "executable": invocation.executable,
                    "argv": list(invocation.argv),
                    "cwd": invocation.cwd,
                },
                "outputs": {
                    name: _source_record(source) for name, source in sorted(output_sources.items())
                },
                "limitations": [
                    "development connection verification only",
                    "not TTSD or early-recognition performance evidence",
                    "not holdout, final-evaluation, or production output",
                ],
            }
            staging_index_path = staging_directory / DEVELOPMENT_INDEX_FILENAME
            _write_json_exclusive(staging_index_path, index_payload)
            index_sha256 = _validate_development_index(
                staging_index_path,
                expected_payload=index_payload,
                staging_directory=staging_directory,
                final_directory=final_directory,
            )
            if final_directory.exists():
                raise FileExistsError(
                    f"development replay output directory already exists: {final_directory}"
                )
            staging_directory.rename(final_directory)

        index_path = final_directory / DEVELOPMENT_INDEX_FILENAME
        reports.append(
            {
                "run_id": run.run_id,
                "fusion_status": restored.fusion_result.fusion_status,
                "outputs": {
                    name: _source_record(source) for name, source in sorted(output_sources.items())
                },
                "development_index": {
                    "path": str(index_path.resolve()),
                    "sha256": index_sha256,
                },
            }
        )
    return tuple(reports)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="validate inputs without outputs")
    mode.add_argument("--execute", action="store_true", help="write development-only outputs")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--run-id", choices=TARGET_RUN_IDS)
    selection.add_argument("--all-runs", action="store_true")
    parser.add_argument("--inputs-root", type=Path, default=DEFAULT_INPUTS_ROOT)
    parser.add_argument("--approval-path", type=Path)
    parser.add_argument("--outputs-root", type=Path)
    parser.add_argument("--fusion-config", type=Path, default=DEFAULT_FUSION_CONFIG_PATH)
    parser.add_argument(
        "--approved-policy-config",
        type=Path,
        default=DEFAULT_APPROVED_POLICY_CONFIG_PATH,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    inputs_root = args.inputs_root.resolve()
    approval_path = (
        args.approval_path.resolve()
        if args.approval_path is not None
        else inputs_root / "development-replay" / "approval" / "usage-scope-v0.1.json"
    )
    outputs_root = (
        args.outputs_root.resolve()
        if args.outputs_root is not None
        else inputs_root / "development-replay" / "outputs"
    )
    selected_run_ids = TARGET_RUN_IDS if args.all_runs else (args.run_id,)
    assert all(isinstance(run_id, str) for run_id in selected_run_ids)
    invocation_argv = tuple(sys.argv if argv is None else (str(Path(__file__)), *argv))
    invocation = ExecutionInvocation(
        executable=sys.executable,
        argv=invocation_argv,
        cwd=str(Path.cwd()),
    )

    try:
        revision = _git_execution_revision(REPOSITORY_ROOT)
        plan = validate_development_replay_inputs(
            inputs_root=inputs_root,
            approval_path=approval_path,
            outputs_root=outputs_root,
            fusion_config_path=args.fusion_config.resolve(),
            approved_policy_config_path=args.approved_policy_config.resolve(),
            run_ids=selected_run_ids,
        )
        if args.check:
            report = build_check_report(plan, revision)
        else:
            report = {
                "mode": "execute",
                "output_classification": "development-only",
                "execution_commit": revision.commit,
                "execution_dirty": revision.dirty,
                "runs": list(
                    execute_development_replays(
                        plan,
                        revision=revision,
                        invocation=invocation,
                    )
                ),
            }
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
