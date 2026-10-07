"""Reproduce the R1 Pair-002 retrospective temporal mechanics probe."""

import argparse
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from incident_awareness.decision.fusion.config import FusionConfig, load_fusion_config
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.temporal_replay import TemporalReplayRunner
from incident_awareness.pipeline.r1_artifacts import (
    R1EvidenceArtifactRun,
    load_r1_evidence_artifacts,
)

ATTACK_RUN_ID = "RUN-20261005-912"
NORMAL_RUN_ID = "RUN-20261005-913"

APPROVED_POLICY_ID = "r1-v02-development-connection"
APPROVED_POLICY_VERSION = "v0.1"
APPROVED_POLICY_CONFIG_HASH = "59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78"
EXTRACTOR_VERSION = "r1-v0.1"

INITIAL_DEVELOP_BASE = "6e096d09ce1c996e4b4c7cc60f51ec265ba0bb63"
INITIAL_ANALYSIS_DOCUMENT_COMMIT = "66648894a7a9a10db0ae1f247e7b402ea1c3ca10"
REVIEW_REPRODUCTION_BASE = "327f2e5b5a681ccf3ecdec3d324d933d3ae08637"

DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "configs"
    / "fusion"
    / "fusion_config_r1_pair002_probe_v0.1.yaml"
)


@dataclass(frozen=True, slots=True)
class ArtifactHashes:
    normalized_input: str
    evidence: str
    extraction_summary: str


@dataclass(frozen=True, slots=True)
class PairRunSpec:
    run_type: str
    run_start: datetime
    run_end: datetime
    replay_end: datetime
    hashes: ArtifactHashes


PAIR002_RUNS = {
    ATTACK_RUN_ID: PairRunSpec(
        run_type="attack",
        run_start=datetime(2026, 10, 5, 19, 33, 25, 834000, tzinfo=UTC),
        run_end=datetime(2026, 10, 5, 19, 44, 28, 494000, tzinfo=UTC),
        replay_end=datetime(2026, 10, 5, 19, 44, 25, 834000, tzinfo=UTC),
        hashes=ArtifactHashes(
            normalized_input=("d62050b01c8bf8edbdd9c7431a448665a6c622220a3739567dbe325cd7776097"),
            evidence="48daef65704b5c0b513550cc4a2fe766f1a418869f66383b5e54e89c08e4ffce",
            extraction_summary=("545d4c6f08c9d2c092a26709ab58f6ea3d15fa49632bb71f98e26d074a0e6671"),
        ),
    ),
    NORMAL_RUN_ID: PairRunSpec(
        run_type="normal",
        run_start=datetime(2026, 10, 5, 19, 56, 52, 355000, tzinfo=UTC),
        run_end=datetime(2026, 10, 5, 20, 7, 54, 631000, tzinfo=UTC),
        replay_end=datetime(2026, 10, 5, 20, 7, 52, 355000, tzinfo=UTC),
        hashes=ArtifactHashes(
            normalized_input=("f5f6b1e81d928be1eb8329c13b13081930d3d363320ee4784e67abe51b241839"),
            evidence="b0fa9a2d2789da1f3dd0257789a4d143988c035eb225aef136be8e5b5455e8b4",
            extraction_summary=("1b882055456c96cf16f26c3163d0d38de9504733d108a951144ef5ce5c15958a"),
        ),
    ),
}


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"required Pair-002 artifact is not readable: {path}") from error


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_raw_bytes(path: Path) -> str:
    return _sha256_bytes(_read_bytes(path))


def _sha256_lf_normalized_text(path: Path) -> str:
    content = _read_bytes(path)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"required Pair-002 text artifact is not valid UTF-8: {path}") from error
    return _sha256_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def _require_sha256(
    path: Path,
    expected: str,
    *,
    label: str,
    hash_file: Callable[[Path], str],
) -> None:
    actual = hash_file(path)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _load_validated_run(
    artifacts_root: Path,
    run_id: str,
    spec: PairRunSpec,
) -> R1EvidenceArtifactRun:
    run_root = artifacts_root / run_id
    _require_sha256(
        run_root / "normalized_events.jsonl",
        spec.hashes.normalized_input,
        label=f"{run_id} normalized input",
        hash_file=_sha256_lf_normalized_text,
    )
    _require_sha256(
        run_root / "r1_evidence.jsonl",
        spec.hashes.evidence,
        label=f"{run_id} Evidence JSONL",
        hash_file=_sha256_raw_bytes,
    )
    _require_sha256(
        run_root / "r1_extraction_summary.json",
        spec.hashes.extraction_summary,
        label=f"{run_id} extraction summary",
        hash_file=_sha256_raw_bytes,
    )

    artifacts = load_r1_evidence_artifacts(run_root)
    summary = artifacts.summary
    if summary.run_id != run_id:
        raise ValueError(f"{run_id} extraction summary run_id mismatch")
    if summary.extractor_version != EXTRACTOR_VERSION:
        raise ValueError(f"{run_id} extractor_version mismatch")
    if not summary.lineage_inputs:
        raise ValueError(f"{run_id} extraction summary has no manual lineage provenance")

    expected_policy = (
        APPROVED_POLICY_ID,
        APPROVED_POLICY_VERSION,
        APPROVED_POLICY_CONFIG_HASH,
    )
    for lineage_input in summary.lineage_inputs:
        actual_policy = (
            lineage_input.policy_id,
            lineage_input.policy_version,
            lineage_input.policy_config_hash,
        )
        if actual_policy != expected_policy:
            raise ValueError(f"{run_id} approved lineage policy provenance mismatch")

    entity_ids = {evidence.entity_id for evidence in artifacts.evidences}
    if len(entity_ids) != 1:
        raise ValueError(f"{run_id} must contain Evidence for exactly one entity")
    return artifacts


def _validate_probe_config(config: FusionConfig) -> None:
    expected = {
        "config_version": "fusion-config-r1-pair002-probe-v0.1",
        "model_version": None,
        "window_size_sec": 300,
        "step_size_sec": 10,
        "method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "profile_id": "r1-pair002-probe-v0.1",
        "evidence_types": (
            "remote_session_process_lineage_deviation",
            "remote_process_network_follow_on",
        ),
        "threshold_on": 0.8,
        "threshold_off": 0.4,
        "persistence_k": 2,
    }
    actual = {
        "config_version": config.config_version,
        "model_version": config.model_version,
        "window_size_sec": config.window.window_size_sec,
        "step_size_sec": config.replay.step_size_sec,
        "method": config.scoring.method,
        "scorer_version": config.scoring.scorer_version,
        "profile_id": config.scoring.profile_id,
        "evidence_types": config.scoring.evidence_types,
        "threshold_on": config.stopping.threshold_on,
        "threshold_off": config.stopping.threshold_off,
        "persistence_k": config.stopping.persistence_k,
    }
    if actual != expected:
        raise ValueError("Fusion config does not match the approved Pair-002 probe settings")


def _variant_runner(
    config: FusionConfig,
    *,
    window_size_sec: int,
    step_size_sec: int,
    persistence_k: int,
) -> TemporalReplayRunner:
    variant = config.model_copy(
        update={
            "window": config.window.model_copy(update={"window_size_sec": window_size_sec}),
            "replay": config.replay.model_copy(update={"step_size_sec": step_size_sec}),
            "stopping": config.stopping.model_copy(update={"persistence_k": persistence_k}),
        }
    )
    return variant.build_runner()


def _iso_milliseconds(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _replay_summary(
    artifacts: R1EvidenceArtifactRun,
    spec: PairRunSpec,
    config: FusionConfig,
    *,
    window_size_sec: int,
    step_size_sec: int,
    persistence_k: int,
) -> dict[str, object]:
    entity_id = artifacts.evidences[0].entity_id
    result = _variant_runner(
        config,
        window_size_sec=window_size_sec,
        step_size_sec=step_size_sec,
        persistence_k=persistence_k,
    ).run(
        artifacts.evidences,
        run_id=artifacts.summary.run_id,
        entity_id=entity_id,
        run_start=spec.run_start,
        run_end=spec.run_end,
        replay_end=spec.replay_end,
    )
    return {
        "max_score": max(point.score for point in result.trajectory),
        "fusion_status": result.stopping_result.fusion_status,
        "fusion_time": _iso_milliseconds(result.stopping_result.fusion_time),
    }


def run_probe(
    artifacts_root: Path,
    *,
    config_path: Path = DEFAULT_CONFIG_PATH,
    run_specs: dict[str, PairRunSpec] = PAIR002_RUNS,
) -> dict[str, object]:
    """Validate immutable inputs and reproduce the documented Pair-002 probe."""
    if set(run_specs) != {ATTACK_RUN_ID, NORMAL_RUN_ID}:
        raise ValueError("run_specs must contain the Pair-002 Attack and Normal run IDs")

    config = load_fusion_config(config_path)
    _validate_probe_config(config)
    runs = {
        run_id: _load_validated_run(artifacts_root, run_id, spec)
        for run_id, spec in run_specs.items()
    }
    scorer = SimpleScorer(config.scoring.evidence_types)

    static_scores = {
        run_specs[run_id].run_type: scorer.score(artifacts.evidences)
        for run_id, artifacts in runs.items()
    }
    basic = {
        run_specs[run_id].run_type: _replay_summary(
            artifacts,
            run_specs[run_id],
            config,
            window_size_sec=300,
            step_size_sec=10,
            persistence_k=2,
        )
        for run_id, artifacts in runs.items()
    }
    attack_artifacts = runs[ATTACK_RUN_ID]
    attack_spec = run_specs[ATTACK_RUN_ID]

    window_ablation = {
        str(window): _replay_summary(
            attack_artifacts,
            attack_spec,
            config,
            window_size_sec=window,
            step_size_sec=10,
            persistence_k=2,
        )
        for window in (180, 190, 200, 300)
    }
    persistence_ablation = {
        str(persistence): _replay_summary(
            attack_artifacts,
            attack_spec,
            config,
            window_size_sec=190,
            step_size_sec=10,
            persistence_k=persistence,
        )
        for persistence in (1, 2, 3)
    }
    cadence_ablation = {
        str(cadence): _replay_summary(
            attack_artifacts,
            attack_spec,
            config,
            window_size_sec=190,
            step_size_sec=cadence,
            persistence_k=2,
        )
        for cadence in (5, 10, 20)
    }

    return {
        "schema_version": "r1-pair002-temporal-probe-v0.1",
        "pair_id": "R1-PAIR-20261005-002",
        "analysis_mode": "retrospective_offline_event_time_mechanics",
        "input_provenance": {
            "artifact_origin": "manual_r1_lineage_input_validation_path",
            "selector_used_to_generate_probe_artifacts": False,
            "extractor_version": EXTRACTOR_VERSION,
            "approved_lineage_policy": {
                "policy_id": APPROVED_POLICY_ID,
                "version": APPROVED_POLICY_VERSION,
                "config_hash": APPROVED_POLICY_CONFIG_HASH,
            },
            "runs": {
                run_id: {
                    "run_type": spec.run_type,
                    "normalized_input_sha256": spec.hashes.normalized_input,
                    "normalized_input_hash_basis": "utf8_text_crlf_canonicalized_to_lf",
                    "evidence_sha256": spec.hashes.evidence,
                    "evidence_hash_basis": "raw_artifact_bytes",
                    "extraction_summary_sha256": spec.hashes.extraction_summary,
                    "extraction_summary_hash_basis": "raw_artifact_bytes",
                }
                for run_id, spec in run_specs.items()
            },
        },
        "analysis_revision": {
            "initial_develop_base": INITIAL_DEVELOP_BASE,
            "initial_analysis_document_commit": INITIAL_ANALYSIS_DOCUMENT_COMMIT,
            "review_reproduction_base": REVIEW_REPRODUCTION_BASE,
        },
        "fusion_config": {
            "config_version": config.config_version,
            "scoring_profile_id": config.scoring.profile_id,
            "scorer_version": config.scoring.scorer_version,
            "sha256": _sha256_lf_normalized_text(config_path),
            "hash_basis": "utf8_text_crlf_canonicalized_to_lf",
        },
        "static_presence": static_scores,
        "basic_replay": basic,
        "window_ablation_sec": window_ablation,
        "persistence_ablation_k": persistence_ablation,
        "cadence_ablation_sec": cadence_ablation,
    }


def write_probe_result(result: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    args = parser.parse_args()

    result = run_probe(args.artifacts_root, config_path=args.config)
    write_probe_result(result, args.output)


if __name__ == "__main__":
    main()
