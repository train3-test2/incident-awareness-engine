import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.output_builder import (
    FusionOutputMetadata,
    build_fusion_output,
    write_fusion_output,
)
from incident_awareness.decision.fusion.replay import replay_fusion
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)

PROFILE_TYPES = (
    "type_a",
    "type_b",
    "type_c",
    "type_d",
)

WINDOW_SIZE = timedelta(minutes=5)
STEP_SIZE = timedelta(seconds=10)


def make_evidence(
    *,
    evidence_id: str,
    run_id: str,
    timestamp: datetime,
    evidence_type: str,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=run_id,
        timestamp=timestamp,
        entity_id="HOST-01",
        evidence_type=evidence_type,
        source_event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="synthetic-fixture-v0.1",
    )


def make_metadata(
    git_commit: str,
) -> FusionOutputMetadata:
    return FusionOutputMetadata(
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        evidence_schema_version="v0.1",
        scoring_config_version="synthetic-fixture-v0.1",
        scoring_profile_id="synthetic-4type-v0.1",
        git_commit=git_commit,
    )


def build_detected_output(
    git_commit: str,
):
    run_id = "SYNTH-DETECTED-01"
    run_start = datetime(2026, 8, 31, 0, 0, tzinfo=UTC)

    evidence = [
        make_evidence(
            evidence_id="E-001",
            run_id=run_id,
            timestamp=run_start,
            evidence_type="type_a",
        ),
        make_evidence(
            evidence_id="E-002",
            run_id=run_id,
            timestamp=run_start + timedelta(seconds=10),
            evidence_type="type_b",
        ),
        make_evidence(
            evidence_id="E-003",
            run_id=run_id,
            timestamp=run_start + timedelta(seconds=20),
            evidence_type="type_c",
        ),
    ]

    scorer = SimpleScorer(PROFILE_TYPES)

    replay_result = replay_fusion(
        evidence=evidence,
        run_id=run_id,
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=40),
        window_size=WINDOW_SIZE,
        step_size=STEP_SIZE,
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=3,
        ),
    )

    return build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id=run_id,
        entity_id="HOST-01",
        window_size=WINDOW_SIZE,
        scorer=scorer,
        metadata=make_metadata(git_commit),
    )


def build_miss_output(
    git_commit: str,
):
    run_id = "SYNTH-MISS-01"
    run_start = datetime(2026, 8, 31, 0, 0, tzinfo=UTC)

    evidence = [
        make_evidence(
            evidence_id="E-101",
            run_id=run_id,
            timestamp=run_start,
            evidence_type="type_a",
        ),
    ]

    scorer = SimpleScorer(PROFILE_TYPES)

    replay_result = replay_fusion(
        evidence=evidence,
        run_id=run_id,
        entity_id="HOST-01",
        run_start=run_start,
        run_end=run_start + timedelta(seconds=40),
        window_size=WINDOW_SIZE,
        step_size=STEP_SIZE,
        scorer=scorer,
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.7,
            persistence_k=3,
        ),
    )

    return build_fusion_output(
        replay_result=replay_result,
        evidence=evidence,
        run_id=run_id,
        entity_id="HOST-01",
        window_size=WINDOW_SIZE,
        scorer=scorer,
        metadata=make_metadata(git_commit),
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(
    *,
    output_dir: Path,
    git_commit: str,
    artifact_paths: list[Path],
) -> None:
    artifacts = [
        {
            "path": path.name,
            "sha256": sha256_file(path),
        }
        for path in sorted(
            artifact_paths,
            key=lambda item: item.name,
        )
    ]

    manifest = {
        "manifest_version": "synthetic-fusion-v0.1",
        "git_commit": git_commit,
        "artifacts": artifacts,
    }

    payload = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    (output_dir / "manifest.json").write_bytes(f"{payload}\n".encode())


def validate_outputs(
    *,
    repo_root: Path,
    output_paths: list[Path],
) -> None:
    schema_path = repo_root / "schemas" / "fusion_output_v0.1.schema.json"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    validator = Draft202012Validator(schema)

    for path in output_paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validator.validate(payload)


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--output-dir",
        default="samples/fusion",
    )

    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    output_dir = Path(args.output_dir)

    if not output_dir.is_absolute():
        output_dir = repo_root / output_dir

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    git_commit = subprocess.check_output(
        [
            "git",
            "rev-parse",
            "--short",
            "HEAD",
        ],
        cwd=repo_root,
        text=True,
    ).strip()

    detected_path = output_dir / "fusion_output_detected.json"

    miss_path = output_dir / "fusion_output_miss.json"

    write_fusion_output(
        build_detected_output(git_commit),
        detected_path,
    )

    write_fusion_output(
        build_miss_output(git_commit),
        miss_path,
    )

    output_paths = [
        detected_path,
        miss_path,
    ]

    validate_outputs(
        repo_root=repo_root,
        output_paths=output_paths,
    )

    write_manifest(
        output_dir=output_dir,
        git_commit=git_commit,
        artifact_paths=output_paths,
    )

    for path in output_paths:
        print(f"{path.name}: schema OK / SHA256={sha256_file(path)}")

    print("manifest.json: created")


if __name__ == "__main__":
    main()
