"""Validate and consume the R1 Pair-002 offline whole-episode delivery."""

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.pipeline.r1_artifacts import (
    load_r1_evidence_artifacts,
    load_r1_extraction_summary,
)

ATTACK_RUN_ID = "RUN-20261005-912"
NORMAL_RUN_ID = "RUN-20261005-913"
DELIVERY_COMMIT = "9ee8680482cdfe0db23c8d01f1394fb57012d5a2"
PROVENANCE_SHA256 = "b927fa9dcad898036a36c29d8ca594dd723bfcc172472c054d85876044923c8a"
REGENERATION_RESULT_SHA256 = "6e04d7bfc034b36cdfaa51672300538e111ebf9a5f0ebe6eb6152b5ac81ff7b6"

SELECTOR_POLICY = {
    "policy_id": "r1-structural-lineage-selector",
    "version": "v0.1",
    "config_hash": "669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
    "lineage_event_count": 3,
}
APPROVED_POLICY = {
    "policy_id": "r1-v02-development-connection",
    "version": "v0.1",
    "config_hash": "59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78",
    "approved_lineage": ["wsmprovhost.exe", "cmd.exe", "powershell.exe"],
    "scope": "development_validation",
    "production_approved": False,
}
SCORING_EVIDENCE_TYPES = (
    "remote_session_process_lineage_deviation",
    "remote_process_network_follow_on",
)
CONSUMER_CONFIG = {
    "config_id": "r1-pair002-delivery-static-presence",
    "version": "v0.1",
    "mode": "offline_whole_episode_static_presence",
    "evidence_types": list(SCORING_EVIDENCE_TYPES),
}


@dataclass(frozen=True, slots=True)
class RunExpectation:
    classification: str
    raw_sha256: str
    normalized_sha256: str
    evidence_sha256: str
    summary_sha256: str
    evidence_ids: tuple[str, ...]
    evidence_types: tuple[tuple[str, int], ...]
    static_presence: float


@dataclass(frozen=True, slots=True)
class DeliveryExpectation:
    provenance_sha256: str
    regeneration_result_sha256: str
    delivery_commit: str
    selector_policy: dict[str, object]
    approved_policy: dict[str, object]
    runs: dict[str, RunExpectation]


@dataclass(frozen=True, slots=True)
class ExecutionRevision:
    execution_commit: str
    execution_dirty: bool
    status_porcelain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutionInvocation:
    sys_argv: tuple[str, ...]
    sys_executable: str
    cwd: str


EXPECTED_DELIVERY = DeliveryExpectation(
    provenance_sha256=PROVENANCE_SHA256,
    regeneration_result_sha256=REGENERATION_RESULT_SHA256,
    delivery_commit=DELIVERY_COMMIT,
    selector_policy=SELECTOR_POLICY,
    approved_policy=APPROVED_POLICY,
    runs={
        ATTACK_RUN_ID: RunExpectation(
            classification="Attack",
            raw_sha256="dddf1d7cb78d4958a7b84fecc8e9ff14de56a63bd631758e6e7638ed6f3a9197",
            normalized_sha256=("d62050b01c8bf8edbdd9c7431a448665a6c622220a3739567dbe325cd7776097"),
            evidence_sha256=("48daef65704b5c0b513550cc4a2fe766f1a418869f66383b5e54e89c08e4ffce"),
            summary_sha256=("545d4c6f08c9d2c092a26709ab58f6ea3d15fa49632bb71f98e26d074a0e6671"),
            evidence_ids=(
                "E-71225400-91e7-598d-8b62-69600484a820",
                "E-198f0a21-dbe6-5a26-9079-dd35dc516613",
            ),
            evidence_types=(
                ("remote_process_network_follow_on", 1),
                ("remote_session_process_lineage_deviation", 1),
            ),
            static_presence=1.0,
        ),
        NORMAL_RUN_ID: RunExpectation(
            classification="Normal",
            raw_sha256="f3b9157f2a4ec56710a555194a701b9b43dea52de1883319c4b94e89616bf95d",
            normalized_sha256=("f5f6b1e81d928be1eb8329c13b13081930d3d363320ee4784e67abe51b241839"),
            evidence_sha256=("b0fa9a2d2789da1f3dd0257789a4d143988c035eb225aef136be8e5b5455e8b4"),
            summary_sha256=("1b882055456c96cf16f26c3163d0d38de9504733d108a951144ef5ce5c15958a"),
            evidence_ids=("E-da1fa18e-8320-5f36-8ac5-97488b4e6eae",),
            evidence_types=(("remote_process_network_follow_on", 1),),
            static_presence=0.5,
        ),
    },
)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise ValueError(f"required delivery file is not readable: {path}") from error


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_read_bytes(path))


def _require_hash(path: Path, expected: str, *, label: str) -> str:
    actual = _sha256_file(path)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")
    return actual


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _git_execution_revision(repository_root: Path) -> ExecutionRevision:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        status_output = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("unable to capture delivery-check execution Git revision") from error
    if not commit:
        raise ValueError("delivery-check execution commit must not be blank")
    status_lines = tuple(line for line in status_output.splitlines() if line)
    return ExecutionRevision(
        execution_commit=commit,
        execution_dirty=bool(status_lines),
        status_porcelain=status_lines,
    )


def _execution_invocation() -> ExecutionInvocation:
    return ExecutionInvocation(
        sys_argv=tuple(sys.argv),
        sys_executable=sys.executable,
        cwd=str(Path.cwd()),
    )


def _run_paths(delivery_root: Path, run_id: str) -> dict[str, Path]:
    return {
        "raw": delivery_root / "_repro" / "raw" / f"{run_id}_sysmon-0001.jsonl",
        "normalized": delivery_root / "_repro" / "normalized" / f"{run_id}.jsonl",
        "evidence": delivery_root / run_id / "r1_evidence.jsonl",
        "summary": delivery_root / run_id / "r1_extraction_summary.json",
    }


def _required_delivery_paths(
    delivery_root: Path,
    expectations: DeliveryExpectation,
) -> tuple[Path, ...]:
    paths = [
        delivery_root / "provenance.md",
        delivery_root / "_repro" / "regeneration-result.json",
    ]
    for run_id in expectations.runs:
        paths.extend(_run_paths(delivery_root, run_id).values())
    return tuple(paths)


def _validate_zip_matches_delivery(
    delivery_zip: Path,
    delivery_root: Path,
    required_paths: tuple[Path, ...],
) -> None:
    try:
        with zipfile.ZipFile(delivery_zip) as archive:
            corrupt_member = archive.testzip()
            if corrupt_member is not None:
                raise ValueError(f"delivery ZIP has a corrupt member: {corrupt_member}")
            file_names = tuple(
                PurePosixPath(info.filename).as_posix()
                for info in archive.infolist()
                if not info.is_dir()
            )
            for path in required_paths:
                relative = path.relative_to(delivery_root).as_posix()
                matches = [
                    name for name in file_names if name == relative or name.endswith(f"/{relative}")
                ]
                if len(matches) != 1:
                    raise ValueError(
                        f"delivery ZIP must contain exactly one {relative}; got {len(matches)}"
                    )
                if archive.read(matches[0]) != _read_bytes(path):
                    raise ValueError(f"delivery ZIP member differs from extracted file: {relative}")
    except (OSError, zipfile.BadZipFile) as error:
        raise ValueError(f"delivery ZIP is not readable: {delivery_zip}") from error


def _load_regeneration_result(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("regeneration-result.json is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise TypeError("regeneration-result.json root must be an object")
    return value


def _validate_regeneration_result(
    result: dict[str, object],
    expectations: DeliveryExpectation,
) -> dict[str, dict[str, object]]:
    if result.get("selector_policy") != expectations.selector_policy:
        raise ValueError("regeneration selector policy provenance mismatch")
    if result.get("approved_policy") != expectations.approved_policy:
        raise ValueError("regeneration approved policy provenance mismatch")
    runs = result.get("runs")
    if not isinstance(runs, list):
        raise TypeError("regeneration runs must be an array")
    by_run: dict[str, dict[str, object]] = {}
    for item in runs:
        if not isinstance(item, dict) or not isinstance(item.get("run_id"), str):
            raise TypeError("regeneration run entry is invalid")
        run_id = item["run_id"]
        if run_id in by_run:
            raise ValueError(f"regeneration contains duplicate run_id: {run_id}")
        by_run[run_id] = item
    if set(by_run) != set(expectations.runs):
        raise ValueError("regeneration run IDs do not match Pair-002")
    return by_run


def _validate_regeneration_run(
    regeneration: dict[str, object],
    expectation: RunExpectation,
) -> None:
    expected_values: dict[str, object] = {
        "classification": expectation.classification,
        "raw_sha256": expectation.raw_sha256,
        "normalized_sha256": expectation.normalized_sha256,
        "evidence_sha256": expectation.evidence_sha256,
        "summary_sha256": expectation.summary_sha256,
        "evidence_count": len(expectation.evidence_ids),
        "resolved_evidence_count": len(expectation.evidence_ids),
        "evidence_types": dict(expectation.evidence_types),
        "selector_diagnostics": [],
        "extraction_diagnostics": [],
    }
    for field_name, expected in expected_values.items():
        if regeneration.get(field_name) != expected:
            raise ValueError(f"regeneration {field_name} mismatch for {regeneration['run_id']}")


def _validate_provenance_text(
    path: Path,
    expectations: DeliveryExpectation,
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("provenance.md is not valid UTF-8 text") from error
    required_values = [
        expectations.delivery_commit,
        str(expectations.selector_policy["policy_id"]),
        str(expectations.selector_policy["version"]),
        str(expectations.selector_policy["config_hash"]),
        str(expectations.approved_policy["policy_id"]),
        str(expectations.approved_policy["version"]),
        str(expectations.approved_policy["config_hash"]),
        *(
            value
            for run in expectations.runs.values()
            for value in (
                run.raw_sha256,
                run.normalized_sha256,
                run.evidence_sha256,
                run.summary_sha256,
            )
        ),
        "OFFLINE WHOLE-EPISODE ONLY",
        "Temporal Replay: `NOT SUPPORTED`",
        "TTSD: `NOT SUPPORTED`",
    ]
    missing = [value for value in required_values if value not in text]
    if missing:
        raise ValueError("provenance.md is missing required values: " + ", ".join(missing))


def _consume_run(
    delivery_root: Path,
    run_id: str,
    expectation: RunExpectation,
    regeneration: dict[str, object],
    scorer: SimpleScorer,
    approved_policy: dict[str, object],
) -> dict[str, object]:
    paths = _run_paths(delivery_root, run_id)
    hashes = {
        "raw": _require_hash(paths["raw"], expectation.raw_sha256, label=f"{run_id} Raw"),
        "normalized": _require_hash(
            paths["normalized"],
            expectation.normalized_sha256,
            label=f"{run_id} Normalized",
        ),
        "evidence": _require_hash(
            paths["evidence"], expectation.evidence_sha256, label=f"{run_id} Evidence"
        ),
        "summary": _require_hash(
            paths["summary"], expectation.summary_sha256, label=f"{run_id} summary"
        ),
    }
    _validate_regeneration_run(regeneration, expectation)

    summary = load_r1_extraction_summary(delivery_root / run_id)
    artifacts = load_r1_evidence_artifacts(delivery_root / run_id)
    if artifacts.summary != summary:
        raise ValueError(f"{run_id} artifact and summary loaders disagree")
    evidence_ids = tuple(evidence.evidence_id for evidence in artifacts.evidences)
    if evidence_ids != expectation.evidence_ids:
        raise ValueError(f"{run_id} Evidence IDs do not match existing Pair-002")
    evidence_types = dict(Counter(evidence.evidence_type for evidence in artifacts.evidences))
    if evidence_types != dict(expectation.evidence_types):
        raise ValueError(f"{run_id} Evidence type counts do not match existing Pair-002")
    static_presence = scorer.score(artifacts.evidences)
    if static_presence != expectation.static_presence:
        raise ValueError(f"{run_id} static presence does not match existing Pair-002")

    lineage_inputs = summary.lineage_inputs
    expected_policy_provenance = {
        "policy_id": approved_policy["policy_id"],
        "version": approved_policy["version"],
        "config_hash": approved_policy["config_hash"],
    }
    if not lineage_inputs or any(
        {
            "policy_id": item.policy_id,
            "version": item.policy_version,
            "config_hash": item.policy_config_hash,
        }
        != expected_policy_provenance
        for item in lineage_inputs
    ):
        raise ValueError(f"{run_id} summary approved policy provenance mismatch")

    return {
        "classification": expectation.classification,
        "run_id": run_id,
        "whole_episode_consumptions": 1,
        "hashes": {
            "raw_sha256": hashes["raw"],
            "normalized_sha256": hashes["normalized"],
            "evidence_sha256": hashes["evidence"],
            "summary_sha256": hashes["summary"],
        },
        "evidence_ids": list(evidence_ids),
        "evidence_type_counts": evidence_types,
        "evidence_count": len(artifacts.evidences),
        "extractor_version": summary.extractor_version,
        "static_presence": static_presence,
        "matches_existing_pair002": True,
    }


def validate_delivery(
    *,
    delivery_zip: Path,
    delivery_root: Path,
    repository_root: Path,
    execution_invocation: ExecutionInvocation,
    reproduction_command: str,
    expectations: DeliveryExpectation = EXPECTED_DELIVERY,
    execution_revision: ExecutionRevision | None = None,
) -> dict[str, object]:
    """Fail closed, then consume each full run once without temporal processing."""
    if not delivery_zip.is_file():
        raise ValueError(f"delivery ZIP does not exist: {delivery_zip}")
    if not delivery_root.is_dir():
        raise ValueError(f"delivery root does not exist: {delivery_root}")
    if execution_revision is None:
        execution_revision = _git_execution_revision(repository_root)

    required_paths = _required_delivery_paths(delivery_root, expectations)
    _validate_zip_matches_delivery(delivery_zip, delivery_root, required_paths)
    provenance_path = delivery_root / "provenance.md"
    regeneration_path = delivery_root / "_repro" / "regeneration-result.json"
    provenance_hash = _require_hash(
        provenance_path,
        expectations.provenance_sha256,
        label="provenance.md",
    )
    regeneration_hash = _require_hash(
        regeneration_path,
        expectations.regeneration_result_sha256,
        label="regeneration-result.json",
    )
    _validate_provenance_text(provenance_path, expectations)
    regeneration = _load_regeneration_result(regeneration_path)
    regeneration_runs = _validate_regeneration_result(regeneration, expectations)

    scorer = SimpleScorer(SCORING_EVIDENCE_TYPES)
    runs = {
        run_id: _consume_run(
            delivery_root,
            run_id,
            expectation,
            regeneration_runs[run_id],
            scorer,
            expectations.approved_policy,
        )
        for run_id, expectation in expectations.runs.items()
    }
    consumer_config_hash = _sha256_bytes(_canonical_json_bytes(CONSUMER_CONFIG))
    result: dict[str, object] = {
        "schema_version": "r1-pair002-delivery-check-v0.1",
        "purpose": "development_connection_check",
        "performance_evaluation": False,
        "processing_mode": "offline_whole_episode_static_presence",
        "temporal_replay_used": False,
        "stopping_policy_used": False,
        "ttsd_computed": False,
        "online_or_per_time_processing_used": False,
        "execution": {
            "sys_argv": list(execution_invocation.sys_argv),
            "sys_executable": execution_invocation.sys_executable,
            "cwd": execution_invocation.cwd,
            "execution_commit": execution_revision.execution_commit,
            "execution_dirty": execution_revision.execution_dirty,
            "git_status_porcelain": list(execution_revision.status_porcelain),
        },
        "reproduction_command": reproduction_command,
        "input": {
            "delivery_zip_sha256": _sha256_file(delivery_zip),
            "delivery_commit": expectations.delivery_commit,
            "provenance_sha256": provenance_hash,
            "regeneration_result_sha256": regeneration_hash,
        },
        "selector_policy": expectations.selector_policy,
        "approved_policy": expectations.approved_policy,
        "consumer_config": {
            **CONSUMER_CONFIG,
            "config_hash": consumer_config_hash,
            "config_hash_basis": "canonical_json",
        },
        "runs": runs,
        "comparison": {
            "evidence_ids_match": True,
            "artifact_hashes_match": True,
            "evidence_type_counts_match": True,
            "static_presence_matches": True,
            "all_match": True,
        },
        "limitations": [
            "development connection check only",
            "not performance evidence",
            "not a Temporal Replay input",
            "not causal or online evidence",
            "TTSD not evaluated",
        ],
    }
    result["output_hash_basis"] = "canonical_json_excluding_output_sha256"
    result["output_sha256"] = _sha256_bytes(_canonical_json_bytes(result))
    return result


def write_result(result: dict[str, object], output: Path, repository_root: Path) -> str:
    if output.resolve().is_relative_to(repository_root.resolve()):
        raise ValueError("delivery-check output must be stored outside the repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return _sha256_file(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delivery-zip", type=Path, required=True)
    parser.add_argument("--delivery-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repository_root = Path(__file__).resolve().parents[2]
    reproduction_command = (
        '$env:PYTHONPATH = "src"; '
        "uv run python tools/analysis/r1_pair002_delivery_check.py "
        f'--delivery-zip "{args.delivery_zip}" '
        f'--delivery-root "{args.delivery_root}" '
        f'--output "{args.output}"'
    )
    result = validate_delivery(
        delivery_zip=args.delivery_zip,
        delivery_root=args.delivery_root,
        repository_root=repository_root,
        execution_invocation=_execution_invocation(),
        reproduction_command=reproduction_command,
    )
    output_file_sha256 = write_result(result, args.output, repository_root)
    print(f"output={args.output}")
    print(f"output_file_sha256={output_file_sha256}")


if __name__ == "__main__":
    main()
