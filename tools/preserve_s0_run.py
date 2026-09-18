"""Preserve the artifacts of one formal S0 run outside the VM.

The run artifacts are first copied out of the VM by hand. This tool then files
that copy, the files the run depended on and the operator evidence under one
directory per run, checks every copy against its source by SHA-256 and writes a
SHA256SUMS.csv for later re-verification. It never changes the source files, the
VM or a firewall; it only copies and hashes. Whether the run passed the S0
artifact validator is decided by the validator or the caller: the validator
output is preserved, not interpreted.

    python tools/preserve_s0_run.py preserve --run-id RUN-YYYYMMDD-NNN \\
        --artifact-root <copied data root> --formal-root <formal root> \\
        --snapshot poc-s0-ready-c62656b --scenario-json <scenario.json> \\
        --sysmon-config <sysmon config> --run-common <run-common.ps1> \\
        --run-script <run.ps1> --execution-log <log> --validator-output <file> \\
        --firewall-removal <file> --approval-record <file>

    python tools/preserve_s0_run.py verify --preserved-dir <formal root>/<run_id>

See docs/scenarios/s0-artifact-preservation.md.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath

TOOL_NAME = "preserve_s0_run"
TOOL_VERSION = "0.1.0"
RECORD_VERSION = "s0-preservation-record-v0.1"

RECORD_FILENAME = "preservation_record.json"
SHA256SUMS_FILENAME = "SHA256SUMS.csv"
SHA256SUMS_HEADER = ("path", "sha256")

REHEARSAL_MARKER = "REHEARSAL.txt"
REHEARSAL_DIRNAME = "_rehearsal"

# Files the S0 runner writes for every run (scenarios/S0/run-common.ps1).
REQUIRED_RAW_FILES = (
    "manifest.json",
    "telemetry/sysmon-0001.evtx",
    "telemetry/sysmon-0001.jsonl",
)
REQUIRED_GROUND_TRUTH_FILES = (
    "execution_record.csv",
    "run_metadata.json",
)

# Where the operator evidence is filed inside a preserved run.
EVIDENCE_PATHS = {
    "execution_log": "verification/execution-log.txt",
    "validator_output": "verification/validator-output.txt",
    "firewall_removal": "verification/firewall-removal.txt",
    "approval_record": "verification/approval-record.txt",
}

# Every file a complete preserved run must hold, besides one Sysmon XML config
# under support/ that keeps its own file name. SHA256SUMS.csv is not listed: it
# does not list itself.
REQUIRED_BUNDLE_FILES = (
    *(f"raw/{{run_id}}/{name}" for name in REQUIRED_RAW_FILES),
    *(f"ground_truth/{{run_id}}/{name}" for name in REQUIRED_GROUND_TRUTH_FILES),
    "support/scenario.json",
    "support/run-common.ps1",
    "support/run.ps1",
    *EVIDENCE_PATHS.values(),
    RECORD_FILENAME,
)

# Same shape RunMetadata requires (docs/schema/run-id.md section 3). It is
# restated here because the value arrives from the command line and must be
# rejected before it is joined onto any path.
_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")

_CHUNK_SIZE = 1024 * 1024


class PreservationError(Exception):
    """Raised when a run cannot be preserved or a preserved run does not verify."""


@dataclass(frozen=True, slots=True)
class PreservationInputs:
    run_id: str
    artifact_root: Path
    formal_root: Path
    snapshot: str
    scenario_json: Path
    sysmon_config: Path
    run_common: Path
    run_script: Path
    execution_log: Path
    validator_output: Path
    firewall_removal: Path
    approval_record: Path


@dataclass(frozen=True, slots=True)
class PreservationResult:
    run_dir: Path
    file_count: int


def validate_run_id(run_id: object) -> str:
    """Return run_id if it is RUN-YYYYMMDD-NNN with a real calendar date."""
    if not isinstance(run_id, str):
        raise PreservationError("run_id must be a string")

    match = _RUN_ID_PATTERN.fullmatch(run_id)
    if match is None:
        raise PreservationError(f"run_id must match RUN-YYYYMMDD-NNN: {run_id!r}")

    try:
        date(
            int(match.group("date")[:4]),
            int(match.group("date")[4:6]),
            int(match.group("date")[6:]),
        )
    except ValueError as error:
        raise PreservationError(f"run_id must contain a valid calendar date: {run_id}") from error

    return run_id


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _is_link_or_reparse_point(path: Path) -> bool:
    if path.is_symlink() or path.is_junction():
        return True

    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _require_regular_file(path: Path, *, label: str, non_empty: bool = False) -> Path:
    if not os.path.lexists(path):
        raise PreservationError(f"{label} is missing: {path}")

    if _is_link_or_reparse_point(path):
        raise PreservationError(f"{label} must not be a symbolic link or reparse point: {path}")

    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise PreservationError(f"{label} must be a regular file: {path}")

    if non_empty and os.lstat(path).st_size == 0:
        raise PreservationError(f"{label} is empty: {path}")

    return path


def _require_real_directory(path: Path, *, label: str) -> Path:
    if not os.path.lexists(path):
        raise PreservationError(f"{label} is missing: {path}")

    if _is_link_or_reparse_point(path):
        raise PreservationError(f"{label} must not be a symbolic link or reparse point: {path}")

    if not stat.S_ISDIR(os.lstat(path).st_mode):
        raise PreservationError(f"{label} must be a directory: {path}")

    return path


def _reject_rehearsal_path(path: Path, *, label: str) -> None:
    if REHEARSAL_DIRNAME in path.resolve().parts:
        raise PreservationError(
            f"{label} is under a {REHEARSAL_DIRNAME} directory; rehearsal output is not preserved "
            f"as a formal run: {path}"
        )


def _collect_tree(source_dir: Path, *, label: str) -> list[PurePosixPath]:
    """Return every regular file under source_dir as a relative POSIX path.

    Links and reparse points are refused instead of followed, so nothing outside
    source_dir can be reached through the tree.
    """
    root = _require_real_directory(source_dir, label=label).resolve()
    found: list[PurePosixPath] = []

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in dirnames:
            _require_real_directory(current_path / name, label=f"{label} directory")
        for name in filenames:
            file_path = current_path / name
            _require_regular_file(file_path, label=f"{label} file")
            if name == REHEARSAL_MARKER:
                raise PreservationError(f"{label} contains a rehearsal marker: {file_path}")
            if not file_path.resolve().is_relative_to(root):
                raise PreservationError(f"{label} file escapes {root}: {file_path}")
            found.append(PurePosixPath(file_path.relative_to(root).as_posix()))

    return sorted(found)


def _read_run_id_field(path: Path, *, label: str) -> object:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreservationError(f"{label} is not readable JSON: {path}: {error}") from error

    if not isinstance(payload, dict):
        raise PreservationError(f"{label} must be a JSON object: {path}")

    return payload.get("run_id")


def _plan_copies(inputs: PreservationInputs) -> dict[PurePosixPath, Path]:
    """Map every destination path, relative to the run directory, to its source."""
    run_id = inputs.run_id
    artifact_root = _require_real_directory(inputs.artifact_root, label="artifact root")
    _reject_rehearsal_path(artifact_root, label="artifact root")

    if os.path.lexists(artifact_root / REHEARSAL_MARKER):
        raise PreservationError(
            f"artifact root holds {REHEARSAL_MARKER}; rehearsal output is not preserved as a "
            f"formal run: {artifact_root}"
        )

    raw_dir = artifact_root / "raw" / run_id
    ground_truth_dir = artifact_root / "ground_truth" / run_id
    _require_real_directory(artifact_root / "raw", label="raw directory")
    _require_real_directory(artifact_root / "ground_truth", label="ground_truth directory")

    plan: dict[PurePosixPath, Path] = {}
    for layer, source_dir, required in (
        ("raw", raw_dir, REQUIRED_RAW_FILES),
        ("ground_truth", ground_truth_dir, REQUIRED_GROUND_TRUTH_FILES),
    ):
        files = _collect_tree(source_dir, label=f"{layer}/{run_id}")
        missing = sorted(set(required) - {path.as_posix() for path in files})
        if missing:
            raise PreservationError(f"{layer}/{run_id} is missing required file(s): {missing}")
        for relative in files:
            plan[PurePosixPath(layer, run_id, relative)] = source_dir.joinpath(*relative.parts)

    # Guard against filing a run under the wrong run_id. This is an identity
    # check only; the artifact contract belongs to the S0 validator.
    for relative, label in (
        (PurePosixPath("raw", run_id, "manifest.json"), "manifest.json"),
        (PurePosixPath("ground_truth", run_id, "run_metadata.json"), "run_metadata.json"),
    ):
        recorded = _read_run_id_field(plan[relative], label=label)
        if recorded != run_id:
            raise PreservationError(f"{label} run_id is {recorded!r}, expected {run_id!r}")

    single_files = (
        ("support/scenario.json", inputs.scenario_json, "scenario.json", False),
        (f"support/{inputs.sysmon_config.name}", inputs.sysmon_config, "Sysmon config", False),
        ("support/run-common.ps1", inputs.run_common, "run-common.ps1", False),
        ("support/run.ps1", inputs.run_script, "run.ps1", False),
        ("verification/execution-log.txt", inputs.execution_log, "execution log", True),
        ("verification/validator-output.txt", inputs.validator_output, "validator output", True),
        (
            "verification/firewall-removal.txt",
            inputs.firewall_removal,
            "firewall removal evidence",
            True,
        ),
        ("verification/approval-record.txt", inputs.approval_record, "approval record", True),
    )
    for destination, source, label, non_empty in single_files:
        _require_regular_file(source, label=label, non_empty=non_empty)
        _reject_rehearsal_path(source, label=label)
        relative = PurePosixPath(destination)
        if relative in plan:
            raise PreservationError(f"two inputs map to the same destination: {relative}")
        plan[relative] = source

    return plan


def _check_roots_do_not_overlap(artifact_root: Path, formal_root: Path) -> None:
    source = artifact_root.resolve()
    target = formal_root.resolve()
    if source == target or source.is_relative_to(target) or target.is_relative_to(source):
        raise PreservationError(
            f"artifact root and formal root must not contain each other: {source} / {target}"
        )


def _copy_verified(source: Path, destination: Path) -> str:
    before = sha256_of(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    copied = sha256_of(destination)
    after = sha256_of(source)

    if after != before:
        raise PreservationError(f"source changed while it was being copied: {source}")
    if copied != before:
        raise PreservationError(f"copy does not match its source by SHA-256: {source}")

    return copied


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _render_sha256sums(hashes: Mapping[str, str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(SHA256SUMS_HEADER)
    for path in sorted(hashes):
        writer.writerow((path, hashes[path]))
    return buffer.getvalue()


def _hash_tree(run_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in _collect_tree(run_dir, label="preserved run"):
        if relative.as_posix() == SHA256SUMS_FILENAME:
            continue
        hashes[relative.as_posix()] = sha256_of(run_dir.joinpath(*relative.parts))
    return hashes


def preserve_s0_run(
    inputs: PreservationInputs,
    *,
    now: datetime | None = None,
) -> PreservationResult:
    """Copy one formal S0 run into <formal_root>/<run_id> and hash every file.

    The run is assembled in a staging directory next to its final place and moved
    there only after every copy, the record and SHA256SUMS.csv have been checked.
    An existing <formal_root>/<run_id> is never touched. On failure only the
    staging directory this call created is removed.
    """
    run_id = validate_run_id(inputs.run_id)

    if not isinstance(inputs.snapshot, str) or not inputs.snapshot.strip():
        raise PreservationError("snapshot must be a non-blank string")

    formal_root = inputs.formal_root
    _reject_rehearsal_path(formal_root, label="formal root")
    if os.path.lexists(formal_root):
        _require_real_directory(formal_root, label="formal root")
    _check_roots_do_not_overlap(inputs.artifact_root, formal_root)

    final_dir = formal_root / run_id
    if os.path.lexists(final_dir):
        raise PreservationError(f"preserved run already exists, refusing to overwrite: {final_dir}")

    plan = _plan_copies(inputs)

    formal_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{run_id}.staging-", dir=formal_root))
    try:
        copied_hashes = {
            relative.as_posix(): _copy_verified(source, staging.joinpath(*relative.parts))
            for relative, source in sorted(plan.items())
        }

        record = {
            "record_version": RECORD_VERSION,
            "run_id": run_id,
            "preserved_at": _utc_timestamp(now or datetime.now(UTC)),
            "snapshot": inputs.snapshot,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "file_count": len(copied_hashes),
            "hash_verification": {
                "method": "sha256",
                "compared_files": len(copied_hashes),
                "all_match": True,
            },
            "files": sorted(copied_hashes),
            "evidence": {**EVIDENCE_PATHS, "validator_output_interpreted": False},
            "sha256sums": {
                "path": SHA256SUMS_FILENAME,
                "format": "UTF-8 CSV without BOM, LF, header path,sha256, rows sorted by path",
                "excludes_itself": True,
                "includes_record": True,
            },
        }
        (staging / RECORD_FILENAME).write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        hashes = _hash_tree(staging)
        for path, digest in copied_hashes.items():
            if hashes.get(path) != digest:
                raise PreservationError(f"staged file changed after copy: {path}")

        (staging / SHA256SUMS_FILENAME).write_text(
            _render_sha256sums(hashes), encoding="utf-8", newline="\n"
        )
        file_count = verify_preserved_run(staging, expected_run_id=run_id)

        if os.path.lexists(final_dir):
            raise PreservationError(
                f"preserved run appeared while staging, refusing to overwrite: {final_dir}"
            )
        os.rename(staging, final_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return PreservationResult(run_dir=final_dir, file_count=file_count)


def verify_preserved_run(run_dir: Path, *, expected_run_id: str | None = None) -> int:
    """Check that a preserved run is complete and intact; return the listed file count.

    Beyond re-hashing every file against SHA256SUMS.csv (every file except
    SHA256SUMS.csv itself must be listed, exist and match), this reads
    preservation_record.json and checks that the bundle is the run it claims to
    be: a valid run_id equal to the directory name, the record's file list equal
    to the SHA256SUMS.csv list minus the record, every required file present and
    the record's counts consistent. An empty or header-only bundle fails.

    It checks the bundle only. Whether the collected artifacts themselves satisfy
    their contracts (Manifest, RunMetadata, execution_record) is the S0
    validator's job.

    expected_run_id is for a staging directory, whose name is not the run_id.
    """
    listed = _read_sha256sums(run_dir)
    if not listed:
        raise PreservationError(f"{SHA256SUMS_FILENAME} lists no files")

    if RECORD_FILENAME not in listed:
        raise PreservationError(f"{RECORD_FILENAME} is not listed in {SHA256SUMS_FILENAME}")

    record_path = _require_regular_file(run_dir / RECORD_FILENAME, label=RECORD_FILENAME)

    actual = _hash_tree(run_dir)
    if set(actual) != set(listed):
        raise PreservationError(
            f"{SHA256SUMS_FILENAME} does not list exactly the preserved files; "
            f"unlisted={sorted(set(actual) - set(listed))} "
            f"missing={sorted(set(listed) - set(actual))}"
        )

    mismatched = sorted(path for path in listed if listed[path] != actual[path])
    if mismatched:
        raise PreservationError(f"SHA-256 mismatch: {mismatched}")

    _check_record(
        _read_record(record_path),
        listed_paths=set(listed),
        directory_run_id=expected_run_id if expected_run_id is not None else run_dir.name,
    )
    return len(listed)


def _read_sha256sums(run_dir: Path) -> dict[str, str]:
    sums_path = _require_regular_file(run_dir / SHA256SUMS_FILENAME, label=SHA256SUMS_FILENAME)
    rows = list(csv.reader(sums_path.read_text(encoding="utf-8").splitlines()))

    if not rows or tuple(rows[0]) != SHA256SUMS_HEADER:
        raise PreservationError(
            f"{SHA256SUMS_FILENAME} header must be {','.join(SHA256SUMS_HEADER)}"
        )

    listed: dict[str, str] = {}
    for row in rows[1:]:
        if len(row) != 2:
            raise PreservationError(f"{SHA256SUMS_FILENAME} row must have two columns: {row}")
        path, digest = row
        if path in listed:
            raise PreservationError(f"{SHA256SUMS_FILENAME} lists a path twice: {path}")
        listed[path] = digest

    paths = [row[0] for row in rows[1:]]
    if paths != sorted(paths):
        raise PreservationError(f"{SHA256SUMS_FILENAME} rows are not sorted by path")

    return listed


def _read_record(record_path: Path) -> dict[str, object]:
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreservationError(f"{RECORD_FILENAME} is not readable JSON: {error}") from error

    if not isinstance(record, dict):
        raise PreservationError(f"{RECORD_FILENAME} must be a JSON object")

    return record


def _is_count(value: object) -> bool:
    # bool is a subclass of int, so it is excluded explicitly.
    return isinstance(value, int) and not isinstance(value, bool)


def _check_record(
    record: dict[str, object],
    *,
    listed_paths: set[str],
    directory_run_id: str,
) -> None:
    """Cross-check preservation_record.json against the files the bundle holds."""
    if record.get("record_version") != RECORD_VERSION:
        raise PreservationError(
            f"{RECORD_FILENAME} record_version is {record.get('record_version')!r}, "
            f"expected {RECORD_VERSION!r}"
        )

    run_id = validate_run_id(record.get("run_id"))
    if run_id != directory_run_id:
        raise PreservationError(
            f"{RECORD_FILENAME} run_id {run_id} does not match the preserved directory "
            f"{directory_run_id}"
        )

    files = record.get("files")
    if not isinstance(files, list) or not all(isinstance(path, str) for path in files):
        raise PreservationError(f"{RECORD_FILENAME} files must be a list of paths")

    expected_files = sorted(listed_paths - {RECORD_FILENAME})
    if files != expected_files:
        raise PreservationError(
            f"{RECORD_FILENAME} files does not match {SHA256SUMS_FILENAME}; "
            f"only_in_record={sorted(set(files) - set(expected_files))} "
            f"only_in_sums={sorted(set(expected_files) - set(files))}"
        )

    required = [path.format(run_id=run_id) for path in REQUIRED_BUNDLE_FILES]
    missing = [path for path in required if path not in listed_paths]
    if missing:
        raise PreservationError(f"preserved run is missing required file(s): {missing}")

    sysmon_configs = sorted(
        path
        for path in listed_paths
        if PurePosixPath(path).parent == PurePosixPath("support")
        and PurePosixPath(path).suffix.lower() == ".xml"
    )
    if len(sysmon_configs) != 1:
        raise PreservationError(
            f"preserved run must hold exactly one Sysmon XML config under support/, "
            f"found {sysmon_configs}"
        )

    evidence = record.get("evidence")
    if (
        not isinstance(evidence, dict)
        or {key: evidence.get(key) for key in EVIDENCE_PATHS} != EVIDENCE_PATHS
        or evidence.get("validator_output_interpreted") is not False
    ):
        raise PreservationError(
            f"{RECORD_FILENAME} evidence must point at {EVIDENCE_PATHS} with "
            "validator_output_interpreted false"
        )

    file_count = record.get("file_count")
    if not _is_count(file_count) or file_count != len(files):
        raise PreservationError(
            f"{RECORD_FILENAME} file_count is {file_count!r}, expected {len(files)}"
        )

    verification = record.get("hash_verification")
    if (
        not isinstance(verification, dict)
        or verification.get("method") != "sha256"
        or verification.get("all_match") is not True
        or not _is_count(verification.get("compared_files"))
        or verification.get("compared_files") != len(files)
    ):
        raise PreservationError(
            f"{RECORD_FILENAME} hash_verification must be sha256, all_match true and "
            f"compared_files {len(files)}, found {verification!r}"
        )

    sums = record.get("sha256sums")
    if (
        not isinstance(sums, dict)
        or sums.get("path") != SHA256SUMS_FILENAME
        or sums.get("excludes_itself") is not True
        or sums.get("includes_record") is not True
    ):
        raise PreservationError(
            f"{RECORD_FILENAME} sha256sums must name {SHA256SUMS_FILENAME}, exclude itself "
            "and include the record"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    preserve = commands.add_parser("preserve", help="preserve one formal S0 run")
    preserve.add_argument("--run-id", required=True)
    for option in (
        "--artifact-root",
        "--formal-root",
        "--scenario-json",
        "--sysmon-config",
        "--run-common",
        "--run-script",
        "--execution-log",
        "--validator-output",
        "--firewall-removal",
        "--approval-record",
    ):
        preserve.add_argument(option, type=Path, required=True)
    preserve.add_argument("--snapshot", required=True)

    verify = commands.add_parser("verify", help="re-verify a preserved run")
    verify.add_argument("--preserved-dir", type=Path, required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            count = verify_preserved_run(args.preserved_dir)
            print(f"[+] {args.preserved_dir}: {count} files match {SHA256SUMS_FILENAME}")
            return 0

        result = preserve_s0_run(
            PreservationInputs(
                run_id=args.run_id,
                artifact_root=args.artifact_root,
                formal_root=args.formal_root,
                snapshot=args.snapshot,
                scenario_json=args.scenario_json,
                sysmon_config=args.sysmon_config,
                run_common=args.run_common,
                run_script=args.run_script,
                execution_log=args.execution_log,
                validator_output=args.validator_output,
                firewall_removal=args.firewall_removal,
                approval_record=args.approval_record,
            )
        )
    except PreservationError as error:
        print(f"[!] {error}")
        return 1

    print(f"[+] preserved {result.file_count} files under {result.run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
