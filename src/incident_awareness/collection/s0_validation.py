"""Validate the four artifacts one S0 run produces.

The S0 runner (`scenarios/S0/`) writes four artifacts per run:

    raw/<run_id>/telemetry/sysmon-0001.evtx
    raw/<run_id>/telemetry/sysmon-0001.jsonl
    raw/<run_id>/manifest.json
    ground_truth/<run_id>/execution_record.csv
    ground_truth/<run_id>/run_metadata.json

This module checks that a collected run matches the contracts before the run is
handed to the pipeline: `RunMetadata` and `ExecutionRecordRow` for the Ground
Truth files, recomputed SHA-256 for the Manifest items, and the Sysmon RecordId
chain behind `reference_time` (`docs/scenarios/s0.md` section 6).

Rehearsal artifacts are not a valid S0 collection. They are accepted only with
`rehearsal=True`, and the report says so in its summary.
"""

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.run import RunMetadata, RunType

EVTX_FILENAME = "sysmon-0001.evtx"
JSONL_FILENAME = "sysmon-0001.jsonl"
REHEARSAL_MARKER = "REHEARSAL.txt"
REHEARSAL_DIRNAME = "_rehearsal"

CSV_HEADER = ("run_id", "action_id", "timestamp", "action_type", "description")

# A Manifest path is written inside the VM, so it is an absolute path that does
# not exist on the host. Only these file names are ever mapped back, and only
# into the run's own telemetry directory (see scenarios/S0/README.md).
ALLOWED_TELEMETRY_FILENAMES = frozenset({EVTX_FILENAME, JSONL_FILENAME})

_SHA256_LENGTH = 64
_HEX_DIGITS = frozenset("0123456789abcdef")
_MANIFEST_TOP_LEVEL_FIELDS = ("run_id", "generated_at", "sysmon", "items")
_MANIFEST_SYSMON_FIELDS = ("config_version", "config_sha256", "config_hash")
_MANIFEST_ITEM_FIELDS = ("raw_log_id", "path", "sha256", "layer", "source")
_SYSMON_PROCESS_CREATE_EVENT_ID = 1


class ManifestPathError(ValueError):
    """Raised when a Manifest path cannot be mapped to a known artifact."""


@dataclass
class S0ValidationReport:
    """Everything one validation run found.

    `errors` is the verdict: an empty list means the artifacts passed. `checks`
    records what was actually verified so a passing run is not a bare exit code.
    """

    run_id: str
    rehearsal: bool
    run_type: str | None = None
    errors: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def passed(self, message: str) -> None:
        self.checks.append(message)


def default_scenario_path() -> Path:
    """`scenarios/S0/scenario.yaml` inside this repository."""
    return Path(__file__).resolve().parents[3] / "scenarios" / "S0" / "scenario.yaml"


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and set(value.lower()) <= _HEX_DIGITS
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as raw_file:
        for chunk in iter(lambda: raw_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def manifest_filename(raw_path: object) -> str:
    """Extract the file name of a Manifest path without trusting the path itself.

    The path was written inside the VM (`C:\\S0\\data\\...`), so it is never
    opened as given. Only the file name survives, and the caller maps it into the
    run's own telemetry directory. Anything that could escape that directory is
    rejected rather than normalised.
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ManifestPathError("path must be a non-empty string")

    segments = raw_path.replace("\\", "/").split("/")
    if any(segment in {"..", "."} for segment in segments):
        raise ManifestPathError(f"path must not contain relative segments: {raw_path}")

    name = segments[-1]
    if not name:
        raise ManifestPathError(f"path must not end with a separator: {raw_path}")

    if name not in ALLOWED_TELEMETRY_FILENAMES:
        raise ManifestPathError(f"unexpected artifact file name: {name}")

    return name


def _parse_jsonl_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None

    text = value.removesuffix("Z") + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    return parsed if parsed.tzinfo is not None else None


def _truncate_to_milliseconds(value: datetime) -> datetime:
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def _load_scenario_actions(scenario_path: Path, run_type: str) -> tuple[set[str], set[str]]:
    """Return (all action ids, action ids that need an external connection)."""
    with scenario_path.open(encoding="utf-8") as stream:
        scenario = yaml.safe_load(stream)

    if not isinstance(scenario, dict):
        raise TypeError(f"scenario must be a mapping: {scenario_path}")

    runs = scenario.get("runs") or {}
    run = runs.get(run_type)
    if not isinstance(run, dict):
        raise TypeError(f"scenario has no runs.{run_type}: {scenario_path}")

    all_ids: set[str] = set()
    external_ids: set[str] = set()
    for action in run.get("actions") or []:
        action_id = action.get("action_id")
        if not isinstance(action_id, str):
            raise TypeError(f"runs.{run_type} has an action without action_id")

        all_ids.add(action_id)
        if action.get("uses_external_connection"):
            external_ids.add(action_id)

    return all_ids, external_ids


def _check_rehearsal_isolation(
    artifact_root: Path, rehearsal: bool, report: S0ValidationReport
) -> None:
    marker = artifact_root / REHEARSAL_MARKER
    has_marker = marker.is_file()
    in_rehearsal_dir = REHEARSAL_DIRNAME in artifact_root.resolve().parts
    detected = has_marker or in_rehearsal_dir

    if not rehearsal:
        if detected:
            report.fail(
                "rehearsal artifacts cannot be validated as a formal S0 collection; "
                f"marker={has_marker} path_isolated={in_rehearsal_dir}. Re-run with --rehearsal."
            )
        else:
            report.passed("no rehearsal marker or _rehearsal path component")
        return

    if not has_marker:
        report.fail(f"--rehearsal given but {REHEARSAL_MARKER} is missing under {artifact_root}")
    if not in_rehearsal_dir:
        report.fail(
            f"--rehearsal given but {artifact_root} is not under a {REHEARSAL_DIRNAME} directory"
        )
    if has_marker and in_rehearsal_dir:
        report.passed(
            f"{REHEARSAL_MARKER} present and artifact root is isolated under {REHEARSAL_DIRNAME}"
        )


def _read_run_metadata(path: Path, report: S0ValidationReport) -> RunMetadata | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        report.fail(f"run_metadata.json is not readable JSON: {error}")
        return None

    try:
        metadata = RunMetadata.model_validate(payload)
    except ValidationError as error:
        report.fail(f"run_metadata.json does not satisfy RunMetadata: {error}")
        return None

    report.passed("run_metadata.json satisfies RunMetadata")
    return metadata


def _read_execution_records(
    path: Path, report: S0ValidationReport
) -> list[ExecutionRecordRow] | None:
    try:
        raw = path.read_bytes()
    except OSError as error:
        report.fail(f"execution_record.csv is not readable: {error}")
        return None

    if raw.startswith(b"\xef\xbb\xbf"):
        report.fail(
            "execution_record.csv starts with a UTF-8 BOM; a reader that opens the file as "
            "plain UTF-8 cannot address the first column"
        )
        return None

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        report.fail(f"execution_record.csv is not valid UTF-8: {error}")
        return None

    rows = list(csv.reader(io.StringIO(text, newline="")))
    if not rows:
        report.fail("execution_record.csv is empty")
        return None

    header = tuple(rows[0])
    if header != CSV_HEADER:
        report.fail(
            f"execution_record.csv header must be exactly {list(CSV_HEADER)} in this order, "
            f"found {list(header)}"
        )
        return None

    data_rows = [row for row in rows[1:] if row]
    if not data_rows:
        report.fail("execution_record.csv has a header but no rows")
        return None

    records: list[ExecutionRecordRow] = []
    for line_no, row in enumerate(data_rows, start=2):
        if len(row) != len(CSV_HEADER):
            report.fail(
                f"execution_record.csv line {line_no} has {len(row)} fields, "
                f"expected {len(CSV_HEADER)}"
            )
            continue

        try:
            records.append(
                ExecutionRecordRow.model_validate(dict(zip(CSV_HEADER, row, strict=True)))
            )
        except ValidationError as error:
            report.fail(
                f"execution_record.csv line {line_no} does not satisfy ExecutionRecordRow: {error}"
            )

    if not records:
        return None

    report.passed(
        f"execution_record.csv header and {len(records)} row(s) satisfy ExecutionRecordRow"
    )
    return records


def _check_manifest(
    manifest_path: Path,
    telemetry_dir: Path,
    run_id: str,
    report: S0ValidationReport,
) -> None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        report.fail(f"manifest.json is not readable JSON: {error}")
        return

    if not isinstance(manifest, dict):
        report.fail("manifest.json must be a JSON object")
        return

    missing = [name for name in _MANIFEST_TOP_LEVEL_FIELDS if name not in manifest]
    if missing:
        report.fail(f"manifest.json is missing top-level field(s): {sorted(missing)}")
        return

    if manifest["run_id"] != run_id:
        report.fail(f"manifest.json run_id is {manifest['run_id']!r}, expected {run_id!r}")

    _check_manifest_sysmon(manifest["sysmon"], report)
    _check_manifest_items(manifest["items"], telemetry_dir, report)


def _check_manifest_sysmon(sysmon: object, report: S0ValidationReport) -> None:
    if not isinstance(sysmon, dict):
        report.fail("manifest.json sysmon must be an object")
        return

    missing = [name for name in _MANIFEST_SYSMON_FIELDS if name not in sysmon]
    if missing:
        report.fail(f"manifest.json sysmon is missing field(s): {sorted(missing)}")
        return

    config_sha256 = sysmon["config_sha256"]
    if not _is_sha256_hex(config_sha256):
        report.fail(f"manifest.json sysmon.config_sha256 is not a SHA-256 value: {config_sha256!r}")
        return

    applied = sysmon["config_hash"]
    if not isinstance(applied, str) or not applied.strip():
        report.fail(
            "manifest.json sysmon.config_hash is empty; the applied config cannot be compared"
        )
        return

    value = applied.strip()
    if "=" in value:
        algorithm, _, value = value.partition("=")
        if algorithm.strip().upper() != "SHA256":
            report.fail(
                f"manifest.json sysmon.config_hash uses {algorithm.strip()!r}; "
                "it cannot be compared with the SHA-256 of the config file"
            )
            return

    if not _is_sha256_hex(value):
        report.fail(f"manifest.json sysmon.config_hash is not a SHA-256 value: {applied!r}")
        return

    if value.lower() != config_sha256.lower():
        report.fail(
            "manifest.json sysmon config hashes differ. "
            f"config_sha256={config_sha256.lower()} config_hash={value.lower()}"
        )
        return

    report.passed(f"Sysmon config file and applied config agree ({value.lower()})")


def _check_manifest_items(items: object, telemetry_dir: Path, report: S0ValidationReport) -> None:
    if not isinstance(items, list) or not items:
        report.fail("manifest.json items must be a non-empty array")
        return

    verified = 0
    for index, item in enumerate(items):
        label = f"manifest.json items[{index}]"
        if not isinstance(item, dict):
            report.fail(f"{label} must be an object")
            continue

        missing = [name for name in _MANIFEST_ITEM_FIELDS if name not in item]
        if missing:
            report.fail(f"{label} is missing field(s): {sorted(missing)}")
            continue

        try:
            name = manifest_filename(item["path"])
        except ManifestPathError as error:
            report.fail(f"{label} path rejected: {error}")
            continue

        if "derived_from" in item:
            try:
                manifest_filename(item["derived_from"])
            except ManifestPathError as error:
                report.fail(f"{label} derived_from rejected: {error}")
                continue

        recorded = item["sha256"]
        if not _is_sha256_hex(recorded):
            report.fail(f"{label} sha256 is not a SHA-256 value: {recorded!r}")
            continue

        local_path = telemetry_dir / name
        if not local_path.is_file():
            report.fail(f"{label} maps to {local_path}, which does not exist")
            continue

        actual = _file_sha256(local_path)
        if actual != recorded.lower():
            report.fail(
                f"{label} sha256 mismatch for {name}. recorded={recorded.lower()} actual={actual}"
            )
            continue

        verified += 1

    if verified:
        report.passed(f"{verified} manifest item hash(es) match the local artifacts")


def _check_reference(
    metadata: RunMetadata,
    jsonl_path: Path,
    action_ids: set[str],
    report: S0ValidationReport,
) -> None:
    if metadata.run_type is RunType.NORMAL:
        unexpected = [
            name
            for name, value in (
                ("reference_time", metadata.reference_time),
                ("reference_action_id", metadata.reference_action_id),
                ("reference_source_event_id", metadata.reference_source_event_id),
            )
            if value is not None
        ]
        if unexpected:
            report.fail(f"a normal run must leave {sorted(unexpected)} null")
        else:
            report.passed("normal run carries no Ground Truth reference")
        return

    missing = [
        name
        for name, value in (
            ("reference_time", metadata.reference_time),
            ("reference_action_id", metadata.reference_action_id),
            ("reference_source_event_id", metadata.reference_source_event_id),
        )
        if value is None
    ]
    if missing:
        report.fail(f"an attack run must set {sorted(missing)}")
        return

    if metadata.reference_action_id not in action_ids:
        report.fail(
            f"reference_action_id {metadata.reference_action_id!r} is not in execution_record "
            f"({sorted(action_ids)})"
        )

    try:
        records = list(read_sysmon_jsonl(jsonl_path))
    except (OSError, SysmonJsonlReadError) as error:
        report.fail(f"{JSONL_FILENAME} is not readable: {error}")
        return

    anchor = next(
        (
            record.data
            for record in records
            if str(record.data.get("RecordId")) == metadata.reference_source_event_id
        ),
        None,
    )
    if anchor is None:
        report.fail(
            f"no {JSONL_FILENAME} record has RecordId {metadata.reference_source_event_id}; "
            "reference_source_event_id is not traceable"
        )
        return

    if anchor.get("EventId") != _SYSMON_PROCESS_CREATE_EVENT_ID:
        report.fail(
            f"RecordId {metadata.reference_source_event_id} is EventId {anchor.get('EventId')!r}, "
            f"expected {_SYSMON_PROCESS_CREATE_EVENT_ID}"
        )
        return

    observed = _parse_jsonl_timestamp(anchor.get("TimeCreated"))
    if observed is None:
        report.fail(
            f"RecordId {metadata.reference_source_event_id} has an unusable TimeCreated: "
            f"{anchor.get('TimeCreated')!r}"
        )
        return

    expected = _truncate_to_milliseconds(metadata.reference_time)
    if _truncate_to_milliseconds(observed) != expected:
        report.fail(
            f"reference_time {metadata.reference_time.isoformat()} does not match the TimeCreated of "
            f"RecordId {metadata.reference_source_event_id} ({observed.isoformat()})"
        )
        return

    report.passed(
        f"reference_time is the Sysmon EID {_SYSMON_PROCESS_CREATE_EVENT_ID} of RecordId "
        f"{metadata.reference_source_event_id}"
    )


def _check_times(
    metadata: RunMetadata,
    records: list[ExecutionRecordRow],
    report: S0ValidationReport,
) -> None:
    # end_time >= start_time is enforced by RunMetadata itself, so a run that
    # reaches this point already has a usable window.
    outside = 0
    for record in records:
        if record.timestamp < metadata.start_time:
            outside += 1
            report.fail(
                f"{record.action_id} ran at {record.timestamp.isoformat()}, before start_time "
                f"{metadata.start_time.isoformat()}"
            )
        elif metadata.end_time is not None and record.timestamp > metadata.end_time:
            outside += 1
            report.fail(
                f"{record.action_id} ran at {record.timestamp.isoformat()}, after end_time "
                f"{metadata.end_time.isoformat()}"
            )

    if not outside:
        report.passed("every execution_record timestamp lies inside the run window")


def _check_actions(
    metadata: RunMetadata,
    action_ids: set[str],
    scenario_path: Path,
    rehearsal: bool,
    report: S0ValidationReport,
) -> None:
    try:
        expected, external = _load_scenario_actions(scenario_path, metadata.run_type.value)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as error:
        report.fail(f"scenario definition is not usable ({scenario_path}): {error}")
        return

    unknown = action_ids - expected
    if unknown:
        report.fail(
            f"execution_record has action_id(s) the scenario does not define: {sorted(unknown)}"
        )

    required = expected - external if rehearsal else expected
    absent = required - action_ids
    if absent:
        report.fail(f"execution_record is missing action_id(s): {sorted(absent)}")

    if not unknown and not absent:
        skipped = sorted(expected - action_ids)
        note = f" (external action(s) {skipped} skipped in rehearsal)" if skipped else ""
        report.passed(
            f"execution_record covers the scenario actions for {metadata.run_type.value}{note}"
        )


def validate_s0_run(
    *,
    artifact_root: Path,
    run_id: str,
    rehearsal: bool = False,
    scenario_path: Path | None = None,
) -> S0ValidationReport:
    """Validate one S0 run under `artifact_root` and report everything found."""
    report = S0ValidationReport(run_id=run_id, rehearsal=rehearsal)
    scenario = scenario_path or default_scenario_path()

    _check_rehearsal_isolation(artifact_root, rehearsal, report)

    telemetry_dir = artifact_root / "raw" / run_id / "telemetry"
    ground_truth_dir = artifact_root / "ground_truth" / run_id
    manifest_path = artifact_root / "raw" / run_id / "manifest.json"
    evtx_path = telemetry_dir / EVTX_FILENAME
    jsonl_path = telemetry_dir / JSONL_FILENAME
    csv_path = ground_truth_dir / "execution_record.csv"
    metadata_path = ground_truth_dir / "run_metadata.json"

    required_files = (evtx_path, jsonl_path, manifest_path, csv_path, metadata_path)
    absent = [str(path) for path in required_files if not path.is_file()]
    if absent:
        for path in absent:
            report.fail(f"required artifact is missing: {path}")
        return report

    report.passed("all five required artifacts exist")

    metadata = _read_run_metadata(metadata_path, report)
    records = _read_execution_records(csv_path, report)
    if metadata is None or records is None:
        return report

    report.run_type = metadata.run_type.value

    if metadata.run_id != run_id:
        report.fail(f"run_metadata.json run_id is {metadata.run_id!r}, expected {run_id!r}")

    mismatched = sorted({record.run_id for record in records} - {metadata.run_id})
    if mismatched:
        report.fail(
            f"execution_record.csv carries run_id(s) other than {metadata.run_id!r}: {mismatched}"
        )
    else:
        report.passed(f"every execution_record row carries run_id {metadata.run_id}")

    action_ids = {record.action_id for record in records}

    _check_manifest(manifest_path, telemetry_dir, run_id, report)
    _check_reference(metadata, jsonl_path, action_ids, report)
    _check_times(metadata, records, report)
    _check_actions(metadata, action_ids, scenario, rehearsal, report)

    return report


def format_report(report: S0ValidationReport) -> str:
    """Render the report for a terminal."""
    lines = [f"run_id      : {report.run_id}"]
    lines.append(f"run_type    : {report.run_type or 'unknown'}")
    lines.append(f"mode        : {'REHEARSAL' if report.rehearsal else 'collection'}")
    lines.append("")

    for check in report.checks:
        lines.append(f"[+] {check}")
    for error in report.errors:
        lines.append(f"[!] {error}")

    lines.append("")
    if report.ok:
        verdict = "PASS"
        if report.rehearsal:
            verdict += " (REHEARSAL - not a valid S0 collection, do not use as an S0 Pair)"
        lines.append(verdict)
    else:
        lines.append(f"FAIL: {len(report.errors)} problem(s)")

    return "\n".join(lines)


__all__ = [
    "ManifestPathError",
    "S0ValidationReport",
    "default_scenario_path",
    "format_report",
    "manifest_filename",
    "validate_s0_run",
]
