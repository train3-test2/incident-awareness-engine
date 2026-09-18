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
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

import yaml
from pydantic import ValidationError

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    SysmonJsonlRecord,
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
_MANIFEST_LAYER = "raw_telemetry"
_MANIFEST_SOURCE = "sysmon"
_SYSMON_PROCESS_CREATE_EVENT_ID = 1

# The same shape RunMetadata and ExecutionRecordRow require of run_id
# (docs/schema/run-id.md section 3): RUN-YYYYMMDD-NNN with a real calendar date.
# The rule is restated here instead of importing the models' private pattern,
# because the value arrives from the command line and has to be rejected before
# it is ever joined onto an artifact path.
_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-(?P<sequence>[0-9]{3})$")

# Distinguishes "the key is absent" from "the key is present and null".
_MISSING = object()


class ManifestPathError(ValueError):
    """Raised when a Manifest path cannot be mapped to a known artifact."""


class ScenarioError(ValueError):
    """Raised when the scenario definition cannot be used to validate a run.

    Every failure mode is surfaced through the report rather than a traceback, so
    a malformed scenario file reads like any other failed check.
    """


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


def check_run_id(run_id: object) -> str | None:
    """Return why `run_id` cannot be used, or None when it is safe.

    This runs before any artifact path is built. The value becomes a directory
    name under `raw/` and `ground_truth/`, so a separator or a relative segment
    would reach outside the artifact root; those are refused by name rather than
    normalised away.
    """
    if not isinstance(run_id, str):
        return f"run_id must be a string, found {type(run_id).__name__}"

    if run_id != run_id.strip():
        return f"run_id must not carry leading or trailing whitespace: {run_id!r}"

    if "/" in run_id or "\\" in run_id:
        return f"run_id must not contain a path separator: {run_id!r}"

    if run_id in {".", ".."} or ".." in run_id:
        return f"run_id must not contain a relative path segment: {run_id!r}"

    match = _RUN_ID_PATTERN.fullmatch(run_id)
    if match is None:
        return f"run_id must match RUN-YYYYMMDD-NNN with a three digit sequence: {run_id!r}"

    try:
        date.fromisoformat(match.group("date"))
    except ValueError:
        return f"run_id must carry a real calendar date: {run_id!r}"

    return None


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


def manifest_artifact_name(raw_path: object, *, run_id: str) -> str:
    """Return the artifact file name a Manifest path refers to.

    The path was written inside the VM (`C:\\S0\\data\\...`), so it is never
    opened as given: the drive and the directories above the run are not trusted.
    What is checked is the tail, which must read `raw/<run_id>/telemetry/<name>`,
    and the name, which must be one of this run's two telemetry files. The caller
    then maps the name into the local telemetry directory.

    Both Windows and POSIX separators are accepted because the runner writes
    Windows paths while the artifacts are validated on either platform.
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

    expected_tail = ["raw", run_id, "telemetry", name]
    if segments[-len(expected_tail) :] != expected_tail:
        raise ManifestPathError(f"path must end with {'/'.join(expected_tail)}, found {raw_path}")

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


@dataclass(frozen=True)
class ScenarioAction:
    """One action the scenario defines for a run type."""

    action_id: str
    action_type: str
    uses_external_connection: bool


@dataclass(frozen=True)
class ScenarioRun:
    """The part of a scenario definition this validator needs."""

    scenario_id: str
    run_type: str
    evaluation_horizon_sec: int
    actions: dict[str, ScenarioAction]
    reference_action_id: str | None

    @property
    def external_action_ids(self) -> set[str]:
        return {
            action_id
            for action_id, action in self.actions.items()
            if action.uses_external_connection
        }


def _require_non_empty_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{label} must be a non-empty string, found {value!r}")

    return value


def _require_optional_flag(raw_action: dict, key: str, label: str) -> bool:
    """Read a YAML boolean flag, refusing anything that only looks like one.

    A missing key is false. A present key must be a real boolean: `"false"` is a
    non-empty string and `0`/`1` are integers, so a truthiness test would read
    them backwards or by accident.
    """
    value = raw_action.get(key, _MISSING)
    if value is _MISSING:
        return False

    if not isinstance(value, bool):
        raise ScenarioError(
            f"{label}.{key} must be a YAML boolean (true or false), found {value!r}"
        )

    return value


def _require_horizon(value: object) -> int:
    # bool is a subclass of int, so it is excluded explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ScenarioError(
            f"run_length.evaluation_horizon_sec must be a positive integer, found {value!r}"
        )

    return value


def load_scenario_run(scenario_path: Path, run_type: str) -> ScenarioRun:
    """Read the scenario definition for one run type.

    Every problem is raised as `ScenarioError` so `validate_s0_run` can report it
    as a failed check instead of letting a malformed file raise a traceback.
    """
    try:
        with scenario_path.open(encoding="utf-8") as stream:
            scenario = yaml.safe_load(stream)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise ScenarioError(f"scenario is not readable YAML ({scenario_path}): {error}") from error

    if not isinstance(scenario, dict):
        raise ScenarioError(f"scenario must be a mapping: {scenario_path}")

    scenario_id = _require_non_empty_str(scenario.get("scenario_id"), "scenario_id")

    run_length = scenario.get("run_length")
    if not isinstance(run_length, dict):
        raise ScenarioError("scenario has no run_length mapping")

    horizon = _require_horizon(run_length.get("evaluation_horizon_sec"))

    runs = scenario.get("runs")
    if not isinstance(runs, dict):
        raise ScenarioError("scenario has no runs mapping")

    run = runs.get(run_type)
    if not isinstance(run, dict):
        raise ScenarioError(f"scenario has no runs.{run_type} mapping")

    declared = _require_non_empty_str(run.get("run_type"), f"runs.{run_type}.run_type")
    if declared != run_type:
        raise ScenarioError(
            f"runs.{run_type}.run_type is {declared!r}; the key and the field must agree"
        )

    raw_actions = run.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise ScenarioError(f"runs.{run_type}.actions must be a non-empty list")

    actions: dict[str, ScenarioAction] = {}
    for index, raw_action in enumerate(raw_actions):
        label = f"runs.{run_type}.actions[{index}]"
        if not isinstance(raw_action, dict):
            raise ScenarioError(f"{label} must be a mapping, found {type(raw_action).__name__}")

        action_id = _require_non_empty_str(raw_action.get("action_id"), f"{label}.action_id")
        if action_id in actions:
            raise ScenarioError(f"runs.{run_type} defines action_id {action_id!r} more than once")

        action_type = _require_non_empty_str(raw_action.get("action_type"), f"{label}.action_type")
        actions[action_id] = ScenarioAction(
            action_id=action_id,
            action_type=action_type,
            uses_external_connection=_require_optional_flag(
                raw_action, "uses_external_connection", label
            ),
        )

    return ScenarioRun(
        scenario_id=scenario_id,
        run_type=run_type,
        evaluation_horizon_sec=horizon,
        actions=actions,
        reference_action_id=_require_reference_action_id(run, run_type, actions),
    )


def _require_reference_action_id(
    run: dict, run_type: str, actions: dict[str, ScenarioAction]
) -> str | None:
    """Read the action the run's reference_time is anchored to.

    The key must be present for both run types. An attack run names one of its
    own actions; a normal run has no reference and must say null.
    """
    value = run.get("reference_action_id", _MISSING)
    if value is _MISSING:
        raise ScenarioError(f"runs.{run_type}.reference_action_id is missing")

    if run_type != RunType.ATTACK.value:
        if value is not None:
            raise ScenarioError(
                f"runs.{run_type}.reference_action_id must be null, found {value!r}"
            )
        return None

    action_id = _require_non_empty_str(value, f"runs.{run_type}.reference_action_id")
    if action_id not in actions:
        raise ScenarioError(
            f"runs.{run_type}.reference_action_id {action_id!r} is not one of its actions "
            f"({sorted(actions)})"
        )

    return action_id


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

    # strict=True turns malformed quoting into csv.Error instead of silently
    # reinterpreting the row, and the error is reported like any other failure.
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as error:
        report.fail(f"execution_record.csv is not parsable CSV: {error}")
        return None

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
    _check_manifest_items(manifest["items"], telemetry_dir, run_id, report)


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


def _check_manifest_items(
    items: object,
    telemetry_dir: Path,
    run_id: str,
    report: S0ValidationReport,
) -> None:
    """Check that the Manifest describes this run's two telemetry files exactly once."""
    if not isinstance(items, list) or not items:
        report.fail("manifest.json items must be a non-empty array")
        return

    resolved: dict[str, dict[str, object]] = {}
    seen_raw_log_ids: set[str] = set()
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

        if item["layer"] != _MANIFEST_LAYER:
            report.fail(f"{label} layer is {item['layer']!r}, expected {_MANIFEST_LAYER!r}")
            continue

        if item["source"] != _MANIFEST_SOURCE:
            report.fail(f"{label} source is {item['source']!r}, expected {_MANIFEST_SOURCE!r}")
            continue

        raw_log_id = item["raw_log_id"]
        if not isinstance(raw_log_id, str) or not raw_log_id.strip():
            report.fail(f"{label} raw_log_id must be a non-empty string, found {raw_log_id!r}")
            continue

        if raw_log_id in seen_raw_log_ids:
            report.fail(f"{label} repeats raw_log_id {raw_log_id!r}")
            continue

        seen_raw_log_ids.add(raw_log_id)

        try:
            name = manifest_artifact_name(item["path"], run_id=run_id)
        except ManifestPathError as error:
            report.fail(f"{label} path rejected: {error}")
            continue

        if name in resolved:
            report.fail(f"{label} repeats the artifact {name}")
            continue

        resolved[name] = item

        recorded = item["sha256"]
        if not _is_sha256_hex(recorded):
            report.fail(f"{label} sha256 is not a SHA-256 value: {recorded!r}")
            continue

        local_path = telemetry_dir / name
        if not local_path.is_file():
            report.fail(f"{label} maps to {local_path}, which does not exist")
            continue

        try:
            actual = _file_sha256(local_path)
        except OSError as error:
            report.fail(f"{label} could not read {name} to recompute its SHA-256: {error}")
            continue

        if actual != recorded.lower():
            report.fail(
                f"{label} sha256 mismatch for {name}. recorded={recorded.lower()} actual={actual}"
            )
            continue

        verified += 1

    absent = sorted(ALLOWED_TELEMETRY_FILENAMES - set(resolved))
    if absent:
        report.fail(f"manifest.json does not describe this run's artifact(s): {absent}")

    if len(items) != len(ALLOWED_TELEMETRY_FILENAMES):
        report.fail(
            f"manifest.json must hold exactly {len(ALLOWED_TELEMETRY_FILENAMES)} items "
            f"({sorted(ALLOWED_TELEMETRY_FILENAMES)}), found {len(items)}"
        )

    _check_manifest_derivation(resolved, run_id, report)

    if verified:
        report.passed(f"{verified} manifest item hash(es) match the local artifacts")


def _check_manifest_derivation(
    resolved: dict[str, dict[str, object]],
    run_id: str,
    report: S0ValidationReport,
) -> None:
    """The JSONL is rendered from the EVTX, so only that direction is valid."""
    evtx_item = resolved.get(EVTX_FILENAME)
    if evtx_item is not None and "derived_from" in evtx_item:
        report.fail(
            f"manifest.json {EVTX_FILENAME} declares derived_from "
            f"({evtx_item['derived_from']!r}); the EVTX is the source artifact"
        )

    jsonl_item = resolved.get(JSONL_FILENAME)
    if jsonl_item is None:
        return

    if "derived_from" not in jsonl_item:
        report.fail(
            f"manifest.json {JSONL_FILENAME} must declare derived_from pointing at {EVTX_FILENAME}"
        )
        return

    try:
        parent = manifest_artifact_name(jsonl_item["derived_from"], run_id=run_id)
    except ManifestPathError as error:
        report.fail(f"manifest.json {JSONL_FILENAME} derived_from rejected: {error}")
        return

    if parent != EVTX_FILENAME:
        report.fail(
            f"manifest.json {JSONL_FILENAME} derived_from points at {parent}, expected "
            f"{EVTX_FILENAME}"
        )
        return

    if parent not in resolved:
        report.fail(
            f"manifest.json {JSONL_FILENAME} derived_from points at {parent}, which is not a "
            "manifest item"
        )
        return

    report.passed(f"{JSONL_FILENAME} is recorded as derived from {EVTX_FILENAME}")


def _read_sysmon_records(
    jsonl_path: Path, report: S0ValidationReport
) -> list[SysmonJsonlRecord] | None:
    """Read the Sysmon JSONL once for both run types.

    The Manifest check only proves the file is the one the runner hashed; it says
    nothing about its content. This check is the one that requires every line to
    be a JSON object with no blank lines, and at least one record.
    """
    try:
        records = list(read_sysmon_jsonl(jsonl_path))
    except (OSError, UnicodeDecodeError, SysmonJsonlReadError) as error:
        report.fail(f"{JSONL_FILENAME} is not readable: {error}")
        return None

    if not records:
        report.fail(f"{JSONL_FILENAME} holds no records; an empty capture is not a collection")
        return None

    report.passed(f"{JSONL_FILENAME} holds {len(records)} record(s), each a JSON object")
    return records


def _check_reference(
    metadata: RunMetadata,
    sysmon_records: list[SysmonJsonlRecord] | None,
    execution_records: list[ExecutionRecordRow],
    scenario: ScenarioRun | None,
    report: S0ValidationReport,
) -> None:
    """Check that reference_time is anchored to the scenario's reference action.

    For an attack run this ties together the scenario's reference_action_id, the
    one execution_record row of that action, the run window, and the Sysmon EID 1
    record whose TimeCreated is reference_time. It checks that the reference
    action and time are consistent; it does not prove the ProcessGuid causality
    between that record and the action.
    """
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

    reference_action_id = metadata.reference_action_id
    reference_time = metadata.reference_time
    consistent = True

    if scenario is not None and reference_action_id != scenario.reference_action_id:
        consistent = False
        report.fail(
            f"reference_action_id is {reference_action_id!r}, but the scenario anchors the "
            f"attack run to {scenario.reference_action_id!r}"
        )

    reference_rows = [row for row in execution_records if row.action_id == reference_action_id]
    if len(reference_rows) != 1:
        consistent = False
        recorded = sorted({row.action_id for row in execution_records})
        report.fail(
            f"reference_action_id {reference_action_id!r} must appear exactly once in "
            f"execution_record, found {len(reference_rows)} ({recorded})"
        )

    if reference_time < metadata.start_time:
        consistent = False
        report.fail(
            f"reference_time {reference_time.isoformat()} is before start_time "
            f"{metadata.start_time.isoformat()}"
        )

    if metadata.end_time is not None and reference_time > metadata.end_time:
        consistent = False
        report.fail(
            f"reference_time {reference_time.isoformat()} is after end_time "
            f"{metadata.end_time.isoformat()}"
        )

    if len(reference_rows) == 1 and reference_time < reference_rows[0].timestamp:
        consistent = False
        report.fail(
            f"reference_time {reference_time.isoformat()} is earlier than {reference_action_id} "
            f"ran ({reference_rows[0].timestamp.isoformat()})"
        )

    if sysmon_records is None:
        # The JSONL itself already failed; there is no record to trace.
        return

    anchor = next(
        (
            record.data
            for record in sysmon_records
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

    expected = _truncate_to_milliseconds(reference_time)
    if _truncate_to_milliseconds(observed) != expected:
        report.fail(
            f"reference_time {reference_time.isoformat()} does not match the TimeCreated of "
            f"RecordId {metadata.reference_source_event_id} ({observed.isoformat()})"
        )
        return

    if consistent:
        report.passed(
            f"reference_time is the Sysmon EID {_SYSMON_PROCESS_CREATE_EVENT_ID} of RecordId "
            f"{metadata.reference_source_event_id}, inside the run and not before "
            f"{reference_action_id} ran"
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


def _check_observation_window(
    metadata: RunMetadata,
    scenario: ScenarioRun,
    rehearsal: bool,
    report: S0ValidationReport,
) -> None:
    """A collection run must stay open for the whole evaluation horizon.

    The attack run is anchored to `reference_time` and the normal run to
    `start_time`, which is how the runner keeps both runs observed for the same
    span (`docs/scenarios/s0.md` sections 7 and 9). `post_reference_margin_sec` is
    the runner's own slack, not part of the minimum contract, so it is not added.

    A rehearsal skips the observation wait on purpose, so only the horizon length
    is exempt. `end_time` is still required: a run that produced all four
    artifacts has finished, and an artifact set without an end has no window at
    all.
    """
    if metadata.end_time is None:
        report.fail("a finished run must record end_time")
        return

    if rehearsal:
        report.passed("end_time recorded; horizon length not checked (rehearsal skips the wait)")
        return

    if metadata.run_type is RunType.ATTACK:
        anchor_name, anchor = "reference_time", metadata.reference_time
    else:
        anchor_name, anchor = "start_time", metadata.start_time

    if anchor is None:
        # An attack run without reference_time already failed the reference check.
        return

    due = anchor + timedelta(seconds=scenario.evaluation_horizon_sec)
    if metadata.end_time < due:
        report.fail(
            f"end_time {metadata.end_time.isoformat()} is before {anchor_name} + "
            f"evaluation_horizon_sec ({scenario.evaluation_horizon_sec}s), which ends at "
            f"{due.isoformat()}"
        )
        return

    report.passed(
        f"the run stayed open for the {scenario.evaluation_horizon_sec}s horizon "
        f"after {anchor_name}"
    )


def _check_actions(
    metadata: RunMetadata,
    records: list[ExecutionRecordRow],
    scenario: ScenarioRun,
    rehearsal: bool,
    report: S0ValidationReport,
) -> None:
    if metadata.scenario_id != scenario.scenario_id:
        report.fail(
            f"run_metadata.json scenario_id is {metadata.scenario_id!r}, but the scenario "
            f"definition is {scenario.scenario_id!r}"
        )

    occurrences = Counter(record.action_id for record in records)
    duplicates = sorted(action_id for action_id, count in occurrences.items() if count > 1)
    if duplicates:
        report.fail(f"execution_record records action_id(s) more than once: {duplicates}")

    action_ids = {record.action_id for record in records}
    expected = set(scenario.actions)
    external = scenario.external_action_ids

    unknown = action_ids - expected
    if unknown:
        report.fail(
            f"execution_record has action_id(s) the scenario does not define: {sorted(unknown)}"
        )

    required = expected - external if rehearsal else expected
    absent = required - action_ids
    if absent:
        report.fail(f"execution_record is missing action_id(s): {sorted(absent)}")

    mismatched = [
        f"{record.action_id} is {record.action_type!r}, scenario says "
        f"{scenario.actions[record.action_id].action_type!r}"
        for record in records
        if record.action_id in scenario.actions
        and record.action_type != scenario.actions[record.action_id].action_type
    ]
    for message in mismatched:
        report.fail(f"execution_record action_type does not match the scenario: {message}")

    if not duplicates and not unknown and not absent and not mismatched:
        skipped = sorted(expected - action_ids)
        note = f" (external action(s) {skipped} skipped in rehearsal)" if skipped else ""
        report.passed(
            f"execution_record matches the scenario actions for {metadata.run_type.value}{note}"
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

    # run_id becomes a path segment, so it is checked before anything touches the
    # file system. Nothing below this point runs for a rejected value.
    run_id_problem = check_run_id(run_id)
    if run_id_problem is not None:
        report.fail(run_id_problem)
        return report

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

    _check_manifest(manifest_path, telemetry_dir, run_id, report)
    sysmon_records = _read_sysmon_records(jsonl_path, report)

    # The scenario is read before the reference check, which needs its
    # reference_action_id. A broken scenario is still reported at the same point
    # as before, and only the checks that depend on it are skipped.
    scenario_run: ScenarioRun | None = None
    scenario_error: ScenarioError | None = None
    try:
        scenario_run = load_scenario_run(scenario, metadata.run_type.value)
    except ScenarioError as error:
        scenario_error = error

    _check_reference(metadata, sysmon_records, records, scenario_run, report)
    _check_times(metadata, records, report)

    if scenario_run is None:
        report.fail(f"scenario definition is not usable ({scenario}): {scenario_error}")
        return report

    _check_observation_window(metadata, scenario_run, rehearsal, report)
    _check_actions(metadata, records, scenario_run, rehearsal, report)

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
    "ScenarioAction",
    "ScenarioError",
    "ScenarioRun",
    "check_run_id",
    "default_scenario_path",
    "format_report",
    "load_scenario_run",
    "manifest_artifact_name",
    "validate_s0_run",
]
