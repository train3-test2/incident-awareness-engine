"""Materialize a unique First Cycle demo input set from the versioned Seed."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

_RUN_ID_PATTERN = re.compile(r"^RUN-(?P<date>[0-9]{8})-[0-9]{3}$")
_REQUIRED_ARTIFACTS = (
    "run_metadata.json",
    "manifest.json",
    "sysmon-0001.jsonl",
    "fast/hits.jsonl",
    "fast/trace.json",
    "fast/selection.json",
    "fast/handoff.csv",
    "fast/config.json",
)


@dataclass(frozen=True, slots=True)
class DemoSeedMaterialization:
    """The local First Cycle input directory created for one demo Run."""

    run_id: str
    destination: Path
    seed_run_id: str


def materialize_first_cycle_demo_seed(
    *,
    seed_root: Path,
    destination: Path,
    run_id: str,
) -> DemoSeedMaterialization:
    """Create one self-consistent First Cycle input set for ``run_id``.

    The versioned Seed is never modified.  All run-scoped identifiers, UTC
    timestamps, and dependent SHA-256 values are rebuilt in the destination so
    that it can be uploaded directly below ``first-cycle/<run_id>/``.
    """
    seed_root = seed_root.resolve()
    destination = destination.resolve()
    target_date = _run_id_date(run_id)
    _validate_seed_root(seed_root)
    if destination.exists():
        raise FileExistsError(f"demo input destination already exists: {destination}")

    seed_metadata = _read_json_object(seed_root / "run_metadata.json")
    seed_run_id = _required_string(seed_metadata, "run_id", label="run_metadata")
    offset = target_date - _run_id_date(seed_run_id)

    shutil.copytree(seed_root, destination)
    _rewrite_run_metadata(destination / "run_metadata.json", run_id=run_id, offset=offset)
    _rewrite_sysmon_jsonl(destination / "sysmon-0001.jsonl", offset=offset)
    _rewrite_fast_handoff(
        destination / "fast", seed_run_id=seed_run_id, run_id=run_id, offset=offset
    )
    _rewrite_manifest(destination / "manifest.json", seed_run_id=seed_run_id, run_id=run_id)

    return DemoSeedMaterialization(
        run_id=run_id,
        destination=destination,
        seed_run_id=seed_run_id,
    )


def _validate_seed_root(seed_root: Path) -> None:
    if not seed_root.is_dir():
        raise FileNotFoundError(f"demo Seed directory does not exist: {seed_root}")

    missing = [artifact for artifact in _REQUIRED_ARTIFACTS if not (seed_root / artifact).is_file()]
    if missing:
        raise FileNotFoundError(f"demo Seed is missing required artifacts: {', '.join(missing)}")


def _rewrite_run_metadata(path: Path, *, run_id: str, offset: timedelta) -> None:
    metadata = _read_json_object(path)
    metadata["run_id"] = run_id
    for field in ("start_time", "end_time", "reference_time"):
        value = metadata.get(field)
        if value is not None:
            metadata[field] = _format_iso_utc(
                _parse_iso_utc(value, label=f"run_metadata.{field}") + offset
            )
    _write_json(path, metadata)


def _rewrite_sysmon_jsonl(path: Path, *, offset: timedelta) -> None:
    rewritten: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Seed Sysmon JSONL is invalid at line {line_number}") from error
        if not isinstance(record, dict):
            raise TypeError(f"Seed Sysmon JSONL record {line_number} must be a JSON object")

        record["TimeCreated"] = _format_iso_utc(
            _parse_iso_utc(record.get("TimeCreated"), label=f"Sysmon[{line_number}].TimeCreated")
            + offset
        )
        event_data = record.get("EventData")
        if not isinstance(event_data, dict):
            raise TypeError(
                f"Seed Sysmon JSONL EventData at line {line_number} must be a JSON object"
            )
        event_data["UtcTime"] = _format_sysmon_utc(
            _parse_sysmon_utc(
                event_data.get("UtcTime"), label=f"Sysmon[{line_number}].EventData.UtcTime"
            )
            + offset
        )
        rewritten.append(json.dumps(record, separators=(",", ":")))

    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def _rewrite_fast_handoff(
    fast_root: Path,
    *,
    seed_run_id: str,
    run_id: str,
    offset: timedelta,
) -> None:
    handoff_path = fast_root / "handoff.csv"
    _rewrite_handoff_csv(handoff_path, offset=offset)

    hits_path = fast_root / "hits.jsonl"
    hit_id_mapping = _rewrite_fast_hits(
        hits_path,
        seed_run_id=seed_run_id,
        run_id=run_id,
        offset=offset,
    )
    _rewrite_fast_selection(fast_root / "selection.json", hit_id_mapping=hit_id_mapping)

    trace_path = fast_root / "trace.json"
    trace = _read_json_object(trace_path)
    trace["run_id"] = run_id
    trace["input_sha256"] = _sha256(handoff_path)
    trace["output_sha256"] = _sha256(hits_path)
    hits = trace.get("hits")
    if not isinstance(hits, list):
        raise TypeError("Seed Fast trace hits must be an array")
    for entry in hits:
        if not isinstance(entry, dict):
            raise TypeError("Seed Fast trace hit must be a JSON object")
        hit_id = _required_string(entry, "hit_id", label="Fast trace hit")
        entry["hit_id"] = _mapped_hit_id(hit_id, hit_id_mapping)
    _write_json(trace_path, trace)


def _rewrite_handoff_csv(path: Path, *, offset: timedelta) -> None:
    with path.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        fieldnames = reader.fieldnames
        if fieldnames is None or "Timestamp" not in fieldnames:
            raise ValueError("Seed Fast handoff CSV must have a Timestamp column")
        rows = list(reader)

    for row_number, row in enumerate(rows, start=2):
        row["Timestamp"] = _format_iso_utc(
            _parse_iso_utc(
                row.get("Timestamp"), label=f"Fast handoff CSV row {row_number} Timestamp"
            )
            + offset
        )

    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _rewrite_fast_hits(
    path: Path,
    *,
    seed_run_id: str,
    run_id: str,
    offset: timedelta,
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    rewritten: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            hit = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Seed FastHit JSONL is invalid at line {line_number}") from error
        if not isinstance(hit, dict):
            raise TypeError(f"Seed FastHit record {line_number} must be a JSON object")

        source_hit_id = _required_string(hit, "hit_id", label=f"FastHit[{line_number}]")
        hit_id = _replace_run_id(source_hit_id, seed_run_id=seed_run_id, run_id=run_id)
        if hit_id in mapping.values():
            raise ValueError("Seed FastHit records must have unique hit_id values")
        mapping[source_hit_id] = hit_id
        hit["hit_id"] = hit_id
        if hit.get("run_id") != seed_run_id:
            raise ValueError("Seed FastHit run_id must match Seed RunMetadata run_id")
        hit["run_id"] = run_id
        hit["timestamp"] = _format_iso_utc(
            _parse_iso_utc(hit.get("timestamp"), label=f"FastHit[{line_number}].timestamp") + offset
        )
        rewritten.append(json.dumps(hit, separators=(",", ":")))

    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    return mapping


def _rewrite_fast_selection(path: Path, *, hit_id_mapping: dict[str, str]) -> None:
    selection = _read_json_object(path)
    selected_hit_id = selection.get("selected_hit_id")
    if selected_hit_id is not None:
        if not isinstance(selected_hit_id, str):
            raise TypeError("Seed Fast selection selected_hit_id must be a string or null")
        selection["selected_hit_id"] = _mapped_hit_id(selected_hit_id, hit_id_mapping)
    _write_json(path, selection)


def _rewrite_manifest(path: Path, *, seed_run_id: str, run_id: str) -> None:
    manifest = _read_json_object(path)
    if manifest.get("run_id") != seed_run_id:
        raise ValueError("Seed manifest run_id must match Seed RunMetadata run_id")
    manifest["run_id"] = run_id

    items = manifest.get("items")
    if not isinstance(items, list):
        raise TypeError("Seed manifest items must be an array")
    for item in items:
        if not isinstance(item, dict):
            raise TypeError("Seed manifest item must be a JSON object")
        for field in ("path", "derived_from"):
            value = item.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise TypeError(f"Seed manifest {field} must be a string when present")
                item[field] = _replace_run_id(value, seed_run_id=seed_run_id, run_id=run_id)
        if item.get("path", "").endswith("sysmon-0001.jsonl"):
            item["sha256"] = _sha256(path.parent / "sysmon-0001.jsonl")
    _write_json(path, manifest)


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Seed JSON is invalid: {path}") from error
    if not isinstance(value, dict):
        raise TypeError(f"Seed JSON must be an object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _run_id_date(run_id: str) -> date:
    match = _RUN_ID_PATTERN.fullmatch(run_id)
    if match is None:
        raise ValueError("run_id must match RUN-YYYYMMDD-NNN")
    try:
        return date.fromisoformat(match.group("date"))
    except ValueError as error:
        raise ValueError("run_id must contain a valid calendar date") from error


def _parse_iso_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be a UTC ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} must be a valid UTC ISO 8601 timestamp") from error
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC")
    return parsed.astimezone(UTC)


def _parse_sysmon_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a valid Sysmon UTC timestamp") from error
    if parsed.tzinfo is not None:
        raise ValueError(f"{label} must not include a timezone offset")
    return parsed.replace(tzinfo=UTC)


def _format_iso_utc(value: datetime) -> str:
    return (
        value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
    )


def _format_sysmon_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.") + f"{value.microsecond // 1000:03d}"


def _required_string(payload: dict[str, Any], field: str, *, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must define non-empty {field}")
    return value


def _replace_run_id(value: str, *, seed_run_id: str, run_id: str) -> str:
    if seed_run_id not in value:
        raise ValueError(f"Seed value must contain {seed_run_id}: {value}")
    return value.replace(seed_run_id, run_id)


def _mapped_hit_id(hit_id: str, mapping: dict[str, str]) -> str:
    try:
        return mapping[hit_id]
    except KeyError as error:
        raise ValueError(f"Seed Fast trace references unknown hit_id: {hit_id}") from error


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Materialize a First Cycle demo input set")
    parser.add_argument("--seed-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = materialize_first_cycle_demo_seed(
        seed_root=args.seed_root,
        destination=args.destination,
        run_id=args.run_id,
    )
    print(json.dumps({"run_id": result.run_id, "destination": str(result.destination)}))


if __name__ == "__main__":
    main()


__all__ = ["DemoSeedMaterialization", "materialize_first_cycle_demo_seed"]
