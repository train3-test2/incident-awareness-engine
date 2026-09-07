from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f %z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
)


def _to_utc_iso8601_millis(timestamp: str) -> str:
    normalized = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp

    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(normalized, fmt)  # noqa: DTZ007
            return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            continue

    raise ValueError(f"unrecognized Hayabusa timestamp format: {timestamp!r}")


def hayabusa_row_to_fast_hit(
    row: dict[str, Any],
    *,
    run_id: str,
    hit_id: str,
    detector_engine_version: str,
    rule_version: str,
    alert_key: str,
    detector_config_version: str,
) -> dict[str, Any]:
    return {
        "hit_id": hit_id,
        "run_id": run_id,
        "timestamp": _to_utc_iso8601_millis(row["Timestamp"]),
        "detector_engine": "hayabusa",
        "detector_engine_version": detector_engine_version,
        "rule_id": row["RuleID"],
        "rule_version": rule_version,
        "alert_key": alert_key,
        "native_host_id": row.get("Computer") or None,
        "native_record_ref": (
            str(row["RecordID"]) if row.get("RecordID") not in (None, "") else None
        ),
        "detector_config_version": detector_config_version,
    }


def read_hayabusa_csv(
    csv_path: str | Path,
) -> list[dict[str, str]]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def hayabusa_rows_to_fast_hits(
    rows: list[dict[str, Any]],
    *,
    run_id: str,
    detector_engine_version: str,
    rule_version: str,
    alert_key: str,
    detector_config_version: str,
    qualifying_rule_ids: set[str],
) -> list[dict[str, Any]]:
    results = []

    for index, row in enumerate(rows, start=1):
        if not is_qualifying_hit(row, qualifying_rule_ids):
            continue

        hit = hayabusa_row_to_fast_hit(
            row,
            run_id=run_id,
            hit_id=f"{run_id}-hit-{index}",
            detector_engine_version=detector_engine_version,
            rule_version=rule_version,
            alert_key=alert_key,
            detector_config_version=detector_config_version,
        )
        results.append(hit)

    return results


def write_fast_hits_jsonl(
    hits: list[dict[str, Any]],
    output_path: str | Path,
) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(hit, ensure_ascii=False) + "\n" for hit in hits)


def is_qualifying_hit(
    row: dict[str, Any],
    qualifying_rule_ids: set[str],
) -> bool:
    rule_id = row["RuleID"]

    return rule_id in qualifying_rule_ids
