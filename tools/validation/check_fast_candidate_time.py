"""후보 CSV와 원본 Sysmon을 연결한다. 최종 detector_time은 산출하지 않는다."""

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

CHANNEL_ALIASES = {"Sysmon": "Microsoft-Windows-Sysmon/Operational"}


def channel(value):
    return CHANNEL_ALIASES.get(value, value)


def parse_time(value, *, require_timezone=False):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp is required; TimeCreated fallback is forbidden")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        if require_timezone:
            raise ValueError("Hayabusa timestamp must include timezone")
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def key(host, source_channel, record_id):
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host is required")
    if not isinstance(source_channel, str) or not source_channel.strip():
        raise ValueError("channel is required")
    if (
        isinstance(record_id, bool)
        or not str(record_id).isascii()
        or not str(record_id).isdecimal()
    ):
        raise ValueError("RecordID must be a nonnegative integer")
    return host, channel(source_channel), int(record_id)


def resolve_hits(hits, records):
    index = defaultdict(list)
    for line, record in enumerate(records, start=1):
        index[key(record.get("Computer"), record.get("Channel"), record.get("RecordId"))].append(
            (line, record)
        )
    results = []
    for csv_row, hit in enumerate(hits, start=1):
        identity = key(hit.get("Computer"), hit.get("Channel"), hit.get("RecordID"))
        matches = index.get(identity, [])
        if len(matches) != 1:
            raise ValueError(
                f"CSV row {csv_row}: expected one raw event for {identity}, got {len(matches)}"
            )
        raw_line, record = matches[0]
        if str(record.get("EventId")) != str(hit.get("EventID")):
            raise ValueError(f"CSV row {csv_row}: EventID mismatch")
        raw_time = parse_time(record.get("EventData", {}).get("UtcTime"))
        csv_time = parse_time(hit.get("Timestamp"), require_timezone=True)
        results.append(
            {
                "csv_data_row": csv_row,
                "raw_jsonl_line": raw_line,
                "host": identity[0],
                "channel": identity[1],
                "record_id": identity[2],
                "event_id": record["EventId"],
                "rule_id": hit.get("RuleID"),
                "hayabusa_timestamp": hit["Timestamp"],
                "event_data_utc_time": raw_time.isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                ),
                "hayabusa_minus_event_time_us": (csv_time - raw_time) // timedelta(microseconds=1),
                "timestamp_source": "EventData.UtcTime",
                "final_detector_time": None,
            }
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--raw-jsonl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.csv.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if args.csv.stat().st_size and not {
            "Computer",
            "Channel",
            "RecordID",
            "EventID",
            "Timestamp",
            "RuleID",
        } <= set(reader.fieldnames or ()):
            raise ValueError("CSV header is missing required fields")
        hits = list(reader)
    records = [json.loads(line) for line in args.raw_jsonl.read_text(encoding="utf-8").splitlines()]
    result = {
        "run_id": args.run_id,
        "run_id_source": "caller_supplied_single_run_files",
        "purpose": "candidate_time_audit",
        "candidate_count": len(hits),
        "csv_sha256": hashlib.sha256(args.csv.read_bytes()).hexdigest(),
        "raw_sha256": hashlib.sha256(args.raw_jsonl.read_bytes()).hexdigest(),
        "matches": resolve_hits(hits, records),
    }
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
