"""Development Pair의 실제 정규화/Evidence 연결 점검 (탐지기/성능 평가 아님)."""

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.collection.r1_destination import (
    validate_internal_port,
    validate_internal_target,
    validate_lab_cidr,
)
from incident_awareness.collection.r1_pair_identity import read_dataset_tier, read_pair_identity
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.r1_artifacts import (
    load_r1_evidence_artifacts,
    run_and_write_r1_evidence_artifacts,
)
from incident_awareness.pipeline.r1_evidence import R1LineageInput


def require(condition, message):
    if not condition:
        raise ValueError(message)


def event_time(value):
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def unique(items, label):
    require(len(items) == 1, f"{label}: expected one candidate, got {len(items)}")
    return items[0]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _approved_policy_provenance(policy: ApprovedLineagePolicy):
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "config_hash": policy.config_hash,
    }


def check_run(pair, run_id, prefix, output, policy: ApprovedLineagePolicy):
    base = pair / run_id / "data"
    scenario_path = base / "operator_trace" / run_id / "scenario.json"
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    pair_identity = read_pair_identity(scenario)
    dataset_tier = read_dataset_tier(scenario)
    target_host = scenario["run_metadata"]["target_host"]
    require(
        isinstance(target_host, str)
        and bool(target_host.strip())
        and target_host == target_host.strip(),
        "scenario target_host is required",
    )
    connection = scenario["internal_connection"]
    destination = validate_internal_target(
        connection["target"], validate_lab_cidr(connection["lab_cidr"])
    )
    port = validate_internal_port(connection["port"])
    require(connection["protocol"] == "TCP", "scenario protocol must be TCP")
    raw = base / "raw" / run_id
    source = raw / "telemetry/sysmon-0001.jsonl"
    manifest_path = raw / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = unique(
        [i for i in manifest["items"] if i["path"].endswith("sysmon-0001.jsonl")],
        "JSONL manifest entry",
    )
    require(sha(source) == entry["sha256"], "JSONL hash mismatch")
    execution_path = base / "ground_truth" / run_id / "execution_record.csv"
    with execution_path.open(encoding="utf-8-sig", newline="") as f:
        actions = list(csv.DictReader(f))
    require(all(a["run_id"] == run_id for a in actions), "execution Run mismatch")
    times = {
        n: event_time(unique([a for a in actions if a["action_id"] == prefix + n], n)["timestamp"])
        for n in ("01", "03", "04")
    }
    records = list(read_sysmon_jsonl(source))
    context = SysmonNormalizationContext(run_id, entry["raw_log_id"], 1)
    events = []
    for record in records:
        data = record.data["EventData"]
        require(record.data["Channel"] == "Microsoft-Windows-Sysmon/Operational", "channel")
        require(record.data["Computer"] == target_host, "host")
        normalizer = {
            1: normalize_sysmon_process_create,
            3: normalize_sysmon_network_connection,
        }.get(record.data["EventId"])
        require(normalizer is not None, "unsupported EventId")
        e = normalizer(record, context=context)
        require(e.timestamp == event_time(data["UtcTime"]), "event timestamp changed")
        require(e.record_time == event_time(record.data["TimeCreated"]), "record time changed")
        require(e.process.process_guid == data.get("ProcessGuid"), "ProcessGuid changed")
        require(e.source_event_id == str(record.data["RecordId"]), "RecordId changed")
        require(e.raw_ref.record_no == record.record_no, "physical line changed")
        require(e.raw_ref.raw_log_id == entry["raw_log_id"], "raw_log_id changed")
        if record.data["EventId"] == 1:
            require(e.process.parent_process_guid == data.get("ParentProcessGuid"), "parent GUID")
            require(e.process.command_line == data.get("CommandLine"), "command line")
        else:
            require(e.network.dst_ip == data.get("DestinationIp"), "destination IP")
            require(e.network.dst_port == int(data["DestinationPort"]), "destination port")
        events.append(e)
    anchor = unique(
        [
            e
            for e in events
            if e.event_type == "process_create"
            and e.process.name.casefold() == "wsmprovhost.exe"
            and abs((e.timestamp - times["01"]).total_seconds()) <= 2
        ],
        "A01/N01 session anchor (audit selector)",
    )
    terminal = unique(
        [
            e
            for e in events
            if e.event_type == "process_create"
            and e.process.name.casefold() == "powershell.exe"
            and abs((e.timestamp - times["03"]).total_seconds()) <= 2
        ],
        "t+5 terminal",
    )
    network = unique(
        [
            e
            for e in events
            if e.event_type == "network_connection"
            and e.process.process_guid == terminal.process.process_guid
            and abs((e.timestamp - times["04"]).total_seconds()) <= 2
            and e.network.dst_ip == destination
            and e.network.dst_port == port
            and e.network.protocol.casefold() == "tcp"
        ],
        "t+8 approved connection",
    )
    chain = [terminal]
    while chain[-1].event_id != anchor.event_id:
        parent = unique(
            [
                e
                for e in events
                if e.event_type == "process_create"
                and e.process.process_guid == chain[-1].process.parent_process_guid
            ],
            "lineage parent",
        )
        require(parent.event_id not in {e.event_id for e in chain}, "lineage cycle")
        chain.append(parent)
    events.sort(key=lambda e: (e.timestamp, e.event_id))
    target = output / run_id
    target.mkdir()
    result = run_and_write_r1_evidence_artifacts(
        events,
        run_id=run_id,
        output_directory=target,
        lineage_inputs=[R1LineageInput(anchor.event_id, terminal.event_id, policy)],
    )
    loaded = load_r1_evidence_artifacts(target)
    by_id = {e.event_id: e for e in events}
    require(len(by_id) == len(events), "duplicate normalized event ID")
    provenance = []
    for evidence in loaded.evidences:
        refs = [by_id[i] for i in evidence.event_ids]
        require(
            all(e.run_id == evidence.run_id and e.host_id == evidence.entity_id for e in refs),
            "Evidence scope",
        )
        require(evidence.timestamp == max(e.timestamp for e in refs), "Evidence timestamp")
        provenance.append(
            {
                "evidence_id": evidence.evidence_id,
                "source_record_ids": [e.source_event_id for e in refs],
            }
        )
    (target / "normalized_events.jsonl").write_text(
        "".join(e.model_dump_json() + "\n" for e in events)
    )
    return {
        "run_id": run_id,
        "source_sha256": sha(source),
        "execution_record_sha256": sha(execution_path),
        "manifest_sha256": sha(manifest_path),
        "rendered_scenario_sha256": sha(scenario_path),
        "validation_provenance": {
            "scenario": {
                "family_id": pair_identity.family_id,
                "variation_id": pair_identity.variation_id,
                "dataset_tier": dataset_tier,
            },
            "approved_policy": _approved_policy_provenance(policy),
        },
        "normalized_count": len(events),
        "event_types": dict(Counter(e.event_type for e in events)),
        "lineage": [
            {
                "record_id": e.source_event_id,
                "name": e.process.name,
                "process_guid": e.process.process_guid,
            }
            for e in reversed(chain)
        ],
        "network_record_id": network.source_event_id,
        "evidence_types": dict(Counter(e.evidence_type for e in result.evidences)),
        "diagnostics": list(result.summary.diagnostics),
        "telemetry_completeness": result.summary.telemetry_completeness,
        "provenance": provenance,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--approved-policy-config",
        type=Path,
        default=DEFAULT_R1_APPROVED_LINEAGE_POLICIES_PATH,
    )
    parser.add_argument(
        "--approved-policy-id",
        default="r1-v02-development-connection",
    )
    parser.add_argument("--approved-policy-version", default="v0.1")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    index = json.loads((args.pair / "index.json").read_text())
    # 저장소에서 관리하는 development validation policy를 사용한다.
    policy = load_r1_approved_lineage_policy(
        args.approved_policy_id,
        args.approved_policy_version,
        config_path=args.approved_policy_config,
    )
    policy_provenance = _approved_policy_provenance(policy)
    (args.output / "audit-policy.json").write_text(
        json.dumps(policy_provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    results = [
        check_run(args.pair, index[k], p, args.output, policy)
        for k, p in [("attack_run_id", "A"), ("normal_run_id", "N")]
    ]
    report = {
        "pair_id": index["pair_id"],
        "purpose": "development_tuning_connection_check",
        "production_selector": False,
        "runs": results,
    }
    (args.output / "connection-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
