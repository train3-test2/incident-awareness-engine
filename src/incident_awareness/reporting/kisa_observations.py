"""Describe only normalized behavior with a verified Evidence -> Event -> Raw chain."""

import json
from datetime import datetime
from zoneinfo import ZoneInfo

from incident_awareness.common.models.event import NetworkInfo, ProcessInfo, RawLogReference


def verified_observations(draft):
    analysis = draft.get("analysis") or {}
    if "evidence_provenance" in analysis:
        from incident_awareness.reporting.observations import snapshot_observations

        observations = snapshot_observations(
            analysis, run_id=draft.get("run_id"), entity_id=draft.get("entity_id")
        )
        selected = observations[:3]
        return [o.behavior_summary for o in selected], list(
            dict.fromkeys(
                ref
                for o in selected
                for ref in (
                    o.evidence_id,
                    o.observation_id,
                    f"report-draft:{draft['draft_id']}#/analysis/verified_observations/{observations.index(o)}",
                )
            )
        )
    events = analysis.get("source_events") or []
    sentences, refs = [], []
    for evidence in analysis.get("evidence") or []:
        if evidence.get("verification") != "VERIFIED" or not evidence.get("evidence_id"):
            continue
        for index, event in enumerate(events):
            if event.get("raw_content_verified") is not True:
                continue
            source_id = event.get("source_event_id")
            source_ids = evidence.get("source_event_ids", [])
            if not isinstance(source_ids, list):
                continue
            if evidence.get("source_event_id"):
                source_ids = [*source_ids, evidence["source_event_id"]]
            if not source_id or source_id not in source_ids:
                continue
            if not event.get("host_id") or event["host_id"] != draft.get("entity_id"):
                continue
            if event.get("run_id") != draft.get("run_id"):
                continue
            try:
                raw = RawLogReference.model_validate(evidence.get("raw_ref"))
                if raw != RawLogReference.model_validate(event.get("raw_ref")):
                    continue
                timestamp = datetime.fromisoformat(event["timestamp"])
                if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                    continue
                details = []
                if event.get("event_type") == "process_create":
                    process = ProcessInfo.model_validate(event.get("process"))
                    if process.name:
                        details.append(
                            "프로세스 " + json.dumps(process.name[:160], ensure_ascii=False)
                        )
                    if process.command_line:
                        details.append(
                            "명령행 " + json.dumps(process.command_line[:200], ensure_ascii=False)
                        )
                elif event.get("event_type") == "network_connection":
                    network = NetworkInfo.model_validate(event.get("network"))
                    if network.dst_ip:
                        details.append(
                            "네트워크 연결 목적지 "
                            + json.dumps(network.dst_ip, ensure_ascii=False)
                            + (f":{network.dst_port}" if network.dst_port is not None else "")
                        )
                if not details:
                    continue
            except (ValueError, TypeError, KeyError):
                continue
            stamp = timestamp.astimezone(ZoneInfo("Asia/Seoul")).isoformat(timespec="seconds")
            sentence = f"{stamp} 관측 시스템 {json.dumps(event['host_id'], ensure_ascii=False)}: {', '.join(details)}."
            if sentence in sentences:
                continue
            sentences.append(sentence)
            refs.extend(
                [
                    evidence["evidence_id"],
                    f"report-draft:{draft['draft_id']}#/analysis/source_events/{index}",
                ]
            )
            if len(sentences) == 3:
                return sentences, refs
    return sentences, refs
