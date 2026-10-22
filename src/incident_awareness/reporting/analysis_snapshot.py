"""Read-only analysis facts for a saved draft. No raw bodies or guessed Evidence joins."""

from incident_awareness.dashboard.provenance_read_model import read_provenance


def iso(value):
    return value.isoformat() if value is not None else None


def build_analysis_snapshot(connection, detail):
    run_id, entity = detail["run_id"], detail["entity_id"]
    row = connection.execute("SELECT metadata FROM runs WHERE run_id=%s", (run_id,)).fetchone()
    if not row:
        raise LookupError("Run not found")
    metadata = row[0]
    counts = connection.execute(
        "SELECT event_type,count(*) FROM events WHERE run_id=%s AND host_id=%s "
        "GROUP BY event_type ORDER BY event_type",
        (run_id, entity),
    ).fetchall()
    bounds = connection.execute(
        "SELECT min(timestamp),max(timestamp) FROM events WHERE run_id=%s AND host_id=%s",
        (run_id, entity),
    ).fetchone()
    source = detail["source_snapshot"]
    try:
        provenance = read_provenance(connection, run_id, fusion_snapshots=[source["fusion"]])
    except (ValueError, TypeError) as error:
        raise ValueError("Evidence provenance verification failed") from error
    raw_verified_ids = {
        eid
        for item in provenance["items"]
        if item["resolution_status"] == "raw_verified"
        for eid in item["event_ids"]
    }
    events = [
        {
            **event,
            "verification": "exact_evidence_event_reference",
            "raw_content_verified": event["event_id"] in raw_verified_ids,
        }
        for event in provenance["source_events"]
    ]
    runtime_row = connection.execute(
        "SELECT payload FROM pipeline_runtime_status WHERE run_id=%s AND entity_id=%s",
        (run_id, entity),
    ).fetchone()
    runtime = runtime_row[0] if runtime_row else {}
    return {
        "schema_version": "stored_report_analysis_v1",
        "context": "development_scenario",
        "run_metadata": {
            k: metadata.get(k)
            for k in ("run_id", "scenario_id", "run_type", "target_host", "start_time", "end_time")
        },
        "entity_id": entity,
        "runtime_observation": {
            k: runtime.get(k)
            for k in ("execution_id", "input_total", "normalization_processed_count")
        },
        "event_statistics": {
            "normalized_event_count": sum(c for _, c in counts),
            "by_type": dict(counts),
            "first_event_at": iso(bounds[0]),
            "last_event_at": iso(bounds[1]),
            "sample_count": len(events),
        },
        "detection": source.get("decision"),
        "fusion": source.get("fusion"),
        "hybrid_status": source["hybrid_status"],
        "evidence": [
            {
                **item,
                "source": "immutable_fusion_result_reference_with_current_reconstruction",
                "verification": "VERIFIED"
                if item["resolution_status"] == "raw_verified"
                else "UNRESOLVED",
            }
            for item in provenance["items"]
        ],
        "source_events": events,
        "evidence_provenance": provenance,
        "verified_observations": provenance["verified_observations"],
        "evidence_link_note": "현재 Extractor 재구성과 당시 원본 Evidence는 구별합니다. "
        "event_verified는 원본 미검증이며 raw_verified 관측만 문장화합니다.",
        "times": {
            "technical_detection_at": iso(detail["detected_at"]),
            "alert_issued_at": iso(detail["issued_at"]),
            "t_h": detail["state"]["t_h"],
            "t_h_recorded_at": detail["state"]["t_h_recorded_at"],
            "incident_occurred_at": "UNKNOWN",
        },
        "human_state": detail["state"],
        "human_history": [
            {
                "action_id": str(a["action_id"]),
                "actor_id": a["actor_id"],
                "action": a["action"],
                "recorded_at": iso(a["recorded_at"]),
                "reason": a["command"].get("reason"),
                "awareness_mode": a["command"].get("awareness_mode", "manual"),
                "previous_t_h": a["previous_state"]["t_h"],
                "new_t_h": a["resulting_state"]["t_h"],
            }
            for a in detail["audit"]
        ],
        "source_tables": ["runs", "events", "human_workflow_alerts", "human_workflow_actions"],
    }
