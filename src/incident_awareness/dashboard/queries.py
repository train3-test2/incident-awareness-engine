"""Parameterized queries; caller owns a repeatable-read, read-only transaction."""

from datetime import UTC, datetime

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult


class MissingResource(Exception):
    def __init__(self, code):
        self.code = code


def utc(value):
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return value


def serialized(row):
    return {key: utc(value) for key, value in row.items()}


def decision(row, *, detail=False):
    if row is None:
        return None
    result = DecisionResult.model_validate(row["payload"]).model_dump(mode="json")
    keys = (
        "decision_id",
        "entity_id",
        "fast_status",
        "fusion_status",
        "detector_time",
        "fusion_time",
        "t_e",
        "decision_path",
        "winning_path",
        "config_version",
        "detector_set_version",
        "supersedes_decision_id",
    )
    if detail:
        keys += (
            "decision_reason",
            "contributing_evidence_ids",
            "source_hit_ids",
            "selected_source_hit_id",
            "model_version",
            "rule_version",
        )
    return {**{key: result[key] for key in keys}, "created_at": utc(row["created_at"])}


RUN_COLUMNS = "run_id, scenario_id, run_type, target_host, start_time, end_time"


class DashboardQueries:
    def __init__(self, connection):
        self.db = connection

    def overview(self):
        """Count one latest Decision per Run, never all Decision history rows."""
        groups = self.db.execute(
            "SELECT d.decision_id IS NOT NULL AS has_decision, "
            "d.fast_status, d.fusion_status, d.decision_path, count(*) AS count "
            "FROM runs r LEFT JOIN LATERAL ("
            "SELECT decision_id, fast_status, fusion_status, decision_path "
            "FROM decisions WHERE run_id = r.run_id "
            "ORDER BY created_at DESC, decision_id DESC LIMIT 1"
            ") d ON true GROUP BY 1, 2, 3, 4"
        ).fetchall()
        status_keys = ("detected", "miss", "not_evaluated", "missing")
        result = {
            "scope": "all_runs",
            "decision_basis": "latest_per_run",
            "total_runs": 0,
            "runs_with_decision": 0,
            "runs_without_decision": 0,
            "fast": dict.fromkeys(status_keys, 0),
            "fusion": dict.fromkeys(status_keys, 0),
            "decision_paths": dict.fromkeys(
                ("fast", "fusion", "fast_and_fusion", "none", "not_evaluated", "missing"), 0
            ),
        }
        for group in groups:
            count = group["count"]
            result["total_runs"] += count
            if not group["has_decision"]:
                result["runs_without_decision"] += count
                for key in ("fast", "fusion", "decision_paths"):
                    result[key]["missing"] += count
                continue
            result["runs_with_decision"] += count
            for key in ("fast", "fusion"):
                result[key][group[f"{key}_status"]] += count
            path = group["decision_path"]
            result["decision_paths"][path if path is not None else "not_evaluated"] += count
        result["total_events"] = self.db.execute("SELECT count(*) AS count FROM events").fetchone()[
            "count"
        ]
        return result

    def latest(self, run_id):
        return self.db.execute(
            "SELECT payload, created_at FROM decisions WHERE run_id = %s "
            "ORDER BY created_at DESC, decision_id DESC LIMIT 1",
            (run_id,),
        ).fetchone()

    def runs(self, limit, offset):
        total = self.db.execute("SELECT count(*) AS count FROM runs").fetchone()["count"]
        rows = self.db.execute(
            f"SELECT {RUN_COLUMNS} FROM runs ORDER BY start_time DESC, run_id DESC "
            "LIMIT %s OFFSET %s",
            (limit, offset),
        ).fetchall()
        items = []
        for row in rows:
            latest = decision(self.latest(row["run_id"]))
            items.append(
                {**serialized(row), "has_decision": latest is not None, "latest_decision": latest}
            )
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def decisions(self, run_id, limit, offset):
        exists = self.db.execute("SELECT run_id FROM runs WHERE run_id = %s", (run_id,)).fetchone()
        if exists is None:
            raise MissingResource("RUN_NOT_FOUND")
        total = self.db.execute(
            "SELECT count(*) AS count FROM decisions WHERE run_id = %s", (run_id,)
        ).fetchone()["count"]
        rows = self.db.execute(
            "SELECT payload, created_at FROM decisions WHERE run_id = %s "
            "ORDER BY created_at DESC, decision_id DESC LIMIT %s OFFSET %s",
            (run_id, limit, offset),
        ).fetchall()
        return {
            "items": [decision(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def event(self, run_id, event_id):
        exists = self.db.execute("SELECT run_id FROM runs WHERE run_id = %s", (run_id,)).fetchone()
        if exists is None:
            raise MissingResource("RUN_NOT_FOUND")
        row = self.db.execute(
            "SELECT event_id, run_id, timestamp, host_id, event_type, "
            "jsonb_build_object("
            "'source', payload->'source', "
            "'source_layer', payload->'source_layer', "
            "'source_event_id', payload->'source_event_id', "
            "'timestamp_source', payload->'timestamp_source', "
            "'raw_ref', jsonb_build_object("
            "'raw_log_id', payload->'raw_ref'->'raw_log_id', "
            "'source_record_id', payload->'raw_ref'->'source_record_id', "
            "'segment_no', payload->'raw_ref'->'segment_no', "
            "'record_no', payload->'raw_ref'->'record_no', "
            "'parser_id', payload->'raw_ref'->'parser_id', "
            "'parser_version', payload->'raw_ref'->'parser_version')) AS provenance "
            "FROM events WHERE run_id = %s AND event_id = %s",
            (run_id, event_id),
        ).fetchone()
        if row is None:
            raise MissingResource("EVENT_NOT_FOUND")
        return serialized(row)

    def detail(self, run_id, decision_id, event_limit, event_offset):
        row = self.db.execute(
            f"SELECT {RUN_COLUMNS} FROM runs WHERE run_id = %s",
            (run_id,),
        ).fetchone()
        if row is None:
            raise MissingResource("RUN_NOT_FOUND")
        run = serialized(row)
        if decision_id is None:
            selected_row = self.latest(run_id)
        else:
            selected_row = self.db.execute(
                "SELECT payload, created_at FROM decisions WHERE run_id = %s AND decision_id = %s",
                (run_id, decision_id),
            ).fetchone()
            if selected_row is None:
                raise MissingResource("DECISION_NOT_FOUND")
        selected = decision(selected_row, detail=True)
        current = None
        if selected is not None:
            current = {
                "entity_id": selected["entity_id"],
                "relation_to_selected_decision": "unverified",
            }
            for name, table, model in (
                ("fast", "detection_results", DetectionResult),
                ("fusion", "fusion_results", FusionResult),
            ):
                result_row = self.db.execute(
                    f"SELECT payload FROM {table} WHERE run_id = %s AND entity_id = %s",
                    (run_id, selected["entity_id"]),
                ).fetchone()
                value = None
                if result_row is not None:
                    value = model.model_validate(result_row["payload"]).model_dump(mode="json")
                    value.pop("run_id")
                    value.pop("entity_id")
                current[name] = {
                    "availability": "available" if value is not None else "missing",
                    "value": value,
                }
        total = self.db.execute(
            "SELECT count(*) AS count FROM events WHERE run_id = %s",
            (run_id,),
        ).fetchone()["count"]
        events = [
            serialized(event)
            for event in self.db.execute(
                "SELECT event_id, timestamp, host_id, event_type FROM events WHERE run_id = %s "
                "ORDER BY timestamp, event_id LIMIT %s OFFSET %s",
                (run_id, event_limit, event_offset),
            ).fetchall()
        ]
        ids = selected["contributing_evidence_ids"] if selected else None
        return {
            "run": run,
            "selected_decision": selected,
            "current_entity_results": current,
            "evidence": {
                "ids": ids if ids is not None else [],
                "availability": "ids_only" if ids is not None else "not_available",
            },
            "events": {
                "items": events,
                "total": total,
                "limit": event_limit,
                "offset": event_offset,
            },
            "timeline": {
                "items": timeline(run, selected, events),
                "event_scope": "returned_page",
                "total_event_count": total,
            },
        }


def timeline(run, selected, events):
    items = []

    def add(kind, timestamp, source_id):
        if timestamp is not None:
            items.append(
                {
                    "key": f"{kind}:{source_id}",
                    "kind": kind,
                    "timestamp": timestamp,
                    "source_id": source_id,
                }
            )

    add("run_start", run["start_time"], run["run_id"])
    add("run_end", run["end_time"], run["run_id"])
    if selected:
        for kind, field in (
            ("fast_detection", "detector_time"),
            ("fusion_detection", "fusion_time"),
            ("system_decision", "t_e"),
        ):
            add(kind, selected[field], selected["decision_id"])
    for event in events:
        add("event", event["timestamp"], event["event_id"])
    return sorted(
        items,
        key=lambda item: (
            datetime.fromisoformat(item["timestamp"]),
            item["key"],
        ),
    )
