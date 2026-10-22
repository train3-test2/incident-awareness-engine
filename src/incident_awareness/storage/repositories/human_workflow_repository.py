"""Transactional append-only workflow storage; never writes analytical tables."""

from uuid import uuid4

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.runtime_snapshot import DecisionRuntimeSnapshot
from incident_awareness.dashboard.human_workflow import (
    DEMO_ACTOR,
    WorkflowCommand,
    WorkflowConflict,
    apply_command,
    initial_state,
    notification_candidate,
    operational_clock,
)
from incident_awareness.storage.repositories.result_repository import DecisionRepository


class HumanWorkflowRepository:
    def __init__(self, connection):
        self.connection = connection

    def _rows(self, query, params=()):
        with self.connection.cursor(row_factory=dict_row) as cursor:
            return cursor.execute(query, params).fetchall()

    def synchronize(self, run_id: str, *, local_demo: bool) -> int:
        """Caller owns transaction. Lock scopes so concurrent syncs converge."""
        self.connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("workflow:" + run_id,)
        )
        if not self.connection.execute("SELECT 1 FROM runs WHERE run_id=%s", (run_id,)).fetchone():
            raise LookupError("Run not found")
        scopes = self.connection.execute(
            "SELECT entity_id FROM fusion_results WHERE run_id=%s UNION "
            "SELECT entity_id FROM decisions WHERE run_id=%s",
            (run_id, run_id),
        ).fetchall()
        created = 0
        for (entity_id,) in scopes:
            decision = DecisionRepository(self.connection).get_current_head(run_id, entity_id)
            if decision:
                row = self.connection.execute(
                    "SELECT payload FROM decision_runtime_snapshots WHERE decision_id=%s",
                    (decision.decision_id,),
                ).fetchone()
                # Never attach a mutable, latest Fusion result to an older Decision version.
                if row is None:
                    continue
                snapshot = DecisionRuntimeSnapshot.model_validate(row[0])
                if (snapshot.decision_id, snapshot.run_id, snapshot.entity_id) != (
                    decision.decision_id,
                    run_id,
                    entity_id,
                ):
                    raise ValueError("Decision snapshot scope mismatch")
                fusion = snapshot.fusion_result
            else:
                row = self.connection.execute(
                    "SELECT payload FROM fusion_results WHERE run_id=%s AND entity_id=%s",
                    (run_id, entity_id),
                ).fetchone()
                if not row:
                    continue
                fusion = FusionResult.model_validate(row[0])
            candidate = notification_candidate(fusion, decision, local_demo=local_demo)
            if candidate is None:
                continue
            result = self.connection.execute(
                "INSERT INTO human_workflow_alerts "
                "(alert_id,source_key,run_id,entity_id,decision_id,detection_kind,detected_at,"
                "source_snapshot) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT(source_key) DO NOTHING RETURNING alert_id",
                tuple(
                    candidate[k]
                    for k in (
                        "alert_id",
                        "source_key",
                        "run_id",
                        "entity_id",
                        "decision_id",
                        "detection_kind",
                        "detected_at",
                    )
                )
                + (Jsonb(candidate["source_snapshot"]),),
            )
            created += result.fetchone() is not None
        return created

    def list_alerts(self, run_id: str):
        return [
            self.detail(row["alert_id"])
            for row in self._rows(
                "SELECT alert_id FROM human_workflow_alerts WHERE run_id=%s "
                "ORDER BY issued_at DESC,alert_id LIMIT 100",
                (run_id,),
            )
        ]

    def report_analysis(self, detail):
        from incident_awareness.reporting.analysis_snapshot import build_analysis_snapshot

        return build_analysis_snapshot(self.connection, detail)

    def detail(self, alert_id: str):
        rows = self._rows("SELECT * FROM human_workflow_alerts WHERE alert_id=%s", (alert_id,))
        if not rows:
            raise LookupError("Alert not found")
        actions = self._rows(
            "SELECT * FROM human_workflow_actions WHERE alert_id=%s ORDER BY version", (alert_id,)
        )
        state = actions[-1]["resulting_state"] if actions else initial_state()
        now = self.connection.execute("SELECT clock_timestamp()").fetchone()[0]
        return {
            **rows[0],
            "state": state,
            "audit": actions,
            "operational_24h": operational_clock(state, now),
            "actor": DEMO_ACTOR,
        }

    def append(self, alert_id: str, command: WorkflowCommand, *, received_at=None):
        if not self.connection.execute(
            "SELECT alert_id FROM human_workflow_alerts WHERE alert_id=%s FOR UPDATE", (alert_id,)
        ).fetchone():
            raise LookupError("Alert not found")
        payload = command.model_dump(mode="json")
        existing = self._rows(
            "SELECT command FROM human_workflow_actions WHERE alert_id=%s AND idempotency_key=%s",
            (alert_id, command.idempotency_key),
        )
        if existing:
            if (
                WorkflowCommand.model_validate(existing[0]["command"]).model_dump(mode="json")
                != payload
            ):
                raise WorkflowConflict("동일 idempotency_key의 입력 내용이 다릅니다.")
            return self.detail(alert_id)
        detail = self.detail(alert_id)
        now = (
            received_at
            if command.awareness_mode == "now"
            else (self.connection.execute("SELECT clock_timestamp()").fetchone()[0])
        )
        if now is None:
            raise ValueError("A server reception timestamp is required")
        state = apply_command(detail["state"], command, now)
        self.connection.execute(
            "INSERT INTO human_workflow_actions "
            "(action_id,alert_id,version,idempotency_key,actor_id,actor_kind,action,recorded_at,"
            "command,previous_state,resulting_state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                alert_id,
                state["version"],
                command.idempotency_key,
                DEMO_ACTOR["actor_id"],
                DEMO_ACTOR["actor_kind"],
                command.action,
                now,
                Jsonb(payload),
                Jsonb(detail["state"]),
                Jsonb(state),
            ),
        )
        return self.detail(alert_id)
