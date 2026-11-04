"""Opt-in local demo actor, never an authenticated production identity."""

import os
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from psycopg.rows import dict_row

from incident_awareness.dashboard.api.analysis_summaries import AnalysisSummaryQuery
from incident_awareness.dashboard.grounded_report_contract import build_report_input
from incident_awareness.dashboard.human_workflow import (
    WorkflowCommand,
    WorkflowConflict,
    initial_state,
)
from incident_awareness.reporting.public_view import public_report_view
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.human_workflow_repository import (
    HumanWorkflowRepository,
)
from incident_awareness.storage.repositories.result_repository import DecisionIntegrityError


def local_actor(request: Request):
    if os.environ.get("INCIDENT_AWARENESS_LOCAL_DEMO") != "1":
        raise HTTPException(403, "Human Workflow requires an explicitly enabled local demo actor")
    if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(403, "Human Workflow requires a loopback client")
    # Reject DNS rebinding and cross-site form/fetch requests, including opaque origins.
    if request.url.hostname not in {"127.0.0.1", "localhost", "::1", "testserver"}:
        raise HTTPException(403, "Local host required")
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Cross-origin Human Workflow access denied")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site Human Workflow access denied")


router = APIRouter(
    prefix="/human-workflow", tags=["human-workflow"], dependencies=[Depends(local_actor)]
)


@contextmanager
def repository():
    try:
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c statement_timeout=5000 -c lock_timeout=2000",
        ) as connection:
            yield HumanWorkflowRepository(connection)
    except LookupError as error:
        raise HTTPException(404, str(error)) from error
    except (WorkflowConflict, DecisionIntegrityError) as error:
        raise HTTPException(409, str(error)) from error
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    except (psycopg.Error, RuntimeError) as error:
        raise HTTPException(
            503, "Human Workflow storage unavailable; retry with the same key"
        ) from error


@contextmanager
def read_only_repository():
    # List summaries never synchronize alerts; the transaction itself refuses writes.
    try:
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=5000",
        ) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield StoredAlertSummaryReader(connection)
    except (psycopg.Error, RuntimeError) as error:
        raise HTTPException(503, "Human Workflow storage unavailable") from error


ALERT_SUMMARY_KEYS = ("alert_id", "run_id", "entity_id", "detection_kind", "issued_at", "state")
MAX_ALERT_SUMMARIES_PER_RUN = 100


class StoredAlertSummaryReader:
    """One SELECT for the entire list; no detail/audit/draft reads and no synchronization."""

    def __init__(self, connection):
        self.connection = connection

    def read(self, run_ids: list[str]) -> list[dict]:
        with self.connection.cursor(row_factory=dict_row) as cursor:
            rows = cursor.execute(
                "WITH ranked AS ("
                " SELECT alert_id,run_id,entity_id,detection_kind,issued_at,"
                " row_number() OVER (PARTITION BY run_id ORDER BY issued_at DESC,alert_id) AS position"
                " FROM human_workflow_alerts WHERE run_id = ANY(%s)"
                ") SELECT a.alert_id,a.run_id,a.entity_id,a.detection_kind,a.issued_at,"
                " latest.resulting_state AS state FROM ranked a"
                " LEFT JOIN LATERAL (SELECT resulting_state FROM human_workflow_actions"
                " WHERE alert_id=a.alert_id ORDER BY version DESC LIMIT 1) latest ON TRUE"
                " WHERE a.position <= %s ORDER BY a.run_id,a.position",
                (run_ids, MAX_ALERT_SUMMARIES_PER_RUN),
            ).fetchall()
        grouped = {run_id: [] for run_id in run_ids}
        for row in rows:
            grouped[row["run_id"]].append(
                {**row, "state": row["state"] if row["state"] is not None else initial_state()}
            )
        return [{"run_id": run_id, "alerts": grouped[run_id]} for run_id in run_ids]


@router.get("/alert-summaries")
def alert_summaries(query: Annotated[AnalysisSummaryQuery, Query()]):
    """Latest 100 stored alerts per listed Run. This read never creates an alert."""
    with read_only_repository() as reader:
        return {
            "schema_version": "human_workflow_alert_summaries_v1",
            "max_alerts_per_run": MAX_ALERT_SUMMARIES_PER_RUN,
            "items": [
                {
                    "run_id": item["run_id"],
                    "alerts": [
                        {key: alert[key] for key in ALERT_SUMMARY_KEYS} for alert in item["alerts"]
                    ],
                }
                for item in reader.read(query.run_id)
            ],
        }


@router.post("/runs/{run_id}/sync")
def synchronize(run_id: str):
    with repository() as repo:
        created = repo.synchronize(run_id, local_demo=True)
        return {"created": created, "items": repo.list_alerts(run_id)}


@router.get("/runs/{run_id}/alerts")
def list_alerts(run_id: str):
    with repository() as repo:
        return {"items": repo.list_alerts(run_id)}


@router.get("/alerts/{alert_id}")
def detail(alert_id: str):
    with repository() as repo:
        return repo.detail(alert_id)


@router.post("/alerts/{alert_id}/actions")
def append_action(alert_id: str, command: WorkflowCommand):
    # Capture once before database acquisition/locking; never use the browser's clock.
    captured = datetime.now(UTC)
    received_at = captured.replace(microsecond=(captured.microsecond // 1000) * 1000)
    with repository() as repo:
        return repo.append(alert_id, command, received_at=received_at)


@router.get("/alerts/{alert_id}/report-input")
def report_input(alert_id: str):
    with repository() as repo:
        value = repo.detail(alert_id)
        return public_report_view(
            build_report_input(value, repo.report_analysis(value)).model_dump(mode="json")
        )
