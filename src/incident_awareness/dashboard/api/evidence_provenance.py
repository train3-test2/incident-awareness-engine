"""Local, read-only provenance details. No raw filesystem paths or request overrides."""

from typing import Annotated

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Path, Response

from incident_awareness.dashboard.api.human_workflow import local_actor
from incident_awareness.dashboard.provenance_read_model import read_provenance
from incident_awareness.storage.config import DatabaseConfig

router = APIRouter(tags=["evidence-provenance"], dependencies=[Depends(local_actor)])


def get_provenance_connection():
    try:
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c statement_timeout=10000 -c default_transaction_read_only=on -c timezone=UTC",
        ) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            yield connection
    except (psycopg.Error, RuntimeError):
        raise HTTPException(503, "Evidence provenance storage unavailable") from None


@router.get("/runs/{run_id}/evidence-provenance")
def evidence_provenance(
    run_id: Annotated[str, Path(min_length=1, max_length=512, pattern=r"^\S(?:.*\S)?$")],
    response: Response,
    connection: Annotated[psycopg.Connection, Depends(get_provenance_connection)],
):
    response.headers["Cache-Control"] = "private, no-store"
    try:
        result = read_provenance(connection, run_id)
        # Local demo is not production authentication. No raw command lines, users,
        # internal IPs or complete source record bodies in this new public read model.
        result["source_events"] = [
            {
                key: event[key]
                for key in (
                    "event_id",
                    "run_id",
                    "host_id",
                    "timestamp",
                    "source",
                    "source_layer",
                    "event_type",
                    "source_event_id",
                    "raw_ref",
                )
            }
            for event in result["source_events"]
        ]
        return result
    except LookupError:
        raise HTTPException(404, "Run not found") from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Stored Evidence provenance could not be verified") from None
