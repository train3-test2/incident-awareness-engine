"""Independent Snapshot GET service; contains no Dashboard, database, Workflow or AI routes."""

import argparse
import hmac
import ipaddress
import json
import os
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from incident_awareness.dashboard.track_b_observations import (
    ObservationEnvelope,
    ObservationQuery,
    SnapshotReader,
    registered_runs,
)


def service_configuration():
    root = Path(
        os.environ.get("TRACK_B_SNAPSHOT_ROOT", r"C:\R1\track-b-demo\operations-observations")
    )
    runs = registered_runs(os.environ.get("TRACK_B_RUN_IDS", ""))
    token = os.environ.get("TRACK_B_READ_TOKEN", "")
    clients = frozenset(
        part.strip()
        for part in os.environ.get("TRACK_B_ALLOWED_CLIENTS", "").split(",")
        if part.strip()
    )
    for address in clients:
        ipaddress.ip_address(address)
    if len(token) < 32 or not clients or not runs or not root.is_absolute():
        raise ValueError(
            "Snapshot root, registered Runs, token and allowed client addresses are required"
        )
    return root, runs, token, clients


def create_snapshot_app(*, reader=None, token=None, allowed_clients=None):
    if reader is None:
        root, runs, token, allowed_clients = service_configuration()
        reader = SnapshotReader(root, runs)
    if not token or len(token) < 32 or not allowed_clients:
        raise ValueError("Explicit Snapshot access control is required")
    app = FastAPI(
        title="Track-B read-only Snapshot", docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.middleware("http")
    async def restrict_access(request: Request, call_next):
        # Never trust X-Forwarded-For; Uvicorn is launched with proxy_headers=False.
        peer = request.client.host if request.client else ""
        if peer not in allowed_clients:
            return JSONResponse(status_code=403, content={"detail": "Snapshot client denied"})
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), ("Bearer " + token).encode()):
            return JSONResponse(
                status_code=401, content={"detail": "Snapshot authorization required"}
            )
        if request.method != "GET":
            return JSONResponse(
                status_code=405, content={"detail": "Read-only service"}, headers={"Allow": "GET"}
            )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def health():
        return {"status": "ok", "service": "track_b_snapshot_read_only"}

    @app.get("/operations/observations", response_model=ObservationEnvelope)
    def observations(query: Annotated[ObservationQuery, Query()]):
        try:
            return reader.read(tuple(query.run_id) if query.run_id else None)
        except LookupError as error:
            raise HTTPException(404, "Unregistered Track-B Run") from error

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8817)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    ipaddress.ip_address(args.host)
    root, runs, token, clients = service_configuration()
    app = create_snapshot_app(
        reader=SnapshotReader(root, runs), token=token, allowed_clients=clients
    )
    if args.check_only:
        # No file contents, absolute path, credentials, DB access, or socket binding.
        print(
            json.dumps(
                {
                    "configuration": "valid",
                    "registered_runs": len(runs),
                    "allowed_clients": len(clients),
                    "read_only": True,
                    "port": args.port,
                }
            )
        )
        return
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
