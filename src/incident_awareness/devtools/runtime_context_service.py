"""Read-only companion for a running 8792 QA process; never restart its writer/server."""

import json
import logging
import os
import socket

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from incident_awareness.dashboard.api.runtime_context import context_repository, router
from incident_awareness.devtools.continuous_qa_database import ContinuousQaIdentity
from incident_awareness.devtools.final_e2e_qa import ROOT
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    identity_record,
    local_admin_dsn,
)
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)


def main():
    session = json.loads(
        (ROOT / "build/view2-reference/continuous-e2e-qa/session.json").read_text(encoding="utf-8")
    )
    identity = ContinuousQaIdentity(**session["identity"])
    if session["address"] != "http://127.0.0.1:8792":
        raise ValueError("Explicit expected QA origin required")
    admin = local_admin_dsn()
    with connect_lab(admin, identity, readonly=True):
        pass
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 8793))
    except OSError:
        sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    app = FastAPI(title="Local read-only Runtime context companion")
    app.include_router(router)
    app.add_middleware(CORSMiddleware, allow_origins=[session["address"]], allow_methods=["GET"])

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if (
            request.headers.get("host") not in {f"127.0.0.1:{port}", f"localhost:{port}"}
            or request.method != "GET"
            or (
                request.headers.get("origin") is not None
                and request.headers["origin"] != session["address"]
            )
        ):
            return JSONResponse({"detail": "Local read-only companion only"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    def repository():
        with connect_lab(admin, identity, readonly=True) as connection:
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield PipelineRuntimeStatusRepository(connection)

    app.dependency_overrides[context_repository] = repository
    out = ROOT / "build/view2-reference/qa-followup"
    discovery = {
        "schema_version": "local_runtime_companion_v1",
        "dashboard_origin": session["address"],
        "origin": f"http://127.0.0.1:{port}",
        "database": identity.database,
    }
    (out / "runtime-service.json").write_text(
        json.dumps(
            {**discovery, "pid": os.getpid(), "identity": identity_record(identity)}, indent=2
        ),
        encoding="utf-8",
    )
    (ROOT / "src/incident_awareness/dashboard/ui/assets/dashboard-local-qa.json").write_text(
        json.dumps(discovery), encoding="utf-8"
    )
    print(json.dumps(discovery), flush=True)
    uvicorn.Server(
        uvicorn.Config(app, log_level="critical", access_log=False, proxy_headers=False)
    ).run(sockets=[sock])


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception as error:  # noqa: BLE001 - never disclose connection credentials.
        print(json.dumps({"error_type": type(error).__name__, "failed_closed": True}))
        raise SystemExit(1) from None
