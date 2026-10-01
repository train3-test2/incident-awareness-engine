"""Authenticated dashboard endpoints for a single project operator group."""

import os
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row
from pydantic import ValidationError

from incident_awareness.dashboard.queries import DashboardQueries, MissingResource
from incident_awareness.dashboard.reports import ReportConflict, ReportStore, SaveReport

security = HTTPBearer(auto_error=False)


def authorize(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]):
    expected = os.environ.get("INCIDENT_DASHBOARD_TOKEN", "")
    if not expected:
        raise HTTPException(503, "AUTH_NOT_CONFIGURED")
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode(), expected.encode()
    ):
        raise HTTPException(401, "UNAUTHORIZED", headers={"WWW-Authenticate": "Bearer"})


def get_queries() -> Iterator[DashboardQueries]:
    dsn = os.environ.get("INCIDENT_AWARENESS_DATABASE_URL")
    if not dsn:
        raise HTTPException(503, "DATA_SOURCE_UNAVAILABLE")
    with (
        psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as connection,
        connection.transaction(),
    ):
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '5s'")
        yield DashboardQueries(connection)


def get_report_store() -> Iterator[ReportStore]:
    dsn = os.environ.get("INCIDENT_AWARENESS_DATABASE_URL")
    if not dsn:
        raise HTTPException(503, "DATA_SOURCE_UNAVAILABLE")
    with (
        psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as connection,
        connection.transaction(),
    ):
        connection.execute("SET LOCAL statement_timeout = '5s'")
        yield ReportStore(connection)


def error(code, status, headers=None):
    messages = {
        "UNAUTHORIZED": "인증이 필요합니다.",
        "AUTH_NOT_CONFIGURED": "인증 설정이 필요합니다.",
        "INVALID_QUERY": "요청값을 확인해 주세요.",
        "INVALID_REPORT": "신고서 입력값과 시각 형식을 확인해 주세요.",
        "REPORT_CONFLICT": "다른 창에서 수정되었습니다. 입력 내용을 보존한 후 최신 초안을 다시 불러오세요.",
        "RUN_NOT_FOUND": "Run을 찾을 수 없습니다.",
        "DECISION_NOT_FOUND": "Decision을 찾을 수 없습니다.",
        "EVENT_NOT_FOUND": "Event를 찾을 수 없습니다.",
        "DATA_SOURCE_UNAVAILABLE": "결과를 조회할 수 없습니다.",
    }
    return JSONResponse(
        {"error": {"code": code, "message": messages.get(code, "요청 실패")}},
        status_code=status,
        headers=headers,
    )


app = FastAPI(
    title="Incident Awareness Dashboard",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    dependencies=[Depends(authorize)],
)


@app.middleware("http")
async def disable_cache(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    return error(exc.detail, exc.status_code, exc.headers)


@app.exception_handler(RequestValidationError)
async def query_error(request, exc):
    return error("INVALID_REPORT" if request.method == "PUT" else "INVALID_QUERY", 400)


@app.exception_handler(MissingResource)
async def missing_error(request, exc):
    return error(exc.code, 404)


@app.exception_handler(psycopg.Error)
@app.exception_handler(ValidationError)
async def source_error(request, exc):
    return error("DATA_SOURCE_UNAVAILABLE", 503)


@app.exception_handler(ReportConflict)
async def report_conflict(request, exc):
    return error("REPORT_CONFLICT", 409)


@app.get("/api/runs/{run_id}/decisions/{decision_id}/report")
def get_report(
    run_id: str,
    decision_id: str,
    store: Annotated[ReportStore, Depends(get_report_store, scope="function")],
):
    return store.get(run_id, decision_id)


@app.put("/api/runs/{run_id}/decisions/{decision_id}/report")
def save_report(
    run_id: str,
    decision_id: str,
    body: SaveReport,
    store: Annotated[ReportStore, Depends(get_report_store, scope="function")],
):
    return store.save(run_id, decision_id, body)


@app.get("/api/overview")
def overview(queries: Annotated[DashboardQueries, Depends(get_queries)]):
    return queries.overview()


@app.get("/api/runs")
def runs(
    queries: Annotated[DashboardQueries, Depends(get_queries)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return queries.runs(limit, offset)


@app.get("/api/runs/{run_id}/decisions")
def decision_history(
    run_id: str,
    queries: Annotated[DashboardQueries, Depends(get_queries)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return queries.decisions(run_id, limit, offset)


@app.get("/api/runs/{run_id}/events/{event_id}")
def event_detail(
    run_id: str,
    event_id: str,
    queries: Annotated[DashboardQueries, Depends(get_queries)],
):
    return queries.event(run_id, event_id)


@app.get("/api/runs/{run_id}")
def run_detail(
    run_id: str,
    queries: Annotated[DashboardQueries, Depends(get_queries)],
    decision_id: Annotated[str | None, Query(min_length=1)] = None,
    event_limit: Annotated[int, Query(ge=1, le=200)] = 50,
    event_offset: Annotated[int, Query(ge=0)] = 0,
):
    return queries.detail(run_id, decision_id, event_limit, event_offset)


# Public shell contains no data or credentials; all data endpoints remain authenticated.
app.mount(
    "/dashboard",
    StaticFiles(directory=Path(__file__).parent / "static", html=True),
    name="dashboard",
)
