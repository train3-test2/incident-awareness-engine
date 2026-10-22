"""Opt-in local full Standalone Pipeline acceptance harness, not operational traffic."""

import argparse
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex

import psycopg
import uvicorn
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.run import RunType
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.devtools import labeled_dashboard
from incident_awareness.devtools.e2e_qa_database import QaIdentity, create_qa_database
from incident_awareness.devtools.telemetry_lab_database import (
    READ_OPTIONS,
    connect_lab,
    identity_record,
    local_admin_dsn,
    target_dsn,
    verify_owner,
)
from incident_awareness.pipeline.runtime_telemetry import PostgresPipelineRuntimeObserver
from incident_awareness.pipeline.stage_timing import PipelineStageTimingCollector
from incident_awareness.pipeline.stage_timing_storage import PostgresPipelineStageTimingObserver
from incident_awareness.pipeline.standalone import (
    prepare_standalone_run,
    run_prepared_standalone_run,
)
from incident_awareness.pipeline.timeseries_observer import PostgresPipelineTelemetryObserver
from incident_awareness.storage.config import DatabaseConfig

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "build/view2-reference/final-e2e-qa"
RESERVED = {8765, 8766, 8767, 8768, 8778, 8787, 8788, 8790}


def fixture_rows(kind: str, count: int) -> tuple[list[dict], dict]:
    """Repeat existing validated input records, not stage outputs or measured timestamps."""
    source = (
        ROOT
        / "tests/fixtures/pipeline/e2e_qa"
        / ("normal.jsonl" if kind == "normal" else "attack.jsonl")
    )
    base = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    if len(base) != 3 or not 2 <= count <= 12000:
        raise ValueError("Bounded reviewed fixture required")
    rows = [{**base[index % 3], "RecordId": index + 1} for index in range(count)]
    provenance = {
        "source": source.relative_to(ROOT).as_posix(),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "original_record_ids": [row["RecordId"] for row in base],
        "input_record_count": count,
        "transformation": "repeat input records; unique RecordId; original Event time/Computer unchanged",
        "operational_measurement": False,
    }
    return rows, provenance


class QaRunner:
    def __init__(self, admin: str, identity: QaIdentity, *, output_dir: Path | None = None):
        self.admin = admin
        self.identity = identity
        self.output_dir = OUT if output_dir is None else output_dir
        self.lock = threading.Lock()
        self.jobs: list[dict] = []
        self.thread: threading.Thread | None = None

    def start(self, kind: str, count: int) -> dict:
        if kind not in {"normal", "attack", "failure"} or not 2 <= count <= 12000:
            raise ValueError("Unknown bounded QA scenario")
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise ValueError("One Pipeline at a time")
            if len(self.jobs) >= 12:
                raise ValueError("QA session limit reached")
            for number in range(701, 800):
                run_id = f"RUN-{datetime.now(UTC):%Y%m%d}-{number:03d}"
                if not (self.output_dir / "runs" / run_id).exists():
                    with connect_lab(self.admin, self.identity, readonly=True) as connection:
                        exists = connection.execute(
                            "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id=%s) "
                            "OR EXISTS(SELECT 1 FROM pipeline_runtime_status WHERE run_id=%s)",
                            (run_id, run_id),
                        ).fetchone()[0]
                    if not exists:
                        break
            else:
                raise ValueError("No fresh QA Run identity")
            job = {
                "run_id": run_id,
                "kind": kind,
                "records": count,
                "phase": "starting",
                "execution_id": None,
                "started_at": datetime.now(UTC).isoformat(),
                "runtime_history": [],
            }
            self.jobs.append(job)
            self.thread = threading.Thread(target=self._execute, args=(job,), daemon=True)
            self.thread.start()
            return {key: value for key, value in job.items() if key != "runtime_history"}

    def _execute(self, job: dict):
        runtime_observer = None
        stage_observer = None
        telemetry_observer = None
        timing = None
        try:
            rows, provenance = fixture_rows(job["kind"], job["records"])
            source = self.output_dir / "inputs" / (job["run_id"] + ".jsonl")
            source.parent.mkdir(parents=True, exist_ok=True)
            # QA input artifact, never a fabricated Pipeline result or observation.
            source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            prepared = prepare_standalone_run(
                sysmon_jsonl_path=source,
                output_dir=self.output_dir / "runs" / job["run_id"],
                run_id=job["run_id"],
                decision_id="DEC-" + job["run_id"],
                scenario_id="QA-" + job["kind"],
                run_type=RunType.NORMAL if job["kind"] == "normal" else RunType.ATTACK,
            )
            if job["kind"] == "failure":
                # Genuine invalid input: Fusion loader fails after successful normalization.
                prepared = replace(
                    prepared,
                    inputs=replace(
                        prepared.inputs,
                        fusion_config_path=self.output_dir
                        / "intentionally-absent-fusion-config.yaml",
                    ),
                )
            factory = lambda: DatabaseConfig(target_dsn(self.admin, self.identity))
            connect = lambda _: connect_lab(self.admin, self.identity)
            runtime_observer = PostgresPipelineRuntimeObserver(
                database_config_factory=factory, connection_factory=connect
            )
            telemetry_observer = PostgresPipelineTelemetryObserver(
                database_config_factory=factory, connection_factory=connect
            )
            stage_observer = PostgresPipelineStageTimingObserver(
                database_config_factory=factory, connection_factory=connect
            )
            timing = PipelineStageTimingCollector(observer=stage_observer)

            def runtime(status):
                runtime_observer(status)
                with self.lock:
                    job["execution_id"] = status.execution_id
                    job["entity_id"] = status.entity_id
                    previous = job["runtime_history"][-1] if job["runtime_history"] else None
                    if (
                        previous is None
                        or (previous["status"], previous["current_stage"])
                        != (
                            status.status.value,
                            status.current_stage.value if status.current_stage else None,
                        )
                        or status.normalization_processed_count == status.input_total
                    ):
                        job["runtime_history"].append(status.model_dump(mode="json"))

            with self.lock:
                job["phase"] = "running"
                job["fixture"] = provenance
            # Separate business write session. Longer transaction budget is for actual bulk
            # persistence; observer sessions retain their short existing timeouts.
            with psycopg.connect(
                target_dsn(self.admin, self.identity),
                connect_timeout=2,
                options="-c default_transaction_read_only=off -c statement_timeout=30000 "
                "-c lock_timeout=2000 -c transaction_timeout=120000 -c timezone=UTC",
            ) as business:
                verify_owner(business, self.identity)
                business.commit()
                summary = run_prepared_standalone_run(
                    prepared,
                    connection=business,
                    runtime_observer=runtime,
                    telemetry_observer=telemetry_observer,
                    stage_timing_collector=timing,
                )
            with self.lock:
                job["summary"] = asdict(summary)
                job["phase"] = "completed"
        except Exception as error:  # noqa: BLE001 - local QA records genuine Pipeline failures.
            with self.lock:
                job["phase"] = "failed"
                job["error_type"] = type(error).__name__
        finally:
            for observer in (stage_observer, telemetry_observer, runtime_observer):
                if observer is not None:
                    observer.close()
            with self.lock:
                if timing is not None:
                    job["timing"] = timing.snapshot().model_dump(mode="json")
                job["ended_at"] = datetime.now(UTC).isoformat()
                (self.output_dir / "run-trace.json").write_text(
                    json.dumps(self.jobs, indent=2), encoding="utf-8"
                )

    def status(self):
        with self.lock:
            return json.loads(
                json.dumps(
                    [{**job, "runtime_history": job["runtime_history"][-12:]} for job in self.jobs]
                )
            )


class QaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    records: int = Field(default=4000, ge=2, le=12000)


def create_qa_app(runner: QaRunner, port: int, token: str):
    app = create_app()
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if request.headers.get("host") not in hosts:
            return HTMLResponse("Local QA only", status_code=403)
        if request.method != "GET" and request.url.path != "/qa/run":
            return HTMLResponse("Read-only Dashboard", status_code=405)
        response = await call_next(request)
        if request.url.path == "/dashboard" and response.status_code == 200:
            body = b"".join([part async for part in response.body_iterator]).decode("utf-8")
            response = labeled_dashboard(body, "격리 인수 검증 운영 실측 아님")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/qa/status", include_in_schema=False)
    def status():
        return {"database": runner.identity.database, "fixture_only": True, "jobs": runner.status()}

    @app.get("/qa", include_in_schema=False)
    def page():
        # QA-only launcher, not an operating View redesign. Token stays same-origin.
        return HTMLResponse(
            '<meta charset="utf-8"><title>격리 Pipeline 인수 QA</title>'
            "<h1>격리 DB · 실제 Standalone Pipeline · 운영 실측 아님</h1>"
            "<p>Fast 미평가 / R1 게시 없음 / Human Workflow 미연동. 실제 처리시간 조작 없음.</p>"
            '<p><a href="/dashboard" target="dashboard">운영 Dashboard 열기</a></p>'
            "<button onclick=\"run('normal')\">정상 입력 실행</button> "
            "<button onclick=\"run('attack')\">공격 입력 실행</button> "
            "<button onclick=\"run('failure')\">잘못된 Fusion 설정 실패 실행</button>"
            "<p>성공 입력 4,000건 / 실패 입력 2건. 원본 fixture 반복 입력이며 원본 고유 Event 수와 다릅니다.</p>"
            '<pre id="state" role="status"></pre><script>'
            f"const token={json.dumps(token)};"
            'async function run(kind){const r=await fetch("/qa/run",{method:"POST",headers:{'
            '"Content-Type":"application/json","X-QA-Token":token},body:JSON.stringify({kind,'
            'records:kind==="failure"?2:4000})});document.getElementById("state").textContent=await r.text();}'
            "</script>"
        )

    @app.post("/qa/run", include_in_schema=False)
    def run(body: QaRequest, request: Request):
        origin = request.headers.get("origin")
        if not hmac.compare_digest(request.headers.get("x-qa-token", ""), token) or (
            origin is not None and origin not in {"http://" + host for host in hosts}
        ):
            raise HTTPException(403, "Local QA control token required")
        try:
            return runner.start(body.kind, body.records)
        except ValueError:
            raise HTTPException(409, "One bounded QA Run at a time") from None

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--reuse-owned", action="store_true")
    args = parser.parse_args()
    if args.port in RESERVED:
        raise ValueError("Protected existing server port")
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", args.port))
    except OSError:
        sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    admin = local_admin_dsn()
    OUT.mkdir(parents=True, exist_ok=True)
    previous = None
    if (OUT / "session.json").exists() and not args.reuse_owned:
        raise ValueError("Never replace an existing QA session")
    if args.reuse_owned:
        previous = json.loads((OUT / "session.json").read_text(encoding="utf-8"))
        identity = QaIdentity(**previous["identity"])
        if previous["port"] != port:
            raise ValueError("QA resume port mismatch")
        with connect_lab(admin, identity, readonly=True):
            pass
        migrations = previous["migrations"]
    else:
        identity, migrations = create_qa_database(admin)
    token = previous["token"] if previous else token_hex(32)
    os.environ["INCIDENT_AWARENESS_DATABASE_URL"] = target_dsn(admin, identity)
    os.environ["PGOPTIONS"] = READ_OPTIONS
    os.environ["INCIDENT_AWARENESS_EVENT_TYPES_PATH"] = str(ROOT / "configs/event_types_v0.2.yaml")
    state = {
        "identity": identity_record(identity),
        "port": port,
        "address": f"http://127.0.0.1:{port}",
        "token": token,
        "migrations": migrations,
        "pid": os.getpid(),
    }
    with (OUT / "session.json").open("w" if previous else "x", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)
    runner = QaRunner(admin, identity)
    if previous and (OUT / "run-trace.json").exists():
        runner.jobs = json.loads((OUT / "run-trace.json").read_text(encoding="utf-8"))
    app = create_qa_app(runner, port, token)
    print(
        json.dumps({"database": identity.database, "dashboard": state["address"] + "/dashboard"}),
        flush=True,
    )
    uvicorn.Server(
        uvicorn.Config(app, log_level="critical", access_log=False, proxy_headers=False)
    ).run(sockets=[sock])


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception as error:  # noqa: BLE001 - never print credentials from DB errors.
        print(json.dumps({"error_type": type(error).__name__, "failed_closed": True}))
        raise SystemExit(1) from None
