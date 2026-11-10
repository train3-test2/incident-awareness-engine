"""Local, opt-in DB-backed fixture workload; never real operational measurements."""

import argparse
import hmac
import json
import logging
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from urllib.error import URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

import uvicorn
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.devtools import labeled_dashboard
from incident_awareness.devtools.telemetry_lab_database import (
    READ_OPTIONS,
    LabIdentity,
    connect_lab,
    create_database,
    drop_database,
    identity_record,
    local_admin_dsn,
    reset_observations,
    target_dsn,
)
from incident_awareness.pipeline.cli import PipelineInputs
from incident_awareness.pipeline.event_evidence import normalize_sysmon_and_extract_evidence
from incident_awareness.pipeline.runtime_telemetry import (
    PipelineRuntimeTracker,
    generate_execution_id,
    utc_now_milliseconds,
)
from incident_awareness.pipeline.s0_artifacts import load_s0_pipeline_artifacts
from incident_awareness.pipeline.telemetry_input import resolve_telemetry_input_identity
from incident_awareness.pipeline.timeseries_observer import (
    PipelineTelemetrySession,
    PostgresPipelineTelemetryObserver,
)
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

ROOT = Path(__file__).resolve().parents[3]
ASSETS = Path(__file__).with_name("telemetry_lab")
PERIODS = {"low": 2.0, "normal": 1.0, "high": 0.25}
MAX_ACTIVE_SECONDS = 180
MAX_BATCHES = 720
RESERVED_PORTS = {8765, 8766, 8767, 8768, 8778, 8787, 8788}


def fixture_inputs() -> PipelineInputs:
    base = ROOT / "tests/fixtures/pipeline/first_cycle"
    return PipelineInputs(
        run_metadata_path=base / "run_metadata.json",
        manifest_path=base / "manifest.json",
        sysmon_jsonl_path=base / "sysmon-0001.jsonl",
        fast_hits_path=base / "fast/hits.jsonl",
        fast_trace_path=base / "fast/trace.json",
        fast_selection_path=base / "fast/selection.json",
        fusion_config_path=ROOT / "configs/fusion_v0.2.yaml",
        entity_id="WIN-01",
        decision_id="unused-telemetry-lab",
        decision_config_version="unused",
    )


@dataclass(frozen=True)
class BatchResult:
    execution_id: str
    revision: int
    completed: int
    evidences_in_memory: int
    latency_sum_ns: int


def process_batch(
    admin_dsn: str, identity: LabIdentity, *, separate_first_second=False
) -> BatchResult:
    """Real normalization+extraction. No process execution or business-result persistence."""
    inputs = fixture_inputs()
    artifacts = load_s0_pipeline_artifacts(
        inputs
    )  # Real manifest/bytes validation before admission.
    input_identity = resolve_telemetry_input_identity(
        inputs.sysmon_jsonl_path, artifacts.sysmon_records, artifacts.sysmon_content_sha256
    )
    if input_identity is None:
        raise ValueError("Verified fixture input identity required")
    execution_id = generate_execution_id()
    tracker = PipelineRuntimeTracker(
        execution_id=execution_id,
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
        input_total=len(artifacts.sysmon_records),
        started_at=utc_now_milliseconds(),
        observer=None,
    )
    # Only this real substage runs; do NOT save a Runtime full-Pipeline completed status.
    tracker.start_stage(PipelineStage.NORMALIZATION)
    collector = PipelineTelemetryCollector(
        execution_id=tracker.execution_id,
        run_id=artifacts.run_metadata.run_id,
        entity_id=inputs.entity_id,
        input_identity=input_identity,
        max_records=len(artifacts.sysmon_records),
        max_buckets=4,
    )
    with PostgresPipelineTelemetryObserver(
        database_config_factory=lambda: DatabaseConfig(target_dsn(admin_dsn, identity)),
        connection_factory=lambda _: connect_lab(admin_dsn, identity),
    ) as observer:
        session = PipelineTelemetrySession(collector, observer)
        collector.accept_batch(len(artifacts.sysmon_records))
        session.flush(force=True)
        if separate_first_second:
            # Workload pacing, BEFORE begin_record. Makes a genuine admission-only second
            # followed by a genuine completion-only second, not synthesized zero samples.
            admitted = collector.snapshot().input_accepted_at
            wait = max(0, admitted.timestamp() + 1.03 - time.time())
            time.sleep(min(wait, 1.03))
        result = normalize_sysmon_and_extract_evidence(
            artifacts,
            telemetry_collector=session,
            progress_callback=tracker.record_normalization_progress,
        )
        session.flush(force=True)
        snapshot = collector.snapshot()
        if snapshot.observation_status != "observed" or collector.is_disabled:
            raise RuntimeError("Fixture telemetry collection/storage was incomplete")
        with connect_lab(admin_dsn, identity, readonly=True) as connection:
            stored = PipelineTelemetryRepository(connection).get_execution(execution_id)
        if stored != snapshot:
            raise RuntimeError("Observer did not persist the exact measured snapshot")
    return BatchResult(
        execution_id,
        snapshot.revision,
        len(result.events),
        len(result.evidences),
        sum(bucket.latency_sum_ns for bucket in snapshot.buckets),
    )


class LabEngine:
    """One bounded worker. Pause/reset acknowledge only after any in-flight batch ends."""

    def __init__(self, admin_dsn: str, identity: LabIdentity):
        self.admin_dsn = admin_dsn
        self.identity = identity
        self.condition = threading.Condition()
        self.phase = "idle"
        self.speed = "low"
        self.used_seconds = 0.0
        self.since = None
        self.next_due = 0.0
        self.batches = 0
        self.generation = token_hex(8)
        self.last = None
        self.error_type = None
        self.closed = False
        self.thread = threading.Thread(target=self._work, daemon=True, name="telemetry-lab-writer")

    def start_worker(self):
        self.thread.start()

    def elapsed(self):
        return self.used_seconds + (time.monotonic() - self.since if self.since is not None else 0)

    def _pause(self, phase="paused"):
        self.used_seconds = self.elapsed()
        self.since = None
        self.phase = phase

    def control(self, action: str, speed: str | None = None) -> None:
        with self.condition:
            if self.closed:
                raise ValueError("Lab worker is closed")
            if action in {"start", "resume"}:
                if self.phase == "running":
                    return
                if self.phase in {"completed", "error"}:
                    raise ValueError("Reset before starting another bounded experiment")
                self.phase = "running"
                self.since = time.monotonic()
                self.next_due = self.since
            elif action == "pause":
                if self.phase == "running":
                    self._pause()
            elif action == "speed":
                if speed not in PERIODS:
                    raise ValueError("Unknown bounded input speed")
                self.speed = speed
                self.next_due = time.monotonic() + PERIODS[speed]
            elif action == "reset":
                self._pause()
                reset_observations(self.admin_dsn, self.identity)
                self.phase = "idle"
                self.used_seconds = 0.0
                self.batches = 0
                self.generation = token_hex(8)
                self.last = None
                self.error_type = None
            else:
                raise ValueError("Unsupported lab control")
            self.condition.notify_all()

    def _work(self):
        with self.condition:
            while not self.closed:
                if self.phase != "running":
                    self.condition.wait()
                    continue
                if self.elapsed() >= MAX_ACTIVE_SECONDS or self.batches >= MAX_BATCHES:
                    self._pause("completed")
                    continue
                delay = self.next_due - time.monotonic()
                if delay > 0:
                    self.condition.wait(timeout=min(delay, MAX_ACTIVE_SECONDS - self.elapsed()))
                    continue
                try:
                    self.last = process_batch(
                        self.admin_dsn, self.identity, separate_first_second=self.batches == 0
                    )
                    self.batches += 1
                except Exception as error:  # noqa: BLE001 - stop the lab on any worker failure.
                    # No exception text/DSN/raw Event content is exposed or logged.
                    self.error_type = type(error).__name__
                    self._pause("error")
                self.next_due = time.monotonic() + PERIODS[self.speed]

    def status(self) -> dict:
        with self.condition:
            state = {
                "schema_version": "telemetry_lab_v1",
                **self.identity.public(),
                "simulation": True,
                "operational_measurement": False,
                "phase": self.phase,
                "speed": self.speed,
                "active_seconds": round(self.elapsed(), 2),
                "limit_seconds": MAX_ACTIVE_SECONDS,
                "max_batches": MAX_BATCHES,
                "batches": self.batches,
                "generation": self.generation,
                "last_execution_id": self.last.execution_id if self.last else None,
                "last_revision": self.last.revision if self.last else None,
                "error_type": self.error_type,
                "measurement": "real_normalization_and_evidence_duration",
                "dashboard_read_only": True,
            }
            with connect_lab(self.admin_dsn, self.identity, readonly=True) as connection:
                row = connection.execute(
                    "SELECT COALESCE(sum(input_accepted_count),0), "
                    "COALESCE(sum(processing_completed_count),0), "
                    "COALESCE(sum(processing_failed_count),0), "
                    "COALESCE(sum(latency_sample_count),0), COALESCE(sum(latency_sum_ns),0), "
                    "count(*) FROM pipeline_telemetry_buckets"
                ).fetchone()
                executions = connection.execute(
                    "SELECT count(*) FROM pipeline_telemetry_executions"
                ).fetchone()[0]
            state["stored"] = dict(
                zip(
                    (
                        "accepted",
                        "completed",
                        "failed",
                        "latency_samples",
                        "latency_sum_ns",
                        "buckets",
                    ),
                    map(int, row),
                    strict=True,
                )
            )
            state["stored"]["executions"] = executions
            return state

    def close(self):
        with self.condition:
            self._pause("closed")
            self.closed = True
            self.condition.notify_all()
        if self.thread.is_alive():
            self.thread.join(timeout=15)
            if self.thread.is_alive():
                raise RuntimeError("Owned lab worker did not stop")


class LabControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    speed: str | None = None


def create_lab_app(engine: LabEngine, port: int, control_token: str):
    """The production app/controllers, with a lab-only parent control page and warning."""
    app = create_app()
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {"http://" + host for host in hosts}

    @asynccontextmanager
    async def lifespan(_):
        engine.start_worker()
        try:
            yield
        finally:
            engine.close()

    app.router.lifespan_context = lifespan

    @app.middleware("http")
    async def lab_boundary(request: Request, call_next):
        if request.headers.get("host") not in hosts:
            return HTMLResponse("Local lab host only", status_code=403)
        if request.method != "GET" and not request.url.path.startswith("/lab/"):
            return HTMLResponse("Dashboard is read-only", status_code=405)
        response = await call_next(request)
        if request.url.path == "/dashboard" and response.status_code == 200:
            body = b"".join([chunk async for chunk in response.body_iterator]).decode("utf-8")
            response = labeled_dashboard(body, "격리 실험 화면 운영 실측 아님")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/lab", include_in_schema=False)
    def lab_page():
        return FileResponse(ASSETS / "lab.html")

    @app.get("/lab/assets/{name}", include_in_schema=False)
    def lab_asset(name: str):
        if name not in {"lab.css", "lab.mjs", "lab-contract.mjs"}:
            raise HTTPException(404, "Unknown lab asset")
        return FileResponse(
            ASSETS / name, media_type="text/css" if name.endswith("css") else "text/javascript"
        )

    @app.get("/lab/config", include_in_schema=False)
    def lab_config():
        return {**engine.identity.public(), "control_token": control_token}

    @app.get("/lab/status", include_in_schema=False)
    def lab_status():
        return engine.status()

    @app.post("/lab/control", include_in_schema=False)
    def lab_control(body: LabControl, request: Request):
        if not hmac.compare_digest(request.headers.get("x-lab-token", ""), control_token):
            raise HTTPException(403, "Lab control token required")
        if request.headers.get("origin") is not None and request.headers["origin"] not in origins:
            raise HTTPException(403, "Same-origin lab controls only")
        try:
            if body.action == "shutdown":
                engine.control("pause")
                app.state.shutdown()
            else:
                engine.control(body.action, body.speed)
        except ValueError:
            raise HTTPException(409, "Control rejected; check phase, speed or reset") from None
        return {"accepted": True}

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "cleanup"))
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--container", default="modeling-postgres-1")
    parser.add_argument(
        "--reuse-owned",
        action="store_true",
        help="Resume only this manifest's verified lab; no migrations",
    )
    parser.add_argument(
        "--state", type=Path, default=ROOT / "build/view2-reference/live-telemetry-lab/session.json"
    )
    args = parser.parse_args()
    admin_dsn = local_admin_dsn(args.container)
    if args.command == "cleanup":
        state = json.loads(args.state.read_text(encoding="utf-8"))
        identity = LabIdentity(**state["identity"])
        identity.validate()
        if state["port"] in RESERVED_PORTS:
            raise ValueError("Reserved server cannot be a cleanup target")
        with connect_lab(admin_dsn, identity, readonly=True):
            pass
        address = state["address"]
        if address != f"http://127.0.0.1:{int(state['port'])}":
            raise ValueError("Unexpected lab server address")
        try:
            request = UrlRequest(
                address + "/lab/control",
                data=b'{"action":"shutdown"}',
                headers={"Content-Type": "application/json", "X-Lab-Token": state["control_token"]},
            )
            with urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise ValueError("Owned lab shutdown was rejected")
            time.sleep(1)
        except URLError as error:
            if not isinstance(error.reason, ConnectionRefusedError):
                raise
        for attempt in range(20):
            try:
                drop_database(admin_dsn, identity)
                break
            except ValueError as error:
                if "sessions are still connected" not in str(error) or attempt == 19:
                    raise
                time.sleep(0.25)
        state["cleaned"] = True
        args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        print(json.dumps({**identity.public(), "dropped": True}))
        return
    if args.state.exists() and not args.reuse_owned:
        raise ValueError("State file already exists; do not overwrite an experiment")
    if args.port in RESERVED_PORTS or not 0 <= args.port <= 65535:
        raise ValueError("Existing server ports are reserved")
    sock = socket.socket()
    sock.bind(("127.0.0.1", args.port))
    port = sock.getsockname()[1]
    previous = None
    if args.reuse_owned:
        previous = json.loads(args.state.read_text(encoding="utf-8"))
        identity = LabIdentity(**previous["identity"])
        if previous["port"] != port or previous.get("cleaned"):
            raise ValueError("Cannot resume this manifest/port")
        with connect_lab(admin_dsn, identity, readonly=True):
            pass
        migrations = previous["migrations"]
    else:
        identity, migrations = create_database(admin_dsn)
    os.environ["INCIDENT_AWARENESS_DATABASE_URL"] = target_dsn(admin_dsn, identity)
    os.environ["PGOPTIONS"] = READ_OPTIONS
    os.environ.setdefault(
        "INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(ROOT / "configs/event_types_v0.2.yaml")
    )
    token = previous["control_token"] if previous else token_hex(32)
    state = {
        "identity": identity_record(identity),
        "control_token": token,
        "port": port,
        "address": f"http://127.0.0.1:{port}",
        "created_at": datetime.now(UTC).isoformat(),
        "migrations": migrations,
        "pid": os.getpid(),
        "simulation": True,
    }
    args.state.parent.mkdir(parents=True, exist_ok=True)
    try:
        # A concurrent fresh launch must not overwrite another experiment's manifest.
        with args.state.open("w" if previous else "x", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
    except OSError:
        if previous is None:
            drop_database(admin_dsn, identity)
        raise
    engine = LabEngine(admin_dsn, identity)
    if previous:
        engine.batches = engine.status()["stored"]["executions"]
        engine.phase = "completed" if engine.batches >= MAX_BATCHES else "paused"
    app = create_lab_app(engine, port, token)
    server = uvicorn.Server(
        uvicorn.Config(app, log_level="critical", access_log=False, proxy_headers=False)
    )
    app.state.shutdown = lambda: setattr(server, "should_exit", True)
    print(
        json.dumps(
            {**identity.public(), "address": state["address"] + "/lab", "read_only_dashboard": True}
        ),
        flush=True,
    )
    server.run(sockets=[sock])


if __name__ == "__main__":
    # The lab never prints raw DB/normalization exceptions, including connection strings.
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception as error:  # noqa: BLE001 - never print secrets from a failed lab command.
        print(
            json.dumps(
                {"error_type": type(error).__name__, "message": "Lab command failed closed"}
            ),
            flush=True,
        )
        raise SystemExit(1) from None
