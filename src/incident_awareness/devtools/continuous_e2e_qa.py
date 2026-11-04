"""Opt-in loopback continuous batch QA; reviewed fixture replay, not live EDR ingest."""

import argparse
import hashlib
import hmac
import json
import logging
import os
import random
import socket
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from typing import Literal

import uvicorn
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict

from incident_awareness.devtools import labeled_dashboard
from incident_awareness.devtools.continuous_qa_database import (
    ContinuousQaIdentity,
    create_continuous_database,
)
from incident_awareness.devtools.final_e2e_qa import ROOT, QaRunner, fixture_rows
from incident_awareness.devtools.telemetry_lab_database import (
    READ_OPTIONS,
    connect_lab,
    identity_record,
    local_admin_dsn,
    target_dsn,
    verify_owner,
)
from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

OUT = ROOT / "build/view2-reference/continuous-e2e-qa"
RESERVED = {8765, 8766, 8767, 8768, 8778, 8787, 8788, 8790, 8791}
PATTERNS = {
    "low": ((3, 6, 9), (4.0, 7.0)),
    "random": ((30, 60, 120, 240), (2.0, 5.0)),
    "burst": ((30, 60, 120, 600), (1.0, 4.0)),
}
# Session-wide persistent caps, not time-based shutdown. No backlog or parallel workers.
MAX_RUNS = 200
MAX_RECORDS = 120000
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_DATABASE_BYTES = 256 * 1024 * 1024
LOCK_KEY = 719203
FIXTURE_HASHES = {
    "normal": "c700f058b2da239c890d5282b02eea8c6c9367ee2b4944068c302996e2110232",
    "attack": "b54904e556a93a75199823686731992fae206d264dfe48801a502cd6832c926d",
}


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def write_state(path: Path, value: dict) -> None:
    """Reserve identity before executing; an interrupted reservation is never replayed."""
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


class ContinuousBackend:
    def __init__(self, admin: str, identity: ContinuousQaIdentity):
        self.admin = admin
        self.identity = identity
        self.lease = connect_lab(admin, identity, readonly=True)
        self.lease.autocommit = True
        if not self.lease.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0]:
            self.lease.close()
            raise ValueError("Another continuous QA owner holds this DB")

    def inventory(self) -> tuple[set[str], int]:
        # Re-check the lease/ownership before every batch; a lost connection stops scheduling.
        verify_owner(self.lease, self.identity)
        with connect_lab(self.admin, self.identity, readonly=True) as connection:
            size = connection.execute("SELECT pg_database_size(current_database())").fetchone()[0]
            ids = connection.execute(
                "SELECT run_id FROM runs UNION SELECT run_id FROM pipeline_runtime_status "
                "UNION SELECT run_id FROM pipeline_telemetry_executions"
            ).fetchall()
        return {row[0] for row in ids}, size

    def observations(self, job: dict) -> dict:
        with connect_lab(self.admin, self.identity, readonly=True) as connection:
            snapshot = PipelineTelemetryRepository(connection).get_execution(job["execution_id"])
        if (
            snapshot is None
            or (snapshot.run_id, snapshot.entity_id) != (job["run_id"], job["entity_id"])
            or snapshot.observation_status != "observed"
        ):
            raise ValueError("Actual observer snapshot missing or inconsistent")
        buckets = snapshot.buckets
        accepted = sum(bucket.input_accepted_count for bucket in buckets)
        completed = sum(bucket.processing_completed_count for bucket in buckets)
        samples = sum(bucket.latency_sample_count for bucket in buckets)
        duration = sum(bucket.latency_sum_ns for bucket in buckets)
        if accepted != job["records"] or completed != job["records"] or samples != completed:
            raise ValueError("Actual counts do not match the completed batch")
        return {
            "input_accepted_count": accepted,
            "processing_completed_count": completed,
            "latency_sample_count": samples,
            "latency_sum_ns": duration,
            "latency_mean_ms": duration / samples / 1000000 if samples else None,
            "execution_id": snapshot.execution_id,
            "last_observed_at": snapshot.last_observed_at.isoformat(),
        }

    def close(self) -> None:
        self.lease.close()  # Releases only this process's session advisory lock.


class ContinuousRunner(QaRunner):
    def __init__(self, admin, identity, *, output_dir=OUT, backend=None, rng=None):
        super().__init__(admin, identity, output_dir=output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.output_dir / "controller-state.json"
        self.backend = backend if backend is not None else ContinuousBackend(admin, identity)
        self.rng = rng if rng is not None else random.SystemRandom()
        self.halt = threading.Event()
        self.phase = "stopped"
        self.pattern = "low"
        self.reason = "ready"
        self.last_error = None
        self.closed = False
        self.current_run_id = None
        if self.state_path.exists():
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
            if (
                saved["schema_version"] != "continuous_batch_qa_v1"
                or saved["database"] != identity.database
            ):
                raise ValueError("Continuous journal ownership mismatch")
            self.jobs = saved["jobs"]
            for job in self.jobs:
                if job["phase"] not in {"completed", "failed", "interrupted"}:
                    job["phase"] = "interrupted"
                    job["ended_at"] = now()
                    self.last_error = (
                        "Interrupted reservation; no automatic replay; inspect stored results"
                    )
            self.reason = "restart_stopped"
        elif self.backend.inventory()[0]:
            raise ValueError("Nonempty DB without its reservation journal; refusing quota reset")
        self._save()

    def _save(self):
        write_state(
            self.state_path,
            {
                "schema_version": "continuous_batch_qa_v1",
                "database": self.identity.database,
                "phase": self.phase,
                "reason": self.reason,
                "jobs": self.jobs,
            },
        )

    def start(self, pattern="low"):
        if pattern not in PATTERNS:
            raise ValueError("Unknown reviewed pattern")
        with self.lock:
            if self.closed or (self.thread is not None and self.thread.is_alive()):
                raise ValueError("Worker already active or shutting down")
            self.pattern = pattern
            self.phase = "scheduling"
            self.reason = None
            self.last_error = None
            self.halt.clear()
            try:
                self._save()
            except OSError:
                self.phase, self.reason, self.last_error = (
                    "failed",
                    "journal_unavailable",
                    "OSError",
                )
                self.halt.set()
                raise
            self.thread = threading.Thread(
                target=self._loop, name="continuous-pipeline", daemon=False
            )
            self.thread.start()
        return self.status()

    def stop(self):
        with self.lock:
            self.halt.set()
            if self.phase not in {"stopped", "failed", "limited"}:
                self.phase = "draining" if self.current_run_id else "stopped"
                self.reason = "user_stop"
            self._save()
        return self.status()

    def _reserve(self):
        used, size = self.backend.inventory()
        used.update(job["run_id"] for job in self.jobs)
        counts, gap = PATTERNS[self.pattern]
        count = self.rng.choice(counts)
        artifact_bytes = sum(
            path.stat().st_size
            for directory in ("inputs", "runs")
            for path in (self.output_dir / directory).rglob("*")
            if path.is_file()
        )
        reserved = sum(job["records"] for job in self.jobs)
        reason = (
            "run_limit"
            if len(self.jobs) >= MAX_RUNS
            else (
                "record_limit"
                if reserved + count > MAX_RECORDS
                else "database_size_limit"
                if size + 16 * 1024 * 1024 >= MAX_DATABASE_BYTES
                else "artifact_size_limit"
                if artifact_bytes + 16 * 1024 * 1024 >= MAX_ARTIFACT_BYTES
                else None
            )
        )
        if reason:
            self.phase, self.reason = "limited", reason
            return None
        prefix = f"RUN-{datetime.now(UTC):%Y%m%d}-"
        run_id = next(
            (
                f"{prefix}{number:03d}"
                for number in range(1, 1000)
                if f"{prefix}{number:03d}" not in used
                and not (self.output_dir / "runs" / f"{prefix}{number:03d}").exists()
            ),
            None,
        )
        if run_id is None:
            self.phase, self.reason = "limited", "run_identity_exhausted"
            return None
        kind = ("normal", "attack")[len(self.jobs) % 2]
        # Alternate both reviewed families; randomness changes complete-batch sizes/gaps only.
        path = ROOT / "tests/fixtures/pipeline/e2e_qa" / f"{kind}.jsonl"
        if hashlib.sha256(path.read_bytes()).hexdigest() != FIXTURE_HASHES[kind]:
            raise ValueError("Reviewed fixture changed since process startup")
        fixture_rows(kind, count)  # Validate before reserving; all patterns use full triplets.
        job = {
            "run_id": run_id,
            "kind": kind,
            "records": count,
            "phase": "reserved",
            "execution_id": None,
            "started_at": now(),
            "runtime_history": [],
            "pattern": self.pattern,
            "next_gap_seconds": self.rng.uniform(*gap),
        }
        self.jobs.append(job)
        self.current_run_id = run_id
        self.phase = "running"
        self._save()  # If disk fails, no Pipeline is started.
        return job

    def _loop(self):
        try:
            while not self.halt.is_set():
                with self.lock:
                    if self.halt.is_set():
                        break
                    job = self._reserve()
                if job is None:
                    break
                self._execute(job)  # Entire existing real Standalone Pipeline, no operation sleeps.
                if job["phase"] != "completed":
                    raise RuntimeError(job.get("error_type", "PipelineFailed"))
                actual = self.backend.observations(job)
                with self.lock:
                    job["observations"] = actual
                    self.current_run_id = None
                    self.phase = "waiting" if not self.halt.is_set() else "stopped"
                    self._save()
                # Only inter-batch scheduling waits, never artificially slow a Pipeline stage.
                self.halt.wait(job["next_gap_seconds"])
        except Exception as error:  # noqa: BLE001 - never expose DB credentials/error text.
            with self.lock:
                self.phase, self.reason = "failed", "safe_stop"
                self.last_error = type(error).__name__
                self.halt.set()
        finally:
            with self.lock:
                self.current_run_id = None
                if self.phase not in {"failed", "limited"}:
                    self.phase = "stopped"
                try:
                    self._save()
                except OSError:
                    self.phase, self.reason, self.last_error = (
                        "failed",
                        "journal_unavailable",
                        "OSError",
                    )

    def status(self):
        with self.lock:
            observed = [job["observations"] for job in self.jobs if "observations" in job]
            return json.loads(
                json.dumps(
                    {
                        "schema_version": "continuous_batch_qa_v1",
                        "fixture_only": True,
                        "pipeline_mode": "repeated_standalone_batch",
                        "database": self.identity.database,
                        "phase": self.phase,
                        "pattern": self.pattern,
                        "reason": self.reason,
                        "last_error": self.last_error,
                        "current_run_id": self.current_run_id,
                        "batch_count": len(self.jobs),
                        "reserved_records": sum(job["records"] for job in self.jobs),
                        "input_accepted_count": sum(
                            item["input_accepted_count"] for item in observed
                        )
                        if observed
                        else None,
                        "processing_completed_count": sum(
                            item["processing_completed_count"] for item in observed
                        )
                        if observed
                        else None,
                        "counter_scope": "verified completed execution snapshots; fixture processing attempts, not unique external events",
                        "limits": {
                            "runs": MAX_RUNS,
                            "records": MAX_RECORDS,
                            "batch_records": 600,
                            "artifact_bytes": MAX_ARTIFACT_BYTES,
                            "database_bytes": MAX_DATABASE_BYTES,
                        },
                        "jobs": [
                            {**job, "runtime_history": job["runtime_history"][-8:]}
                            for job in self.jobs[-20:]
                        ],
                    }
                )
            )

    def close(self):
        with self.lock:
            self.closed = True
        self.stop()
        if self.thread is not None:
            self.thread.join()  # Drain the actual business transaction, no thread kill/DB cancellation.
        self.backend.close()


class StartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pattern: Literal["low", "random", "burst"] = "low"


def create_continuous_app(runner, port: int, token: str):
    from incident_awareness.dashboard.api.app import create_app

    @asynccontextmanager
    async def lifespan(_app):
        yield
        # FastAPI shutdown stops scheduling and drains before the ownership lease is released.
        await __import__("asyncio").to_thread(runner.close)

    app = create_app()
    app.router.lifespan_context = lifespan
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.headers.get("host") not in hosts or request.client.host not in {
            "127.0.0.1",
            "::1",
            "testclient",
        }:
            return HTMLResponse("Loopback QA only", status_code=403)
        if request.method != "GET":
            if request.method != "POST" or request.url.path not in {"/qa/start", "/qa/stop"}:
                return HTMLResponse("Read-only Dashboard", status_code=405)
            if not hmac.compare_digest(request.headers.get("x-qa-token", ""), token) or (
                request.headers.get("origin") not in {"http://" + host for host in hosts}
            ):
                return HTMLResponse("Same-origin local control required", status_code=403)
        response = await call_next(request)
        if request.url.path == "/dashboard" and response.status_code == 200:
            body = b"".join([part async for part in response.body_iterator]).decode("utf-8")
            response = labeled_dashboard(body, "연속 Batch QA · fixture 반복 · 운영 실측 아님")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/qa", include_in_schema=False)
    def page():
        template = (Path(__file__).parent / "continuous_qa.html").read_text(encoding="utf-8")
        return HTMLResponse(template.replace("__CONTROL_TOKEN__", json.dumps(token)))

    @app.get("/qa/status", include_in_schema=False)
    def status():
        return runner.status()

    @app.post("/qa/start", include_in_schema=False)
    def start(body: StartRequest):
        try:
            return runner.start(body.pattern)
        except ValueError:
            raise HTTPException(409, "Worker already active or invalid state") from None
        except OSError:
            raise HTTPException(503, "Control journal unavailable; no input scheduled") from None

    @app.post("/qa/stop", include_in_schema=False)
    def stop():
        return runner.stop()

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument("--reuse-owned", action="store_true")
    parser.add_argument("--cleanup-owned", action="store_true")
    args = parser.parse_args()
    if args.port in RESERVED or not 1024 <= args.port <= 65535:
        raise ValueError("Protected or invalid server port")
    admin = local_admin_dsn()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = OUT / "session.json"
    previous = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else None
    if args.cleanup_owned:
        from incident_awareness.devtools.telemetry_lab_database import drop_database

        if previous is None:
            raise ValueError("Owned cleanup manifest required")
        drop_database(admin, ContinuousQaIdentity(**previous["identity"]))
        print(json.dumps({"dropped": previous["identity"]["database"], "artifacts_retained": True}))
        return
    if bool(previous) != args.reuse_owned:
        raise ValueError("Explicit --reuse-owned required for an existing continuous QA session")
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", args.port))
    except OSError:
        if previous:
            raise ValueError("Resume port occupied; no second controller") from None
        sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    if previous:
        if previous["port"] != port:
            raise ValueError("Resume port mismatch")
        identity = ContinuousQaIdentity(**previous["identity"])
        migrations = previous["migrations"]
    else:
        identity, migrations = create_continuous_database(admin)
    token = previous["token"] if previous else token_hex(32)
    os.environ["INCIDENT_AWARENESS_DATABASE_URL"] = target_dsn(admin, identity)
    os.environ["PGOPTIONS"] = READ_OPTIONS
    os.environ["INCIDENT_AWARENESS_EVENT_TYPES_PATH"] = str(ROOT / "configs/event_types_v0.2.yaml")
    runner = ContinuousRunner(admin, identity)
    state = {
        "identity": identity_record(identity),
        "port": port,
        "address": f"http://127.0.0.1:{port}",
        "token": token,
        "migrations": migrations,
        "pid": os.getpid(),
    }
    write_state(manifest, state)
    print(
        json.dumps(
            {"database": identity.database, "qa": state["address"] + "/qa", "phase": "stopped"}
        ),
        flush=True,
    )
    try:
        uvicorn.Server(
            uvicorn.Config(
                create_continuous_app(runner, port, token),
                log_level="critical",
                access_log=False,
                proxy_headers=False,
            )
        ).run(sockets=[sock])
    finally:
        runner.close()


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception as error:  # noqa: BLE001 - do not print DSNs or database exception text.
        print(json.dumps({"error_type": type(error).__name__, "failed_closed": True}))
        raise SystemExit(1) from None
