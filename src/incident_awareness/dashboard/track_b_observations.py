"""Read-only, bounded Track-B projection. Never creates canonical or human records."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, field_validator

from incident_awareness.demo.r1_live_signal import DemoSignalState, R1LocalDemoSignal

RUN_PATTERN = re.compile(r"RUN-[0-9]{8}-[0-9]{3,6}\Z", re.ASCII)
SAFE_ID = re.compile(r"[A-Za-z0-9_.:{}-]{1,256}\Z", re.ASCII)
PROCESS_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)
MAX_BYTES = 262144
MAX_RUNS = 20
VERSION = "track_b_observations_v1"
KNOWN_DIAGNOSTICS = {"duplicate_process_guid", "ambiguous_demo_candidate"}
ReadStatus = Literal[
    "ok",
    "file_missing",
    "read_failed",
    "invalid_snapshot",
    "timeout",
    "connection_failed",
    "remote_error",
    "clock_skew",
    "configuration_error",
]


class ObservationQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("run_id")
    @classmethod
    def validate_runs(cls, values):
        if len(set(values)) != len(values) or any(not RUN_PATTERN.fullmatch(run) for run in values):
            raise ValueError("Invalid Track-B Run identity")
        return values


def registered_runs(value: str) -> tuple[str, ...]:
    runs = tuple(part.strip() for part in value.split(",") if part.strip())
    if (
        len(runs) > MAX_RUNS
        or len(set(runs)) != len(runs)
        or any(not RUN_PATTERN.fullmatch(run) for run in runs)
    ):
        raise ValueError("Invalid Track-B Run registration")
    return runs


class PublicObservation(BaseModel):
    """Only these allowlisted fields may cross the Snapshot service boundary."""

    model_config = ConfigDict(extra="forbid")
    source_kind: Literal["live_observation"] = "live_observation"
    data_class: Literal["demo_only"] = "demo_only"
    canonical_result: None = None
    run_id: str
    host_id: str | None = None
    detector_state: DemoSignalState | None = None
    state: Literal[
        "waiting", "observing", "condition_not_met", "demo_rule_match", "delayed", "unknown"
    ] = "unknown"
    read_status: ReadStatus = "ok"
    generated_at: AwareDatetime | None = None
    last_accepted_at: AwareDatetime | None = None
    accepted_chunk_count: int | None = Field(default=None, ge=0, strict=True)
    accepted_event_count: int | None = Field(default=None, ge=0, strict=True)
    policy_id: str | None = None
    policy_version: str | None = None
    policy_config_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_lineage: tuple[str, ...] = ()
    lineage_event_ids: tuple[str, ...] = ()
    network_event_id: str | None = None
    source_event_ids: tuple[str, ...] = ()
    terminal_process_guid: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    diagnostics: tuple[str, ...] = ()
    snapshot_age_ms: int | None = Field(default=None, ge=0, strict=True)
    acceptance: Literal["pending", "post_commit_ack_verified", "unknown"] = "unknown"
    acceptance_scope: Literal["detector_reported"] = "detector_reported"
    ledger_independently_verified: Literal[False] = False
    human_workflow: Literal[False] = False
    ai_report: Literal[False] = False
    formal_analysis: Literal[False] = False


class ObservationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["track_b_observations_v1"] = VERSION
    enabled: bool = True
    server_time: AwareDatetime
    items: tuple[PublicObservation, ...]


def _safe_projection(item: PublicObservation) -> None:
    if not RUN_PATTERN.fullmatch(item.run_id):
        raise ValueError("Invalid Run")
    ids = [
        item.host_id,
        item.policy_id,
        item.policy_version,
        item.network_event_id,
        item.terminal_process_guid,
        *item.lineage_event_ids,
        *item.source_event_ids,
    ]
    if any(value is not None and not SAFE_ID.fullmatch(value) for value in ids):
        raise ValueError("Invalid display identifier")
    if any(not PROCESS_NAME.fullmatch(name) for name in item.observed_lineage):
        raise ValueError("Invalid process name")
    if item.destination_ip is not None:
        ipaddress.ip_address(item.destination_ip)
    if any(code not in KNOWN_DIAGNOSTICS | {"other_input_diagnostic"} for code in item.diagnostics):
        raise ValueError("Invalid diagnostic")
    if item.read_status == "ok":
        if (
            item.generated_at is None
            or item.detector_state is None
            or item.accepted_chunk_count is None
            or item.accepted_event_count is None
        ):
            raise ValueError("Incomplete display projection")
        expected = "post_commit_ack_verified" if item.accepted_chunk_count else "pending"
        if (
            item.acceptance != expected
            or not item.policy_id
            or not item.policy_version
            or not item.policy_config_hash
        ):
            raise ValueError("Invalid acceptance projection")
        if item.accepted_chunk_count and (not item.host_id or item.last_accepted_at is None):
            raise ValueError("Incomplete accepted input")
        if item.last_accepted_at is not None and item.last_accepted_at > item.generated_at:
            raise ValueError("Invalid projected clock")
    if item.detector_state in {"condition_not_met", "demo_rule_match"} and (
        not item.accepted_chunk_count
        or not item.accepted_event_count
        or not item.host_id
        or len(item.observed_lineage) < 2
        or len(item.lineage_event_ids) != len(item.observed_lineage)
        or not item.network_event_id
        or not item.source_event_ids
        or not item.terminal_process_guid
        or item.diagnostics
        or len(set(item.lineage_event_ids)) != len(item.lineage_event_ids)
        or item.network_event_id in item.lineage_event_ids
        or item.accepted_event_count < len(item.lineage_event_ids) + 1
    ):
        raise ValueError("Incomplete candidate")


def age_state(item: PublicObservation, age_ms: int | None) -> PublicObservation:
    """Heartbeat freshness wins over an old Match. ACK time is never event time."""
    state = "unknown"
    if item.read_status == "ok" and age_ms is not None:
        if age_ms > 15000:
            state = "unknown"
        elif age_ms > 5000:
            state = "delayed"
        elif item.detector_state == "observing":
            state = "waiting" if item.accepted_chunk_count == 0 else "observing"
        elif item.detector_state in {"condition_not_met", "demo_rule_match"}:
            state = item.detector_state
    return item.model_copy(update={"state": state, "snapshot_age_ms": age_ms})


def _failure(run_id: str, status: ReadStatus) -> PublicObservation:
    return PublicObservation(run_id=run_id, read_status=status)


def _reject_links(path: Path) -> None:
    for part in [path, *path.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError("Linked Snapshot path")


class SnapshotReader:
    def __init__(
        self, root: Path, runs: tuple[str, ...], *, clock: Callable = lambda: datetime.now(UTC)
    ):
        if not root.is_absolute() or registered_runs(",".join(runs)) != runs:
            raise ValueError("Invalid Snapshot configuration")
        self.root, self.runs, self.clock = root, runs, clock

    def _read(self, run_id: str, now: datetime) -> PublicObservation:
        path = self.root / run_id / "demo-state.json"
        try:
            _reject_links(path)
            if path.resolve().parent.parent != self.root.resolve():
                raise ValueError("Snapshot path escape")
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
                raise ValueError("Invalid Snapshot file")
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                    raise ValueError("Invalid Snapshot file")
                raw = stream.read(MAX_BYTES + 1)
                after = os.fstat(stream.fileno())
            _reject_links(path)
            final = path.stat(follow_symlinks=False)
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or (final.st_ino, final.st_dev) != (after.st_ino, after.st_dev):
                raise ValueError("Snapshot changed during read")
            if len(raw) > MAX_BYTES:
                raise ValueError("Oversized Snapshot")

            # Reject duplicate keys and omitted defaulted fields, not just parseable JSON.
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate JSON key")
                    result[key] = value
                return result

            payload = json.loads(raw, object_pairs_hook=unique)
            required = {
                field.serialization_alias or name
                for name, field in R1LocalDemoSignal.model_fields.items()
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise ValueError("Incomplete Snapshot")
            for name in ("generated_at", "last_accepted_at"):
                value = payload[name]
                if name == "last_accepted_at" and value is None:
                    continue
                if not isinstance(value, str) or not re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value
                ):
                    raise ValueError("Explicit zoned timestamp required")
            signal = R1LocalDemoSignal.model_validate_json(raw, strict=True)
            if signal.run_id != run_id or signal.generated_at.tzinfo is None:
                raise ValueError("Snapshot scope or clock")
            if signal.last_accepted_at is not None and (
                signal.last_accepted_at.tzinfo is None
                or signal.last_accepted_at > signal.generated_at
            ):
                raise ValueError("Invalid acceptance clock")
            if signal.accepted_chunk_count and signal.last_accepted_at is None:
                raise ValueError("Missing acceptance clock")
            if signal.accepted_chunk_count == 0 and (
                signal.accepted_event_count or signal.last_accepted_at is not None
            ):
                raise ValueError("Contradictory acceptance")
            item = PublicObservation(
                run_id=run_id,
                host_id=signal.host_id,
                detector_state=signal.state,
                generated_at=signal.generated_at,
                last_accepted_at=signal.last_accepted_at,
                accepted_chunk_count=signal.accepted_chunk_count,
                accepted_event_count=signal.accepted_event_count,
                policy_id=signal.policy.policy_id,
                policy_version=signal.policy.version,
                policy_config_hash=signal.policy.config_hash,
                observed_lineage=signal.observed_lineage or (),
                lineage_event_ids=signal.lineage_event_ids,
                network_event_id=signal.network_event_id,
                source_event_ids=signal.source_event_ids,
                terminal_process_guid=signal.terminal_process_guid,
                destination_ip=signal.destination_ip,
                destination_port=signal.destination_port,
                diagnostics=tuple(
                    code if code in KNOWN_DIAGNOSTICS else "other_input_diagnostic"
                    for code in signal.diagnostics
                ),
                acceptance="post_commit_ack_verified" if signal.accepted_chunk_count else "pending",
            )
            _safe_projection(item)
            delta = now - signal.generated_at
            microseconds = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
            if microseconds < 0:
                return item.model_copy(update={"read_status": "clock_skew"})
            return age_state(item, (microseconds + 999) // 1000)
        except FileNotFoundError:
            return _failure(run_id, "file_missing")
        except OSError:
            return _failure(run_id, "read_failed")
        except (ValueError, TypeError, OverflowError, ValidationError):
            return _failure(run_id, "invalid_snapshot")

    def read(self, runs: tuple[str, ...] | None = None) -> ObservationEnvelope:
        selected = self.runs if runs is None else runs
        if any(not RUN_PATTERN.fullmatch(run) or run not in self.runs for run in selected):
            raise LookupError("Unregistered Track-B Run")
        now = self.clock()
        return ObservationEnvelope(
            server_time=now, items=tuple(self._read(run, now) for run in selected)
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


@dataclass(frozen=True)
class RemoteSettings:
    enabled: bool = False
    origin: str = ""
    runs: tuple[str, ...] = ()
    token: str = ""
    timeout: float = 2.0

    @classmethod
    def from_environment(cls):
        return cls(
            enabled=os.environ.get("TRACK_B_OBSERVATIONS_ENABLED") == "1",
            origin=os.environ.get("TRACK_B_OBSERVATIONS_ORIGIN", ""),
            runs=registered_runs(os.environ.get("TRACK_B_RUN_IDS", "")),
            token=os.environ.get("TRACK_B_READ_TOKEN", ""),
        )

    def validate(self):
        url = urllib.parse.urlsplit(self.origin)
        if (
            url.scheme not in {"http", "https"}
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
            or url.username
            or url.password
        ):
            raise ValueError("Invalid fixed Snapshot origin")
        ipaddress.ip_address(
            url.hostname or ""
        )  # Fixed literal address; no DNS or request-supplied destination.
        if url.port is None or not self.runs or len(self.token) < 32 or not 0 < self.timeout <= 5:
            raise ValueError("Incomplete Snapshot remote configuration")


class RemoteObservationReader:
    def __init__(self, settings: RemoteSettings, *, clock=lambda: datetime.now(UTC), opener=None):
        self.settings, self.clock = settings, clock
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def read(self, runs: tuple[str, ...] | None = None) -> ObservationEnvelope:
        settings = self.settings
        selected = settings.runs if runs is None else runs
        if any(not RUN_PATTERN.fullmatch(run) or run not in settings.runs for run in selected):
            raise LookupError("Unregistered Track-B Run")
        if not settings.enabled:
            return ObservationEnvelope(enabled=False, server_time=self.clock(), items=())
        status: ReadStatus = "remote_error"
        try:
            settings.validate()
        except ValueError:
            return ObservationEnvelope(
                server_time=self.clock(),
                items=tuple(_failure(run, "configuration_error") for run in selected),
            )
        try:
            start, tick = self.clock(), time.monotonic_ns()
            query = urllib.parse.urlencode([("run_id", run) for run in selected])
            request = urllib.request.Request(
                settings.origin.rstrip("/") + "/operations/observations?" + query,
                headers={"Authorization": "Bearer " + settings.token, "Accept": "application/json"},
            )
            with self.opener.open(request, timeout=settings.timeout) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Oversized remote response")
            remote = ObservationEnvelope.model_validate_json(raw, strict=True)
            elapsed_ms = max(0, (time.monotonic_ns() - tick + 999999) // 1000000)
            finish = self.clock()
            midpoint = start + (finish - start) / 2
            if not remote.enabled or tuple(item.run_id for item in remote.items) != selected:
                raise ValueError("Remote scope mismatch")
            skew = abs((remote.server_time - midpoint).total_seconds()) > 2
            values = []
            for item in remote.items:
                _safe_projection(item)
                if skew or (
                    item.generated_at is not None and item.generated_at > remote.server_time
                ):
                    values.append(
                        age_state(item.model_copy(update={"read_status": "clock_skew"}), None)
                    )
                else:
                    age = (
                        None if item.snapshot_age_ms is None else item.snapshot_age_ms + elapsed_ms
                    )
                    if item.generated_at is not None:
                        age = max(
                            age or 0, int((finish - item.generated_at).total_seconds() * 1000)
                        )
                    values.append(age_state(item, age))
            return ObservationEnvelope(server_time=finish, items=tuple(values))
        except TimeoutError:
            status = "timeout"
        except urllib.error.HTTPError:
            status = "remote_error"
        except urllib.error.URLError as error:
            status = (
                "timeout"
                if isinstance(error.reason, (TimeoutError, socket.timeout))
                else "connection_failed"
            )
        except OSError:
            status = "connection_failed"
        except (ValueError, TypeError, OverflowError, ValidationError):
            status = "remote_error"
        return ObservationEnvelope(
            server_time=self.clock(), items=tuple(_failure(run, status) for run in selected)
        )
